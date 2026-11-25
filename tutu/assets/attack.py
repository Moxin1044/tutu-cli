"""资产搜集主流程：子域名 / IP → DNS → HTTP 指纹 → 端口 → 漏洞关联。"""
from __future__ import annotations

import ipaddress
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Sequence

from ..http import HttpClient
from ..lookup.ip import lookup_ip
from ..utils import utc_now
from .correlate import correlate_assets
from .dns import is_wildcard, public_ips, resolve_host
from .models import Asset, AttackSurface, PortResult
from .ports import scan_hosts
from .probe import probe_host
from .subdomain import collect_subdomains, normalize_domain

log = logging.getLogger("tutu.assets")

DEFAULT_LIMIT = 120


def _resolve_asset(asset: Asset, timeout: float) -> None:
    http = HttpClient(timeout=timeout)
    data = resolve_host(asset.host, http)
    asset.ips = data.get("A", []) + data.get("AAAA", [])
    asset.cnames = data.get("CNAME", [])
    if not asset.ips and asset.extra_ip:
        asset.ips = [asset.extra_ip]
        asset.note = "仅来自被动源的 IP，未解析成功"


def _probe_asset(asset: Asset, timeout: float) -> None:
    http = HttpClient(timeout=timeout)
    asset.services = probe_host(asset.host, http, timeout=min(timeout, 12.0))


def _ip_target(
    network: ipaddress._BaseNetwork,
    limit: int,
    surface: AttackSurface,
) -> List[Asset]:
    if network.num_addresses <= 2:
        addresses = [str(network.network_address)]
    else:
        addresses = [str(ip) for ip in network.hosts()]
    if len(addresses) > limit:
        surface.notes.append(
            f"{network} 共 {network.num_addresses} 个地址，按 --asset-limit {limit} 仅处理前 {limit} 个"
        )
        addresses = addresses[:limit]
    surface.notes.append("IP / CIDR 输入：跳过被动子域名与泛解析检测")
    return [Asset(host=address, ips=[address], sources=["输入"]) for address in addresses]


def collect_assets(
    target: str,
    timeout: float = 20.0,
    limit: int = DEFAULT_LIMIT,
    ports: Optional[Sequence[int]] = None,
    probe_http: bool = True,
    threads: int = 12,
    correlate: bool = True,
    max_fingerprints: int = 5,
    ip_intel: bool = False,
    debug: bool = False,
) -> AttackSurface:
    started = time.monotonic()
    surface = AttackSurface(domain=target, generated=utc_now())

    network: Optional[ipaddress._BaseNetwork]
    try:
        network = ipaddress.ip_network((target or "").strip(), strict=False)
    except ValueError:
        network = None

    wildcard = False
    if network is not None:
        surface.domain = (
            str(network)
            if network.num_addresses > 1
            else str(network.network_address)
        )
        assets = _ip_target(network, max(1, limit), surface)
    else:
        domain = normalize_domain(target)
        if (
            not domain
            or "." not in domain
            or " " in domain
            or domain.replace(".", "").isdigit()
        ):
            raise ValueError(f"无效域名 / IP: {target}")
        surface.domain = domain

        merged, statuses = collect_subdomains(domain, timeout, debug=debug)
        surface.source_results = statuses

        discovered: Dict[str, Dict[str, str]] = {}
        for item in merged.items:
            extra = item.extra or {}
            discovered[item.title] = {
                "sources": ", ".join(extra.get("sources") or [item.source]),
                "ip": str(extra.get("ip") or ""),
            }
        discovered.setdefault(domain, {"sources": "根域", "ip": ""})

        def rank(host: str) -> tuple:
            meta = discovered.get(host, {})
            source_count = len(
                [s for s in str(meta.get("sources", "")).split(",") if s.strip()]
            )
            return (
                0 if host == domain else 1,
                -source_count,
                host.count("."),
                len(host),
                host,
            )

        hosts = [domain] + sorted(
            (host for host in discovered if host != domain), key=rank
        )
        if len(hosts) > max(1, limit):
            surface.notes.append(
                f"子域名共 {len(hosts) - 1} 个，按 --asset-limit {limit} 仅处理前 {limit - 1} 个"
            )
            hosts = hosts[: max(1, limit)]

        wildcard = is_wildcard(domain, HttpClient(timeout=timeout))
        if wildcard:
            surface.notes.append("检测到泛解析（wildcard DNS），未解析子域名的 IP 可能不可信")

        assets = []
        for host in hosts:
            meta = discovered.get(host, {})
            asset = Asset(
                host=host,
                sources=[
                    s.strip()
                    for s in str(meta.get("sources", "")).split(",")
                    if s.strip()
                ],
                wildcard=wildcard,
            )
            asset.extra_ip = str(meta.get("ip") or "")
            assets.append(asset)

        with ThreadPoolExecutor(max_workers=max(1, min(threads, 32))) as pool:
            futures = {
                pool.submit(_resolve_asset, asset, timeout): asset
                for asset in assets
            }
            for future in as_completed(futures):
                asset = futures[future]
                try:
                    future.result()
                except Exception as exc:  # noqa: BLE001
                    asset.note = str(exc)[:160] or exc.__class__.__name__
                    if debug:
                        log.debug("解析 %s 失败: %s", asset.host, exc)

        unresolved = sum(1 for asset in assets if not asset.ips)
        if unresolved:
            surface.notes.append(
                f"{unresolved} 个子域名未解析成功（可能已下线、仅内网可见或受泛解析影响）"
            )

    if probe_http:
        with ThreadPoolExecutor(max_workers=max(1, min(threads, 32))) as pool:
            futures = {
                pool.submit(_probe_asset, asset, timeout): asset
                for asset in assets
                if asset.ips
            }
            for future in as_completed(futures):
                asset = futures[future]
                try:
                    future.result()
                except Exception as exc:  # noqa: BLE001
                    if debug:
                        log.debug("探测 %s 失败: %s", asset.host, exc)
                if asset.services and not asset.note:
                    status = asset.services[0].status
                    if status in (401, 403):
                        asset.note = f"HTTP {status}（需要认证/被拦截）"
                elif not asset.services and asset.ips and not asset.note:
                    asset.note = "未响应 HTTP(S)"

    port_results: List[PortResult] = []
    if ports:
        scan_targets = [asset.host for asset in assets if asset.ips]
        port_results = scan_hosts(
            scan_targets,
            ports,
            timeout=min(timeout, 3.0),
            threads=max(threads, 32),
        )
        by_host: Dict[str, List[PortResult]] = {}
        for row in port_results:
            by_host.setdefault(row.host, []).append(row)
        for asset in assets:
            if asset.host in by_host:
                asset.open_ports = by_host[asset.host]
                if not asset.note:
                    asset.note = f"开放 {len(asset.open_ports)} 个端口"

    if correlate and any(asset.services for asset in assets):
        hits, notes = correlate_assets(
            assets,
            timeout=timeout,
            max_fingerprints=max_fingerprints,
            debug=debug,
        )
        surface.cve_hits = hits
        surface.notes.extend(notes)

    if ip_intel:
        unique = public_ips([ip for asset in assets for ip in asset.ips])
        if unique:
            intel: Dict[str, Dict[str, object]] = {}
            with ThreadPoolExecutor(max_workers=min(4, len(unique))) as pool:
                futures = {
                    pool.submit(lookup_ip, ip, timeout=max(timeout, 15.0)): ip
                    for ip in unique[:20]
                }
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        report = future.result()
                    except Exception as exc:  # noqa: BLE001
                        if debug:
                            log.debug("IP 情报 %s 失败: %s", ip, exc)
                        continue
                    reputation = report.get("reputation") or {}
                    soc = report.get("socradar_ioc") or {}
                    intel[ip] = {
                        "risk": reputation.get("risk", "unknown"),
                        "reasons": reputation.get("reasons") or [],
                        "asn": report.get("asn", ""),
                        "org": report.get("org", ""),
                        "country": (report.get("geo") or {}).get("country", ""),
                        "open_ports": soc.get("open_ports") or [],
                        "passive_dns": soc.get("passive_dns") or [],
                    }
            surface.stats["ip_intel"] = intel
            risky = [
                ip
                for ip, row in intel.items()
                if row.get("risk") in ("malicious", "suspicious")
            ]
            if risky:
                surface.notes.append("IP 情报标记可疑: " + ", ".join(risky))

    assets.sort(
        key=lambda a: (
            0 if a.services else (1 if a.ips else 2),
            a.host.count("."),
            a.host,
        )
    )
    surface.assets = assets
    surface.stats.update(
        {
            "subdomains": 0 if network is not None else max(0, len(assets) - 1),
            "hosts_processed": len(assets),
            "resolved": sum(1 for a in assets if a.ips),
            "unresolved": sum(1 for a in assets if not a.ips),
            "alive": sum(1 for a in assets if a.services),
            "services": sum(len(a.services) for a in assets),
            "open_ports": len(port_results),
            "unique_ips": len({ip for a in assets for ip in a.ips}),
            "cve_hits": len(surface.cve_hits),
            "port_scan": "on" if ports else "off",
            "input": "ip" if network is not None else "domain",
            "elapsed": round(time.monotonic() - started, 1),
        }
    )
    if not ports:
        surface.notes.append("端口扫描未启用；如需扫描请加 --ports top100 或 --ports 80,443,8080")
    surface.notes = list(dict.fromkeys(note for note in surface.notes if note))
    return surface
