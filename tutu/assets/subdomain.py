"""被动子域名搜集：只使用公开证书日志 / 公开 API，不发包探测目标。"""
from __future__ import annotations

import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional, Tuple

from ..cache import cached
from ..http import DEFAULT_UA, HttpClient
from ..models import Item, SourceResult

log = logging.getLogger("tutu.assets.subdomain")

HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9_\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9_\-]*[a-z0-9])?)+$")
SUBDOMAIN_TTL = 3600


def normalize_domain(value: str) -> str:
    """接受 example.com / https://example.com/path / *.example.com。"""
    value = (value or "").strip().lower()
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value)
    value = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    value = value.split("@")[-1].split(":", 1)[0]
    value = value.strip(".")
    if value.startswith("*."):
        value = value[2:]
    return value


def _clean_host(raw: str, domain: str) -> str:
    host = (raw or "").strip().lower().rstrip(".")
    if not host or "@" in host or " " in host:
        return ""
    if host.startswith("*."):
        host = host[2:]
    if not HOST_RE.match(host):
        return ""
    if not (host == domain or host.endswith("." + domain)):
        return ""
    return host


def _item(host: str, source: str, extra: Optional[Dict[str, str]] = None) -> Item:
    return Item(
        source=source,
        category="subdomain",
        title=host,
        extra=dict(extra or {}),
    )


def _crtsh(domain: str, http: HttpClient) -> List[Item]:
    data = http.get_json(
        "https://crt.sh/",
        params={"q": f"%.{domain}", "output": "json"},
        timeout=max(http.timeout, 45.0),
    )
    hosts: List[str] = []
    for row in data if isinstance(data, list) else []:
        if not isinstance(row, dict):
            continue
        for field in ("name_value", "common_name"):
            for line in str(row.get(field) or "").splitlines():
                host = _clean_host(line, domain)
                if host and host not in hosts:
                    hosts.append(host)
        if len(hosts) >= 2000:
            break
    return [_item(host, "crtsh") for host in hosts]


def _certspotter(domain: str, http: HttpClient) -> List[Item]:
    data = http.get_json(
        "https://api.certspotter.com/v1/issuances",
        params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
    )
    hosts: List[str] = []
    for row in data if isinstance(data, list) else []:
        if not isinstance(row, dict):
            continue
        for name in row.get("dns_names") or []:
            host = _clean_host(str(name), domain)
            if host and host not in hosts:
                hosts.append(host)
    return [_item(host, "certspotter") for host in hosts]


def _hackertarget(domain: str, http: HttpClient) -> List[Item]:
    text = http.get_text(
        "https://api.hackertarget.com/hostsearch/",
        params={"q": domain},
    )
    if "error" in text.lower()[:80] or "API count exceeded" in text:
        return []
    items: List[Item] = []
    for line in text.splitlines():
        parts = line.strip().split(",")
        host = _clean_host(parts[0], domain) if parts else ""
        if not host:
            continue
        ip = parts[1].strip() if len(parts) > 1 else ""
        items.append(_item(host, "hackertarget", {"ip": ip} if ip else None))
    return items


def _rapiddns(domain: str, http: HttpClient) -> List[Item]:
    text = http.get_text(
        f"https://rapiddns.io/subdomain/{domain}",
        params={"full": "1"},
        timeout=max(http.timeout, 30.0),
    )
    hosts: List[str] = []
    for cell in re.findall(r"<td[^>]*>\s*([^<\s]+)\s*</td>", text):
        host = _clean_host(cell, domain)
        if host and host not in hosts:
            hosts.append(host)
    return [_item(host, "rapiddns") for host in hosts]


def _urlscan(domain: str, http: HttpClient) -> List[Item]:
    data = http.get_json(
        "https://urlscan.io/api/v1/search/",
        params={"q": f"domain:{domain}", "size": 100},
    )
    hosts: List[str] = []
    for row in data.get("results") or []:
        if not isinstance(row, dict):
            continue
        page = row.get("page") or {}
        for value in (page.get("domain"), (row.get("task") or {}).get("domain")):
            host = _clean_host(str(value or ""), domain)
            if host and host not in hosts:
                hosts.append(host)
    return [_item(host, "urlscan") for host in hosts]


def _subdomain_center(domain: str, http: HttpClient) -> List[Item]:
    data = http.get_json(
        "https://api.subdomain.center/",
        params={"domain": domain},
        timeout=max(http.timeout, 30.0),
    )
    hosts: List[str] = []
    if isinstance(data, list):
        for value in data:
            host = _clean_host(str(value), domain)
            if host and host not in hosts:
                hosts.append(host)
    return [_item(host, "subdomain_center") for host in hosts]


PROVIDERS: List[Tuple[str, str, str, Callable[[str, HttpClient], List[Item]]]] = [
    ("crtsh", "crt.sh 证书日志", "公开 CT 日志，覆盖最全", _crtsh),
    ("certspotter", "Cert Spotter", "公开 CT 日志 API", _certspotter),
    ("hackertarget", "HackerTarget", "公开 hostsearch API", _hackertarget),
    ("rapiddns", "RapidDNS", "公开子域名聚合站", _rapiddns),
    ("urlscan", "urlscan.io", "公开扫描结果中的域名", _urlscan),
    ("subdomain_center", "subdomain.center", "公开聚合 API（可能繁忙）", _subdomain_center),
]

PROVIDER_LABELS = {name: label for name, label, _desc, _fn in PROVIDERS}


def _run_provider(
    name: str,
    label: str,
    func: Callable[[str, HttpClient], List[Item]],
    domain: str,
    timeout: float,
) -> SourceResult:
    started = time.monotonic()
    result = SourceResult(source=name, label=label)
    try:
        http = HttpClient(timeout=timeout, user_agent=DEFAULT_UA)
        result.items = cached(
            f"asset_subdomains_{name}_{domain}",
            SUBDOMAIN_TTL,
            lambda: [item.to_dict() for item in func(domain, http)],
        )
        result.items = [
            Item(
                source=row.get("source", name),
                category="subdomain",
                title=row.get("title", ""),
                extra=row.get("extra") or {},
            )
            for row in result.items
            if isinstance(row, dict) and row.get("title")
        ]
    except Exception as exc:  # noqa: BLE001 - 单源失败不影响整体
        result.error = str(exc)[:240] or exc.__class__.__name__
    result.elapsed = time.monotonic() - started
    return result


def collect_subdomains(
    domain: str,
    timeout: float = 20.0,
    debug: bool = False,
) -> Tuple[SourceResult, List[SourceResult]]:
    """并行运行所有被动源，返回合并后的子域名来源表。"""
    merged: Dict[str, Item] = {}
    statuses: List[SourceResult] = []
    with ThreadPoolExecutor(max_workers=min(6, len(PROVIDERS))) as pool:
        futures = {
            pool.submit(_run_provider, name, label, func, domain, timeout): (name, label)
            for name, label, _desc, func in PROVIDERS
        }
        for future in as_completed(futures):
            name, label = futures[future]
            try:
                result = future.result()
            except Exception as exc:  # noqa: BLE001
                result = SourceResult(
                    source=name,
                    label=label,
                    error=str(exc)[:240] or exc.__class__.__name__,
                )
            statuses.append(result)
            for item in result.items:
                host = item.title
                if not host:
                    continue
                existing = merged.get(host)
                if existing is None:
                    extra = dict(item.extra or {})
                    extra["sources"] = [item.source]
                    merged[host] = _item(host, item.source, extra)
                    continue
                sources = existing.extra.setdefault("sources", [existing.source])
                if item.source not in sources:
                    sources.append(item.source)
                if (item.extra or {}).get("ip") and not existing.extra.get("ip"):
                    existing.extra["ip"] = item.extra["ip"]
            if debug and result.error:
                log.debug("被动源 %s 失败: %s", name, result.error)
    order = {name: index for index, (name, _label, _d, _f) in enumerate(PROVIDERS)}
    statuses.sort(key=lambda r: order.get(r.source, 99))
    total = SourceResult(
        source="passive",
        label="被动子域名汇总",
        items=[merged[host] for host in sorted(merged)],
    )
    total.note = (
        "、".join(f"{r.label} {len(r.items)}" for r in statuses if r.items)
        or "所有被动源均未返回结果"
    )
    return total, statuses
