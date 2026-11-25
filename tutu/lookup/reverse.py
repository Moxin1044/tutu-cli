"""IP 反查域名（被动 DNS / 公开反查站）。

只使用公开接口，不向目标发包。不同来源覆盖范围不同：
- webscan.cc：国内常用反查接口，通常带页面标题
- HackerTarget：reverseiplookup 文本接口，免费额度有限
- OTX AlienVault：被动 DNS，含历史记录
- RapidDNS：sameip 页面，HTML 解析
"""
from __future__ import annotations

import ipaddress
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

from ..cache import read_cache, write_cache
from ..http import HttpClient
from ..utils import clean_text, repair_mojibake, truncate

log = logging.getLogger("tutu.lookup.reverse")

WEBSCAN = "https://api.webscan.cc/"
HACKERTARGET = "https://api.hackertarget.com/reverseiplookup/"
OTX = "https://otx.alienvault.com/api/v1/indicators/{family}/{ip}/passive_dns"
RAPIDDNS = "https://rapiddns.io/sameip/{ip}"

REVERSE_TTL = 6 * 3600
DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I
)

PROVIDERS: List[Tuple[str, str, str]] = [
    ("webscan", "webscan.cc", "公开 IP 反查接口，含页面标题，国内覆盖较好"),
    ("hackertarget", "HackerTarget", "公开 reverseiplookup API，免费额度有限"),
    ("otx", "OTX AlienVault", "被动 DNS 历史记录，无需 Key"),
    ("rapiddns", "RapidDNS", "公开 sameip 聚合页，HTML 解析"),
]


def _clean_domain(value: str, ip: str) -> str:
    host = clean_text(value).lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    if not host or "@" in host or " " in host:
        return ""
    if host == ip or host.startswith("http://") or host.startswith("https://"):
        return ""
    if not DOMAIN_RE.match(host):
        return ""
    return host


def _fetch(name: str, func) -> Tuple[str, Optional[Dict[str, object]], str]:
    try:
        return name, func(), ""
    except Exception as exc:  # noqa: BLE001 - 单源失败不影响反查
        return name, None, str(exc)[:240] or exc.__class__.__name__


def _webscan(http: HttpClient, ip: str) -> Dict[str, object]:
    data = http.get_json(
        WEBSCAN,
        params={"action": "query", "ip": ip},
        timeout=max(http.timeout, 20.0),
    )
    rows = data if isinstance(data, list) else []
    domains: Dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        domain = _clean_domain(str(row.get("domain") or ""), ip)
        if not domain:
            continue
        title = repair_mojibake(clean_text(str(row.get("title") or "")))
        if title.lower() in ("null", "none", "undefined"):
            title = ""
        if title:
            domains[domain] = truncate(title, 120)
        else:
            domains.setdefault(domain, "")
    return {"domains": domains}


def _hackertarget(http: HttpClient, ip: str) -> Dict[str, object]:
    text = http.get_text(
        HACKERTARGET,
        params={"q": ip},
        timeout=max(http.timeout, 20.0),
    )
    lowered = text.lower()[:120]
    if "error" in lowered or "api count exceeded" in lowered or "no ptr records" in lowered:
        return {"domains": {}}
    domains: Dict[str, str] = {}
    for line in text.splitlines():
        domain = _clean_domain(line.strip(), ip)
        if domain:
            domains.setdefault(domain, "")
    return {"domains": domains}


def _otx(http: HttpClient, ip: str, family: str) -> Dict[str, object]:
    data = http.get_json(
        OTX.format(family=family, ip=ip),
        timeout=max(http.timeout, 20.0),
    )
    domains: Dict[str, str] = {}
    for row in data.get("passive_dns") or []:
        if not isinstance(row, dict):
            continue
        hostname = str(row.get("hostname") or "")
        domain = _clean_domain(hostname, ip)
        if domain:
            domains.setdefault(domain, "")
    return {"domains": domains}


def _rapiddns(http: HttpClient, ip: str) -> Dict[str, object]:
    text = http.get_text(
        RAPIDDNS.format(ip=ip),
        params={"full": "1"},
        timeout=max(http.timeout, 25.0),
    )
    domains: Dict[str, str] = {}
    for cell in re.findall(r"<td[^>]*>\s*([^<\s]+)\s*</td>", text):
        domain = _clean_domain(cell, ip)
        if domain:
            domains.setdefault(domain, "")
    return {"domains": domains}


def _collect(ip: str, timeout: float, family: str, limit: int) -> Dict[str, object]:
    http = HttpClient(timeout=timeout)
    tasks = {
        "webscan": lambda: _webscan(http, ip),
        "hackertarget": lambda: _hackertarget(http, ip),
        "otx": lambda: _otx(http, ip, family),
        "rapiddns": lambda: _rapiddns(http, ip),
    }
    merged: Dict[str, str] = {}
    sources: Dict[str, List[str]] = {}
    errors: Dict[str, str] = {}
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
        futures = [pool.submit(_fetch, name, func) for name, func in tasks.items()]
        for future in as_completed(futures):
            name, data, error = future.result()
            if error:
                errors[name] = error
                continue
            rows = (data or {}).get("domains") or {}
            for domain, title in rows.items():
                merged.setdefault(domain, "")
                if title and not merged.get(domain):
                    merged[domain] = str(title)
                sources.setdefault(domain, [])
                if name not in sources[domain]:
                    sources[domain].append(name)
    ordered = sorted(
        merged,
        key=lambda domain: (
            0 if merged.get(domain) else 1,
            -len(sources.get(domain) or []),
            domain.count("."),
            domain,
        ),
    )
    total = len(ordered)
    ordered = ordered[: max(1, limit)]
    return {
        "ip": ip,
        "domains": ordered,
        "titles": {domain: merged[domain] for domain in ordered if merged.get(domain)},
        "sources": {domain: sources.get(domain, []) for domain in ordered},
        "errors": errors,
        "total": total,
        "truncated": total > len(ordered),
        "elapsed": round(time.monotonic() - started, 1),
    }


def reverse_ip(
    ip: str,
    timeout: float = 20.0,
    limit: int = 100,
) -> Dict[str, object]:
    """反查与 IP 关联的域名；私有 / 保留地址直接返回空结果。"""
    try:
        address = ipaddress.ip_address((ip or "").strip())
    except ValueError as exc:
        raise ValueError(f"无效 IP 地址: {ip}") from exc
    ip_text = str(address)
    if address.is_private or address.is_loopback or address.is_link_local:
        return {
            "ip": ip_text,
            "domains": [],
            "titles": {},
            "sources": {},
            "errors": {},
            "total": 0,
            "truncated": False,
            "note": "私有/保留地址，跳过反查",
        }
    family = "IPv6" if address.version == 6 else "IPv4"
    cache_name = f"reverse_ip_{ip_text}_{max(1, limit)}"
    entry = read_cache(cache_name)
    now = time.time()
    if entry and now - float(entry.get("ts", 0) or 0) <= REVERSE_TTL:
        data = entry.get("data") or {}
        if data.get("domains"):
            return data
    data = _collect(ip_text, timeout, family, max(1, limit))
    # 只缓存有结果的查询，避免把临时限流/故障缓存 6 小时。
    if data.get("domains"):
        write_cache(cache_name, data)
    return data
