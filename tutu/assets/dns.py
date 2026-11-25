"""DNS 解析：优先使用 DNS-over-HTTPS，失败时回退到系统解析。"""
from __future__ import annotations

import ipaddress
import logging
import socket
from typing import Dict, List

from ..http import HttpClient, SourceError

log = logging.getLogger("tutu.assets.dns")

DOH = "https://dns.google/resolve"
DEFAULT_TYPES = ("A", "AAAA", "CNAME")
RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")


def _clean_name(value: str) -> str:
    return (value or "").strip().strip(".").lower()


def _answers(http: HttpClient, host: str, rtype: str) -> List[str]:
    data = http.get_json(
        DOH,
        params={"name": host, "type": rtype},
        headers={"Accept": "application/dns-json"},
    )
    status = data.get("Status")
    if status == 3:  # NXDOMAIN
        return []
    if status not in (0, None):
        raise SourceError(f"DNS {rtype} 查询失败 (Status={status})")
    out: List[str] = []
    for row in data.get("Answer") or []:
        if not isinstance(row, dict):
            continue
        data_value = str(row.get("data") or "").strip()
        if not data_value:
            continue
        if rtype == "MX":
            data_value = data_value.split()[-1]
        if rtype == "TXT":
            data_value = data_value.strip('"')
        value = _clean_name(data_value)
        if value and value not in out:
            out.append(value)
    return out


def _socket_resolve(host: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {"A": [], "AAAA": []}
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, OSError):
        return out
    for info in infos:
        address = info[4][0]
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        key = "A" if parsed.version == 4 else "AAAA"
        if address not in out[key]:
            out[key].append(address)
    return out


def resolve_host(
    host: str,
    http: HttpClient,
    types: tuple = DEFAULT_TYPES,
) -> Dict[str, List[str]]:
    """解析 A/AAAA/CNAME（可选 MX/NS/TXT）；A 为空时跟随一层 CNAME。"""
    result: Dict[str, List[str]] = {rtype: [] for rtype in types}
    errors = 0
    for rtype in types:
        try:
            result[rtype] = _answers(http, host, rtype)
        except Exception as exc:  # noqa: BLE001
            errors += 1
            log.debug("DoH %s %s 失败: %s", host, rtype, exc)
    if errors == len(types):
        fallback = _socket_resolve(host)
        for rtype in ("A", "AAAA"):
            if rtype in result:
                result[rtype] = fallback.get(rtype, [])
    if "A" in result and not result.get("A") and result.get("CNAME"):
        target = result["CNAME"][0]
        try:
            result["A"] = _answers(http, target, "A")
            if "AAAA" in result and not result.get("AAAA"):
                result["AAAA"] = _answers(http, target, "AAAA")
        except Exception as exc:  # noqa: BLE001
            log.debug("跟随 CNAME %s 失败: %s", target, exc)
    return {k: v for k, v in result.items() if v}


def is_wildcard(domain: str, http: HttpClient) -> bool:
    """通过随机子域名判断是否存在泛解析。"""
    token = f"tutu-wildcard-{abs(hash(domain)) % 100000}.{domain}"
    try:
        answers = _answers(http, token, "A")
    except Exception:  # noqa: BLE001
        return False
    return bool(answers)


def reverse_lookup(ip: str, http: HttpClient) -> str:
    try:
        answers = _answers(http, ip, "PTR")
    except Exception:  # noqa: BLE001
        return ""
    return answers[0] if answers else ""


def public_ips(values: List[str]) -> List[str]:
    out: List[str] = []
    for value in values:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.is_private or address.is_loopback or address.is_link_local:
            continue
        if value not in out:
            out.append(value)
    return out
