from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_address
from typing import Any, Dict, List, Optional

from ..config import get_api_key
from ..http import HttpClient, SourceError
from ..utils import clean_text, truncate
from .reverse import reverse_ip as reverse_ip_lookup
from .socradar import ioc_detail as socradar_ioc_detail
from .socradar import ioc_risk as socradar_ioc_risk
from .socradar import parse_ioc as parse_socradar_ioc

IPWHO = "https://ipwho.is/{ip}"
IPINFO = "https://ipinfo.io/{ip}/json"
IPAPI = "http://ip-api.com/json/{ip}"
OTX = "https://otx.alienvault.com/api/v1/indicators/{family}/{ip}/general"
THREATBOOK = "https://api.threatbook.cn/v3/scene/ip_reputation"
VIRUSTOTAL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"


def _first(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return None


def _fetch(name: str, func) -> tuple:
    try:
        return name, func(), ""
    except Exception as exc:  # noqa: BLE001
        return name, None, str(exc)[:240]


def _ipwho(http: HttpClient, ip: str) -> Dict[str, Any]:
    data = http.get_json(IPWHO.format(ip=ip))
    if not data.get("success", True):
        raise SourceError(clean_text(data.get("message") or "查询失败"))
    return data


def _ipinfo(http: HttpClient, ip: str) -> Dict[str, Any]:
    return http.get_json(IPINFO.format(ip=ip))


def _ipapi(http: HttpClient, ip: str) -> Dict[str, Any]:
    data = http.get_json(
        IPAPI.format(ip=ip),
        params={
            "fields": "status,message,country,regionName,city,isp,org,as,query,"
            "timezone,lat,lon,reverse,mobile,proxy,hosting"
        },
    )
    if data.get("status") != "success":
        raise SourceError(clean_text(data.get("message") or "查询失败"))
    return data


def _otx(http: HttpClient, ip: str, family: str = "IPv4") -> Dict[str, Any]:
    return http.get_json(OTX.format(family=family, ip=ip))


def _threatbook(http: HttpClient, ip: str, key: str) -> Dict[str, Any]:
    data = http.get_json(
        THREATBOOK,
        params={"apikey": key, "resource": ip},
        headers={"Accept": "application/json"},
    )
    if data.get("response_code") not in (0, "0"):
        raise SourceError(clean_text(data.get("verbose_msg") or "ThreatBook 查询失败"))
    payload = data.get("data") or {}
    if isinstance(payload, dict):
        if ip in payload:
            payload = payload[ip]
        elif "severity" not in payload:
            first = next((v for v in payload.values() if isinstance(v, dict)), None)
            if first is not None:
                payload = first
    return payload if isinstance(payload, dict) else {}


def _socradar_ioc(http: HttpClient, ip: str) -> Dict[str, Any]:
    try:
        return socradar_ioc_detail(http, ip)
    except SourceError as exc:
        if "404" in str(exc):
            return {}
        raise


def _virustotal(http: HttpClient, ip: str, key: str) -> Dict[str, Any]:
    data = http.get_json(
        VIRUSTOTAL.format(ip=ip),
        headers={"x-apikey": key, "Accept": "application/json"},
    )
    return (data.get("data") or {}).get("attributes") or {}


def _parse_threatbook(data: Dict[str, Any]) -> Dict[str, Any]:
    basic = data.get("basic") or {}
    location = basic.get("location") or {}
    judgments = data.get("judgments") or []
    tags: List[str] = []
    for row in data.get("tags_classes") or []:
        for tag in (row or {}).get("tags") or []:
            if tag and tag not in tags:
                tags.append(str(tag))
    for tag in data.get("tags") or []:
        if tag and tag not in tags:
            tags.append(str(tag))
    asn_obj = data.get("asn") or {}
    asn_number = asn_obj.get("number") if isinstance(asn_obj, dict) else None
    asn_info = asn_obj.get("info") if isinstance(asn_obj, dict) else None
    return {
        "severity": clean_text(data.get("severity") or ""),
        "confidence": data.get("confidence_level") or data.get("confidence"),
        "judgments": [clean_text(j) for j in judgments if clean_text(j)],
        "tags": [clean_text(t) for t in tags if clean_text(t)],
        "carrier": clean_text(basic.get("carrier") or ""),
        "location": clean_text(
            ", ".join(
                str(x)
                for x in (
                    location.get("country"),
                    location.get("province"),
                    location.get("city"),
                )
                if x
            )
        ),
        "asn": clean_text(f"AS{asn_number} {asn_info or ''}".strip()) if asn_number else clean_text(str(basic.get("asn") or "")),
        "scene": clean_text(data.get("scene") or ""),
        "is_malicious": data.get("is_malicious"),
        "permalink": clean_text(data.get("permalink") or ""),
        "update_time": clean_text(data.get("update_time") or ""),
        "intelligences": truncate(
            clean_text(str(data.get("intelligences") or "")), 500
        ),
    }


def _parse_otx(data: Dict[str, Any]) -> Dict[str, Any]:
    pulse_info = data.get("pulse_info") or {}
    pulses = pulse_info.get("pulses") or []
    validation = data.get("validation") or []
    tags: List[str] = []
    for pulse in pulses[:10]:
        for tag in pulse.get("tags") or []:
            if tag and tag not in tags:
                tags.append(tag)
    return {
        "pulse_count": pulse_info.get("count", len(pulses)),
        "pulses": [
            {
                "name": clean_text(p.get("name") or ""),
                "tags": (p.get("tags") or [])[:6],
            }
            for p in pulses[:5]
        ],
        "validation": [
            clean_text(v.get("message") or v.get("name") or "")
            for v in validation
            if isinstance(v, dict)
        ],
        "tags": tags[:12],
        "asn": clean_text(data.get("asn") or ""),
        "country": clean_text(data.get("country_name") or ""),
        "city": clean_text(data.get("city") or ""),
        "reputation": data.get("reputation"),
    }


def _parse_vt(data: Dict[str, Any]) -> Dict[str, Any]:
    stats = data.get("last_analysis_stats") or {}
    votes = data.get("total_votes") or {}
    return {
        "as_owner": clean_text(data.get("as_owner") or ""),
        "asn": data.get("asn"),
        "country": clean_text(data.get("country") or ""),
        "network": clean_text(data.get("network") or ""),
        "reputation": data.get("reputation"),
        "tags": (data.get("tags") or [])[:12],
        "stats": {
            "malicious": int(stats.get("malicious") or 0),
            "suspicious": int(stats.get("suspicious") or 0),
            "harmless": int(stats.get("harmless") or 0),
            "undetected": int(stats.get("undetected") or 0),
        },
        "votes": {
            "malicious": int(votes.get("malicious") or 0),
            "harmless": int(votes.get("harmless") or 0),
        },
    }


def lookup_ip(
    ip: str,
    timeout: float = 20.0,
    reverse: bool = True,
    reverse_limit: int = 100,
) -> Dict[str, Any]:
    try:
        address = ip_address(ip.strip())
    except ValueError as exc:
        raise ValueError(f"无效 IP 地址: {ip}") from exc

    ip_text = str(address)
    report: Dict[str, Any] = {
        "ip": ip_text,
        "version": address.version,
        "private": address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast,
        "geo": {},
        "sources": {},
        "errors": {},
        "reputation": {},
        "reverse": {},
    }
    if report["private"]:
        report["geo"] = {
            "country": "私有/保留地址",
            "city": "",
            "region": "",
        }
        report["reputation"] = {"risk": "n/a", "reason": "私有或保留地址，跳过外部情报查询"}
        return report

    http = HttpClient(timeout=timeout)
    tasks = {
        "ipwho": lambda: _ipwho(http, ip_text),
        "ipinfo": lambda: _ipinfo(http, ip_text),
        "ipapi": lambda: _ipapi(http, ip_text),
        "otx": lambda: _otx(
            http, ip_text, "IPv6" if address.version == 6 else "IPv4"
        ),
        "socradar_ioc": lambda: _socradar_ioc(http, ip_text),
    }
    tb_key = get_api_key("threatbook")
    vt_key = get_api_key("virustotal")
    if tb_key:
        tasks["threatbook"] = lambda: _threatbook(http, ip_text, tb_key)
    if vt_key:
        tasks["virustotal"] = lambda: _virustotal(http, ip_text, vt_key)
    if reverse:
        tasks["reverse"] = lambda: reverse_ip_lookup(
            ip_text,
            timeout=max(timeout, 15.0),
            limit=max(1, reverse_limit),
        )

    raw: Dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=min(8, len(tasks))) as pool:
        futures = [pool.submit(_fetch, name, func) for name, func in tasks.items()]
        for future in futures:
            name, data, error = future.result()
            if error:
                report["errors"][name] = error
            else:
                raw[name] = data
                report["sources"][name] = "ok"

    ipwho = raw.get("ipwho") or {}
    ipinfo = raw.get("ipinfo") or {}
    ipapi = raw.get("ipapi") or {}
    otx = _parse_otx(raw["otx"]) if raw.get("otx") else {}
    tb = _parse_threatbook(raw["threatbook"]) if raw.get("threatbook") else {}
    vt = _parse_vt(raw["virustotal"]) if raw.get("virustotal") else {}
    soc = parse_socradar_ioc(raw["socradar_ioc"]) if raw.get("socradar_ioc") else {}

    connection = ipwho.get("connection") or {}
    loc = ipinfo.get("loc") or ""
    lat = lon = None
    if "," in loc:
        try:
            lat, lon = [float(x) for x in loc.split(",", 1)]
        except ValueError:
            lat = lon = None

    soc_geo = soc.get("geo") or {}
    report["geo"] = {
        "country": _first(ipwho.get("country"), ipinfo.get("country"), ipapi.get("country"), otx.get("country"), soc_geo.get("country"), vt.get("country")) or "",
        "country_code": _first(ipwho.get("country_code"), ipinfo.get("country"), soc_geo.get("country_code"), "") or "",
        "region": _first(ipwho.get("region"), ipinfo.get("region"), ipapi.get("regionName"), soc_geo.get("region")) or "",
        "city": _first(ipwho.get("city"), ipinfo.get("city"), ipapi.get("city"), otx.get("city"), soc_geo.get("city")) or "",
        "postal": _first(ipwho.get("postal"), ipinfo.get("postal")) or "",
        "timezone": _first(ipwho.get("timezone", {}).get("id") if isinstance(ipwho.get("timezone"), dict) else None, ipinfo.get("timezone"), ipapi.get("timezone")) or "",
        "latitude": _first(ipwho.get("latitude"), lat, ipapi.get("lat"), soc_geo.get("lat")),
        "longitude": _first(ipwho.get("longitude"), lon, ipapi.get("lon"), soc_geo.get("lon")),
        "hostname": _first(ipinfo.get("hostname"), ipapi.get("reverse")) or "",
    }
    asn = _first(
        connection.get("asn") if isinstance(connection, dict) else None,
        otx.get("asn"),
        ipapi.get("as"),
        soc_geo.get("asn"),
        vt.get("asn"),
    )
    if asn is not None and str(asn).strip().isdigit():
        asn = f"AS{asn}"
    report["asn"] = asn
    report["org"] = _first(
        connection.get("org") if isinstance(connection, dict) else None,
        ipinfo.get("org"),
        ipapi.get("org"),
        soc_geo.get("org"),
        vt.get("as_owner"),
    ) or ""
    report["isp"] = _first(
        connection.get("isp") if isinstance(connection, dict) else None,
        ipapi.get("isp"),
        tb.get("carrier"),
    ) or ""
    soc_flags = soc.get("flags") or {}
    report["flags"] = {
        "proxy": ipapi.get("proxy") or soc_flags.get("is_proxy"),
        "hosting": ipapi.get("hosting") or soc_flags.get("is_hosting"),
        "mobile": ipapi.get("mobile"),
        "tor": soc_flags.get("is_tor"),
        "vpn": soc_flags.get("is_vpn"),
        "scanner": soc_flags.get("is_scanner"),
        "botnet": soc_flags.get("is_botnet"),
        "whitelisted": soc_flags.get("is_whitelisted"),
    }
    report["threatbook"] = tb
    report["virustotal"] = vt
    report["otx"] = otx
    report["socradar_ioc"] = soc
    report["reverse"] = raw.get("reverse") or {}
    report["reputation"] = _risk(tb, vt, otx, soc)
    return report


def _risk(
    tb: Dict[str, Any],
    vt: Dict[str, Any],
    otx: Dict[str, Any],
    soc: Dict[str, Any],
) -> Dict[str, Any]:
    reasons: List[str] = []
    level = "unknown"
    validations = otx.get("validation") or []
    whitelisted = any(
        "whitelist" in v.lower() or "false positive" in v.lower() for v in validations
    )
    tb_sev = (tb.get("severity") or "").lower()
    tb_malicious = bool(tb.get("is_malicious"))
    if tb_malicious or tb_sev in ("critical", "high"):
        level = "malicious"
        reasons.append(f"ThreatBook: {tb_sev or 'malicious'}")
    elif tb_sev in ("medium", "low"):
        level = "suspicious"
        reasons.append(f"ThreatBook 严重性: {tb_sev}")
    stats = vt.get("stats") or {}
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    if malicious >= 2:
        level = "malicious"
        reasons.append(f"VirusTotal malicious: {malicious}")
    elif malicious == 1:
        if level == "unknown":
            level = "suspicious"
        reasons.append("VirusTotal 1 个引擎标记")
    elif suspicious > 0 and level == "unknown":
        level = "suspicious"
        reasons.append(f"VirusTotal suspicious: {suspicious}")
    if otx.get("pulse_count", 0) > 0:
        if level == "unknown":
            level = "suspicious"
        reasons.append(f"OTX pulses: {otx['pulse_count']}")
    if soc:
        soc_risk = socradar_ioc_risk(soc)
        if soc_risk.get("risk") in ("malicious", "suspicious"):
            if soc_risk["risk"] == "malicious" or level == "unknown":
                level = soc_risk["risk"]
            reasons.extend(soc_risk.get("reasons") or [])
    if whitelisted:
        reasons.append("OTX 白名单/误报标记")
        if level in ("malicious", "suspicious") and malicious < 3 and not tb_malicious:
            level = "clean"
    if not reasons:
        reasons.append("公开源未发现明显恶意标记")
    return {"risk": level, "reasons": reasons, "otx_pulses": otx.get("pulse_count", 0)}
