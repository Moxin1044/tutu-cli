from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import quote

from ..http import HttpClient, SourceError
from ..utils import clean_text

CVE_BASE = "https://cve.socradar.io"
IOC_BASE = "https://ioc.socradar.io"


def bootstrap(http: HttpClient, base: str) -> None:
    """访问首页获取 Cloudflare 正常 Cookie。"""
    try:
        resp = http.get(base + "/", headers={"Accept": "text/html"})
    except SourceError as exc:
        if "403" in str(exc) or "503" in str(exc):
            raise SourceError("Cloudflare 人机挑战拦截") from exc
        raise
    text = resp.text or ""
    if "Just a moment" in text or "challenge-platform" in text:
        raise SourceError("Cloudflare 人机挑战拦截")


def _headers(base: str) -> Dict[str, str]:
    return {
        "Accept": "application/json",
        "Referer": base + "/",
        "Origin": base,
    }


def cve_detail(http: HttpClient, cve_id: str) -> Dict[str, Any]:
    bootstrap(http, CVE_BASE)
    return http.get_json(
        f"{CVE_BASE}/api/cves/{quote(cve_id.upper(), safe='')}",
        headers=_headers(CVE_BASE),
    )


def cve_search(http: HttpClient, query: str, limit: int = 20) -> Dict[str, Any]:
    bootstrap(http, CVE_BASE)
    return http.get_json(
        f"{CVE_BASE}/api/catalog/cves",
        params={
            "q": query,
            "page": 1,
            "per_page": max(1, min(limit, 50)),
        },
        headers=_headers(CVE_BASE),
    )


def _double_encode(value: str) -> str:
    return quote(quote(value, safe=""), safe="")


def ioc_detail(http: HttpClient, value: str) -> Dict[str, Any]:
    bootstrap(http, IOC_BASE)
    return http.get_json(
        f"{IOC_BASE}/api/v1/iocs/{_double_encode(value)}",
        headers=_headers(IOC_BASE),
    )


def ioc_search(http: HttpClient, query: str, limit: int = 20) -> Dict[str, Any]:
    bootstrap(http, IOC_BASE)
    return http.get_json(
        f"{IOC_BASE}/api/v1/iocs",
        params={"q": query, "page": 1, "per_page": max(1, min(limit, 50))},
        headers=_headers(IOC_BASE),
    )


def parse_cve(data: Dict[str, Any]) -> Dict[str, Any]:
    cwes = [
        clean_text(row.get("id") or "")
        for row in (data.get("cwes") or [])
        if isinstance(row, dict) and row.get("id")
    ]
    products = []
    for row in data.get("products") or []:
        if not isinstance(row, dict):
            continue
        label = "/".join(
            clean_text(str(x))
            for x in (row.get("vendor"), row.get("product"))
            if x
        )
        if label and label not in products:
            products.append(label)
    references = [
        clean_text(row.get("url") or "")
        for row in (data.get("references") or [])
        if isinstance(row, dict) and row.get("url")
    ]
    exploits = []
    for row in data.get("exploits") or []:
        if not isinstance(row, dict):
            continue
        exploits.append(
            {
                "id": row.get("id") or "",
                "title": clean_text(row.get("title") or ""),
                "url": clean_text(row.get("url") or ""),
                "date": clean_text(row.get("date") or ""),
                "type": clean_text(row.get("type") or ""),
                "platform": clean_text(row.get("platform") or ""),
            }
        )
    return {
        "cve": clean_text(data.get("id") or ""),
        "title": clean_text(data.get("title") or ""),
        "summary": clean_text(data.get("summary") or ""),
        "severity": clean_text(data.get("severity") or ""),
        "cvss": data.get("cvss"),
        "epss": data.get("epss"),
        "kev": bool(data.get("kev")),
        "kev_added": clean_text(data.get("kevAdded") or ""),
        "ransomware": clean_text(data.get("ransomwareUse") or "").lower() == "known",
        "published": clean_text(data.get("published") or ""),
        "modified": clean_text(data.get("modified") or ""),
        "cwes": cwes,
        "products": products[:8],
        "references": references[:12],
        "exploits": exploits[:10],
        "poc_count": data.get("pocs"),
        "repo_total": data.get("repoTotal"),
        "actors": data.get("actors") or [],
        "solution": clean_text(data.get("solution") or ""),
        "required_action": clean_text(data.get("requiredAction") or ""),
        "ssvc": data.get("ssvc") or {},
        "sources": data.get("sources") or [],
    }


def parse_ioc(data: Dict[str, Any]) -> Dict[str, Any]:
    flags = {
        key: data.get(key)
        for key in (
            "is_tor",
            "is_vpn",
            "is_proxy",
            "is_scanner",
            "is_botnet",
            "is_cdn",
            "is_cloud",
            "is_hosting",
            "is_whitelisted",
            "is_verified",
        )
    }
    return {
        "value": clean_text(data.get("value") or ""),
        "type": clean_text(data.get("type") or ""),
        "categories": data.get("categories") or [],
        "confidence": data.get("confidence"),
        "confidence_label": clean_text(data.get("confidence_label") or ""),
        "first_seen": clean_text(data.get("first_seen") or ""),
        "last_seen": clean_text(data.get("last_seen") or ""),
        "geo": {
            "country": clean_text(data.get("geo_country_name") or ""),
            "country_code": clean_text(data.get("geo_country") or ""),
            "region": clean_text(data.get("geo_region") or ""),
            "city": clean_text(data.get("geo_city") or ""),
            "lat": data.get("geo_lat"),
            "lon": data.get("geo_lon"),
            "org": clean_text(data.get("geo_org") or ""),
            "asn": clean_text(data.get("geo_asn") or ""),
        },
        "flags": flags,
        "malware_families": data.get("malware_families") or [],
        "campaigns": data.get("campaigns") or [],
        "mitre_ttps": data.get("mitre_ttps") or [],
        "open_ports": data.get("open_ports") or [],
        "passive_dns": data.get("passive_dns") or [],
        "linked_reports": data.get("linked_report_count"),
        "otx_pulse_count": data.get("otx_pulse_count"),
        "tags": data.get("tags") or [],
        "misp_category": clean_text(data.get("misp_category") or ""),
        "opencti": {
            "cvss": data.get("opencti_cvss_score"),
            "severity": clean_text(data.get("opencti_cvss_severity") or ""),
            "description": clean_text(data.get("opencti_description") or ""),
            "references": data.get("opencti_references") or [],
        },
    }


def ioc_risk(ioc: Dict[str, Any]) -> Dict[str, Any]:
    flags = ioc.get("flags") or {}
    categories = [str(c).lower() for c in ioc.get("categories") or []]
    reasons: List[str] = []
    level = "unknown"
    if flags.get("is_whitelisted"):
        level = "clean"
        reasons.append("SOCRadar 白名单")
    if flags.get("is_tor"):
        level = "suspicious"
        reasons.append("Tor 出口节点")
    if flags.get("is_proxy") or flags.get("is_vpn"):
        level = "suspicious"
        reasons.append("代理/VPN")
    if flags.get("is_scanner") or flags.get("is_botnet"):
        level = "malicious"
        reasons.append("扫描器/僵尸网络")
    if any(c in ("malware", "c2", "phishing", "ransomware", "botnet") for c in categories):
        level = "malicious"
        reasons.append("分类: " + ", ".join(categories))
    if ioc.get("malware_families"):
        level = "malicious"
        reasons.append("家族: " + ", ".join(map(str, ioc["malware_families"][:4])))
    if ioc.get("linked_reports"):
        level = "suspicious" if level == "unknown" else level
        reasons.append(f"关联报告: {ioc['linked_reports']}")
    if not reasons:
        reasons.append("SOCRadar 未发现明显恶意标记")
    return {"risk": level, "reasons": reasons}
