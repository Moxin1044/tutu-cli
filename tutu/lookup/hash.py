from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

from ..config import get_api_key
from ..http import HttpClient, SourceError
from ..utils import clean_text
from .socradar import ioc_detail as socradar_ioc_detail
from .socradar import ioc_risk as socradar_ioc_risk
from .socradar import parse_ioc as parse_socradar_ioc

CIRCL = "https://hashlookup.circl.lu/lookup/{kind}/{value}"
OTX = "https://otx.alienvault.com/api/v1/indicators/file/{value}/general"
THREATBOOK = "https://api.threatbook.cn/v3/file/report"
THREATBOOK_MULTI = "https://api.threatbook.cn/v3/file/report/multiengines"
VIRUSTOTAL = "https://www.virustotal.com/api/v3/files/{value}"
HEX_RE = re.compile(r"^[a-fA-F0-9]+$")


def hash_kind(value: str) -> Optional[str]:
    value = value.strip()
    if not HEX_RE.fullmatch(value):
        return None
    return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(value))


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


def _circl(http: HttpClient, kind: str, value: str) -> Dict[str, Any]:
    return http.get_json(CIRCL.format(kind=kind, value=value))


def _otx(http: HttpClient, value: str) -> Dict[str, Any]:
    return http.get_json(OTX.format(value=value))


def _threatbook(http: HttpClient, value: str, key: str) -> Dict[str, Any]:
    data = http.get_json(
        THREATBOOK,
        params={"apikey": key, "resource": value},
        headers={"Accept": "application/json"},
    )
    if data.get("response_code") not in (0, "0"):
        raise SourceError(clean_text(data.get("verbose_msg") or "ThreatBook 查询失败"))
    return data.get("data") or {}


def _threatbook_multi(http: HttpClient, value: str, key: str) -> Dict[str, Any]:
    data = http.get_json(
        THREATBOOK_MULTI,
        params={"apikey": key, "resource": value},
        headers={"Accept": "application/json"},
    )
    if data.get("response_code") not in (0, "0"):
        raise SourceError(clean_text(data.get("verbose_msg") or "ThreatBook 多引擎查询失败"))
    return (data.get("data") or {}).get("multiengines") or {}


def _socradar_ioc(http: HttpClient, value: str) -> Dict[str, Any]:
    try:
        return socradar_ioc_detail(http, value)
    except SourceError as exc:
        if "404" in str(exc):
            return {}
        raise


def _virustotal(http: HttpClient, value: str, key: str) -> Dict[str, Any]:
    data = http.get_json(
        VIRUSTOTAL.format(value=value),
        headers={"x-apikey": key, "Accept": "application/json"},
    )
    return (data.get("data") or {}).get("attributes") or {}


def _parse_threatbook(data: Dict[str, Any]) -> Dict[str, Any]:
    summary = data.get("summary") or {}
    engines = ((data.get("multiengines") or {}).get("result")) or {}
    detections = [
        f"{name}: {result}"
        for name, result in engines.items()
        if clean_text(result).lower() not in ("safe", "unknown", "")
    ]
    tags = []
    tag_obj = summary.get("tag") or {}
    for key in ("x", "s"):
        for tag in tag_obj.get(key) or []:
            if tag and tag not in tags:
                tags.append(str(tag))
    return {
        "threat_level": clean_text(summary.get("threat_level") or ""),
        "malware_family": clean_text(summary.get("malware_family") or ""),
        "malware_type": clean_text(summary.get("malware_type") or ""),
        "threat_score": summary.get("threat_score"),
        "file_name": clean_text(summary.get("file_name") or ""),
        "file_size": summary.get("file_size"),
        "file_type": clean_text(summary.get("file_type") or ""),
        "multi_engines": clean_text(summary.get("multi_engines") or ""),
        "sandbox_types": summary.get("sandbox_type_list") or [],
        "submit_time": clean_text(summary.get("submit_time") or ""),
        "last_detection_time": clean_text(summary.get("last_detection_time") or ""),
        "is_whitelist": bool(summary.get("is_whitelist")),
        "tags": tags[:12],
        "detections": detections[:10],
        "permalink": clean_text(data.get("permalink") or ""),
        "hashes": {
            "md5": clean_text(summary.get("md5") or ""),
            "sha1": clean_text(summary.get("sha1") or ""),
            "sha256": clean_text(summary.get("sample_sha256") or ""),
        },
    }


def _parse_threatbook_multi(data: Dict[str, Any]) -> Dict[str, Any]:
    scans = data.get("scans") or {}
    detections = [
        f"{name}: {result}"
        for name, result in scans.items()
        if clean_text(result).lower() not in ("safe", "unknown", "")
    ]
    return {
        "threat_level": clean_text(data.get("threat_level") or ""),
        "positives": data.get("positives"),
        "total": data.get("total"),
        "scan_date": clean_text(data.get("scan_date") or ""),
        "malware_type": clean_text(data.get("malware_type") or ""),
        "malware_family": clean_text(data.get("malware_family") or ""),
        "detections": detections[:10],
    }


def _parse_virustotal(data: Dict[str, Any]) -> Dict[str, Any]:
    stats = data.get("last_analysis_stats") or {}
    threat = data.get("popular_threat_classification") or {}
    names = data.get("names") or []
    return {
        "meaningful_name": clean_text(data.get("meaningful_name") or ""),
        "type_description": clean_text(data.get("type_description") or ""),
        "size": data.get("size"),
        "reputation": data.get("reputation"),
        "tags": (data.get("tags") or [])[:12],
        "stats": {
            "malicious": int(stats.get("malicious") or 0),
            "suspicious": int(stats.get("suspicious") or 0),
            "harmless": int(stats.get("harmless") or 0),
            "undetected": int(stats.get("undetected") or 0),
        },
        "threat_label": clean_text(threat.get("suggested_threat_label") or ""),
        "names": names[:8],
        "hashes": {
            "md5": clean_text(data.get("md5") or ""),
            "sha1": clean_text(data.get("sha1") or ""),
            "sha256": clean_text(data.get("sha256") or ""),
        },
    }


def _parse_otx(data: Dict[str, Any]) -> Dict[str, Any]:
    pulse_info = data.get("pulse_info") or {}
    pulses = pulse_info.get("pulses") or []
    tags: List[str] = []
    for pulse in pulses[:15]:
        for tag in pulse.get("tags") or []:
            if tag and tag not in tags:
                tags.append(str(tag))
    validation = [
        clean_text(v.get("message") or v.get("name") or "")
        for v in (data.get("validation") or [])
        if isinstance(v, dict)
    ]
    return {
        "pulse_count": pulse_info.get("count", len(pulses)),
        "pulses": [clean_text(p.get("name") or "") for p in pulses[:5]],
        "tags": tags[:12],
        "validation": validation,
    }


def _parse_circl(data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "file_name": clean_text(data.get("FileName") or ""),
        "file_size": data.get("FileSize"),
        "known_malicious": clean_text(data.get("KnownMalicious") or ""),
        "product": clean_text(
            str(data.get("ProductCode") or "")
            if not isinstance(data.get("ProductCode"), dict)
            else str((data.get("ProductCode") or {}).get("ProductName") or "")
        ),
        "os": clean_text(
            str((data.get("OpSystemCode") or {}).get("OpSystemName") or "")
            if isinstance(data.get("OpSystemCode"), dict)
            else ""
        ),
        "trust": data.get("hashlookup:trust"),
        "source": clean_text(data.get("source") or ""),
        "hashes": {
            "md5": clean_text(data.get("MD5") or ""),
            "sha1": clean_text(data.get("SHA-1") or data.get("SHA1") or ""),
            "sha256": clean_text(data.get("SHA-256") or data.get("SHA256") or ""),
        },
    }


def _risk(
    tb: Dict[str, Any],
    tb_multi: Dict[str, Any],
    vt: Dict[str, Any],
    circl: Dict[str, Any],
    otx: Dict[str, Any],
    soc: Dict[str, Any],
) -> Dict[str, Any]:
    reasons: List[str] = []
    level = "unknown"
    tb_level = (tb.get("threat_level") or tb_multi.get("threat_level") or "").lower()
    if tb_level in ("malicious", "suspicious"):
        level = "malicious" if tb_level == "malicious" else "suspicious"
        reasons.append(f"ThreatBook: {tb_level}")
    if tb_multi.get("positives"):
        reasons.append(
            f"ThreatBook 多引擎: {tb_multi.get('positives')}/{tb_multi.get('total')}"
        )
    stats = vt.get("stats") or {}
    if stats.get("malicious", 0) > 0:
        level = "malicious"
        reasons.append(f"VirusTotal malicious: {stats['malicious']}")
    elif stats.get("suspicious", 0) > 0 and level == "unknown":
        level = "suspicious"
        reasons.append(f"VirusTotal suspicious: {stats['suspicious']}")
    if circl.get("known_malicious"):
        level = "malicious"
        reasons.append(f"CIRCL KnownMalicious: {circl['known_malicious']}")
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
    if not reasons:
        reasons.append("公开源未发现明显恶意标记")
    return {"risk": level, "reasons": reasons}


def lookup_hash(value: str, timeout: float = 25.0) -> Dict[str, Any]:
    value = value.strip()
    kind = hash_kind(value)
    if not kind:
        raise ValueError("无效哈希：需要 32 位 MD5、40 位 SHA1 或 64 位 SHA256 十六进制字符串")

    http = HttpClient(timeout=timeout)
    tasks = {
        "circl": lambda: _circl(http, kind, value),
        "otx": lambda: _otx(http, value),
        "socradar_ioc": lambda: _socradar_ioc(http, value),
    }
    tb_key = get_api_key("threatbook")
    vt_key = get_api_key("virustotal")
    if tb_key:
        tasks["threatbook"] = lambda: _threatbook(http, value, tb_key)
        tasks["threatbook_multi"] = lambda: _threatbook_multi(http, value, tb_key)
    if vt_key:
        tasks["virustotal"] = lambda: _virustotal(http, value, vt_key)

    report: Dict[str, Any] = {
        "hash": value.lower(),
        "kind": kind,
        "sources": {},
        "errors": {},
        "hashes": {kind: value.lower()},
        "file": {},
        "reputation": {},
    }
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

    circl = _parse_circl(raw["circl"]) if raw.get("circl") else {}
    otx = _parse_otx(raw["otx"]) if raw.get("otx") else {}
    tb = _parse_threatbook(raw["threatbook"]) if raw.get("threatbook") else {}
    tb_multi = (
        _parse_threatbook_multi(raw["threatbook_multi"])
        if raw.get("threatbook_multi")
        else {}
    )
    vt = _parse_virustotal(raw["virustotal"]) if raw.get("virustotal") else {}
    soc = parse_socradar_ioc(raw["socradar_ioc"]) if raw.get("socradar_ioc") else {}

    report["circl"] = circl
    report["otx"] = otx
    report["threatbook"] = tb
    report["threatbook_multi"] = tb_multi
    report["virustotal"] = vt
    report["socradar_ioc"] = soc
    report["file"] = {
        "name": _first(tb.get("file_name"), vt.get("meaningful_name"), circl.get("file_name")) or "",
        "size": _first(tb.get("file_size"), vt.get("size"), circl.get("file_size")),
        "type": _first(tb.get("file_type"), vt.get("type_description"), circl.get("os")) or "",
        "malware_family": tb.get("malware_family")
        or tb_multi.get("malware_family")
        or vt.get("threat_label")
        or "",
        "malware_type": tb.get("malware_type") or tb_multi.get("malware_type") or "",
        "detections": _first(
            tb.get("multi_engines"),
            f"{tb_multi.get('positives')}/{tb_multi.get('total')}"
            if tb_multi.get("positives") is not None
            else None,
        )
        or "",
        "tags": (tb.get("tags") or []) + (vt.get("tags") or []) + (otx.get("tags") or []),
    }
    seen = set()
    report["file"]["tags"] = [
        t for t in report["file"]["tags"] if not (t in seen or seen.add(t))
    ][:12]
    report["hashes"] = {
        key: _first(
            tb.get("hashes", {}).get(key),
            vt.get("hashes", {}).get(key),
            circl.get("hashes", {}).get(key),
            value.lower() if key == kind else "",
        )
        or ""
        for key in ("md5", "sha1", "sha256")
    }
    report["reputation"] = _risk(tb, tb_multi, vt, circl, otx, soc)
    return report
