"""ICP 备案查询（域名 / 备案号 / 主办单位）。

主数据源使用公开的糖豆子 API（数据来自工信部，带缓存），
失败时回退到 vvhan / oioweb / uomg 等公开聚合接口。
"""
from __future__ import annotations

import logging
import re
import time
from typing import Any, Dict, Iterable, List, Tuple

from ..cache import read_cache, write_cache
from ..http import HttpClient, SourceError
from ..utils import clean_text, repair_mojibake, truncate

log = logging.getLogger("tutu.lookup.icp")

TANGDOUZ = "https://api.tangdouz.com/a/icp/"
VVHAN = "https://api.vvhan.com/api/icp"
OIOWEB = "https://api.oioweb.cn/api/site/icp"
UOMG = "https://api.uomg.com/api/icp"

ICP_TTL = 3600
DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I
)
PROVIDERS: List[Tuple[str, str, str]] = [
    ("tangdouz", "糖豆子 API", "工信部数据，支持域名 / 备案号 / 单位名，自动缓存"),
    ("vvhan", "vvhan API", "公开备案查询接口，作为备用源"),
    ("oioweb", "oioweb API", "公开备案查询接口，作为备用源"),
    ("uomg", "uomg API", "公开备案查询接口，作为备用源"),
]


def normalize_query(value: str) -> str:
    """域名统一小写去协议/路径；备案号、单位名保持原样。"""
    text = clean_text(value)
    if not text:
        return ""
    if "://" in text:
        text = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text, flags=re.I)
        text = text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in text:
        text = text.rsplit("@", 1)[-1]
    if ":" in text and DOMAIN_RE.match(text.split(":", 1)[0]):
        text = text.split(":", 1)[0]
    candidate = text.strip().strip(".")
    if DOMAIN_RE.match(candidate):
        return candidate.lower()
    return text


def _pick(row: Dict[str, Any], *keys: str) -> str:
    lowered = {str(key).lower(): value for key, value in row.items()}
    for key in keys:
        value = lowered.get(key.lower())
        if value not in (None, "", [], {}):
            return repair_mojibake(clean_text(str(value)))
    return ""


def _record_from_mapping(row: Dict[str, Any], source: str, default_domain: str = "") -> Dict[str, str]:
    service = _pick(row, "serviceLicence", "service_licence", "serviceLicenceNo")
    main = _pick(row, "mainLicence", "main_licence", "mainLicenceNo")
    return {
        "domain": _pick(row, "domain", "domainName", "url", "website") or default_domain,
        "unit_name": _pick(row, "unitName", "unit_name", "name", "company", "owner"),
        "nature": _pick(row, "natureName", "nature", "type", "unitType"),
        "icp": service or main or _pick(row, "icp", "icpCode", "licence", "license"),
        "main_licence": main,
        "service_licence": service,
        "updated": _pick(
            row, "updateRecordTime", "update_time", "updateTime", "time", "auditTime"
        ),
        "source": source,
    }


def _records_from_payload(data: Any, source: str, default_domain: str = "") -> List[Dict[str, str]]:
    if not isinstance(data, dict):
        return []
    payload: Any = data.get("data")
    if payload is None:
        payload = data.get("params")
    if isinstance(payload, dict):
        payload = payload.get("list") or payload.get("records") or payload.get("data") or payload
    if isinstance(payload, dict):
        rows: Iterable[Any] = [payload]
    elif isinstance(payload, list):
        rows = payload
    else:
        rows = []
    records: List[Dict[str, str]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        record = _record_from_mapping(row, source, default_domain)
        if record.get("domain") or record.get("icp") or record.get("unit_name"):
            records.append(record)
    return records


def _tangdouz(http: HttpClient, query: str, timeout: float) -> List[Dict[str, str]]:
    last_error = ""
    for attempt in range(2):
        try:
            resp = http.request_raw(
                "GET",
                TANGDOUZ,
                params={"type": "web", "search": query, "return": "json"},
                timeout=max(timeout, 25.0),
            )
        except SourceError as exc:
            last_error = str(exc)
            break
        try:
            data = resp.json()
        except ValueError as exc:
            raise SourceError("ICP 接口返回的不是合法 JSON") from exc
        code = data.get("code")
        if str(code) == "429" or resp.status_code == 429:
            last_error = "ICP 接口限流（1 秒后再试）"
            if attempt == 0:
                time.sleep(1.2)
                continue
            break
        if str(code) not in ("200", "0") or not data.get("success", True):
            last_error = clean_text(data.get("msg") or "ICP 查询失败")
            break
        records = _records_from_payload(data, "tangdouz", query)
        if records:
            return records
        return []
    if last_error:
        raise SourceError(last_error)
    return []


def _generic(
    http: HttpClient,
    url: str,
    params: Dict[str, str],
    source: str,
    query: str,
    timeout: float,
) -> List[Dict[str, str]]:
    data = http.get_json(url, params=params, timeout=max(timeout, 20.0))
    return _records_from_payload(data, source, query)


def _fetch_provider(
    http: HttpClient,
    name: str,
    query: str,
    timeout: float,
    is_domain: bool,
) -> List[Dict[str, str]]:
    if name == "tangdouz":
        return _tangdouz(http, query, timeout)
    if not is_domain:
        raise SourceError("该备用源只支持域名查询")
    if name == "vvhan":
        return _generic(http, VVHAN, {"url": query}, "vvhan", query, timeout)
    if name == "oioweb":
        return _generic(http, OIOWEB, {"domain": query}, "oioweb", query, timeout)
    if name == "uomg":
        return _generic(http, UOMG, {"url": query}, "uomg", query, timeout)
    return []


def lookup_icp(
    value: str,
    timeout: float = 25.0,
    limit: int = 50,
) -> Dict[str, Any]:
    """查询 ICP 备案信息。

    value 可以是域名、备案号（如 豫ICP备16005160号）或主办单位名称。
    """
    original = clean_text(value)
    query = normalize_query(original)
    if not query:
        raise ValueError("ICP 查询内容不能为空")
    is_domain = bool(DOMAIN_RE.match(query))
    cache_name = f"icp_{query}"
    entry = read_cache(cache_name)
    now = time.time()
    if entry and now - float(entry.get("ts", 0) or 0) <= ICP_TTL:
        cached_data = entry.get("data") or {}
        if cached_data.get("records"):
            return cached_data

    http = HttpClient(timeout=max(timeout, 25.0))
    errors: Dict[str, str] = {}
    records: List[Dict[str, str]] = []
    used_source = ""
    for name, _label, _description in PROVIDERS:
        try:
            rows = _fetch_provider(http, name, query, timeout, is_domain)
        except Exception as exc:  # noqa: BLE001 - 单源失败继续尝试
            errors[name] = str(exc)[:240] or exc.__class__.__name__
            continue
        if rows:
            records = rows
            used_source = name
            break
        # 主源明确返回空，说明大概率未备案，无需再试备用源（避免重复限流）。
        if name == "tangdouz":
            break

    deduped: List[Dict[str, str]] = []
    seen = set()
    for record in records:
        key = (
            record.get("domain", ""),
            record.get("service_licence") or record.get("icp", ""),
            record.get("unit_name", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(record)
    deduped = deduped[: max(1, limit)]

    report: Dict[str, Any] = {
        "query": original,
        "normalized": query,
        "type": "domain" if is_domain else "keyword",
        "records": deduped,
        "source": used_source,
        "success": bool(deduped),
        "errors": errors,
        "note": "",
    }
    if not deduped:
        if errors and not any(name == "tangdouz" for name in errors):
            report["note"] = "未查询到备案记录（可能未备案或接口暂不可用）"
        elif errors:
            report["note"] = "未查询到备案记录，且部分数据源失败"
        else:
            report["note"] = "未查询到备案记录（该域名/主体可能未备案）"
    if deduped:
        write_cache(cache_name, report)
    return report


def summarize(report: Dict[str, Any]) -> str:
    """给资产报告用的一行摘要。"""
    records = report.get("records") or []
    if not records:
        return ""
    first = records[0]
    return truncate(
        " · ".join(
            value
            for value in (
                first.get("unit_name"),
                first.get("icp"),
                first.get("nature"),
            )
            if value
        ),
        120,
    )
