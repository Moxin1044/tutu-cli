from __future__ import annotations

from typing import Any, Dict, List

from ..http import HttpClient
from ..models import Item
from ..utils import (
    clean_text,
    first_sentence,
    is_exact_cve,
    normalize_severity,
    short_date,
)
from ..versions import VersionRange, ranges_from_cpe
from .base import Source

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _pick_metric(metrics: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(metrics, dict):
        return {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key) or []
        for row in rows:
            data = row.get("cvssData") or {}
            if data:
                return {
                    "score": data.get("baseScore"),
                    "severity": row.get("baseSeverity") or data.get("baseSeverity"),
                    "vector": data.get("vectorString"),
                    "version": data.get("version"),
                }
    return {}


def _description(cve: Dict[str, Any]) -> str:
    rows = cve.get("descriptions") or []
    for row in rows:
        if row.get("lang") == "en":
            return clean_text(row.get("value", ""))
    for row in rows:
        if row.get("lang") in ("zh", "zh-CN"):
            return clean_text(row.get("value", ""))
    return clean_text(rows[0].get("value", "")) if rows else ""


def _cwe(cve: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for weakness in cve.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            value = desc.get("value")
            if value and value.startswith("CWE-") and value not in out:
                out.append(value)
    return out


def _version_ranges(cve: Dict[str, Any], limit: int = 400) -> List[VersionRange]:
    out: List[VersionRange] = []
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if isinstance(match, dict) and match.get("vulnerable") is False:
                    continue
                rng = ranges_from_cpe(match, "nvd")
                if rng is not None:
                    out.append(rng)
                if len(out) >= limit:
                    return out
    return out


def _product_labels(ranges: List[VersionRange], limit: int = 6) -> List[str]:
    out: List[str] = []
    for rng in ranges:
        if rng.product and rng.product not in out:
            out.append(rng.product)
        if len(out) >= limit:
            break
    return out


def _products(cve: Dict[str, Any], limit: int = 6) -> List[str]:
    return _product_labels(_version_ranges(cve), limit)


def parse_vulnerability(cve: Dict[str, Any]) -> "Item":
    """把 NVD 单条记录转换成 Item（供漏洞搜索与资产关联复用）。"""
    cve_id = (cve.get("id") or "").upper()
    metric = _pick_metric(cve.get("metrics") or {})
    desc = _description(cve)
    refs = [
        r.get("url")
        for r in (cve.get("references") or [])
        if isinstance(r, dict) and r.get("url")
    ][:5]
    ranges = _version_ranges(cve)
    return Item(
        source="nvd",
        category="vulnerability",
        title=cve_id,
        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        date=short_date(cve.get("published") or ""),
        summary=first_sentence(desc, 500),
        severity=normalize_severity(metric.get("severity") or ""),
        score=str(metric.get("score") or ""),
        tags=_cwe(cve),
        extra={
            "cve": cve_id,
            "published": cve.get("published") or "",
            "modified": cve.get("lastModified") or "",
            "status": cve.get("vulnStatus") or "",
            "vector": metric.get("vector") or "",
            "cvss_version": metric.get("version") or "",
            "references": refs,
            "description": desc,
            "products": _product_labels(ranges, 6),
            "version_ranges": ranges,
        },
    )


class NvdSource(Source):
    name = "nvd"
    label = "NVD"
    kind = "vuln"
    description = "NIST 国家漏洞数据库（官方 REST API，无需 Key）"

    def _search(self, query: str, limit: int, http: HttpClient) -> List[Item]:
        query = query.strip()
        params: Dict[str, Any] = {
            "resultsPerPage": max(1, min(limit, 50)),
            "noRejected": "",
        }
        if is_exact_cve(query):
            params["cveId"] = query.upper()
        else:
            params["keywordSearch"] = query

        data = http.get_json(
            NVD_API,
            params=params,
            headers={"Accept": "application/json"},
        )
        items: List[Item] = []
        for row in data.get("vulnerabilities") or []:
            cve = row.get("cve") or {}
            cve_id = (cve.get("id") or "").upper()
            if not cve_id:
                continue
            items.append(parse_vulnerability(cve))
        total = data.get("totalResults")
        if total and int(total) > len(items):
            self.last_note = f"NVD 共 {total} 条，仅展示前 {len(items)} 条"
        return items
