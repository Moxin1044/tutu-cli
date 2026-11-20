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


def _products(cve: Dict[str, Any], limit: int = 6) -> List[str]:
    out: List[str] = []
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                criteria = match.get("criteria") or ""
                parts = criteria.split(":")
                if len(parts) > 4:
                    vendor, product = parts[3], parts[4]
                    version = parts[5] if len(parts) > 5 else ""
                    label = f"{vendor}/{product}"
                    if version and version not in ("*", "-", ""):
                        label += f" {version}"
                    if label not in out:
                        out.append(label)
                if len(out) >= limit:
                    return out
    return out


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
            metric = _pick_metric(cve.get("metrics") or {})
            desc = _description(cve)
            refs = [
                r.get("url")
                for r in (cve.get("references") or [])
                if isinstance(r, dict) and r.get("url")
            ][:5]
            tags = _cwe(cve)
            items.append(
                Item(
                    source=self.name,
                    category="vulnerability",
                    title=cve_id,
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    date=short_date(cve.get("published") or ""),
                    summary=first_sentence(desc, 500),
                    severity=normalize_severity(metric.get("severity") or ""),
                    score=str(metric.get("score") or ""),
                    tags=tags,
                    extra={
                        "cve": cve_id,
                        "published": cve.get("published") or "",
                        "modified": cve.get("lastModified") or "",
                        "status": cve.get("vulnStatus") or "",
                        "vector": metric.get("vector") or "",
                        "cvss_version": metric.get("version") or "",
                        "references": refs,
                        "description": desc,
                        "products": _products(cve),
                        "total_results": data.get("totalResults"),
                    },
                )
            )
        total = data.get("totalResults")
        if total and int(total) > len(items):
            self.last_note = f"NVD 共 {total} 条，仅展示前 {len(items)} 条"
        return items
