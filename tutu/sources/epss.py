from __future__ import annotations

from typing import Dict, List

from ..http import HttpClient
from ..utils import extract_cves

EPSS_API = "https://api.first.org/data/v1/epss"


def enrich_epss(items: List, http: HttpClient) -> None:
    """批量为漏洞条目补充 EPSS 分数（原地修改 extra）。"""
    cve_ids: List[str] = []
    for item in items:
        cve_id = (item.extra or {}).get("cve") or ""
        if cve_id and cve_id not in cve_ids:
            cve_ids.append(cve_id)
        if len(cve_ids) >= 100:
            break
    if not cve_ids:
        return
    try:
        data = http.get_json(
            EPSS_API,
            params={"cve": ",".join(cve_ids)},
            headers={"Accept": "application/json"},
        )
    except Exception:
        return
    by_cve: Dict[str, dict] = {}
    for row in data.get("data") or []:
        cve = (row.get("cve") or "").upper()
        if cve:
            by_cve[cve] = row
    for item in items:
        cve = (item.extra or {}).get("cve") or ""
        row = by_cve.get(cve.upper())
        if not row:
            continue
        try:
            epss = float(row.get("epss"))
            percentile = float(row.get("percentile"))
        except (TypeError, ValueError):
            continue
        item.extra["epss"] = epss
        item.extra["epss_percentile"] = percentile
        item.extra["epss_date"] = row.get("date") or ""


def cve_ids_in_text(text: str) -> List[str]:
    return extract_cves(text)
