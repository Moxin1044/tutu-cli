from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from ..http import HttpClient
from ..models import Item
from ..utils import (
    clean_text,
    first_sentence,
    is_exact_cve,
    normalize_severity,
    short_date,
    truncate,
)
from .base import Source

BASE = "https://api.projectdiscovery.io"
SEARCH = BASE + "/v2/vulnerability/search"
DETAIL = BASE + "/v2/vulnerability/{cve_id}"


def _tags(row: Dict[str, Any]) -> List[str]:
    tags: List[str] = []
    for value in (row.get("cwe") or []) + (row.get("tags") or []):
        value = clean_text(str(value))
        if value and value not in tags:
            tags.append(value)
    if row.get("is_kev"):
        tags.append("KEV")
    if row.get("is_poc"):
        tags.append("POC")
    if row.get("is_template"):
        tags.append("Nuclei")
    return tags[:12]


def _products(row: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for item in row.get("affected_products") or []:
        if not isinstance(item, dict):
            continue
        label = "/".join(
            clean_text(str(x))
            for x in (item.get("vendor"), item.get("product"))
            if x
        )
        if label and label not in out:
            out.append(label)
    return out[:8]


def _references(row: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for poc in row.get("pocs") or []:
        if isinstance(poc, dict):
            url = clean_text(poc.get("url") or "")
            if url and url not in out:
                out.append(url)
    if not out and row.get("uri"):
        out.append(clean_text(row.get("uri")))
    return out[:8]


def parse_row(row: Dict[str, Any]) -> Optional[Item]:
    cve_id = clean_text(row.get("cve_id") or row.get("id") or "")
    if not cve_id.upper().startswith("CVE-"):
        return None
    name = clean_text(row.get("name") or row.get("title") or "")
    desc = clean_text(row.get("description") or "")
    kev = bool(row.get("is_kev") or row.get("kev"))
    published = row.get("cve_created_at") or row.get("created_at") or ""
    return Item(
        source="vulnx",
        category="vulnerability",
        title=cve_id.upper(),
        url=f"https://cloud.projectdiscovery.io/library/{cve_id.upper()}",
        date=short_date(str(published)),
        summary=truncate(desc or name, 700),
        severity=normalize_severity(row.get("severity") or ""),
        score=str(row.get("cvss_score") or ""),
        tags=_tags(row),
        extra={
            "cve": cve_id.upper(),
            "description": desc or name,
            "published": str(published),
            "modified": str(row.get("updated_at") or row.get("cve_updated_at") or ""),
            "epss": row.get("epss_score"),
            "epss_percentile": row.get("epss_percentile"),
            "kev": kev,
            "references": _references(row),
            "products": _products(row),
            "poc_count": row.get("poc_count"),
            "ntps": row.get("ntps"),
            "is_remote": row.get("is_remote"),
            "is_template": row.get("is_template"),
            "nuclei": bool(row.get("is_template")),
            "cvss_metrics": row.get("cvss_metrics"),
        },
    )


class VulnxSource(Source):
    name = "vulnx"
    label = "ProjectDiscovery vulnx"
    kind = "vuln"
    description = "ProjectDiscovery vulnx 漏洞库：CVE / Nuclei 模板 / POC / KEV / EPSS（公开 API）"

    def _search(self, query: str, limit: int, http: HttpClient) -> List[Item]:
        query = query.strip()
        headers = {"Accept": "application/json", "User-Agent": "tutu-cli"}
        pdcp_key = os.environ.get("TUTU_PDCP_API_KEY") or os.environ.get("PDCP_API_KEY")
        if pdcp_key:
            headers["X-Api-Key"] = pdcp_key
        if is_exact_cve(query):
            data = http.get_json(
                DETAIL.format(cve_id=query.upper()),
                headers=headers,
            )
            row = data.get("data") or {}
            items = [parse_row(row)] if row else []
            return [item for item in items if item]
        data = http.get_json(
            SEARCH,
            params={"q": query, "limit": max(1, min(limit, 50))},
            headers=headers,
        )
        items: List[Item] = []
        for row in (data.get("results") or [])[: max(limit * 2, limit)]:
            item = parse_row(row)
            if item:
                items.append(item)
            if len(items) >= limit:
                break
        if data.get("total") and int(data["total"]) > len(items):
            self.last_note = f"vulnx 共 {data['total']} 条，仅展示前 {len(items)} 条"
        return items
