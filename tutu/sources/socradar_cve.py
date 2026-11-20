from __future__ import annotations

from typing import Any, Dict, List

from ..http import HttpClient
from ..lookup.socradar import cve_detail, cve_search, parse_cve
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


def _exploit_items(data: Dict[str, Any]) -> List[Item]:
    items: List[Item] = []
    for row in data.get("exploits") or []:
        items.append(
            Item(
                source="socradar_cve",
                category="exploit",
                title=clean_text(row.get("title") or "Exploit"),
                url=clean_text(row.get("url") or ""),
                date=short_date(row.get("date") or ""),
                summary=clean_text(row.get("platform") or ""),
                tags=[clean_text(row.get("type") or "")],
                extra={
                    "exploit_id": row.get("id") or "",
                    "cve": data.get("cve") or "",
                },
            )
        )
    return items


class SocradarCveSource(Source):
    name = "socradar_cve"
    label = "SOCRadar CVE"
    kind = "vuln"
    description = "SOCRadar CVE Radar：CVE 详情、PoC、Exploit-DB、KEV、SSVC（公开 API）"

    def _search(self, query: str, limit: int, http: HttpClient) -> List[Item]:
        query = query.strip()
        if is_exact_cve(query):
            raw = cve_detail(http, query)
            parsed = parse_cve(raw)
            cve_id = parsed["cve"] or query.upper()
            exploits = _exploit_items({**raw, "cve": cve_id})
            item = Item(
                source=self.name,
                category="vulnerability",
                title=cve_id,
                url=f"https://cve.socradar.io/cve/{cve_id}",
                date=short_date(parsed["published"] or ""),
                summary=truncate(parsed["summary"] or parsed["title"], 700),
                severity=normalize_severity(parsed["severity"]),
                score=str(parsed["cvss"] or ""),
                tags=(parsed["cwes"] + parsed["products"])[:10],
                extra={
                    "cve": cve_id,
                    "description": parsed["summary"] or parsed["title"],
                    "published": parsed["published"],
                    "modified": parsed["modified"],
                    "epss": parsed["epss"],
                    "kev": parsed["kev"],
                    "ransomware": parsed["ransomware"],
                    "references": parsed["references"],
                    "exploits": exploits,
                    "poc_count": parsed["poc_count"],
                    "repo_total": parsed["repo_total"],
                    "ssvc": parsed["ssvc"],
                    "solution": parsed["solution"],
                    "required_action": parsed["required_action"],
                    "sources": parsed["sources"],
                    "vectors": [],
                },
            )
            if parsed["kev"]:
                self.last_note = f"SOCRadar CVE：KEV 收录 {parsed['kev_added'] or ''}".strip()
            return [item]

        data = cve_search(http, query, limit)
        items: List[Item] = []
        for row in (data.get("cves") or [])[:limit]:
            cve_id = clean_text(row.get("id") or "")
            if not cve_id:
                continue
            tags = [
                clean_text(c)
                for c in (row.get("cwe_ids") or [])
                if clean_text(c)
            ]
            tags += [clean_text(v) for v in (row.get("vendors") or []) if clean_text(v)]
            if row.get("has_poc"):
                tags.append("POC")
            if row.get("nuclei"):
                tags.append("Nuclei")
            items.append(
                Item(
                    source=self.name,
                    category="vulnerability",
                    title=cve_id,
                    url=f"https://cve.socradar.io/cve/{cve_id}",
                    date=short_date(row.get("published_at") or ""),
                    summary=truncate(row.get("title") or "", 500),
                    severity=normalize_severity(row.get("severity") or ""),
                    score=str(row.get("cvss") or ""),
                    tags=tags,
                    extra={
                        "cve": cve_id,
                        "epss": row.get("epss"),
                        "kev": bool(row.get("kev")),
                        "published": row.get("published_at") or "",
                        "poc_sources": row.get("poc_sources") or [],
                        "total_results": data.get("total"),
                    },
                )
            )
        if data.get("total") and int(data["total"]) > len(items):
            self.last_note = f"SOCRadar 共 {data['total']} 条，仅展示前 {len(items)} 条"
        return items
