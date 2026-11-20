from __future__ import annotations

from typing import Any, Dict, List

from ..http import HttpClient, SourceError
from ..models import Item
from ..utils import (
    clean_text,
    first_sentence,
    is_exact_cve,
    normalize_severity,
    short_date,
)
from .base import Source

OSV_VULN_API = "https://api.osv.dev/v1/vulns/{vuln_id}"


def _severity(rows: List[Dict[str, Any]]) -> Dict[str, str]:
    for row in rows or []:
        score = clean_text(str(row.get("score", "")))
        if "CVSS" in (row.get("type") or "").upper() or score.startswith("CVSS:"):
            return {"vector": score, "severity": ""}
    return {}


def _packages(affected: List[Dict[str, Any]], limit: int = 8) -> List[str]:
    out: List[str] = []
    for row in affected or []:
        package = row.get("package") or {}
        name = clean_text(package.get("name", ""))
        ecosystem = clean_text(package.get("ecosystem", ""))
        label = f"{ecosystem}/{name}" if ecosystem else name
        if label and label not in out:
            out.append(label)
        if len(out) >= limit:
            break
    return out


class OsvSource(Source):
    name = "osv"
    label = "OSV.dev"
    kind = "vuln"
    description = "Google OSV 开源漏洞数据库（无需 Key）"

    def _search(self, query: str, limit: int, http: HttpClient) -> List[Item]:
        query = query.strip()
        if not is_exact_cve(query):
            return []
        cve_id = query.upper()
        try:
            data = http.get_json(OSV_VULN_API.format(vuln_id=cve_id))
        except SourceError as exc:
            if "404" in str(exc):
                self.last_note = "OSV 未收录该 CVE"
                return []
            raise
        detail = clean_text(data.get("details", ""))
        summary = first_sentence(data.get("summary") or detail, 500)
        sev = _severity(data.get("severity") or [])
        tags = _packages(data.get("affected") or [])
        aliases = [a for a in (data.get("aliases") or []) if a and a != cve_id]
        refs = [
            r.get("url")
            for r in (data.get("references") or [])
            if isinstance(r, dict) and r.get("url")
        ][:5]
        return [
            Item(
                source=self.name,
                category="vulnerability",
                title=cve_id,
                url=f"https://osv.dev/vulnerability/{data.get('id') or cve_id}",
                date=short_date(data.get("published") or ""),
                summary=summary,
                severity=normalize_severity(sev.get("severity") or ""),
                score="",
                tags=tags + aliases[:3],
                extra={
                    "cve": cve_id,
                    "osv_id": data.get("id") or cve_id,
                    "modified": data.get("modified") or "",
                    "aliases": aliases,
                    "vector": sev.get("vector") or "",
                    "references": refs,
                    "description": detail,
                },
            )
        ]
