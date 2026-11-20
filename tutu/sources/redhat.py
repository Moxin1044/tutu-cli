from __future__ import annotations

from typing import Any, Dict, List

from ..http import HttpClient, SourceError
from ..models import Item
from ..utils import clean_text, first_sentence, is_exact_cve, normalize_severity, short_date, truncate
from .base import Source

API = "https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json"


class RedHatSource(Source):
    name = "redhat"
    label = "Red Hat Security Data"
    kind = "vuln"
    description = "Red Hat 安全数据 API：CVE、CVSS、受影响产品（免 Key，仅完整 CVE）"

    def _search(self, query: str, limit: int, http: HttpClient) -> List[Item]:
        query = query.strip()
        if not is_exact_cve(query):
            return []
        cve_id = query.upper()
        try:
            data = http.get_json(
                API.format(cve_id=cve_id),
                headers={"Accept": "application/json"},
            )
        except SourceError as exc:
            if "404" in str(exc):
                self.last_note = "Red Hat 未收录该 CVE"
                return []
            raise
        bugzilla = data.get("bugzilla") or {}
        cvss3 = data.get("cvss3") or {}
        affected = []
        for row in data.get("affected_release") or []:
            if not isinstance(row, dict):
                continue
            label = " ".join(
                clean_text(str(x))
                for x in (row.get("product_name"), row.get("package"))
                if x
            )
            if label and label not in affected:
                affected.append(label)
        tags: List[str] = []
        for row in data.get("package_state") or []:
            if isinstance(row, dict):
                product = clean_text(row.get("product_name") or "")
                state = clean_text(row.get("fix_state") or "")
                if product and state:
                    tags.append(f"{product}: {state}")
        refs = [
            clean_text(r.get("url") or "")
            for r in (data.get("references") or [])
            if isinstance(r, dict) and r.get("url")
        ]
        summary = clean_text(bugzilla.get("description") or data.get("statement") or "")
        return [
            Item(
                source=self.name,
                category="vulnerability",
                title=cve_id,
                url=f"https://access.redhat.com/security/cve/{cve_id}",
                date=short_date(data.get("public_date") or ""),
                summary=truncate(summary, 600),
                severity=normalize_severity(data.get("threat_severity") or ""),
                score=str(cvss3.get("cvss3_base_score") or ""),
                tags=tags[:10],
                extra={
                    "cve": cve_id,
                    "description": summary,
                    "published": data.get("public_date") or "",
                    "modified": data.get("last_modified_date") or "",
                    "vector": cvss3.get("cvss3_scoring_vector") or "",
                    "references": refs[:8],
                    "products": affected,
                    "statement": clean_text(data.get("statement") or ""),
                    "upstream": data.get("upstream") or [],
                },
            )
        ]
