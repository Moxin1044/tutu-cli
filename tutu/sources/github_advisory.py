from __future__ import annotations

import os
from typing import List

from ..http import HttpClient
from ..models import Item
from ..utils import clean_text, first_sentence, normalize_severity, short_date
from ..versions import format_ranges, ranges_from_string
from .base import Source

GH_ADVISORIES = "https://api.github.com/advisories"


class GithubAdvisorySource(Source):
    name = "github"
    label = "GitHub Advisory"
    kind = "vuln"
    description = "GitHub Advisory Database（可选；未认证时受 60 次/小时限流）"

    def _search(self, query: str, limit: int, http: HttpClient) -> List[Item]:
        headers = {"Accept": "application/vnd.github+json"}
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = http.get_json(
            GH_ADVISORIES,
            params={"cve_id": query.strip(), "per_page": max(1, min(limit, 20))},
            headers=headers,
        )
        if not isinstance(data, list):
            return []
        items: List[Item] = []
        for row in data:
            cve_id = row.get("cve_id") or ""
            if not cve_id:
                continue
            tags = [t for t in (row.get("cwes") or []) if t]
            products = []
            ranges = []
            patched = []
            for vuln in row.get("vulnerabilities") or []:
                package = (vuln or {}).get("package") or {}
                name = clean_text(package.get("name") or "")
                ecosystem = clean_text(package.get("ecosystem") or "")
                label = f"{ecosystem}/{name}" if ecosystem else name
                if label and label not in products:
                    products.append(label)
                vuln_range = clean_text((vuln or {}).get("vulnerable_version_range") or "")
                ranges.extend(ranges_from_string(label, vuln_range, "github"))
                patched_range = clean_text((vuln or {}).get("patched_versions") or "")
                if patched_range and patched_range not in patched:
                    patched.append(f"{label}: {patched_range}")
            items.append(
                Item(
                    source=self.name,
                    category="vulnerability",
                    title=cve_id,
                    url=row.get("html_url") or "",
                    date=short_date(row.get("published_at") or ""),
                    summary=first_sentence(row.get("summary") or "", 500),
                    severity=normalize_severity(row.get("severity") or ""),
                    score=str((row.get("cvss") or {}).get("score") or ""),
                    tags=tags,
                    extra={
                        "cve": cve_id,
                        "ghsa": row.get("ghsa_id") or "",
                        "modified": row.get("updated_at") or "",
                        "references": row.get("references") or [],
                        "products": products[:8],
                        "version_ranges": ranges,
                        "affected_versions": format_ranges(ranges),
                        "patched_versions": patched[:6],
                    },
                )
            )
        return items
