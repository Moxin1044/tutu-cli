from __future__ import annotations

import os
from typing import List

from ..http import HttpClient
from ..models import Item
from ..utils import clean_text, first_sentence, normalize_severity, short_date
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
                    },
                )
            )
        return items
