from __future__ import annotations

from typing import Any, Dict, List

from ..http import HttpClient
from ..models import Item
from ..utils import clean_text, short_date, truncate
from .base import Source

SPLOITUS_SEARCH = "https://sploitus.com/search"


class SploitusSource(Source):
    name = "sploitus"
    label = "Sploitus"
    kind = "vuln"
    description = "公开 Exploit / PoC 搜索引擎（POST API，无需 Key）"

    def _search(self, query: str, limit: int, http: HttpClient) -> List[Item]:
        payload = {
            "type": "exploits",
            "sort": "default",
            "query": query,
            "title": False,
            "offset": 0,
        }
        data = http.post_json(SPLOITUS_SEARCH, payload)
        items: List[Item] = []
        for row in (data.get("exploits") or [])[: max(1, limit)]:
            title = clean_text(row.get("title") or row.get("id") or "Exploit")
            href = clean_text(row.get("href") or "")
            tags = [clean_text(row.get("type", ""))]
            if row.get("score") is not None:
                tags.append(f"score {row.get('score')}")
            items.append(
                Item(
                    source=self.name,
                    category="exploit",
                    title=title,
                    url=href,
                    date=short_date(row.get("published") or ""),
                    summary=truncate(
                        f"{row.get('id', '')} · {row.get('type', '')}", 200
                    ),
                    tags=[t for t in tags if t],
                    extra={
                        "exploit_id": row.get("id") or "",
                        "exploit_type": row.get("type") or "",
                    },
                )
            )
        return items
