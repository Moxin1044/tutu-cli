from __future__ import annotations

from typing import Any, Dict, List

from ..cache import cached
from ..http import HttpClient
from ..models import Item
from ..utils import clean_text, short_date, truncate
from .base import Source

POSTS_URL = (
    "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
)
SITE = "https://www.ransomwatch.org"
TTL = 12 * 3600


class RansomwatchSource(Source):
    name = "ransomwatch"
    label = "Ransomwatch"
    kind = "intel"
    description = "Ransomwatch 公开泄露帖子聚合（GitHub JSON，无需 Key）"

    def _search(self, query: str, limit: int, http: HttpClient) -> List[Item]:
        rows = cached("ransomwatch_posts", TTL, lambda: http.get_json(POSTS_URL))
        if not isinstance(rows, list):
            return []
        needle = query.lower()
        items: List[Item] = []
        for row in rows:
            title = clean_text(row.get("post_title") or "")
            group = clean_text(row.get("group_name") or "")
            if needle not in (title + " " + group).lower():
                continue
            items.append(
                Item(
                    source=self.name,
                    category="ransomware",
                    title=f"勒索帖子 · {title}",
                    url=f"{SITE}/#/groups/{group}" if group else SITE,
                    date=short_date(row.get("discovered") or ""),
                    summary=f"组织: {group}" if group else "",
                    tags=[group] if group else [],
                    extra={"group": group},
                )
            )
            if len(items) >= limit:
                break
        return items
