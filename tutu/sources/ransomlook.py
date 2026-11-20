from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import quote

from ..http import HttpClient
from ..models import Item
from ..utils import clean_text, short_date, truncate
from .base import Source

API = "https://www.ransomlook.io/api"
SITE = "https://www.ransomlook.io"


def _post_url(link: str) -> str:
    link = clean_text(link)
    if not link:
        return SITE
    if link.startswith("http"):
        return link
    return SITE + (link if link.startswith("/") else "/" + link)


class RansomlookSource(Source):
    name = "ransomlook"
    label = "RansomLook"
    kind = "intel"
    description = "开源勒索软件情报库（公开 API，无需 Key）"

    def _search(self, query: str, limit: int, http: HttpClient) -> List[Item]:
        data: Dict[str, Any] = http.get_json(
            API + "/search",
            params={"q": query},
            headers={"Accept": "application/json"},
        )
        items: List[Item] = []
        for row in (data.get("groups") or [])[:limit]:
            name = clean_text(row.get("name") or "")
            items.append(
                Item(
                    source=self.name,
                    category="group",
                    title=f"勒索组织 · {name}",
                    url=f"{SITE}/group/{quote(name, safe='')}",
                    summary=truncate(row.get("meta") or "", 500),
                    tags=["勒索软件"],
                    extra={"group": name},
                )
            )
        for row in (data.get("markets") or [])[: max(1, limit // 2)]:
            name = clean_text(row.get("name") or "")
            items.append(
                Item(
                    source=self.name,
                    category="group",
                    title=f"勒索市场 · {name}",
                    url=f"{SITE}/market/{quote(name, safe='')}",
                    summary=truncate(row.get("meta") or "", 500),
                    tags=["勒索市场"],
                )
            )
        for row in (data.get("posts") or [])[: max(1, limit)]:
            group = clean_text(row.get("group_name") or "")
            title = clean_text(row.get("post_title") or "泄露帖子")
            items.append(
                Item(
                    source=self.name,
                    category="ransomware",
                    title=f"勒索帖子 · {title}",
                    url=_post_url(row.get("link") or ""),
                    date=short_date(row.get("discovered") or ""),
                    summary=truncate(row.get("description") or "", 500),
                    tags=[group] if group else [],
                    extra={
                        "group": group,
                        "magnet": row.get("magnet"),
                        "misp_uuid": row.get("misp_uuid") or "",
                    },
                )
            )
        return items[: max(limit * 2, limit)]
