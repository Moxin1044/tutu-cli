from __future__ import annotations

from typing import List
from urllib.parse import quote

from ..http import HttpClient
from ..models import Item
from ..utils import clean_text, short_date, truncate
from .base import Source

BASE = "https://ti.360.cn"
RESEARCH_API = BASE + "/api/custom/sc/v3/researches"


class Ti360Source(Source):
    name = "360"
    label = "360 威胁情报"
    kind = "intel"
    description = "360 安全大脑：公开安全通告 / 研究文章（公开内容 API）"

    def _search(self, query: str, limit: int, http: HttpClient) -> List[Item]:
        data = http.get_json(
            RESEARCH_API,
            params={"page": 1, "size": max(20, min(limit * 4, 60))},
            headers={"Accept": "application/json", "Referer": BASE + "/"},
        )
        rows = (data.get("data") or {}).get("records") or []
        needle = query.lower()
        items: List[Item] = []
        for row in rows:
            title = clean_text(row.get("title") or "")
            summary = clean_text(row.get("summary") or "")
            publisher = clean_text(row.get("publisher") or "")
            haystack = " ".join([title, summary, publisher, clean_text(row.get("url") or "")]).lower()
            if needle not in haystack:
                continue
            items.append(
                Item(
                    source=self.name,
                    category="news",
                    title=title or "360 安全通告",
                    url=clean_text(row.get("url") or ""),
                    date=short_date(row.get("publish_time") or ""),
                    summary=truncate(summary, 500),
                    tags=[publisher] if publisher else [],
                    extra={"publisher": publisher},
                )
            )
            if len(items) >= limit:
                break

        if not items:
            portal = f"{BASE}/#/search-result?q={quote(query, safe='')}"
            self.last_note = (
                "公开内容 API 只返回最新安全通告，未命中关键词；"
                "站内搜索接口被云防护拦截，可打开搜索页查看。"
            )
            items.append(
                Item(
                    source=self.name,
                    category="portal",
                    title="360 威胁情报 · 站内搜索入口",
                    url=portal,
                    summary=(
                        "360 的 APT/漏洞检索接口目前对非浏览器请求返回云防护拦截页；"
                        "此入口可在浏览器中继续检索。"
                    ),
                    tags=["入口", "公开API受限"],
                    extra={"portal": True},
                )
            )
        return items
