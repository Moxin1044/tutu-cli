from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import quote

from ..cache import cached
from ..http import HttpClient
from ..models import Item
from ..utils import clean_text, short_date, truncate
from .base import Source

API = "https://api.ransomware.live/v2"
SITE = "https://www.ransomware.live"
GROUPS_TTL = 6 * 3600
SEARCH_TTL = 600


def _groups(http: HttpClient) -> List[Dict[str, Any]]:
    data = cached(
        "ransomware_live_groups",
        GROUPS_TTL,
        lambda: http.get_json(API + "/groups"),
    )
    return data if isinstance(data, list) else []


class RansomwareLiveSource(Source):
    name = "ransomware_live"
    label = "ransomware.live"
    kind = "intel"
    description = "勒索软件泄露站监控（公开 API v2，无需认证；每端点 1 次/分钟）"

    def _search(self, query: str, limit: int, http: HttpClient) -> List[Item]:
        items: List[Item] = []
        needle = query.lower()

        # 先匹配已知组织（缓存全量 groups，避免频繁请求）
        try:
            for row in _groups(http):
                haystack = " ".join(
                    [
                        str(row.get("name") or ""),
                        str(row.get("altname") or ""),
                        str(row.get("description") or ""),
                    ]
                ).lower()
                if needle not in haystack:
                    continue
                name = clean_text(row.get("name") or "")
                items.append(
                    Item(
                        source=self.name,
                        category="group",
                        title=f"勒索组织 · {name}",
                        url=f"{SITE}/group/{quote(name, safe='')}",
                        date=short_date(row.get("added_date") or ""),
                        summary=truncate(row.get("description") or "", 500),
                        tags=["勒索软件", "RaaS"],
                        extra={
                            "group": name,
                            "altname": row.get("altname") or "",
                            "locations": len(row.get("locations") or []),
                        },
                    )
                )
                if len(items) >= limit:
                    break
        except Exception:
            pass

        # 受害者检索（带缓存，降低 1 req/min 的限制影响）
        try:
            data = cached(
                f"ransomware_live_search_{query}",
                SEARCH_TTL,
                lambda: http.get_json(API + "/searchvictims/" + quote(query, safe="")),
            )
        except Exception as exc:  # noqa: BLE001
            message = str(exc)
            if "404" in message:
                data = []
            elif not items:
                raise
            else:
                self.last_note = f"受害者检索失败: {exc}"
                data = []

        for row in (data if isinstance(data, list) else [])[: max(1, limit)]:
            victim = clean_text(row.get("victim") or row.get("domain") or "受害者")
            group = clean_text(row.get("group") or "")
            country = clean_text(row.get("country") or "")
            activity = clean_text(row.get("activity") or "")
            tags = [t for t in (group, country, activity) if t]
            items.append(
                Item(
                    source=self.name,
                    category="ransomware",
                    title=f"勒索受害者 · {victim}",
                    url=clean_text(row.get("url") or ""),
                    date=short_date(row.get("attackdate") or row.get("discovered") or ""),
                    summary=truncate(row.get("description") or "", 500),
                    tags=tags,
                    extra={
                        "group": group,
                        "country": country,
                        "activity": activity,
                        "claim_url": row.get("claim_url") or "",
                        "data_size": row.get("data_size"),
                    },
                )
            )
            if len(items) >= limit:
                break

        if not items:
            self.last_note = (
                "ransomware.live 未找到匹配；该免费 API 每端点限 1 次/分钟，"
                "结果已缓存 10 分钟。"
            )
        return items
