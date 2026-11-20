from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import quote

from ..http import HttpClient, SourceError
from ..models import Item
from ..utils import clean_text, short_date, truncate
from .base import Source

BASE = "https://ransomware.socradar.io"
SEARCH_API = BASE + "/api/ransomware/search"


def _looks_challenged(text: str) -> bool:
    return "Just a moment" in text or "cf-chl" in text or "challenge-platform" in text


class SocradarRansomwareSource(Source):
    name = "socradar"
    label = "SOCRadar Ransomware"
    kind = "intel"
    description = "SOCRadar 勒索软件情报（公开 Web API，无需 Key；可能有 Cloudflare 挑战）"

    def _search(self, query: str, limit: int, http: HttpClient) -> List[Item]:
        # 先访问首页拿 Cloudflare 正常 Cookie，再调 API。
        home = http.get(BASE + "/", headers={"Accept": "text/html"})
        if _looks_challenged(home.text):
            raise SourceError("Cloudflare 人机挑战拦截（浏览器可访问，脚本暂不可用）")
        headers = {
            "Accept": "application/json",
            "Referer": BASE + "/",
            "Origin": BASE,
        }
        try:
            data: Dict[str, Any] = http.get_json(
                SEARCH_API,
                params={"q": query},
                headers=headers,
            )
        except SourceError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise SourceError(f"API 请求失败: {exc}") from exc

        items: List[Item] = []
        victims = (data.get("victims") or {}).get("items") or []
        for row in victims[: max(1, limit)]:
            company = clean_text(row.get("company") or "受害者")
            actor = clean_text(row.get("threat_actor") or "")
            country = clean_text(row.get("country") or "")
            status = clean_text(row.get("status") or "")
            tags = [t for t in (actor, country, status) if t]
            items.append(
                Item(
                    source=self.name,
                    category="ransomware",
                    title=f"勒索受害者 · {company}",
                    url=BASE + (row.get("path") or ""),
                    date=short_date(
                        row.get("attack_at")
                        or row.get("discovered_at")
                        or row.get("published_at")
                        or ""
                    ),
                    summary=truncate(
                        f"组织: {actor or '未知'} · 国家: {country or '未知'} · "
                        f"行业: {clean_text(row.get('industry') or '未知')}",
                        400,
                    ),
                    tags=tags,
                    extra={
                        "group": actor,
                        "country": country,
                        "status": status,
                        "confidence": row.get("confidence_score"),
                        "data_volume_gb": row.get("data_volume_gb"),
                    },
                )
            )

        for row in (data.get("groups") or [])[:limit]:
            name = clean_text(row.get("name") or "")
            items.append(
                Item(
                    source=self.name,
                    category="group",
                    title=f"勒索组织 · {name}",
                    url=f"{BASE}/groups/{quote(row.get('slug') or name)}",
                    summary=f"关联受害者 {row.get('count', 'N/A')}",
                    tags=["勒索软件"],
                    extra={"group": name, "count": row.get("count")},
                )
            )

        if not items:
            self.last_note = "SOCRadar 公开搜索未返回匹配项。"
        return items
