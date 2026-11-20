from __future__ import annotations

from typing import Any, Dict, List

from ..http import HttpClient
from ..models import Item
from ..utils import clean_text, short_date, truncate
from .base import Source

BASE = "https://nti.nsfocus.com"
API = BASE + "/api/v2"


def _tags(values: List[Any], limit: int = 8) -> List[str]:
    out: List[str] = []
    for value in values or []:
        label = clean_text(value if isinstance(value, str) else str(value))
        if label and label not in out:
            out.append(label)
        if len(out) >= limit:
            break
    return out


class NsfocusSource(Source):
    name = "nsfocus"
    label = "绿盟 NTI"
    kind = "intel"
    description = "绿盟威胁情报中心：APT 组织 / 攻击活动 / 威胁新闻 / 漏洞通告（公开 API）"

    def _fetch(self, path: str, query: str, limit: int, http: HttpClient) -> Dict[str, Any]:
        return http.get_json(
            API + path,
            params={"query": query, "page": 1, "size": max(1, min(limit, 20))},
            headers={"Accept": "application/json", "Referer": BASE + "/apt/home"},
        )

    def _search(self, query: str, limit: int, http: HttpClient) -> List[Item]:
        items: List[Item] = []
        errors: List[str] = []

        # APT 组织
        try:
            data = self._fetch("/apt/objects/", query, limit, http)
            for row in (data.get("objects") or [])[:limit]:
                object_id = row.get("id") or ""
                names = _tags([row.get("name")] + list(row.get("aliases") or []))
                countries = [
                    loc.get("country")
                    for loc in (row.get("locations") or [])
                    if isinstance(loc, dict) and loc.get("country")
                ]
                items.append(
                    Item(
                        source=self.name,
                        category="apt",
                        title=f"APT 组织 · {row.get('name') or object_id}",
                        url=f"{BASE}/apt?query={object_id}",
                        date=short_date(row.get("first_seen") or row.get("created") or ""),
                        summary=truncate(row.get("description") or "", 500),
                        tags=names[:5] + countries[:3],
                        extra={
                            "id": object_id,
                            "aliases": row.get("aliases") or [],
                            "ioc_count": row.get("ioc-count"),
                            "campaign_count": row.get("campaign-count"),
                            "last_seen": row.get("last_seen") or "",
                        },
                    )
                )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"APT组织: {exc}")

        # 攻击活动 / 报告
        try:
            data = self._fetch("/apt/campaign/", query, limit, http)
            for row in (data.get("objects") or [])[:limit]:
                object_id = row.get("id") or ""
                items.append(
                    Item(
                        source=self.name,
                        category="campaign",
                        title=clean_text(row.get("name") or "攻击活动"),
                        url=f"{BASE}/apt/event?query={object_id}",
                        date=short_date(row.get("created") or row.get("first_seen") or ""),
                        summary=truncate(row.get("description") or "", 500),
                        tags=_tags(
                            [f"IOC {row.get('ioc-count')}" if row.get("ioc-count") else ""]
                        ),
                        extra={
                            "id": object_id,
                            "reportid": row.get("reportid") or "",
                            "ioc_count": row.get("ioc-count"),
                        },
                    )
                )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"攻击活动: {exc}")

        # 威胁新闻
        try:
            data = self._fetch("/apt/news/", query, limit, http)
            for row in (data.get("objects") or [])[:limit]:
                urls = row.get("url") or []
                url = urls[0] if isinstance(urls, list) and urls else f"{BASE}/news"
                items.append(
                    Item(
                        source=self.name,
                        category="news",
                        title=clean_text(row.get("title") or "威胁新闻"),
                        url=url,
                        date=short_date(row.get("reported") or row.get("created") or ""),
                        summary=truncate(row.get("description") or "", 500),
                        tags=[],
                        extra={"id": row.get("id") or ""},
                    )
                )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"威胁新闻: {exc}")

        # 漏洞通告 / 处置手册
        try:
            data = self._fetch("/report/notie/", query, limit, http)
            for row in (data.get("data") or [])[:limit]:
                children = row.get("children") or []
                desc = ""
                if children and isinstance(children[0], dict):
                    desc = children[0].get("description") or ""
                object_id = row.get("id") or ""
                items.append(
                    Item(
                        source=self.name,
                        category="notice",
                        title=clean_text(row.get("title") or "漏洞通告"),
                        url=f"{BASE}/threatNotice?query={object_id}",
                        date=short_date(
                            row.get("reported") or row.get("created") or row.get("modified") or ""
                        ),
                        summary=truncate(desc, 500),
                        tags=_tags(row.get("cve_ids") or []),
                        extra={"id": object_id, "cve_ids": row.get("cve_ids") or []},
                    )
                )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"漏洞通告: {exc}")

        if errors:
            self.last_note = "；".join(errors)
        return items
