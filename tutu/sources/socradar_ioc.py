from __future__ import annotations

from typing import List
from urllib.parse import quote

from ..http import HttpClient
from ..lookup.socradar import ioc_risk, ioc_search, parse_ioc
from ..models import Item
from ..utils import clean_text, short_date, truncate
from .base import Source


class SocradarIocSource(Source):
    name = "socradar_ioc"
    label = "SOCRadar IOC"
    kind = "intel"
    description = "SOCRadar IOC Radar：恶意 IP / 域名 / URL / 哈希指标（公开 API）"

    def _search(self, query: str, limit: int, http: HttpClient) -> List[Item]:
        data = ioc_search(http, query, limit)
        items: List[Item] = []
        for row in (data.get("items") or [])[:limit]:
            parsed = parse_ioc(row)
            value = parsed["value"]
            if not value:
                continue
            risk = ioc_risk(parsed)
            tags = list(parsed["categories"]) + list(parsed["malware_families"])
            if parsed["flags"].get("is_tor"):
                tags.append("Tor")
            if parsed["flags"].get("is_proxy"):
                tags.append("Proxy")
            if parsed["flags"].get("is_scanner"):
                tags.append("Scanner")
            items.append(
                Item(
                    source=self.name,
                    category="ioc",
                    title=f"{parsed['type'] or 'IOC'} · {value}",
                    url=f"https://ioc.socradar.io/iocs?q={quote(value, safe='')}",
                    date=short_date(parsed["last_seen"] or parsed["first_seen"]),
                    summary=truncate(
                        f"置信度 {parsed['confidence_label'] or parsed['confidence']} · "
                        f"{risk['risk']} · "
                        + " · ".join(risk["reasons"]),
                        400,
                    ),
                    severity="",
                    tags=tags[:8],
                    extra={
                        "ioc_type": parsed["type"],
                        "value": value,
                        "risk": risk["risk"],
                        "confidence": parsed["confidence"],
                        "geo": parsed["geo"],
                        "flags": parsed["flags"],
                        "linked_reports": parsed["linked_reports"],
                        "otx_pulse_count": parsed["otx_pulse_count"],
                    },
                )
            )
        if data.get("total") and int(data["total"]) > len(items):
            self.last_note = f"SOCRadar IOC 共 {data['total']} 条，仅展示前 {len(items)} 条"
        return items
