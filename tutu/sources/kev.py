from __future__ import annotations

from typing import Any, Dict, List

from ..cache import cached
from ..http import HttpClient
from ..models import Item
from ..utils import clean_text, is_exact_cve, short_date, truncate
from .base import Source

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
KEV_TTL = 6 * 3600


def get_kev_feed(http: HttpClient) -> Dict[str, Any]:
    return cached("cisa_kev", KEV_TTL, lambda: http.get_json(KEV_URL))


def _matches(record: Dict[str, Any], query: str) -> bool:
    q = query.lower()
    fields = (
        "cveID",
        "vendorProject",
        "product",
        "vulnerabilityName",
        "shortDescription",
        "requiredAction",
        "knownRansomwareCampaignUse",
    )
    return any(q in str(record.get(field, "")).lower() for field in fields)


class CisaKevSource(Source):
    name = "kev"
    label = "CISA KEV"
    kind = "vuln"
    description = "CISA 已知利用漏洞目录（官方 JSON Feed，无需 Key）"

    def _search(self, query: str, limit: int, http: HttpClient) -> List[Item]:
        feed = get_kev_feed(http)
        records = feed.get("vulnerabilities") or []
        query = query.strip()
        exact = is_exact_cve(query)
        matched: List[Dict[str, Any]] = []
        for record in records:
            if exact:
                if (record.get("cveID") or "").upper() == query.upper():
                    matched.append(record)
            elif _matches(record, query):
                matched.append(record)
            if len(matched) >= limit:
                break

        items: List[Item] = []
        for record in matched:
            cve_id = (record.get("cveID") or "").upper()
            tags = [
                clean_text(record.get("vendorProject", "")),
                clean_text(record.get("product", "")),
            ]
            if str(record.get("knownRansomwareCampaignUse", "")).lower() == "known":
                tags.append("勒索软件利用")
            items.append(
                Item(
                    source=self.name,
                    category="vulnerability",
                    title=cve_id,
                    url=(
                        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                        f"?search_api_fulltext={cve_id}"
                    ),
                    date=short_date(record.get("dateAdded") or ""),
                    summary=truncate(
                        f"{record.get('vulnerabilityName', '')} — "
                        f"{record.get('shortDescription', '')}",
                        500,
                    ),
                    severity="KEV",
                    score="",
                    tags=[t for t in tags if t],
                    extra={
                        "cve": cve_id,
                        "kev": True,
                        "vendor": record.get("vendorProject") or "",
                        "product": record.get("product") or "",
                        "ransomware": str(
                            record.get("knownRansomwareCampaignUse", "")
                        ).lower()
                        == "known",
                        "required_action": record.get("requiredAction") or "",
                        "due_date": record.get("dueDate") or "",
                        "feed_date": feed.get("dateReleased") or "",
                        "feed_count": feed.get("count"),
                    },
                )
            )
        if not items:
            self.last_note = (
                f"KEV feed 共 {feed.get('count', '?')} 条"
                f"（更新于 {feed.get('dateReleased', '未知')}），未命中"
            )
        return items
