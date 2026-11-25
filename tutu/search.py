from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Sequence, Tuple

from .http import DEFAULT_UA, HttpClient
from .models import Item, SourceResult, VulnCard
from .sources.base import Source
from .sources.epss import enrich_epss
from .utils import (
    extract_cves,
    is_exact_cve,
    normalize_severity,
    short_date,
    severity_rank,
)
from .versions import VersionRange, range_matches_product, sort_ranges

log = logging.getLogger("tutu.search")


def run_sources(
    sources: Sequence[Source],
    query: str,
    limit: int,
    timeout: float,
    deep: bool = False,
    debug: bool = False,
) -> List[SourceResult]:
    if not sources:
        return []

    def work(source: Source) -> SourceResult:
        http = HttpClient(timeout=timeout, user_agent=DEFAULT_UA)
        if deep and hasattr(source, "deep"):
            source.deep = True
        result = source.search(query, limit, http)
        if debug and result.error:
            log.debug("%s 失败: %s", source.name, result.error)
        return result

    results: Dict[str, SourceResult] = {}
    with ThreadPoolExecutor(max_workers=min(8, len(sources))) as pool:
        futures = {pool.submit(work, source): source for source in sources}
        for future in as_completed(futures):
            source = futures[future]
            try:
                results[source.name] = future.result()
            except Exception as exc:  # noqa: BLE001
                results[source.name] = SourceResult(
                    source=source.name,
                    label=source.label,
                    error=str(exc)[:300] or exc.__class__.__name__,
                )
    return [results[s.name] for s in sources if s.name in results]


def _earliest(values: List[str]) -> str:
    values = [short_date(v) for v in values if v]
    return min(values) if values else ""


def _latest(values: List[str]) -> str:
    values = [short_date(v) for v in values if v]
    return max(values) if values else ""


def _numeric(value: str) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return 0.0


def merge_vulnerabilities(
    results: Sequence[SourceResult],
    limit: int,
) -> Tuple[List[VulnCard], List[Item]]:
    labels = {r.source: r.label for r in results}
    cards: Dict[str, VulnCard] = {}
    standalone_exploits: List[Item] = []

    def card_for(cve: str) -> VulnCard:
        cve = cve.upper()
        if cve not in cards:
            cards[cve] = VulnCard(cve=cve)
        return cards[cve]

    for result in results:
        for item in result.items:
            if item.category == "exploit":
                cves = extract_cves(
                    " ".join([item.title, item.summary] + list(item.tags))
                )
                extra_cve = (item.extra or {}).get("cve")
                if not cves and extra_cve:
                    cves = [str(extra_cve).upper()]
                if cves:
                    for cve in cves:
                        card_for(cve).exploits.append(item)
                else:
                    standalone_exploits.append(item)
                continue
            if item.category != "vulnerability":
                continue
            cve = (item.extra or {}).get("cve") or ""
            if not cve:
                match = re.search(r"CVE-\d{4}-\d{4,}", item.title, re.I)
                cve = match.group(0) if match else ""
            if not cve:
                continue
            card = card_for(cve)
            card.items.append(item)
            if item.source not in card.sources:
                card.sources.append(item.source)
            description = (
                (item.extra or {}).get("description")
                or item.summary
                or ""
            )
            if len(description) > len(card.summary):
                card.summary = description[:900]
            if item.severity and item.severity.upper() not in ("KEV",):
                if severity_rank(item.severity) >= severity_rank(card.severity):
                    card.severity = normalize_severity(item.severity)
                    card.score = item.score or card.score
            elif item.score and not card.score:
                card.score = item.score
            published = (
                (item.extra or {}).get("published")
                or item.date
                or ""
            )
            if published:
                card.published = (
                    _earliest([card.published, published])
                    if card.published
                    else short_date(published)
                )
            modified = (item.extra or {}).get("modified") or ""
            if modified:
                card.modified = (
                    _latest([card.modified, modified])
                    if card.modified
                    else short_date(modified)
                )
            if (item.extra or {}).get("kev"):
                card.kev = True
                card.ransomware = card.ransomware or bool(
                    (item.extra or {}).get("ransomware")
                )
            for product in (item.extra or {}).get("products") or []:
                product = str(product).strip()
                if product and product not in card.affected_products:
                    card.affected_products.append(product)
            for rng in (item.extra or {}).get("version_ranges") or []:
                if isinstance(rng, VersionRange):
                    card.version_ranges.append(rng)
            for tag in item.tags:
                tag = str(tag).strip()
                if tag and tag not in card.tags:
                    card.tags.append(tag)
            for ref in (item.extra or {}).get("references") or []:
                if isinstance(ref, str) and ref and ref not in card.refs:
                    card.refs.append(ref)
            for exploit in item.extra.get("exploits") or []:
                if isinstance(exploit, Item):
                    card.exploits.append(exploit)

    for card in cards.values():
        card.tags = card.tags[:10]
        card.affected_products = card.affected_products[:12]
        card.version_ranges = sort_ranges(card.version_ranges)[:40]
        card.refs = card.refs[:8]
        deduped: List[Item] = []
        seen_urls = set()
        for exploit in card.exploits:
            key = exploit.url or exploit.title
            if key and key in seen_urls:
                continue
            seen_urls.add(key)
            deduped.append(exploit)
        card.exploits = deduped
        card.sources = [labels.get(s, s) for s in card.sources]
        if not card.severity:
            card.severity = "KEV" if card.kev else "UNKNOWN"
        if card.score:
            card.score = f"{_numeric(card.score):.1f}"
        if not card.summary:
            card.summary = "（多个来源暂无摘要）"

    ordered = sort_cards(cards.values())
    return ordered[: max(1, limit)], standalone_exploits


def sort_cards(cards: Sequence[VulnCard]) -> List[VulnCard]:
    return sorted(
        cards,
        key=lambda c: (
            0 if c.kev else 1,
            -severity_rank(c.severity),
            -c.epss,
            c.published or "9999",
            c.cve,
        ),
    )


def enrich_cards(cards: Sequence[VulnCard], timeout: float) -> None:
    items: List[Item] = []
    for card in cards:
        items.extend(card.items)
    if not items:
        return
    http = HttpClient(timeout=timeout, user_agent=DEFAULT_UA)
    enrich_epss(items, http)
    by_cve: Dict[str, Item] = {}
    for item in items:
        cve = (item.extra or {}).get("cve")
        if cve:
            by_cve[cve.upper()] = item
    for card in cards:
        item = by_cve.get(card.cve.upper())
        if not item:
            continue
        card.epss = float(item.extra.get("epss") or 0.0)
        card.epss_percentile = float(item.extra.get("epss_percentile") or 0.0)


def is_exact_query(query: str) -> bool:
    return is_exact_cve(query)


def check_version(
    cards: Sequence[VulnCard],
    product: str,
    version: str,
) -> Dict[str, Any]:
    """判断给定产品/版本是否落在卡片披露的受影响区间内。

    返回 {affected, unaffected, unknown}，每项是 {cve, product, range}。
    """
    affected: List[Dict[str, str]] = []
    unaffected: List[Dict[str, str]] = []
    unknown: List[Dict[str, str]] = []
    for card in cards:
        ranges = [
            rng
            for rng in card.version_ranges
            if not product or range_matches_product(rng, product)
        ]
        if not ranges:
            unknown.append({"cve": card.cve, "product": product, "range": ""})
            continue
        hits = [rng for rng in ranges if rng.contains(version)]
        if hits:
            affected.append(
                {
                    "cve": card.cve,
                    "product": hits[0].product,
                    "range": hits[0].label(),
                }
            )
            continue
        unaffected.append(
            {
                "cve": card.cve,
                "product": ranges[0].product,
                "range": ranges[0].label(),
            }
        )
    return {
        "affected": affected,
        "unaffected": unaffected,
        "unknown": unknown,
    }
