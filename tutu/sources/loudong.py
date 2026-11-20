from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import quote

from ..cache import cached
from ..http import HttpClient
from ..models import Item
from ..utils import clean_text, short_date, strip_html, truncate
from .base import Source

BASE = "https://loudong.org.cn"
CARD_RE = re.compile(r'<article class="vuln-card">(.*?)</article>', re.S)


def _card_items(html: str, query: str, limit: int) -> List[Item]:
    items: List[Item] = []
    needle = query.lower()
    for card in CARD_RE.findall(html):
        cve = re.search(r'class="vc-cve">([^<]+)', card)
        title = re.search(r"<h3>\s*<a[^>]*>(.*?)</a>", card, re.S)
        summary = re.search(r'class="vc-summary">(.*?)</p>', card, re.S)
        cvss = re.search(r'class="vc-cvss">([^<]+)', card)
        sev = re.search(r'class="vc-sev[^"]*">([^<]+)', card)
        href = re.search(r'href="(/vulns/\d+)"', card)
        date = re.search(r"fa-clock\)?</i>\s*([0-9]{4}-[0-9]{2}-[0-9]{2})", card)
        cve_id = clean_text(cve.group(1)) if cve else ""
        title_text = strip_html(title.group(1)) if title else ""
        summary_text = strip_html(summary.group(1)) if summary else ""
        haystack = " ".join([cve_id, title_text, summary_text]).lower()
        if needle not in haystack:
            continue
        url = BASE + href.group(1) if href else BASE + "/vulns"
        items.append(
            Item(
                source="loudong",
                category="vulnerability",
                title=cve_id or title_text or "漏洞情报",
                url=url,
                date=short_date(date.group(1) if date else ""),
                summary=truncate(summary_text or title_text, 500),
                severity=clean_text(sev.group(1)) if sev else "",
                score=clean_text(cvss.group(1)).replace("CVSS", "").strip() if cvss else "",
                tags=["漏洞情报"],
                extra={"cve": cve_id},
            )
        )
        if len(items) >= limit:
            break
    return items


def _generic_links(html: str, query: str, limit: int) -> List[Item]:
    """搜索页结构变化时的兜底：抓取包含关键词的 /vulns|/news 链接。"""
    items: List[Item] = []
    needle = query.lower()
    pattern = re.compile(
        r'<a[^>]+href="(/(?:vulns|news)/\d+)"[^>]*>(.*?)</a>', re.S
    )
    for href, text in pattern.findall(html):
        text = strip_html(text)
        if not text or needle not in text.lower():
            continue
        items.append(
            Item(
                source="loudong",
                category="news",
                title=truncate(text, 200),
                url=BASE + href,
                summary="",
                tags=["漏洞情报"],
            )
        )
        if len(items) >= limit:
            break
    return items


class LoudongSource(Source):
    name = "loudong"
    label = "漏洞情报 loudong"
    kind = "intel"
    description = "loudong.org.cn 漏洞/情报站（HTML 爬虫，支持 --deep 翻页）"

    deep = False

    def _search(self, query: str, limit: int, http: HttpClient) -> List[Item]:
        html = cached(
            f"loudong_search_{query}",
            1800,
            lambda: http.get_text(
                BASE + "/search",
                params={"q": query},
                headers={"Referer": BASE + "/"},
            ),
        )
        items = _card_items(html, query, limit)
        if not items:
            items = _generic_links(html, query, limit)

        if not items:
            pages = range(1, 4) if self.deep else range(1, 2)
            for page in pages:
                try:
                    page_html = cached(
                        f"loudong_vulns_{page}",
                        3600,
                        lambda p=page: http.get_text(
                            BASE + "/vulns",
                            params={"page": p},
                            headers={"Referer": BASE + "/vulns"},
                        ),
                    )
                    items.extend(_card_items(page_html, query, limit - len(items)))
                    if len(items) >= limit:
                        break
                    time.sleep(0.5)
                except Exception as exc:  # noqa: BLE001
                    self.last_note = f"翻页失败: {exc}"
                    break

        if not items:
            note = "站内搜索与最近列表均未命中"
            if not self.deep:
                note += "；可加 --deep 翻更多列表页"
            self.last_note = (
                note + "。该站搜索接口经常返回空结果，且对高频请求会返回 403。"
            )
            items.append(
                Item(
                    source=self.name,
                    category="portal",
                    title="loudong.org.cn · 站内搜索入口",
                    url=f"{BASE}/search?q={quote(query, safe='')}",
                    summary=truncate(self.last_note, 300),
                    tags=["入口"],
                    extra={"portal": True},
                )
            )
        return items
