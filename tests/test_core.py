from __future__ import annotations

from tutu.models import Item, SourceResult
from tutu.search import merge_vulnerabilities, sort_cards
from tutu.sources.loudong import _card_items
from tutu.sources.threatbook import solve_challenge
from tutu.utils import is_cve_prefix, is_exact_cve


def test_threatbook_challenge_solver():
    # 来自实际反爬页的已知 Challenge / 计算结果
    assert solve_challenge("713713") == "-214115161"
    assert solve_challenge("541703") == "-162512161"


def test_cve_matchers():
    assert is_exact_cve("CVE-2021-44228")
    assert not is_exact_cve("CVE-2026")
    assert is_cve_prefix("CVE-2026")
    assert not is_cve_prefix("log4j")


def test_loudong_card_parser():
    html = """
    <article class="vuln-card">
      <a class="vc-cover" href="/vulns/95"><span class="vc-sev sev-4">严重</span></a>
      <div class="vc-body">
        <div class="vc-meta"><span class="vc-cve">CVE-2026-12345</span>
        <span class="vc-cvss">CVSS 9.8</span></div>
        <h3><a href="/vulns/95">Example RCE</a></h3>
        <p class="vc-summary">A demo vulnerability in Example.</p>
        <div class="vc-foot"><span><i class="fa-regular fa-clock"></i> 2026-11-20</span></div>
      </div>
    </article>
    """
    items = _card_items(html, "CVE-2026-12345", 5)
    assert len(items) == 1
    assert items[0].title == "CVE-2026-12345"
    assert items[0].score == "9.8"
    assert items[0].severity == "严重"


def test_merge_vulnerabilities():
    nvd = SourceResult(
        source="nvd",
        label="NVD",
        items=[
            Item(
                source="nvd",
                category="vulnerability",
                title="CVE-2026-0001",
                severity="HIGH",
                score="8.1",
                date="2026-01-01",
                summary="NVD summary",
                extra={"cve": "CVE-2026-0001", "description": "A demo bug"},
            )
        ],
    )
    kev = SourceResult(
        source="kev",
        label="CISA KEV",
        items=[
            Item(
                source="kev",
                category="vulnerability",
                title="CVE-2026-0001",
                severity="KEV",
                summary="KEV summary",
                extra={
                    "cve": "CVE-2026-0001",
                    "kev": True,
                    "ransomware": True,
                    "references": ["https://example.com/advisory"],
                },
            )
        ],
    )
    sploitus = SourceResult(
        source="sploitus",
        label="Sploitus",
        items=[
            Item(
                source="sploitus",
                category="exploit",
                title="PoC for CVE-2026-0001",
                url="https://example.com/poc",
            )
        ],
    )
    cards, standalone = merge_vulnerabilities([nvd, kev, sploitus], 10)
    assert not standalone
    assert len(cards) == 1
    card = cards[0]
    assert card.cve == "CVE-2026-0001"
    assert card.kev is True
    assert card.ransomware is True
    assert card.severity == "HIGH"
    assert card.score == "8.1"
    assert len(card.exploits) == 1
    assert "NVD" in card.sources and "CISA KEV" in card.sources
    assert card.refs == ["https://example.com/advisory"]


def test_sort_cards_prefers_kev():
    a = merge_vulnerabilities(
        [
            SourceResult(
                source="nvd",
                label="NVD",
                items=[
                    Item(
                        source="nvd",
                        category="vulnerability",
                        title="CVE-2026-0002",
                        severity="CRITICAL",
                        score="10.0",
                        extra={"cve": "CVE-2026-0002"},
                    )
                ],
            )
        ],
        10,
    )[0]
    b = merge_vulnerabilities(
        [
            SourceResult(
                source="kev",
                label="CISA KEV",
                items=[
                    Item(
                        source="kev",
                        category="vulnerability",
                        title="CVE-2026-0003",
                        severity="KEV",
                        extra={"cve": "CVE-2026-0003", "kev": True},
                    )
                ],
            )
        ],
        10,
    )[0]
    cards = sort_cards(a + b)
    assert cards[0].cve == "CVE-2026-0003"
