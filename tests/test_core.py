from __future__ import annotations

import tempfile
from pathlib import Path

from tutu.cli import build_parser
from tutu.config import masked
from tutu.lookup.file import local_file_info
from tutu.lookup.hash import hash_kind
from tutu.lookup.socradar import ioc_risk, parse_ioc
from tutu.sources.exploitdb import _match as edb_match
from tutu.sources.vulnx import parse_row as vulnx_parse_row
from tutu.models import Item, SourceResult
from tutu.search import merge_vulnerabilities, sort_cards
from tutu.sources.loudong import _card_items
from tutu.sources.threatbook import solve_challenge
from tutu.utils import is_cve_prefix, is_exact_cve


def test_hash_kind_and_mask():
    assert hash_kind("44d88612fea8a8f36de82e1278abb02f") == "md5"
    assert hash_kind("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f") == "sha256"
    assert hash_kind("not-a-hash") is None
    assert masked("abcdef1234567890").startswith("abcd")
    assert masked(None) == "未配置"


def test_local_file_info():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "sample.txt"
        path.write_text("hello tutu\n", encoding="utf-8")
        info = local_file_info(path)
    assert info["name"] == "sample.txt"
    assert info["size"] == len("hello tutu\n")
    assert len(info["hashes"]["sha256"]) == 64
    assert "text" in info["type"]


def test_cli_new_modes_parse():
    args = build_parser().parse_args(["-ip", "8.8.8.8"])
    assert args.ip == "8.8.8.8"
    args = build_parser().parse_args(["-hash", "44d88612fea8a8f36de82e1278abb02f"])
    assert args.hash.startswith("44d8")
    args = build_parser().parse_args(["config", "set", "threatbook", "x"])
    assert args.query == "config"
    assert args.extra == ["set", "threatbook", "x"]


def test_vulnx_parse_row():
    item = vulnx_parse_row(
        {
            "cve_id": "CVE-2021-44228",
            "name": "Log4j RCE",
            "description": "demo",
            "severity": "critical",
            "cvss_score": 10,
            "is_kev": True,
            "is_poc": True,
            "tags": ["rce"],
            "cwe": ["CWE-502"],
            "pocs": [{"url": "https://example.com/poc"}],
        }
    )
    assert item is not None
    assert item.title == "CVE-2021-44228"
    assert item.severity == "CRITICAL"
    assert item.extra["kev"] is True
    assert item.extra["references"] == ["https://example.com/poc"]


def test_exploitdb_exact_match():
    row = {
        "description": "Apache Log4j RCE",
        "codes": "CVE-2021-44228;OSVDB-1",
        "platform": "java",
        "type": "remote",
    }
    assert edb_match(row, "CVE-2021-44228", True)
    assert edb_match(row, "log4j", False)
    assert not edb_match(row, "CVE-2020-0001", True)


def test_socradar_ioc_risk():
    parsed = parse_ioc(
        {
            "value": "1.2.3.4",
            "type": "ip",
            "categories": ["c2", "malware"],
            "confidence": 0.9,
            "is_tor": True,
            "malware_families": ["Cobalt Strike"],
            "linked_report_count": 4,
        }
    )
    risk = ioc_risk(parsed)
    assert risk["risk"] in ("malicious", "suspicious")
    assert any("Cobalt" in reason for reason in risk["reasons"])


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
