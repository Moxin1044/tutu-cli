from __future__ import annotations

from tutu.assets.correlate import _slug, fingerprint_targets
from tutu.assets.attack import _ip_target
from tutu.assets.models import Asset, AttackSurface, Service
from tutu.assets.ports import PortSpecError, parse_ports
from tutu.assets.probe import _tech_from_text
from tutu.assets.subdomain import _clean_host, normalize_domain
from tutu.cli import build_parser
from tutu.models import Item, SourceResult
from tutu.search import check_version, merge_vulnerabilities
from tutu.versions import (
    VersionRange,
    compare_versions,
    format_ranges,
    ranges_from_cpe,
    ranges_from_mitre_versions,
    ranges_from_osv,
    ranges_from_string,
)


def test_compare_versions():
    assert compare_versions("2.9", "2.10") < 0
    assert compare_versions("1.2", "1.2.0") == 0
    assert compare_versions("1.0.0-rc1", "1.0.0") < 0
    assert compare_versions("v2.4.51", "2.4.51") == 0


def test_ranges_from_cpe_bounds():
    rng = ranges_from_cpe(
        {
            "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "2.4.0",
            "versionEndExcluding": "2.4.51",
        },
        "nvd",
    )
    assert rng is not None
    assert rng.contains("2.4.49")
    assert not rng.contains("2.4.51")
    assert rng.contains("2.4.0")
    assert rng.start_including == "2.4.0"
    assert "apache/http_server" in rng.label()


def test_ranges_from_cpe_exact_and_wildcard():
    exact = ranges_from_cpe(
        {"criteria": "cpe:2.3:a:vendor:product:1.2.3:*:*:*:*:*:*:*"}, "nvd"
    )
    assert exact is not None and exact.contains("1.2.3")
    wildcard = ranges_from_cpe(
        {"criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}, "nvd"
    )
    assert wildcard is not None
    assert wildcard.is_wildcard()
    assert wildcard.contains("9.9.9")
    assert "所有版本" in wildcard.label()


def test_ranges_from_osv_events():
    ranges = ranges_from_osv(
        {
            "affected": [
                {
                    "package": {"name": "log4j-core", "ecosystem": "Maven"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "2.0"},
                                {"fixed": "2.15.0"},
                            ],
                        }
                    ],
                }
            ]
        }
    )
    assert len(ranges) == 1
    assert ranges[0].contains("2.14.1")
    assert not ranges[0].contains("2.15.0")
    assert "Maven" in ranges[0].product


def test_ranges_from_mitre_and_string():
    ranges = ranges_from_mitre_versions(
        "vendor/product",
        [{"status": "affected", "version": "1.0", "lessThan": "1.5"}],
    )
    assert ranges[0].contains("1.4")
    parsed = ranges_from_string("npm/pkg", ">= 1.0.0, < 1.4.2")
    assert parsed[0].contains("1.4.1")
    assert not parsed[0].contains("1.4.2")


def test_format_ranges_prioritizes_bounded():
    ranges = [
        VersionRange(product="a/b", source="nvd"),
        VersionRange(product="a/b", end_excluding="2.0", source="nvd"),
        VersionRange(product="a/b", start_including="1.0", end_excluding="1.5", source="nvd"),
    ]
    labels = format_ranges(ranges, 3)
    assert labels[0].startswith("a/b 1.0 ~ 1.5")


def test_merge_collects_version_ranges():
    result = SourceResult(
        source="nvd",
        label="NVD",
        items=[
            Item(
                source="nvd",
                category="vulnerability",
                title="CVE-2026-1000",
                severity="HIGH",
                extra={
                    "cve": "CVE-2026-1000",
                    "version_ranges": [
                        VersionRange(
                            product="demo/server",
                            start_including="1.0",
                            end_excluding="1.5",
                            source="nvd",
                        )
                    ],
                },
            )
        ],
    )
    cards, _ = merge_vulnerabilities([result], 5)
    card = cards[0]
    assert len(card.version_ranges) == 1
    assert "demo/server" in card.to_dict()["affected_versions"][0]
    check = check_version(cards, "demo", "1.2")
    assert check["affected"][0]["cve"] == "CVE-2026-1000"
    check = check_version(cards, "demo", "2.0")
    assert not check["affected"]


def test_check_version_without_ranges_is_unknown():
    result = SourceResult(
        source="kev",
        label="CISA KEV",
        items=[
            Item(
                source="kev",
                category="vulnerability",
                title="CVE-2026-2000",
                severity="KEV",
                extra={"cve": "CVE-2026-2000", "kev": True},
            )
        ],
    )
    cards, _ = merge_vulnerabilities([result], 5)
    check = check_version(cards, "demo", "1.0")
    assert check["unknown"][0]["cve"] == "CVE-2026-2000"


def test_parse_ports():
    assert parse_ports(None) == []
    assert 80 in parse_ports("80,443")
    assert 8080 in parse_ports("8000-8100")
    assert 443 in parse_ports("web")
    assert len(parse_ports("top100")) > 50
    try:
        parse_ports("70000")
    except PortSpecError:
        pass
    else:  # pragma: no cover
        raise AssertionError("无效端口应报错")


def test_domain_and_host_cleaning():
    assert normalize_domain("https://Sub.Example.com/path?q=1") == "sub.example.com"
    assert normalize_domain("*.example.com") == "example.com"
    assert _clean_host("*.a.example.com", "example.com") == "a.example.com"
    assert _clean_host("evil.com", "example.com") == ""
    assert _clean_host("bad host.example.com", "example.com") == ""


def test_tech_fingerprint():
    tech = _tech_from_text(
        "Server: nginx/1.18.0\nX-Powered-By: PHP/7.4.3",
        "<html><title>x</title>wp-content/themes/a.css</html>",
    )
    mapping = {row["product"]: row["version"] for row in tech}
    assert mapping["nginx"] == "1.18.0"
    assert mapping["PHP"] == "7.4.3"
    assert "WordPress" in mapping


def test_asset_fingerprint_targets_and_slug():
    asset = Asset(
        host="a.example.com",
        services=[
            Service(
                host="a.example.com",
                tech=[
                    {"product": "nginx", "version": "1.18.0"},
                    {"product": "PHP", "version": ""},
                ],
            )
        ],
    )
    targets = fingerprint_targets([asset])
    assert len(targets) == 1
    assert targets[0]["product"] == "nginx"
    assert _slug("Apache httpd") == "http_server"
    assert _slug("WordPress") == "wordpress"


def test_ip_target_expansion():
    import ipaddress

    surface = AttackSurface(domain="10.0.0.0/29")
    assets = _ip_target(ipaddress.ip_network("10.0.0.0/29", strict=False), 3, surface)
    assert len(assets) == 3
    assert assets[0].host == "10.0.0.1"
    assert assets[0].ips == ["10.0.0.1"]
    assert any("--asset-limit" in note for note in surface.notes)


def test_cli_asset_args():
    args = build_parser().parse_args(["-asset", "example.com", "--ports", "top100"])
    assert args.asset == "example.com"
    assert args.ports == "top100"
    args = build_parser().parse_args(
        ["-v", "CVE-2024-3400", "--product", "nginx", "--check-version", "1.18.0"]
    )
    assert args.check_version == "1.18.0"
    assert args.product == "nginx"
