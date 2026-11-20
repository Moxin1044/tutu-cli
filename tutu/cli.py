from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Dict, List, Optional, Sequence

from rich.console import Console

from . import __version__
from .models import SourceResult
from .render import (
    print_error,
    print_intel_results,
    print_no_args,
    print_sources,
    print_vuln_results,
)
from .search import enrich_cards, merge_vulnerabilities, run_sources, sort_cards
from .sources import (
    DEFAULT_INTEL_SOURCES,
    DEFAULT_VULN_SOURCES,
    INTEL_SOURCES,
    VULN_SOURCES,
    build_sources,
)


def _parse_source_names(value: Optional[str]) -> Optional[List[str]]:
    if not value:
        return None
    names = [n.strip() for n in value.split(",") if n.strip()]
    if any(n.lower() == "all" for n in names):
        return ["__all__"]
    return names


def _select(kind: str, requested: Optional[List[str]]) -> List:
    registry = VULN_SOURCES if kind == "vuln" else INTEL_SOURCES
    defaults = DEFAULT_VULN_SOURCES if kind == "vuln" else DEFAULT_INTEL_SOURCES
    if requested is None:
        return build_sources(kind, defaults)
    if "__all__" in requested:
        return build_sources(kind, list(registry.keys()))
    valid = [name for name in requested if name in registry]
    return build_sources(kind, valid)


def _result_dict(result: SourceResult) -> Dict:
    return {
        "source": result.source,
        "label": result.label,
        "items": [item.to_dict() for item in result.items],
        "elapsed": round(result.elapsed, 2),
        "error": result.error,
        "note": result.note,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tutu",
        description="tutu — 多源漏洞与威胁情报聚合搜索（无需账号/Token）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  tutu -v CVE-2026\n"
            "  tutu CVE-2021-44228\n"
            "  tutu -v log4j --limit 5\n"
            "  tutu -t APT28\n"
            "  tutu -t lockbit --sources ransomware_live,ransomlook,socradar\n"
            "  tutu -v CVE-2024-3400 -t CVE-2024-3400 --json\n"
            "  tutu sources\n"
        ),
    )
    parser.add_argument("query", nargs="?", help="查询词；省略 -v/-t 时默认按漏洞搜索")
    parser.add_argument("-v", "--vuln", metavar="QUERY", help="漏洞聚合搜索（CVE / 关键词）")
    parser.add_argument("-t", "--threat", metavar="QUERY", help="威胁情报搜索（APT / 勒索 / 关键词）")
    parser.add_argument(
        "-s",
        "--sources",
        metavar="LIST",
        help="逗号分隔的数据源；all 表示全部。例: nvd,kev 或 nsfocus,ransomlook",
    )
    parser.add_argument(
        "-l",
        "--limit",
        type=int,
        default=8,
        metavar="N",
        help="每个来源/漏洞卡片的最大条数（默认 8）",
    )
    parser.add_argument("--timeout", type=float, default=20.0, help="单请求超时秒数（默认 20）")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument(
        "--deep",
        action="store_true",
        help="对支持翻页的站点（loudong）进行更深抓取",
    )
    parser.add_argument("--no-color", action="store_true", help="禁用彩色输出")
    parser.add_argument("--debug", action="store_true", help="输出调试日志")
    parser.add_argument("--version", action="version", version=f"tutu {__version__}")
    return parser


def _json_output(
    vuln_query: Optional[str],
    threat_query: Optional[str],
    vuln_results: Sequence[SourceResult],
    cards,
    exploits,
    intel_results: Sequence[SourceResult],
) -> str:
    payload = {
        "version": __version__,
        "query": {"vuln": vuln_query, "threat": threat_query},
        "vulnerabilities": [card.to_dict() for card in cards],
        "exploits": [item.to_dict() for item in exploits],
        "threat_intel": [_result_dict(r) for r in intel_results],
        "sources": [_result_dict(r) for r in vuln_results],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.debug:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(levelname)s %(name)s: %(message)s",
        )

    console = Console(no_color=args.no_color, highlight=False)
    limit = max(1, args.limit)

    if args.query and args.query.lower() in ("sources", "source", "list"):
        print_sources(console, [cls() for cls in VULN_SOURCES.values()], [cls() for cls in INTEL_SOURCES.values()])
        return 0

    vuln_query = args.vuln
    threat_query = args.threat
    if args.query and not vuln_query and not threat_query:
        vuln_query = args.query

    if not vuln_query and not threat_query:
        print_no_args(console)
        return 0

    requested = _parse_source_names(args.sources)
    vuln_sources = _select("vuln", requested) if vuln_query else []
    intel_sources = _select("intel", requested) if threat_query else []

    if vuln_query and not vuln_sources:
        print_error(console, "没有可用的漏洞数据源，请检查 --sources")
        return 2
    if threat_query and not intel_sources:
        print_error(console, "没有可用的威胁情报数据源，请检查 --sources")
        return 2

    vuln_results: List[SourceResult] = []
    intel_results: List[SourceResult] = []
    cards = []
    exploits = []

    if not args.json:
        with console.status("[cyan]正在聚合搜索…[/cyan]", spinner="dots"):
            if vuln_query:
                vuln_results = run_sources(
                    vuln_sources,
                    vuln_query,
                    limit,
                    args.timeout,
                    deep=args.deep,
                    debug=args.debug,
                )
                cards, exploits = merge_vulnerabilities(vuln_results, limit)
                if cards:
                    enrich_cards(cards, args.timeout)
                    cards = sort_cards(cards)[:limit]
            if threat_query:
                intel_results = run_sources(
                    intel_sources,
                    threat_query,
                    limit,
                    args.timeout,
                    deep=args.deep,
                    debug=args.debug,
                )
    else:
        if vuln_query:
            vuln_results = run_sources(
                vuln_sources,
                vuln_query,
                limit,
                args.timeout,
                deep=args.deep,
                debug=args.debug,
            )
            cards, exploits = merge_vulnerabilities(vuln_results, limit)
            if cards:
                enrich_cards(cards, args.timeout)
                cards = sort_cards(cards)[:limit]
        if threat_query:
            intel_results = run_sources(
                intel_sources,
                threat_query,
                limit,
                args.timeout,
                deep=args.deep,
                debug=args.debug,
            )
        print(
            _json_output(
                vuln_query,
                threat_query,
                vuln_results,
                cards,
                exploits,
                intel_results,
            )
        )
        return 0

    if vuln_query:
        print_vuln_results(
            console,
            vuln_query,
            cards,
            exploits,
            vuln_results,
            limit,
        )
    if threat_query:
        if vuln_query:
            console.print()
        print_intel_results(console, threat_query, intel_results, limit)
    return 0


if __name__ == "__main__":  # pragma: no cover
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n已取消", file=sys.stderr)
        raise SystemExit(130)
