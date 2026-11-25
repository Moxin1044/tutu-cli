from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Dict, List, Optional, Sequence

from rich.console import Console

from . import __version__
from .assets import PROVIDERS as ASSET_PROVIDERS, collect_assets
from .assets.ports import PortSpecError, parse_ports
from .config import (
    PROVIDERS,
    config_path,
    interactive_config,
    set_key,
    show_config,
)
from .export import export_report
from .http import SourceError
from .lookup.file import analyze_file
from .lookup.hash import lookup_hash
from .lookup.icp import PROVIDERS as ICP_PROVIDERS
from .lookup.icp import lookup_icp
from .lookup.ip import lookup_ip
from .lookup.reverse import PROVIDERS as REVERSE_PROVIDERS
from .models import SourceResult
from .render import (
    print_asset_report,
    print_error,
    print_file_report,
    print_hash_report,
    print_icp_report,
    print_intel_results,
    print_ip_report,
    print_no_args,
    print_sources,
    print_vuln_results,
)
from .search import (
    check_version,
    enrich_cards,
    merge_vulnerabilities,
    run_sources,
    sort_cards,
)
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
            "  tutu -ip 8.8.8.8\n"
            "  tutu -hash 44d88612fea8a8f36de82e1278abb02f\n"
            "  tutu -file sample.exe --no-upload\n"
            "  tutu -asset example.com\n"
            "  tutu -asset example.com --ports top100 --ip-intel --reverse-ip\n"
            "  tutu -asset example.com -o assets.xlsx\n"
            "  tutu -ip 8.8.8.8 --reverse-limit 50\n"
            "  tutu -icp example.com\n"
            "  tutu -icp 豫ICP备16005160号\n"
            "  tutu -v CVE-2024-3400 --product nginx --check-version 1.18.0\n"
            "  tutu -config\n"
            "  tutu sources\n"
        ),
    )
    parser.add_argument("query", nargs="?", help="查询词；省略 -v/-t 时默认按漏洞搜索")
    parser.add_argument("extra", nargs="*", help=argparse.SUPPRESS)
    parser.add_argument("-v", "--vuln", metavar="QUERY", help="漏洞聚合搜索（CVE / 关键词）")
    parser.add_argument("-t", "--threat", metavar="QUERY", help="威胁情报搜索（APT / 勒索 / 关键词）")
    parser.add_argument("-ip", "--ip", metavar="IP", help="IP 信誉 / 归属 / IOC / 反查域名查询")
    parser.add_argument(
        "-icp",
        "--icp",
        metavar="QUERY",
        help="ICP 备案查询：域名 / 备案号 / 主办单位名称",
    )
    parser.add_argument(
        "--reverse-ip",
        action="store_true",
        help="资产模式：按解析到的每个公网 IP 反查关联域名",
    )
    parser.add_argument(
        "--reverse-limit",
        type=int,
        default=100,
        metavar="N",
        help="反查域名时每个 IP 最多保留多少个域名（默认 100）",
    )
    parser.add_argument(
        "--no-reverse",
        action="store_true",
        help="-ip 查询时跳过反查域名",
    )
    parser.add_argument(
        "--no-icp",
        action="store_true",
        help="资产模式跳过 ICP 备案查询",
    )
    parser.add_argument("-hash", "--hash", metavar="HASH", help="MD5 / SHA1 / SHA256 哈希情报查询")
    parser.add_argument("-file", "--file", metavar="PATH", help="文件哈希、公开情报查询与沙箱上传")
    parser.add_argument(
        "-asset",
        "--asset",
        metavar="DOMAIN|IP|CIDR",
        help="资产搜集：子域名 / DNS / 存活 / Web 指纹 / 端口 / 关联漏洞",
    )
    parser.add_argument(
        "--check-version",
        metavar="VERSION",
        help="配合 -v 使用：判断该版本是否落在披露的受影响区间",
    )
    parser.add_argument(
        "--product",
        metavar="NAME",
        help="配合 --check-version 指定产品名（如 nginx、log4j）",
    )
    parser.add_argument(
        "--ports",
        metavar="PORTS",
        help="资产模式端口范围：top100 / web / 80,443 / 1-1024（默认不扫描）",
    )
    parser.add_argument(
        "--no-probe",
        action="store_true",
        help="资产模式跳过 HTTP(S) 存活探测与指纹识别",
    )
    parser.add_argument(
        "--asset-limit",
        type=int,
        default=120,
        metavar="N",
        help="资产模式最多处理的子域名数量（默认 120）",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=12,
        metavar="N",
        help="资产模式并发线程数（默认 12）",
    )
    parser.add_argument(
        "--no-asset-vuln",
        action="store_true",
        help="资产模式不关联漏洞（默认对带版本号的技术栈查询 NVD）",
    )
    parser.add_argument(
        "--max-fingerprints",
        type=int,
        default=5,
        metavar="N",
        help="资产模式最多关联漏洞的指纹数量（默认 5）",
    )
    parser.add_argument(
        "--ip-intel",
        action="store_true",
        help="资产模式为解析到的公网 IP 补充信誉 / 归属 / 被动端口情报",
    )
    parser.add_argument("-config", "--config", action="store_true", help="交互配置微步 / VirusTotal API Key")
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
    parser.add_argument(
        "--no-upload",
        action="store_true",
        help="-file 模式只做本地哈希与公开情报查询，不上传沙箱",
    )
    parser.add_argument(
        "--sandbox",
        default="win7_sp1_enx86_office2013",
        metavar="TYPE",
        help="微步沙箱类型（默认 win7_sp1_enx86_office2013）",
    )
    parser.add_argument(
        "--run-time",
        type=int,
        default=60,
        metavar="SEC",
        help="微步沙箱运行时间秒数（默认 60）",
    )
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help="导出结果到 .json / .csv / .xlsx（可与终端输出同时使用）",
    )
    parser.add_argument(
        "--export-format",
        choices=("json", "csv", "xlsx"),
        help="覆盖导出格式；默认根据输出文件扩展名判断",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="对支持翻页的站点（loudong）进行更深抓取",
    )
    parser.add_argument("--no-color", action="store_true", help="禁用彩色输出")
    parser.add_argument("--debug", action="store_true", help="输出调试日志")
    parser.add_argument("--version", action="version", version=f"tutu {__version__}")
    return parser


def _build_search_payload(
    vuln_query: Optional[str],
    threat_query: Optional[str],
    vuln_results: Sequence[SourceResult],
    cards,
    exploits,
    intel_results: Sequence[SourceResult],
    version_check: Optional[Dict] = None,
) -> Dict:
    payload = {
        "version": __version__,
        "query": {"vuln": vuln_query, "threat": threat_query},
        "vulnerabilities": [card.to_dict() for card in cards],
        "exploits": [item.to_dict() for item in exploits],
        "threat_intel": [_result_dict(r) for r in intel_results],
        "sources": [_result_dict(r) for r in vuln_results],
    }
    if version_check is not None:
        payload["version_check"] = version_check
    return payload


def _json_output(
    vuln_query: Optional[str],
    threat_query: Optional[str],
    vuln_results: Sequence[SourceResult],
    cards,
    exploits,
    intel_results: Sequence[SourceResult],
    version_check: Optional[Dict] = None,
) -> str:
    return json.dumps(
        _build_search_payload(
            vuln_query,
            threat_query,
            vuln_results,
            cards,
            exploits,
            intel_results,
            version_check,
        ),
        ensure_ascii=False,
        indent=2,
    )


def _export_result(kind: str, payload, args, console) -> bool:
    if not args.output:
        return True
    try:
        fmt = export_report(
            kind,
            payload,
            args.output,
            args.export_format,
            version=__version__,
        )
    except (ValueError, OSError, RuntimeError) as exc:
        print_error(console, f"导出失败: {exc}")
        return False
    if not args.json:
        console.print(f"[green]已导出:[/green] {args.output} ({fmt})")
    return True


def _json_special(kind: str, report: Dict) -> str:
    return json.dumps(
        {"version": __version__, kind: report},
        ensure_ascii=False,
        indent=2,
    )


def _version_check_payload(cards, args) -> Dict:
    result = check_version(cards, args.product or "", args.check_version or "")
    result["product"] = args.product or ""
    result["version"] = args.check_version or ""
    result["empty"] = not cards
    return result


def _handle_config(args, console) -> int:
    rest = list(args.extra or [])
    if not args.config and not (args.query and args.query.lower() in ("config", "cfg")):
        return -1
    if not rest:
        return interactive_config(console)
    action = rest[0].lower()
    if action in ("show", "status", "list"):
        return show_config(console)
    if action in ("path", "where"):
        console.print(str(config_path()))
        return 0
    if action in ("set", "add"):
        if len(rest) < 3:
            print_error(console, "用法: tutu config set <threatbook|virustotal> <KEY>")
            return 2
        provider = rest[1].lower()
        if provider not in PROVIDERS:
            print_error(console, f"未知 provider: {provider}，可选: {', '.join(PROVIDERS)}")
            return 2
        path = set_key(provider, rest[2])
        console.print(f"[green]已保存:[/green] {path}")
        return 0
    if action in ("unset", "remove", "clear"):
        if len(rest) < 2:
            print_error(console, "用法: tutu config unset <threatbook|virustotal>")
            return 2
        provider = rest[1].lower()
        if provider not in PROVIDERS:
            print_error(console, f"未知 provider: {provider}")
            return 2
        path = set_key(provider, "")
        console.print(f"[green]已清除 {provider}:[/green] {path}")
        return 0
    console.print(
        "[bold]配置命令[/bold]\n"
        "  tutu -config                   交互配置\n"
        "  tutu config show               查看配置状态（脱敏）\n"
        "  tutu config set threatbook KEY\n"
        "  tutu config set virustotal KEY\n"
        "  tutu config unset <provider>\n"
        "  tutu config path               显示配置文件路径"
    )
    return 0


def _run_special(kind: str, value: str, args) -> Dict:
    if kind == "ip":
        return lookup_ip(
            value,
            timeout=max(args.timeout, 15.0),
            reverse=not args.no_reverse,
            reverse_limit=max(1, args.reverse_limit),
        )
    if kind == "icp":
        return lookup_icp(
            value,
            timeout=max(args.timeout, 25.0),
            limit=max(1, args.limit),
        )
    if kind == "hash":
        return lookup_hash(value, timeout=max(args.timeout, 20.0))
    return analyze_file(
        value,
        timeout=max(args.timeout, 30.0),
        no_upload=args.no_upload,
        sandbox_type=args.sandbox,
        run_time=args.run_time,
    )


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

    config_rc = _handle_config(args, console)
    if config_rc >= 0:
        return config_rc

    if args.query and args.query.lower() in ("sources", "source", "list"):
        print_sources(
            console,
            [cls() for cls in VULN_SOURCES.values()],
            [cls() for cls in INTEL_SOURCES.values()],
            ASSET_PROVIDERS,
            list(REVERSE_PROVIDERS) + list(ICP_PROVIDERS),
        )
        return 0

    if args.asset:
        if args.vuln or args.threat or args.ip or args.icp or args.hash or args.file:
            print_error(
                console,
                "-asset 不能和 -v / -t / -ip / -icp / -hash / -file 同时使用",
            )
            return 2
        if args.check_version:
            print_error(console, "--check-version 不能与 -asset 同时使用")
            return 2
        if args.extra:
            print_error(console, "无法识别的参数: " + " ".join(args.extra))
            return 2
        try:
            ports = parse_ports(args.ports)
        except PortSpecError as exc:
            print_error(console, str(exc))
            return 2

        def _collect():
            return collect_assets(
                args.asset,
                timeout=args.timeout,
                limit=max(1, args.asset_limit),
                ports=ports,
                probe_http=not args.no_probe,
                threads=max(1, args.threads),
                correlate=not args.no_asset_vuln,
                max_fingerprints=max(1, args.max_fingerprints),
                ip_intel=args.ip_intel,
                reverse_ip_lookup=args.reverse_ip,
                reverse_limit=max(1, args.reverse_limit),
                icp=not args.no_icp,
                debug=args.debug,
            )

        try:
            if args.json:
                surface = _collect()
            else:
                with console.status("[cyan]正在搜集资产…[/cyan]", spinner="dots"):
                    surface = _collect()
        except (ValueError, SourceError) as exc:
            print_error(console, str(exc))
            return 2
        if args.json:
            print(_json_special("assets", surface.to_dict()))
        else:
            print_asset_report(console, surface)
        exported = _export_result("assets", surface, args, console)
        return 0 if exported else 1

    if args.ports:
        print_error(console, "--ports 仅用于 -asset 资产搜集模式")
        return 2

    if args.reverse_ip and not args.asset:
        print_error(console, "--reverse-ip 仅用于 -asset 资产搜集模式")
        return 2
    if args.no_icp and not args.asset:
        print_error(console, "--no-icp 仅用于 -asset 资产搜集模式")
        return 2
    if args.no_reverse and not args.ip:
        print_error(console, "--no-reverse 仅用于 -ip 查询")
        return 2

    special = [
        ("ip", args.ip),
        ("icp", args.icp),
        ("hash", args.hash),
        ("file", args.file),
    ]
    special = [(kind, value) for kind, value in special if value]
    if len(special) > 1:
        print_error(console, "-ip / -icp / -hash / -file 一次只能使用一个")
        return 2
    if special and (args.vuln or args.threat):
        print_error(console, "-ip / -icp / -hash / -file 不能和 -v / -t 同时使用")
        return 2
    if special:
        kind, value = special[0]
        try:
            if args.json:
                report = _run_special(kind, value, args)
            else:
                with console.status("[cyan]正在查询…[/cyan]", spinner="dots"):
                    report = _run_special(kind, value, args)
        except (ValueError, SourceError) as exc:
            print_error(console, str(exc))
            return 2
        if args.json:
            print(_json_special(kind, report))
        elif kind == "ip":
            print_ip_report(console, report)
        elif kind == "icp":
            print_icp_report(console, report)
        elif kind == "hash":
            print_hash_report(console, report)
        else:
            print_file_report(console, report)
        exported = _export_result(kind, report, args, console)
        return 0 if exported else 1

    if args.extra:
        print_error(console, "无法识别的参数: " + " ".join(args.extra))
        return 2

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

    if args.check_version and not vuln_query:
        print_error(console, "--check-version 需要配合 -v 或 CVE 查询使用")
        return 2

    vuln_results: List[SourceResult] = []
    intel_results: List[SourceResult] = []
    cards = []
    exploits = []
    version_check: Optional[Dict] = None

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
                if args.check_version:
                    version_check = _version_check_payload(cards, args)
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
            if args.check_version:
                version_check = _version_check_payload(cards, args)
        if threat_query:
            intel_results = run_sources(
                intel_sources,
                threat_query,
                limit,
                args.timeout,
                deep=args.deep,
                debug=args.debug,
            )
        payload = _build_search_payload(
            vuln_query,
            threat_query,
            vuln_results,
            cards,
            exploits,
            intel_results,
            version_check,
        )
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        exported = _export_result("search", payload, args, console)
        return 0 if exported else 1

    if vuln_query:
        print_vuln_results(
            console,
            vuln_query,
            cards,
            exploits,
            vuln_results,
            limit,
            version_check,
        )
    if threat_query:
        if vuln_query:
            console.print()
        print_intel_results(console, threat_query, intel_results, limit)
    if args.output:
        payload = _build_search_payload(
            vuln_query,
            threat_query,
            vuln_results,
            cards,
            exploits,
            intel_results,
            version_check,
        )
        exported = _export_result("search", payload, args, console)
        if not exported:
            return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n已取消", file=sys.stderr)
        raise SystemExit(130)
