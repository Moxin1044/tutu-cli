from __future__ import annotations

from typing import Iterable, List, Sequence

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import Item, SourceResult, VulnCard
from .utils import normalize_severity, severity_rank, truncate

CATEGORY_LABELS = {
    "vulnerability": "漏洞",
    "exploit": "Exploit/PoC",
    "apt": "APT 组织",
    "campaign": "攻击活动",
    "news": "威胁新闻",
    "notice": "漏洞通告",
    "ransomware": "勒索受害者",
    "group": "勒索组织",
    "ioc": "IOC/情报",
    "portal": "检索入口",
}


def severity_style(severity: str) -> str:
    sev = normalize_severity(severity)
    return {
        "CRITICAL": "bold red",
        "HIGH": "bold dark_orange",
        "MEDIUM": "bold yellow",
        "LOW": "bold cyan",
        "KEV": "bold magenta",
        "NONE": "dim",
    }.get(sev, "bold white")


def banner(console: Console, query: str, mode: str, source_names: Sequence[str]) -> None:
    title = Text()
    title.append("tutu", style="bold cyan")
    title.append("  ·  ", style="dim")
    title.append("漏洞与威胁情报聚合搜索", style="bold white")
    console.print(title)
    meta = Text()
    meta.append(f"查询: ", style="dim")
    meta.append(query, style="bold")
    meta.append(f"   模式: ", style="dim")
    meta.append("漏洞" if mode == "vuln" else "威胁情报", style="bold green")
    meta.append(f"   源: ", style="dim")
    meta.append(", ".join(source_names), style="cyan")
    console.print(meta)
    console.print()


def _card_panel(card: VulnCard, console: Console) -> Panel:
    head = Text()
    head.append(card.cve, style="bold white")
    if card.severity and card.severity.upper() != "KEV":
        head.append("  ")
        head.append(f" {card.severity} ", style=severity_style(card.severity))
    if card.score:
        head.append(f" CVSS {card.score}", style="bold")
    if card.kev:
        head.append("  ")
        head.append(" KEV ", style="bold white on magenta")
    if card.ransomware:
        head.append("  勒索利用", style="bold red")
    if card.epss:
        head.append(f"  EPSS {card.epss * 100:.2f}%", style="cyan")

    body = Text()
    body.append(card.summary or "（暂无摘要）", style="white")
    body.append("\n")
    if card.sources:
        body.append("来源: ", style="dim")
        body.append(" · ".join(card.sources), style="green")
    if card.published:
        body.append("   发布: ", style="dim")
        body.append(card.published, style="white")
    if card.modified:
        body.append("   更新: ", style="dim")
        body.append(card.modified, style="white")
    if card.epss_percentile:
        body.append(f"   EPSS 百分位: {card.epss_percentile * 100:.1f}%", style="dim")
    if card.tags:
        body.append("\n标签: ", style="dim")
        body.append(", ".join(card.tags[:10]), style="magenta")
    if card.refs:
        body.append("\n参考: ", style="dim")
        body.append(card.refs[0], style="blue underline")

    if card.exploits:
        body.append(f"\nExploit/PoC ({len(card.exploits)}):", style="bold red")
        for exploit in card.exploits[:3]:
            body.append("\n  ↳ ", style="red")
            body.append(truncate(exploit.title, 120), style="white")
            if exploit.url:
                body.append(f"  {exploit.url}", style="dim")

    return Panel(
        Group(head, Text(""), body),
        border_style="red" if card.kev else "cyan",
        box=box.ROUNDED,
        padding=(0, 1),
    )


def print_vuln_results(
    console: Console,
    query: str,
    cards: Sequence[VulnCard],
    standalone_exploits: Sequence[Item],
    results: Sequence[SourceResult],
    limit: int,
) -> None:
    banner(console, query, "vuln", [r.label for r in results])
    if not cards:
        console.print("[yellow]未找到匹配的漏洞结果。[/yellow]")
    else:
        for card in cards[:limit]:
            console.print(_card_panel(card, console))
        console.print(f"[dim]共展示 {min(len(cards), limit)} 条漏洞；--limit 可调整。[/dim]")

    if standalone_exploits:
        console.print()
        console.print("[bold red]未关联到 CVE 的 Exploit/PoC[/bold red]")
        for item in standalone_exploits[:limit]:
            console.print(f"  • {item.title}  [dim]{item.url}[/dim]")

    print_source_status(console, results)


def _intel_line(item: Item, console: Console) -> None:
    label = CATEGORY_LABELS.get(item.category, item.category)
    line = Text()
    style = "yellow" if item.category == "portal" else "cyan"
    line.append(f"[{label}] ", style=style)
    line.append(item.title or "（无标题）", style="bold white")
    if item.date:
        line.append(f"  {item.date}", style="dim")
    if item.severity:
        line.append(f"  {item.severity}", style=severity_style(item.severity))
    console.print(line)
    if item.summary:
        console.print(Text("  " + truncate(item.summary, 280), style="grey70"))
    if item.tags:
        console.print(Text("  " + " · ".join(str(t) for t in item.tags[:8]), style="magenta"))
    if item.url:
        console.print(Text("  " + item.url, style="blue underline"))


def print_intel_results(
    console: Console,
    query: str,
    results: Sequence[SourceResult],
    limit: int,
) -> None:
    banner(console, query, "intel", [r.label for r in results])
    any_item = False
    for result in results:
        if not result.items:
            continue
        any_item = True
        shown = min(len(result.items), max(limit, 1))
        console.rule(
            f"[bold cyan]{result.label}[/bold cyan]  "
            f"[dim]{shown}/{len(result.items)} 条[/dim]"
        )
        for item in result.items[: max(limit, 1)]:
            _intel_line(item, console)
        if result.note:
            console.print(Text("  " + result.note, style="yellow"))
        console.print()
    if not any_item:
        console.print("[yellow]未找到匹配的威胁情报。[/yellow]")
    print_source_status(console, results)


def print_source_status(console: Console, results: Sequence[SourceResult]) -> None:
    if not results:
        return
    table = Table(
        title="数据源状态",
        box=box.SIMPLE_HEAD,
        show_edge=False,
        pad_edge=False,
        title_justify="left",
    )
    table.add_column("源", style="cyan", no_wrap=True)
    table.add_column("状态", no_wrap=True)
    table.add_column("条数", justify="right", no_wrap=True)
    table.add_column("耗时", justify="right", no_wrap=True)
    table.add_column("说明", overflow="fold")
    for result in results:
        if result.error:
            status = Text("失败", style="bold red")
            note = result.error
        elif result.items:
            status = Text("OK", style="bold green")
            note = result.note
        else:
            status = Text("空", style="yellow")
            note = result.note or "无结果"
        table.add_row(
            result.label,
            status,
            str(len(result.items)),
            f"{result.elapsed:.1f}s",
            Text(note, style="dim"),
        )
    console.print(table)


def print_sources(
    console: Console,
    vuln_sources: Iterable,
    intel_sources: Iterable,
) -> None:
    console.print("[bold cyan]tutu[/bold cyan] 可用数据源\n")
    for title, sources in (("漏洞 / Exploit", vuln_sources), ("威胁情报", intel_sources)):
        console.print(f"[bold]{title}[/bold]")
        for src in sources:
            console.print(
                f"  [cyan]{src.name:<18}[/cyan] {src.label}\n"
                f"  {'':<18} [dim]{src.description}[/dim]"
            )
        console.print()
    console.print(
        "[dim]默认漏洞源: nvd, kev, mitre, osv, vulnrichment, vulnx, "
        "socradar_cve, exploitdb, sploitus, redhat\n"
        "默认情报源: nsfocus, 360, threatbook, loudong, socradar_ioc, "
        "ransomware_live, ransomlook, socradar, ransomwatch[/dim]"
    )


def print_error(console: Console, message: str) -> None:
    console.print(f"[bold red]错误:[/bold red] {message}")


def _kv_table(title: str, rows: Sequence[tuple]) -> Table:
    table = Table(title=title, box=box.SIMPLE_HEAD, show_edge=False, title_justify="left")
    table.add_column("字段", style="cyan", no_wrap=True)
    table.add_column("值", overflow="fold")
    for key, value in rows:
        if value in (None, "", [], {}):
            continue
        table.add_row(str(key), str(value))
    return table


def risk_style(risk: str) -> str:
    return {
        "malicious": "bold red",
        "suspicious": "bold yellow",
        "clean": "bold green",
        "unknown": "bold white",
    }.get((risk or "").lower(), "bold white")


def print_ip_report(console: Console, report: dict) -> None:
    console.print()
    title = Text()
    title.append("IP 情报  ", style="bold cyan")
    title.append(report.get("ip", ""), style="bold white")
    rep = report.get("reputation") or {}
    title.append("  ")
    title.append(f" {rep.get('risk', 'unknown').upper()} ", style=risk_style(rep.get("risk", "")))
    console.print(title)
    console.print(Text(f"私有/保留地址: {'是' if report.get('private') else '否'}", style="dim"))

    geo = report.get("geo") or {}
    console.print(
        _kv_table(
            "地理位置",
            [
                ("国家", geo.get("country")),
                ("地区", geo.get("region")),
                ("城市", geo.get("city")),
                ("时区", geo.get("timezone")),
                ("经纬度", f"{geo.get('latitude')}, {geo.get('longitude')}" if geo.get("latitude") is not None else ""),
                ("主机名", geo.get("hostname")),
            ],
        )
    )
    console.print(
        _kv_table(
            "网络归属",
            [
                ("ASN", report.get("asn")),
                ("组织", report.get("org")),
                ("ISP", report.get("isp")),
                ("代理", report.get("flags", {}).get("proxy")),
                ("托管/IDC", report.get("flags", {}).get("hosting")),
                ("移动网络", report.get("flags", {}).get("mobile")),
                ("Tor", report.get("flags", {}).get("tor")),
                ("VPN", report.get("flags", {}).get("vpn")),
                ("扫描器", report.get("flags", {}).get("scanner")),
                ("僵尸网络", report.get("flags", {}).get("botnet")),
            ],
        )
    )

    tb = report.get("threatbook") or {}
    vt = report.get("virustotal") or {}
    otx = report.get("otx") or {}
    soc = report.get("socradar_ioc") or {}
    soc_text = ""
    if soc:
        soc_text = " · ".join(
            str(x)
            for x in (
                f"{soc.get('type')} {soc.get('value')}",
                f"confidence={soc.get('confidence')}",
                "categories=" + ",".join(soc.get("categories") or []) if soc.get("categories") else "",
                "flags=" + ",".join(
                    key for key, value in (soc.get("flags") or {}).items() if value
                ) if soc.get("flags") else "",
                f"reports={soc.get('linked_reports')}",
            )
            if x
        )
    rep_rows = [
        ("综合判定", " · ".join(rep.get("reasons") or [])),
        ("ThreatBook", " · ".join(
            str(x)
            for x in (
                tb.get("severity"),
                f"scene={tb.get('scene')}" if tb.get("scene") else "",
                f"confidence={tb.get('confidence')}" if tb.get("confidence") else "",
                f"malicious={tb.get('is_malicious')}" if tb.get("is_malicious") is not None else "",
                tb.get("permalink"),
            )
            if x
        ) or "未配置或未返回"),
        ("ThreatBook 标签", " · ".join(tb.get("tags") or [])),
        ("ThreatBook 判定", " · ".join(tb.get("judgments") or [])),
        ("ThreatBook 更新时间", tb.get("update_time")),
        ("VirusTotal", f"reputation={vt.get('reputation')} stats={vt.get('stats')}" if vt else "未配置或未返回"),
        ("OTX pulses", otx.get("pulse_count")),
        ("OTX 标签", " · ".join(otx.get("tags") or [])),
        ("OTX 校验", " · ".join(otx.get("validation") or [])),
        ("SOCRadar IOC", soc_text or "未命中/无记录"),
    ]
    console.print(_kv_table("威胁情报", rep_rows))
    if report.get("errors"):
        console.print(
            _kv_table(
                "未成功的数据源",
                [(k, v) for k, v in report["errors"].items()],
            )
        )
    console.print()


def print_hash_report(console: Console, report: dict) -> None:
    console.print()
    rep = report.get("reputation") or {}
    title = Text()
    title.append("文件哈希  ", style="bold cyan")
    title.append(report.get("hash", ""), style="bold white")
    title.append("  ")
    title.append(f" {rep.get('risk', 'unknown').upper()} ", style=risk_style(rep.get("risk", "")))
    console.print(title)
    console.print(Text(f"类型: {report.get('kind', '')}", style="dim"))

    file_info = report.get("file") or {}
    console.print(
        _kv_table(
            "文件信息",
            [
                ("文件名", file_info.get("name")),
                ("大小", file_info.get("size")),
                ("类型", file_info.get("type")),
                ("恶意家族", file_info.get("malware_family")),
                ("恶意类型", file_info.get("malware_type")),
                ("多引擎", file_info.get("detections")),
                ("标签", " · ".join(file_info.get("tags") or [])),
            ],
        )
    )
    console.print(
        _kv_table(
            "哈希",
            [(k.upper(), v) for k, v in (report.get("hashes") or {}).items() if v],
        )
    )

    tb = report.get("threatbook") or {}
    tb_multi = report.get("threatbook_multi") or {}
    vt = report.get("virustotal") or {}
    circl = report.get("circl") or {}
    otx = report.get("otx") or {}
    soc = report.get("socradar_ioc") or {}
    console.print(
        _kv_table(
            "检测结果",
            [
                ("综合判定", " · ".join(rep.get("reasons") or [])),
                ("ThreatBook", f"{tb.get('threat_level', '')} {tb.get('malware_family', '')} score={tb.get('threat_score', '')}".strip() if tb else "无记录/未配置"),
                ("ThreatBook 多引擎", f"{tb_multi.get('positives', '?')}/{tb_multi.get('total', '?')} {tb_multi.get('scan_date', '')}".strip() if tb_multi else "无记录/未配置"),
                ("VirusTotal", f"malicious={vt.get('stats', {}).get('malicious', 'N/A')} label={vt.get('threat_label', '')}" if vt else "无记录/未配置"),
                ("CIRCL", f"{circl.get('file_name', '')} {circl.get('known_malicious', '')}".strip() if circl else "未命中"),
                ("OTX pulses", otx.get("pulse_count")),
                ("OTX 标签", " · ".join(otx.get("tags") or [])),
                (
                    "SOCRadar IOC",
                    " · ".join(
                        str(x)
                        for x in (
                            soc.get("type"),
                            f"confidence={soc.get('confidence')}" if soc else "",
                            "categories=" + ",".join(soc.get("categories") or []) if soc and soc.get("categories") else "",
                            f"reports={soc.get('linked_reports')}" if soc else "",
                        )
                        if x
                    )
                    or "未命中/无记录",
                ),
                ("链接", tb.get("permalink")),
            ],
        )
    )
    detections = tb.get("detections") or tb_multi.get("detections") or []
    if detections:
        console.print("[bold]ThreatBook 引擎命中[/bold]")
        for line in detections[:8]:
            console.print(f"  • {line}")
    if report.get("errors"):
        console.print(_kv_table("未成功的数据源", [(k, v) for k, v in report["errors"].items()]))
    console.print()


def print_file_report(console: Console, report: dict) -> None:
    info = report.get("file") or {}
    console.print()
    console.print(Text.assemble(("文件分析  ", "bold cyan"), (info.get("name", ""), "bold white")))
    console.print(
        _kv_table(
            "本地信息",
            [
                ("路径", info.get("path")),
                ("大小", info.get("size")),
                ("类型", info.get("type")),
                ("修改时间", info.get("mtime")),
            ],
        )
    )
    console.print(
        _kv_table(
            "哈希",
            [(k.upper(), v) for k, v in (info.get("hashes") or {}).items() if v],
        )
    )
    lookup = report.get("lookup") or {}
    if lookup:
        rep = lookup.get("reputation") or {}
        console.print(
            _kv_table(
                "哈希情报",
                [
                    ("综合判定", f"{rep.get('risk', 'unknown')} · " + " · ".join(rep.get("reasons") or [])),
                    ("文件名", (lookup.get("file") or {}).get("name")),
                    ("恶意家族", (lookup.get("file") or {}).get("malware_family")),
                    ("VirusTotal", str((lookup.get("virustotal") or {}).get("stats")) if lookup.get("virustotal") else "无记录/未配置"),
                    ("ThreatBook", (lookup.get("threatbook") or {}).get("threat_level") if lookup.get("threatbook") else "无记录/未配置"),
                ],
            )
        )
    uploads = report.get("uploads") or {}
    if uploads:
        rows = []
        for name, data in uploads.items():
            if not isinstance(data, dict):
                continue
            rows.append(
                (
                    name,
                    " · ".join(
                        str(x)
                        for x in (
                            data.get("status"),
                            data.get("stats"),
                            data.get("summary"),
                            data.get("error"),
                        )
                        if x
                    ),
                )
            )
        console.print(_kv_table("沙箱上传", rows))
    for note in report.get("notes") or []:
        console.print(Text("• " + note, style="yellow"))
    console.print()


def print_no_args(console: Console) -> None:
    banner(console, "-", "vuln", [])
    console.print("[bold]用法[/bold]")
    console.print("  [cyan]tutu -v CVE-2026[/cyan]              漏洞聚合搜索（NVD / KEV / OSV / Exploit…）")
    console.print("  [cyan]tutu CVE-2021-44228[/cyan]          省略 -v 时默认按漏洞搜索")
    console.print("  [cyan]tutu -t APT28[/cyan]                威胁情报搜索（绿盟 / 微步 / 360 / 勒索软件…）")
    console.print("  [cyan]tutu -t lockbit --limit 10[/cyan]   限制每个来源的展示条数")
    console.print("  [cyan]tutu -ip 8.8.8.8[/cyan]             IP 信誉 / 归属 / IOC 查询")
    console.print("  [cyan]tutu -hash <MD5|SHA1|SHA256>[/cyan] 哈希情报查询")
    console.print("  [cyan]tutu -file sample.exe[/cyan]        文件哈希 + 沙箱上传")
    console.print("  [cyan]tutu -config[/cyan]                 配置微步 / VirusTotal API Key")
    console.print("  [cyan]tutu sources[/cyan]                 查看全部数据源")
    console.print("  [cyan]tutu -v log4j --json[/cyan]         输出 JSON")
    console.print()
    console.print("[dim]提示: -v/-t 默认无需账号；-ip/-hash/-file 的增强情报可使用微步/VirusTotal Key。[/dim]")
