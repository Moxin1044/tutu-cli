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
        "[dim]默认漏洞源: nvd, kev, mitre, osv, vulnrichment, sploitus\n"
        "默认情报源: nsfocus, 360, threatbook, loudong, ransomware_live, "
        "ransomlook, socradar, ransomwatch[/dim]"
    )


def print_error(console: Console, message: str) -> None:
    console.print(f"[bold red]错误:[/bold red] {message}")


def print_no_args(console: Console) -> None:
    banner(console, "-", "vuln", [])
    console.print("[bold]用法[/bold]")
    console.print("  [cyan]tutu -v CVE-2026[/cyan]              漏洞聚合搜索（NVD / KEV / OSV / Exploit…）")
    console.print("  [cyan]tutu CVE-2021-44228[/cyan]          省略 -v 时默认按漏洞搜索")
    console.print("  [cyan]tutu -t APT28[/cyan]                威胁情报搜索（绿盟 / 微步 / 360 / 勒索软件…）")
    console.print("  [cyan]tutu -t lockbit --limit 10[/cyan]   限制每个来源的展示条数")
    console.print("  [cyan]tutu sources[/cyan]                 查看全部数据源")
    console.print("  [cyan]tutu -v log4j --json[/cyan]         输出 JSON")
    console.print()
    console.print("[dim]提示: 所有默认数据源均无需账号或 Token；部分站点有反爬/登录限制，会在结果中标注。[/dim]")
