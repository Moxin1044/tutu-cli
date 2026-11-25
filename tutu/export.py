"""把查询结果导出为 JSON / CSV / XLSX。

XLSX 使用可选的 openpyxl（已在项目依赖中声明）；CSV 使用 utf-8-sig，
方便 Excel 直接打开中文内容而不乱码。
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .utils import clean_text

EXPORT_FORMATS = ("json", "csv", "xlsx")


def resolve_format(path: str, explicit: Optional[str] = None) -> str:
    if explicit:
        fmt = explicit.lower().lstrip(".")
        if fmt in EXPORT_FORMATS:
            return fmt
        raise ValueError(f"不支持的导出格式: {explicit}")
    suffix = Path(path).suffix.lower().lstrip(".")
    if suffix in ("xlsx", "xlsm"):
        return "xlsx"
    if suffix in ("csv", "txt"):
        return "csv"
    if suffix in ("json", "jsonl"):
        return "json"
    raise ValueError(
        f"无法从文件名推断导出格式: {path}（请使用 .json / .csv / .xlsx，或 --export-format）"
    )


def _cell(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return " | ".join(str(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, str):
        return clean_text(value)
    return value


def _write_json(path: str, payload: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)


def _write_csv(path: str, headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(list(headers))
        for row in rows:
            writer.writerow([_cell(value) for value in row])


def _require_openpyxl():
    try:
        import openpyxl
    except ImportError as exc:  # pragma: no cover - 环境缺依赖时给出明确提示
        raise RuntimeError(
            "导出 XLSX 需要 openpyxl，请执行: pip install openpyxl"
        ) from exc
    return openpyxl


def _sheet_title(title: str) -> str:
    cleaned = "".join(ch for ch in title if ch not in "[]:*?/\\")
    return (cleaned or "Sheet")[:31]


def _write_xlsx(
    path: str,
    sheets: Sequence[Tuple[str, Sequence[str], Sequence[Sequence[Any]]]],
) -> None:
    openpyxl = _require_openpyxl()
    from openpyxl.utils import get_column_letter

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    workbook = openpyxl.Workbook()
    workbook.remove(workbook.active)
    used_titles = set()
    for title, headers, rows in sheets:
        base = _sheet_title(title)
        name = base
        index = 2
        while name in used_titles:
            suffix = f"-{index}"
            name = base[: 31 - len(suffix)] + suffix
            index += 1
        used_titles.add(name)
        sheet = workbook.create_sheet(title=name)
        sheet.append([str(header) for header in headers])
        for row in rows:
            sheet.append([_cell(value) for value in row])
        sheet.freeze_panes = "A2"
        for column, header in enumerate(headers, 1):
            width = min(70, max(10, len(str(header)) + 4))
            sheet.column_dimensions[get_column_letter(column)].width = width
    workbook.save(str(target))


def _asset_reverse(surface) -> Dict[str, List[str]]:
    by_ip: Dict[str, List[str]] = {}
    for row in getattr(surface, "reverse_ips", []) or []:
        ip = str(row.get("ip") or "")
        for domain in row.get("domains") or []:
            by_ip.setdefault(ip, [])
            if domain not in by_ip[ip]:
                by_ip[ip].append(domain)
    return by_ip


def _asset_icp(surface) -> List[Dict[str, Any]]:
    return list((getattr(surface, "icp", {}) or {}).get("records") or [])


def _asset_rows(surface) -> Tuple[List[str], List[List[Any]]]:
    headers = [
        "主机",
        "IP",
        "CNAME",
        "HTTP",
        "Server",
        "标题",
        "技术栈",
        "来源",
        "备注",
        "开放端口",
        "反查域名",
        "备案号",
        "主办单位",
    ]
    reverse_by_ip = _asset_reverse(surface)
    icp_records = _asset_icp(surface)
    icp = icp_records[0] if icp_records else {}
    rows: List[List[Any]] = []
    for asset in surface.assets:
        service = asset.services[0] if asset.services else None
        ports = ", ".join(
            f"{row.ip or asset.host}:{row.port}/{row.service or '?'}"
            for row in asset.open_ports
        )
        reverse_domains: List[str] = []
        for ip in asset.ips:
            for domain in reverse_by_ip.get(ip, []):
                if domain != asset.host and domain not in reverse_domains:
                    reverse_domains.append(domain)
        rows.append(
            [
                ("*." if asset.wildcard and not asset.ips else "") + asset.host,
                ", ".join(asset.ips),
                ", ".join(asset.cnames),
                service.status if service else "",
                service.server if service else "",
                service.title if service else "",
                ", ".join(service.tech_names if service else []),
                ", ".join(asset.sources),
                asset.note,
                ports,
                ", ".join(reverse_domains),
                icp.get("service_licence") or icp.get("icp") or "",
                icp.get("unit_name") or "",
            ]
        )
    return headers, rows


def _port_rows(surface) -> Tuple[List[str], List[List[Any]]]:
    headers = ["主机", "IP", "端口", "服务", "HTTP", "标题", "技术栈", "Banner"]
    rows: List[List[Any]] = []
    seen = set()
    for asset in surface.assets:
        for row in asset.open_ports:
            key = (row.ip or asset.host, row.port)
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                [
                    asset.host,
                    row.ip or asset.host,
                    row.port,
                    row.service,
                    row.status or "",
                    row.title,
                    ", ".join(row.tech),
                    row.banner,
                ]
            )
    return headers, rows


def _reverse_rows(surface) -> Tuple[List[str], List[List[Any]]]:
    headers = ["IP", "域名", "标题", "来源"]
    rows: List[List[Any]] = []
    for row in getattr(surface, "reverse_ips", []) or []:
        ip = row.get("ip") or ""
        titles = row.get("titles") or {}
        sources = row.get("sources") or {}
        domains = row.get("domains") or []
        for domain in domains:
            rows.append([ip, domain, titles.get(domain, ""), ", ".join(sources.get(domain, []))])
    return headers, rows


def _icp_rows(records: Sequence[Dict[str, Any]]) -> Tuple[List[str], List[List[Any]]]:
    headers = ["域名", "主办单位", "性质", "备案号", "服务备案号", "审核时间", "来源"]
    rows = [
        [
            record.get("domain", ""),
            record.get("unit_name", ""),
            record.get("nature", ""),
            record.get("main_licence", "") or record.get("icp", ""),
            record.get("service_licence", "") or record.get("icp", ""),
            record.get("updated", ""),
            record.get("source", ""),
        ]
        for record in records
    ]
    return headers, rows


def _cve_rows(surface) -> Tuple[List[str], List[List[Any]]]:
    headers = ["CVE", "严重性", "评分", "主机", "产品", "版本", "受影响区间", "摘要", "链接"]
    rows = [
        [
            hit.cve,
            hit.severity,
            hit.score,
            hit.host,
            hit.product,
            hit.version,
            hit.affected,
            hit.summary,
            hit.url,
        ]
        for hit in surface.cve_hits
    ]
    return headers, rows


def _source_rows(sources: Sequence[Any]) -> Tuple[List[str], List[List[Any]]]:
    headers = ["数据源", "名称", "结果数", "耗时(s)", "状态", "说明"]
    rows = []
    for source in sources:
        rows.append(
            [
                source.source,
                source.label,
                len(source.items),
                round(source.elapsed, 2),
                "失败" if source.error else "成功",
                source.error or source.note or "",
            ]
        )
    return headers, rows


def _export_assets(surface, path: str, fmt: str, version: str) -> None:
    if fmt == "json":
        _write_json(path, {"version": version, "assets": surface.to_dict()})
        return
    headers, rows = _asset_rows(surface)
    if fmt == "csv":
        _write_csv(path, headers, rows)
        return
    port_headers, port_rows = _port_rows(surface)
    reverse_headers, reverse_rows = _reverse_rows(surface)
    icp_headers, icp_rows = _icp_rows(_asset_icp(surface))
    cve_headers, cve_rows = _cve_rows(surface)
    source_headers, source_rows = _source_rows(surface.source_results)
    _write_xlsx(
        path,
        [
            ("资产清单", headers, rows),
            ("开放端口", port_headers, port_rows),
            ("反查域名", reverse_headers, reverse_rows),
            ("ICP备案", icp_headers, icp_rows),
            ("关联CVE", cve_headers, cve_rows),
            ("数据源", source_headers, source_rows),
        ],
    )


def _ip_rows(report: Dict[str, Any]) -> Tuple[List[str], List[List[Any]]]:
    headers = ["类别", "字段/域名", "值", "来源/说明"]
    rows: List[List[Any]] = []
    geo = report.get("geo") or {}
    for key, label in (
        ("country", "国家"),
        ("region", "地区"),
        ("city", "城市"),
        ("timezone", "时区"),
        ("hostname", "主机名"),
    ):
        if geo.get(key):
            rows.append(["地理", label, geo.get(key), ""])
    for key, label in (
        ("asn", "ASN"),
        ("org", "组织"),
        ("isp", "ISP"),
    ):
        if report.get(key):
            rows.append(["网络", label, report.get(key), ""])
    rep = report.get("reputation") or {}
    rows.append(["判定", "风险", rep.get("risk", "unknown"), " · ".join(rep.get("reasons") or [])])
    reverse = report.get("reverse") or {}
    titles = reverse.get("titles") or {}
    sources = reverse.get("sources") or {}
    for domain in reverse.get("domains") or []:
        rows.append(
            ["反查域名", domain, titles.get(domain, ""), ", ".join(sources.get(domain, []))]
        )
    for name, error in (reverse.get("errors") or {}).items():
        rows.append(["反查失败", name, error, ""])
    for name, error in (report.get("errors") or {}).items():
        rows.append(["数据源失败", name, error, ""])
    return headers, rows


def _export_ip(report: Dict[str, Any], path: str, fmt: str, version: str) -> None:
    if fmt == "json":
        _write_json(path, {"version": version, "ip": report})
        return
    headers, rows = _ip_rows(report)
    if fmt == "csv":
        _write_csv(path, headers, rows)
        return
    reverse = report.get("reverse") or {}
    rev_titles = reverse.get("titles") or {}
    rev_sources = reverse.get("sources") or {}
    reverse_rows = [
        [domain, rev_titles.get(domain, ""), ", ".join(rev_sources.get(domain, [])), reverse.get("ip", "")]
        for domain in reverse.get("domains") or []
    ]
    _write_xlsx(
        path,
        [
            ("IP信息", headers, rows),
            (
                "反查域名",
                ["域名", "标题", "来源", "IP"],
                reverse_rows,
            ),
            (
                "数据源",
                ["数据源", "状态", "说明"],
                [
                    [name, "失败", error]
                    for name, error in (report.get("errors") or {}).items()
                ]
                + [
                    [name, "成功", ""]
                    for name in (report.get("sources") or {})
                ],
            ),
        ],
    )


def _export_icp(report: Dict[str, Any], path: str, fmt: str, version: str) -> None:
    records = report.get("records") or []
    if fmt == "json":
        _write_json(path, {"version": version, "icp": report})
        return
    headers, rows = _icp_rows(records)
    if fmt == "csv":
        _write_csv(path, headers, rows)
        return
    _write_xlsx(
        path,
        [
            ("ICP备案", headers, rows),
            (
                "查询信息",
                ["字段", "值"],
                [
                    ["查询内容", report.get("query", "")],
                    ["规范化", report.get("normalized", "")],
                    ["类型", report.get("type", "")],
                    ["数据源", report.get("source", "")],
                    ["说明", report.get("note", "")],
                ]
                + [[f"失败源 {name}", error] for name, error in (report.get("errors") or {}).items()],
            ),
        ],
    )


def _vuln_rows(payload: Dict[str, Any]) -> Tuple[List[str], List[List[Any]]]:
    headers = [
        "CVE",
        "严重性",
        "评分",
        "受影响产品",
        "受影响版本",
        "来源",
        "KEV",
        "勒索",
        "EPSS",
        "摘要",
    ]
    rows = []
    for card in payload.get("vulnerabilities") or []:
        rows.append(
            [
                card.get("cve", ""),
                card.get("severity", ""),
                card.get("score", ""),
                ", ".join(card.get("affected_products") or []),
                " | ".join(card.get("affected_versions") or []),
                ", ".join(card.get("sources") or []),
                "是" if card.get("kev") else "",
                "是" if card.get("ransomware") else "",
                card.get("epss", ""),
                card.get("summary", ""),
            ]
        )
    return headers, rows


def _exploit_rows(payload: Dict[str, Any]) -> Tuple[List[str], List[List[Any]]]:
    headers = ["标题", "来源", "类型", "日期", "链接", "摘要"]
    rows = []
    for item in payload.get("exploits") or []:
        rows.append(
            [
                item.get("title", ""),
                item.get("source", ""),
                item.get("category", ""),
                item.get("date", ""),
                item.get("url", ""),
                item.get("summary", ""),
            ]
        )
    return headers, rows


def _intel_rows(payload: Dict[str, Any]) -> Tuple[List[str], List[List[Any]]]:
    headers = ["来源", "标题", "类型", "日期", "链接", "摘要"]
    rows = []
    for result in payload.get("threat_intel") or []:
        for item in result.get("items") or []:
            rows.append(
                [
                    item.get("source", result.get("source", "")),
                    item.get("title", ""),
                    item.get("category", ""),
                    item.get("date", ""),
                    item.get("url", ""),
                    item.get("summary", ""),
                ]
            )
    return headers, rows


def _flatten(value: Any, prefix: str = "") -> Iterable[Tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _flatten(item, f"{prefix}.{key}" if prefix else str(key))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            yield from _flatten(item, f"{prefix}[{index}]")
    else:
        yield prefix, value


def _export_search(payload: Dict[str, Any], path: str, fmt: str, version: str) -> None:
    if fmt == "json":
        _write_json(path, payload)
        return
    vuln_headers, vuln_rows = _vuln_rows(payload)
    exploit_headers, exploit_rows = _exploit_rows(payload)
    intel_headers, intel_rows = _intel_rows(payload)
    source_headers, source_rows = _source_rows_from_dicts(payload.get("sources") or [])
    if fmt == "csv":
        if vuln_rows:
            _write_csv(path, vuln_headers, vuln_rows)
        elif intel_rows:
            _write_csv(path, intel_headers, intel_rows)
        else:
            _write_csv(path, ["字段", "值"], _flatten(payload))
        return
    _write_xlsx(
        path,
        [
            ("漏洞", vuln_headers, vuln_rows),
            ("Exploit", exploit_headers, exploit_rows),
            ("威胁情报", intel_headers, intel_rows),
            ("数据源", source_headers, source_rows),
        ],
    )


def _source_rows_from_dicts(sources: Sequence[Dict[str, Any]]) -> Tuple[List[str], List[List[Any]]]:
    headers = ["数据源", "名称", "结果数", "耗时(s)", "状态", "说明"]
    rows = []
    for source in sources:
        rows.append(
            [
                source.get("source", ""),
                source.get("label", ""),
                len(source.get("items") or []),
                source.get("elapsed", ""),
                "失败" if source.get("error") else "成功",
                source.get("error") or source.get("note") or "",
            ]
        )
    return headers, rows


def _export_mapping(kind: str, payload: Dict[str, Any], path: str, fmt: str, version: str) -> None:
    if fmt == "json":
        _write_json(path, {"version": version, kind: payload})
        return
    rows = list(_flatten(payload))
    headers = ["字段", "值"]
    if fmt == "csv":
        _write_csv(path, headers, rows)
        return
    _write_xlsx(path, [(kind, headers, rows)])


def export_report(
    kind: str,
    payload: Any,
    path: str,
    fmt: Optional[str] = None,
    version: str = "",
) -> str:
    """导出结果，返回实际写入的格式。"""
    resolved = resolve_format(path, fmt)
    if kind == "assets":
        _export_assets(payload, path, resolved, version)
    elif kind == "ip":
        _export_ip(payload, path, resolved, version)
    elif kind == "icp":
        _export_icp(payload, path, resolved, version)
    elif kind == "search":
        _export_search(payload, path, resolved, version)
    else:
        _export_mapping(kind, payload, path, resolved, version)
    return resolved
