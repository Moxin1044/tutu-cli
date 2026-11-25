from __future__ import annotations

import json
from pathlib import Path

from tutu.assets.models import PortResult
from tutu.cli import build_parser
from tutu.export import export_report, resolve_format
from tutu.lookup.icp import _records_from_payload, normalize_query
from tutu.lookup.reverse import _clean_domain
from tutu.utils import decode_html, repair_mojibake


def test_decode_html_ignores_latin1_default():
    body = "信阳职业技术学院".encode("utf-8")
    # requests 对无 charset 的 text/html 会给出 ISO-8859-1，这里不应采用。
    assert decode_html(body, "ISO-8859-1", "text/html") == "信阳职业技术学院"
    # 页面声明与实际编码不一致时（声明 gb2312，实际 UTF-8）也应尽量还原。
    html = '<meta charset="gb2312"><title>新闻网</title>'.encode("utf-8")
    assert "新闻网" in decode_html(html, None, "text/html")


def test_repair_mojibake():
    mojibake = "信阳职业技术学院".encode("utf-8").decode("latin-1")
    assert repair_mojibake(mojibake) == "信阳职业技术学院"
    assert repair_mojibake("正常中文") == "正常中文"
    assert repair_mojibake("") == ""


def test_port_result_includes_ip_and_service():
    row = PortResult(
        host="a.example.com",
        ip="203.0.113.10",
        port=443,
        service="https",
        scheme="https",
        status=200,
        title="示例站点",
        tech=["nginx 1.18.0"],
    )
    data = row.to_dict()
    assert data["ip"] == "203.0.113.10"
    assert data["scheme"] == "https"
    assert data["status"] == 200
    assert data["title"] == "示例站点"
    assert data["tech"] == ["nginx 1.18.0"]


def test_icp_payload_parsing():
    payload = {
        "code": 200,
        "params": {
            "list": [
                {
                    "domain": "xyvtc.edu.cn",
                    "unitName": "信阳职业技术学院",
                    "natureName": "事业单位",
                    "mainLicence": "豫ICP备16005160号",
                    "serviceLicence": "豫ICP备16005160号-1",
                    "updateRecordTime": "2020-11-27 10:10:04",
                }
            ]
        },
    }
    records = _records_from_payload(payload, "tangdouz", "xyvtc.edu.cn")
    assert len(records) == 1
    record = records[0]
    assert record["unit_name"] == "信阳职业技术学院"
    assert record["icp"] == "豫ICP备16005160号-1"
    assert record["main_licence"] == "豫ICP备16005160号"
    assert record["source"] == "tangdouz"


def test_icp_normalize_query():
    assert normalize_query("https://Xyvtc.edu.cn/path") == "xyvtc.edu.cn"
    # 备案号与单位名保持原样，不做域名小写化。
    assert normalize_query("豫ICP备16005160号") == "豫ICP备16005160号"
    assert normalize_query("信阳职业技术学院") == "信阳职业技术学院"


def test_reverse_domain_cleaning():
    assert _clean_domain("*.Example.com.", "203.0.113.10") == "example.com"
    assert _clean_domain("http://a.example.com", "203.0.113.10") == ""
    assert _clean_domain("203.0.113.10", "203.0.113.10") == ""
    assert _clean_domain("bad host.example.com", "203.0.113.10") == ""
    assert _clean_domain("a.example.com", "203.0.113.10") == "a.example.com"


def test_resolve_format():
    assert resolve_format("out.json") == "json"
    assert resolve_format("out.CSV") == "csv"
    assert resolve_format("out.xlsx") == "xlsx"
    assert resolve_format("out.dat", "xlsx") == "xlsx"


def test_export_icp_json_and_csv(tmp_path: Path):
    report = {
        "query": "xyvtc.edu.cn",
        "normalized": "xyvtc.edu.cn",
        "type": "domain",
        "records": [
            {
                "domain": "xyvtc.edu.cn",
                "unit_name": "信阳职业技术学院",
                "nature": "事业单位",
                "icp": "豫ICP备16005160号-1",
                "main_licence": "豫ICP备16005160号",
                "service_licence": "豫ICP备16005160号-1",
                "updated": "2020-11-27 10:10:04",
                "source": "tangdouz",
            }
        ],
        "source": "tangdouz",
        "success": True,
        "errors": {},
        "note": "",
    }
    json_path = tmp_path / "icp.json"
    assert export_report("icp", report, str(json_path), version="0.4.0") == "json"
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["icp"]["records"][0]["unit_name"] == "信阳职业技术学院"

    csv_path = tmp_path / "icp.csv"
    assert export_report("icp", report, str(csv_path)) == "csv"
    text = csv_path.read_text(encoding="utf-8-sig")
    assert "信阳职业技术学院" in text
    assert "豫ICP备16005160号-1" in text


def test_export_assets_json(tmp_path: Path):
    from tutu.assets.models import Asset, AttackSurface

    surface = AttackSurface(domain="example.com")
    surface.assets = [
        Asset(
            host="a.example.com",
            ips=["203.0.113.10"],
            open_ports=[
                PortResult(
                    host="a.example.com",
                    ip="203.0.113.10",
                    port=443,
                    service="https",
                    status=200,
                    title="示例",
                )
            ],
        )
    ]
    surface.icp = {"records": [{"unit_name": "示例单位", "icp": "京ICP备00000000号"}]}
    surface.reverse_ips = [
        {
            "ip": "203.0.113.10",
            "domains": ["b.example.com"],
            "titles": {"b.example.com": "关联站点"},
            "sources": {"b.example.com": ["webscan"]},
        }
    ]
    path = tmp_path / "assets.json"
    export_report("assets", surface, str(path), version="0.4.0")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["assets"]["assets"][0]["open_ports"][0]["ip"] == "203.0.113.10"
    assert data["assets"]["icp"]["records"][0]["unit_name"] == "示例单位"
    assert data["assets"]["reverse_ips"][0]["domains"] == ["b.example.com"]


def test_export_assets_csv(tmp_path: Path):
    from tutu.assets.models import Asset, AttackSurface

    surface = AttackSurface(domain="example.com")
    surface.assets = [
        Asset(
            host="a.example.com",
            ips=["203.0.113.10"],
            open_ports=[
                PortResult(
                    host="a.example.com",
                    ip="203.0.113.10",
                    port=443,
                    service="https",
                    status=200,
                    title="示例",
                )
            ],
        )
    ]
    path = tmp_path / "assets.csv"
    export_report("assets", surface, str(path))
    text = path.read_text(encoding="utf-8-sig")
    assert "a.example.com" in text
    assert "203.0.113.10:443/https" in text


def test_cli_new_args():
    args = build_parser().parse_args(
        [
            "-asset",
            "example.com",
            "--reverse-ip",
            "--reverse-limit",
            "20",
            "--no-icp",
            "-o",
            "out.xlsx",
            "--export-format",
            "xlsx",
        ]
    )
    assert args.reverse_ip is True
    assert args.reverse_limit == 20
    assert args.no_icp is True
    assert args.output == "out.xlsx"
    assert args.export_format == "xlsx"

    args = build_parser().parse_args(["-ip", "8.8.8.8", "--no-reverse"])
    assert args.ip == "8.8.8.8"
    assert args.no_reverse is True

    args = build_parser().parse_args(["-icp", "豫ICP备16005160号"])
    assert args.icp == "豫ICP备16005160号"
