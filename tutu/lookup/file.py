from __future__ import annotations

import hashlib
import mimetypes
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional

from ..config import get_api_key
from ..http import HttpClient
from ..utils import clean_text, truncate
from .hash import lookup_hash

VT_FILES = "https://www.virustotal.com/api/v3/files"
VT_ANALYSES = "https://www.virustotal.com/api/v3/analyses/{analysis_id}"
TB_UPLOAD = "https://api.threatbook.cn/v3/file/upload"
TB_REPORT = "https://api.threatbook.cn/v3/file/report"

MAGIC = [
    (b"MZ", "PE / DOS executable"),
    (b"\x7fELF", "ELF executable"),
    (b"PK\x03\x04", "ZIP / JAR / APK / Office"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"%PDF", "PDF document"),
    (b"\xca\xfe\xba\xbe", "Mach-O / Java class"),
    (b"\x1f\x8b", "gzip archive"),
    (b"BZh", "bzip2 archive"),
    (b"\xfd7zXZ\x00", "xz archive"),
    (b"\xd0\xcf\x11\xe0", "OLE / legacy Office"),
    (b"<!DOCTYPE", "HTML document"),
    (b"<html", "HTML document"),
]


def _identify(path: Path, head: bytes) -> str:
    for magic, label in MAGIC:
        if head.startswith(magic):
            return label
    try:
        head.decode("utf-8")
        if head and all(
            (32 <= b < 127) or b in (9, 10, 13) for b in head[:512]
        ):
            return "text / script"
    except UnicodeDecodeError:
        pass
    guessed, _ = mimetypes.guess_type(str(path))
    return guessed or "unknown"


def local_file_info(path: Path) -> Dict[str, Any]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    size = 0
    head = b""
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            if not head:
                head = chunk[:4096]
            size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)
    info = {
        "path": str(path),
        "name": path.name,
        "size": size,
        "type": _identify(path, head),
        "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(path.stat().st_mtime)),
        "hashes": {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
            "sha512": sha512.hexdigest(),
        },
    }
    return info


def _vt_upload(http: HttpClient, path: Path, key: str) -> Dict[str, Any]:
    with path.open("rb") as fh:
        resp = http.post(
            VT_FILES,
            headers={"x-apikey": key, "Accept": "application/json"},
            files={"file": (path.name, fh, "application/octet-stream")},
        )
    data = resp.json()
    analysis_id = ((data.get("data") or {}).get("id")) or ""
    result: Dict[str, Any] = {
        "status": "uploaded",
        "analysis_id": analysis_id,
        "permalink": data.get("data", {}).get("links", {}).get("self", "")
        if isinstance(data.get("data"), dict)
        else "",
    }
    if not analysis_id:
        return result
    for attempt in range(5):
        time.sleep(3)
        try:
            analysis = http.get_json(
                VT_ANALYSES.format(analysis_id=analysis_id),
                headers={"x-apikey": key, "Accept": "application/json"},
            )
        except Exception as exc:  # noqa: BLE001
            result["error"] = str(exc)[:200]
            return result
        attrs = (analysis.get("data") or {}).get("attributes") or {}
        result["status"] = clean_text(attrs.get("status") or result["status"])
        result["stats"] = attrs.get("stats") or {}
        if result["status"] == "completed":
            break
    return result


def _tb_upload(
    http: HttpClient,
    path: Path,
    key: str,
    sandbox_type: str,
    run_time: int,
) -> Dict[str, Any]:
    with path.open("rb") as fh:
        resp = http.post(
            TB_UPLOAD,
            data={
                "apikey": key,
                "sandbox_type": sandbox_type,
                "run_time": str(run_time),
            },
            headers={"Accept": "application/json"},
            files={"file": (path.name, fh, "application/octet-stream")},
        )
    data = resp.json()
    result: Dict[str, Any] = {
        "response_code": data.get("response_code"),
        "message": clean_text(data.get("verbose_msg") or ""),
    }
    payload = data.get("data") or {}
    if isinstance(payload, dict):
        result["sha256"] = clean_text(payload.get("sha256") or "")
        result["md5"] = clean_text(payload.get("md5") or "")
        result["permalink"] = clean_text(payload.get("permalink") or "")
        result["task_id"] = clean_text(str(payload.get("task_id") or ""))
    if data.get("response_code") not in (0, "0"):
        result["status"] = "failed"
        return result
    result["status"] = "uploaded"
    sha256 = result.get("sha256") or ""
    if sha256:
        for attempt in range(3):
            time.sleep(2)
            try:
                report = http.get_json(
                    TB_REPORT,
                    params={
                        "apikey": key,
                        "resource": sha256,
                        "sandbox_type": sandbox_type,
                    },
                    headers={"Accept": "application/json"},
                )
            except Exception as exc:  # noqa: BLE001
                result["error"] = str(exc)[:200]
                break
            if report.get("response_code") not in (0, "0"):
                continue
            summary = (report.get("data") or {}).get("summary") or {}
            if summary:
                result["status"] = "reported"
                result["summary"] = {
                    "threat_level": clean_text(summary.get("threat_level") or ""),
                    "malware_family": clean_text(summary.get("malware_family") or ""),
                    "malware_type": clean_text(summary.get("malware_type") or ""),
                    "threat_score": summary.get("threat_score"),
                    "multi_engines": clean_text(summary.get("multi_engines") or ""),
                }
                break
    return result


def analyze_file(
    path: str,
    timeout: float = 60.0,
    no_upload: bool = False,
    sandbox_type: str = "win7_sp1_enx86_office2013",
    run_time: int = 60,
) -> Dict[str, Any]:
    file_path = Path(path).expanduser()
    if not file_path.exists():
        raise ValueError(f"文件不存在: {file_path}")
    if not file_path.is_file():
        raise ValueError(f"不是普通文件: {file_path}")
    info = local_file_info(file_path)
    report: Dict[str, Any] = {
        "file": info,
        "lookup": {},
        "uploads": {},
        "notes": [],
    }

    try:
        report["lookup"] = lookup_hash(info["hashes"]["sha256"], timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        report["notes"].append(f"哈希查询失败: {exc}")

    if no_upload:
        report["notes"].append("已指定 --no-upload，跳过沙箱上传")
        return report

    vt_key = get_api_key("virustotal")
    tb_key = get_api_key("threatbook")
    http = HttpClient(timeout=max(timeout, 60.0))
    if vt_key:
        try:
            report["uploads"]["virustotal"] = _vt_upload(http, file_path, vt_key)
            report["notes"].append("文件已上传至 VirusTotal")
        except Exception as exc:  # noqa: BLE001
            report["uploads"]["virustotal"] = {"status": "failed", "error": str(exc)[:300]}
    if tb_key:
        try:
            report["uploads"]["threatbook"] = _tb_upload(
                http, file_path, tb_key, sandbox_type, run_time
            )
            report["notes"].append(
                f"文件已上传至微步在线沙箱（{sandbox_type}，run_time={run_time}s）"
            )
        except Exception as exc:  # noqa: BLE001
            report["uploads"]["threatbook"] = {"status": "failed", "error": str(exc)[:300]}
    if not vt_key and not tb_key:
        report["notes"].append(
            "未配置 VirusTotal / 微步 API Key，仅完成本地哈希与公开哈希库查询；"
            "可运行 tutu -config 配置后上传沙箱。"
        )
    vt_status = (report["uploads"].get("virustotal") or {}).get("status")
    tb_status = (report["uploads"].get("threatbook") or {}).get("status")
    if vt_status and vt_status != "completed":
        report["notes"].append(
            "VirusTotal 分析尚未完成，稍后可用 "
            f"`tutu -hash {info['hashes']['sha256']}` 查询结果。"
        )
    if tb_status and tb_status not in ("reported", "completed"):
        report["notes"].append(
            "微步沙箱分析尚未完成，稍后可用 "
            f"`tutu -hash {info['hashes']['sha256']}` 查询结果。"
        )
    return report
