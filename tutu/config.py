from __future__ import annotations

import getpass
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Dict, Optional

PROVIDERS = {
    "threatbook": {
        "field": "threatbook_api_key",
        "label": "微步在线 ThreatBook",
        "env": ("TUTU_THREATBOOK_API_KEY", "THREATBOOK_API_KEY"),
        "url": "https://x.threatbook.com/",
    },
    "virustotal": {
        "field": "virustotal_api_key",
        "label": "VirusTotal",
        "env": ("TUTU_VIRUSTOTAL_API_KEY", "VIRUSTOTAL_API_KEY", "VT_API_KEY"),
        "url": "https://www.virustotal.com/",
    },
}


def config_dir() -> Path:
    override = os.environ.get("TUTU_CONFIG_DIR")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA") or Path.home())
        return base / "tutu"
    base = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
    return base / "tutu"


def config_path() -> Path:
    return config_dir() / "config.json"


def load_config() -> Dict[str, str]:
    path = config_path()
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items() if v}
    except (OSError, ValueError):
        pass
    return {}


def save_config(config: Dict[str, str]) -> Path:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix="config-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(config, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, path)
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def get_api_key(provider: str) -> Optional[str]:
    spec = PROVIDERS.get(provider)
    if not spec:
        return None
    for env_name in spec["env"]:
        value = os.environ.get(env_name)
        if value and value.strip():
            return value.strip()
    value = load_config().get(spec["field"])
    return value.strip() if value and value.strip() else None


def masked(value: Optional[str]) -> str:
    if not value:
        return "未配置"
    value = value.strip()
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}…{value[-4:]}"


def key_status() -> Dict[str, Dict[str, str]]:
    out: Dict[str, Dict[str, str]] = {}
    for name, spec in PROVIDERS.items():
        value = get_api_key(name)
        source = "环境变量" if any(os.environ.get(e) for e in spec["env"]) else "配置文件"
        out[name] = {
            "label": spec["label"],
            "masked": masked(value),
            "source": source if value else "-",
            "configured": "yes" if value else "no",
        }
    return out


def prompt_for_value(label: str, current: Optional[str]) -> Optional[str]:
    suffix = "（已配置，留空保持不变；输入 - 清除）" if current else "（留空跳过）"
    try:
        value = getpass.getpass(f"{label} API Key {suffix}: ")
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if value is None:
        return None
    value = value.strip()
    if not value:
        return current
    if value.lower() in ("-", "clear", "none", "unset"):
        return ""
    return value


def interactive_config(console) -> int:
    if not sys.stdin.isatty():
        console.print(
            "[yellow]当前不是交互终端。[/yellow]\n"
            "请使用：\n"
            "  [cyan]tutu config set threatbook <KEY>[/cyan]\n"
            "  [cyan]tutu config set virustotal <KEY>[/cyan]\n"
            "或设置环境变量 [cyan]TUTU_THREATBOOK_API_KEY[/cyan] / "
            "[cyan]TUTU_VIRUSTOTAL_API_KEY[/cyan]。"
        )
        return 2

    config = load_config()
    console.print("[bold cyan]tutu 配置[/bold cyan]")
    console.print("[dim]Key 只保存在本地配置文件，权限 0600；不会上传到 GitHub。[/dim]\n")
    for name, spec in PROVIDERS.items():
        field = spec["field"]
        current = get_api_key(name)
        console.print(f"[bold]{spec['label']}[/bold]  {masked(current)}")
        console.print(f"[dim]{spec['url']}[/dim]")
        value = prompt_for_value(spec["label"], current)
        if value is None:
            continue
        if value == "":
            config.pop(field, None)
        else:
            config[field] = value
        console.print()
    path = save_config(config)
    console.print(f"[green]已保存:[/green] {path}")
    console.print("[dim]提示: 环境变量优先级高于配置文件。[/dim]")
    return 0


def set_key(provider: str, value: str) -> Path:
    spec = PROVIDERS.get(provider)
    if not spec:
        raise ValueError(f"未知 provider: {provider}")
    config = load_config()
    field = spec["field"]
    value = value.strip()
    if not value or value.lower() in ("-", "clear", "none", "unset"):
        config.pop(field, None)
    else:
        config[field] = value
    return save_config(config)


def show_config(console) -> int:
    status = key_status()
    for name, row in status.items():
        console.print(
            f"[cyan]{row['label']:<18}[/cyan] {row['masked']:<18} "
            f"[dim]{row['source']}[/dim]"
        )
    console.print(f"[dim]配置文件: {config_path()}[/dim]")
    return 0
