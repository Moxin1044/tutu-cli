from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Optional

log = logging.getLogger("tutu.cache")

CACHE_DIR = Path(
    os.environ.get("TUTU_CACHE_DIR", str(Path.home() / ".cache" / "tutu"))
)


def _safe_name(name: str) -> str:
    base = re.sub(r"[^a-zA-Z0-9_.-]+", "_", name)[:80]
    digest = hashlib.sha1(name.encode("utf-8")).hexdigest()[:8]
    return f"{base}_{digest}"


def _path(name: str) -> Path:
    return CACHE_DIR / (_safe_name(name) + ".json")


def read_cache(name: str) -> Optional[dict]:
    path = _path(name)
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and "ts" in data and "data" in data:
            return data
    except (OSError, ValueError):
        pass
    return None


def write_cache(name: str, data: Any) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        path = _path(name)
        fd, tmp = tempfile.mkstemp(prefix=path.name, dir=str(CACHE_DIR))
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"ts": time.time(), "data": data}, fh, ensure_ascii=False)
        os.replace(tmp, path)
    except OSError as exc:  # 缓存失败不应影响查询
        log.debug("写入缓存失败 %s: %s", name, exc)


def cached(name: str, ttl: float, fetch: Callable[[], Any]) -> Any:
    """按 TTL 缓存 JSON；网络失败时尽量回退到过期缓存。"""
    entry = read_cache(name)
    now = time.time()
    if entry and now - float(entry.get("ts", 0)) <= ttl:
        return entry["data"]
    try:
        data = fetch()
    except Exception:
        if entry is not None:
            log.warning("缓存 %s 已过期，网络请求失败，使用旧缓存", name)
            return entry["data"]
        raise
    write_cache(name, data)
    return data
