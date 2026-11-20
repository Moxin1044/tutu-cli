from __future__ import annotations

import time
from typing import List

from ..http import HttpClient
from ..models import SourceResult


class Source:
    name: str = ""
    label: str = ""
    kind: str = "vuln"  # vuln | intel
    description: str = ""
    last_note: str = ""

    def search(self, query: str, limit: int, http: HttpClient) -> SourceResult:
        started = time.monotonic()
        result = SourceResult(source=self.name, label=self.label)
        self.last_note = ""
        try:
            result.items = self._search(query, limit, http) or []
        except Exception as exc:  # noqa: BLE001 - 单源失败不终止聚合
            result.error = str(exc)[:300] or exc.__class__.__name__
        result.note = getattr(self, "last_note", "")
        result.elapsed = time.monotonic() - started
        return result

    def _search(self, query: str, limit: int, http: HttpClient) -> List:
        raise NotImplementedError
