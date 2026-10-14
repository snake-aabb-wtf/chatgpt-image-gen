"""HAR 抓包读取（只为取真值而存在）。

为什么不直接 ``json.load``：`legacy/har/` 里有 117 MB 与 83 MB 的两份抓包，
一次性解析成 Python 对象会吃掉上 GB 内存。这里用 ``JSONDecoder.raw_decode``
配滑动缓冲**逐条**解析 entries 数组，任一时刻只持有一条 entry。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

_DEFAULT_WINDOW = 4 << 20          # 4 MiB 起步的滑动窗口
_ENTRIES_KEY = '"entries"'
_WHITESPACE_AND_COMMAS = " \t\r\n,"


@dataclass
class HarEntry:
    """一条 HAR entry 的只读视图。"""

    index: int
    raw: dict[str, Any]

    @property
    def request(self) -> dict[str, Any]:
        return self.raw.get("request") or {}

    @property
    def response(self) -> dict[str, Any]:
        return self.raw.get("response") or {}

    @property
    def url(self) -> str:
        return self.request.get("url") or ""

    @property
    def method(self) -> str:
        return (self.request.get("method") or "").upper()

    @property
    def status(self) -> int:
        return int(self.response.get("status") or 0)

    @property
    def started_date_time(self) -> str:
        return self.raw.get("startedDateTime") or ""

    # --- 头部 ---------------------------------------------------------

    @staticmethod
    def _find_header(headers: list[dict[str, Any]] | None,
                     name: str) -> str | None:
        target = name.lower()
        for header in headers or []:
            if str(header.get("name", "")).lower() == target:
                return header.get("value")
        return None

    def request_header(self, name: str) -> str | None:
        return self._find_header(self.request.get("headers"), name)

    def response_header(self, name: str) -> str | None:
        return self._find_header(self.response.get("headers"), name)

    # --- 体 -----------------------------------------------------------

    def _content_text(self, side: dict[str, Any]) -> str | None:
        content = side.get("content") or {}
        text = content.get("text")
        if text is None:
            return None
        if content.get("encoding") == "base64":
            import base64

            try:
                return base64.b64decode(text).decode("utf-8", errors="replace")
            except (ValueError, TypeError):
                return None
        return text

    def request_text(self) -> str | None:
        return self.request.get("postData", {}).get("text") or self._content_text(self.request)

    def response_text(self) -> str | None:
        return self._content_text(self.response)

    def request_json(self) -> Any | None:
        text = self.request.get("postData", {}).get("text")
        if not text:
            return None
        try:
            return json.loads(text)
        except ValueError:
            return None

    def response_json(self) -> Any | None:
        text = self.response_text()
        if not text:
            return None
        try:
            return json.loads(text)
        except ValueError:
            return None

    def label(self, filename: str) -> str:
        return f"{filename}[{self.index}]"


class HarError(Exception):
    """HAR 文件结构异常。"""


def iter_har_entries(path: Path | str,
                     window: int = _DEFAULT_WINDOW) -> Iterator[HarEntry]:
    """逐条产出 entries，内存占用与单条 entry 同量级。"""
    path = Path(path)
    decoder = json.JSONDecoder()
    with path.open("r", encoding="utf-8") as handle:
        head = handle.read(window)
        marker = head.find(_ENTRIES_KEY)
        if marker < 0:
            raise HarError(f"{path.name} 中找不到 log.entries")
        start = head.find("[", marker)
        if start < 0:
            raise HarError(f"{path.name} 中 entries 不是数组")

        buffer = head
        pos = start + 1
        index = 0
        while True:
            while pos < len(buffer) and buffer[pos] in _WHITESPACE_AND_COMMAS:
                pos += 1
            if pos >= len(buffer):
                chunk = handle.read(window)
                if not chunk:
                    return
                buffer = buffer[pos:] + chunk
                pos = 0
                continue
            if buffer[pos] == "]":
                return

            while True:
                try:
                    obj, end = decoder.raw_decode(buffer, pos)
                    break
                except ValueError:
                    chunk = handle.read(window)
                    if not chunk:
                        raise HarError(
                            f"{path.name}: 第 {index} 条 entry 解析失败（文件可能被截断）")
                    buffer += chunk
            yield HarEntry(index=index, raw=obj)
            index += 1
            pos = end
            if pos > window:
                buffer = buffer[pos:]
                pos = 0


def load_har_entries(path: Path | str,
                     only: set[int] | None = None) -> dict[int, HarEntry]:
    """只保留 ``only`` 里的 entry（None 表示全要）。

    这是读大抓包的正确姿势：117 MB 的登录抓包我们只关心 5 条，
    没必要把 826 条全留在内存里。
    """
    found: dict[int, HarEntry] = {}
    for entry in iter_har_entries(path):
        if only is None or entry.index in only:
            found[entry.index] = entry
            if only is not None and len(found) == len(only):
                break
    return found


def find_entries(path: Path | str, *, url_contains: str,
                 method: str | None = None,
                 limit: int | None = None) -> list[HarEntry]:
    """按 URL 子串（可选方法）筛选 entry。"""
    results: list[HarEntry] = []
    for entry in iter_har_entries(path):
        if url_contains not in entry.url:
            continue
        if method and entry.method != method.upper():
            continue
        results.append(entry)
        if limit is not None and len(results) >= limit:
            break
    return results
