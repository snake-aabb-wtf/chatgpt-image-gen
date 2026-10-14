"""SSE 事件流解析（docs/03 §4.7.1 / docs/04 §2.2）。

流的结构（真实抓包里的 12 个事件）：

======  ==================  ==================================================
序号    event               要点
======  ==================  ==================================================
0       ``delta_encoding``  载荷是字符串 ``"v1"``
1       —                   ``resume_conversation_token``（4 小时续传票据）
2       ``delta``           ``p:"" o:"add"`` 追加消息，并把 ``conversation_id`` 带出来
3       —                   ``message_marker``
4       ``delta``           ``o:"add"`` 追加助手 ``code`` 消息（工具调用信封）
5       ``delta``           ``p:"/message/status" o:"replace"``（JSON-Patch 语义）
6 / 8   —                   ``title_generation``（自动标题）
**7**   ``delta``           **``o:"add"`` 追加 ``tool`` 消息 → ``image_asset_pointer``**
9       —                   ``server_ste_metadata``
10      —                   ``message_stream_complete``
11      —                   ``[DONE]``
======  ==================  ==================================================

关于"找图"的策略：文档记录的是"事件 7 的 ``delta.v.message.content.parts[0]``"，
但正文在原始抓包里曾缺失（docs/03 §0 边界 2），说明结构并非永远可预期。
因此这里**以文档路径为准、再做一次受深度限制的递归兜底**：先走明确路径，
没找到就在本事件的 JSON 里递归找 ``image_asset_pointer``。
这样结构微调时不会漏图，同时递归有深度上限、不会爆炸。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

from cgpt.models import ImageAsset

#: 递归兜底的最大深度（真实结构在 6 层以内）
MAX_SCAN_DEPTH = 14


@dataclass
class SseEvent:
    event: str | None
    data: str


def iter_sse(lines: Iterable[str]) -> Iterator[SseEvent]:
    """把 SSE 行流切成事件。

    遵循 SSE 规范：``event:`` 设事件名，``data:`` 累加（多行以 ``\\n`` 连接），
    空行结束一个事件，以 ``:`` 开头的是注释（忽略）。
    """
    event_name: str | None = None
    data_parts: list[str] = []

    for raw_line in lines:
        line = raw_line.rstrip("\r\n")
        if line == "":
            if data_parts or event_name is not None:
                yield SseEvent(event=event_name, data="\n".join(data_parts))
            event_name = None
            data_parts = []
            continue
        if line.startswith(":"):
            continue
        if line.startswith("event:"):
            event_name = line[len("event:"):].strip()
            continue
        if line.startswith("data:"):
            value = line[len("data:"):]
            data_parts.append(value[1:] if value.startswith(" ") else value)
            continue
        # 其它字段（id: / retry:）对本次任务无用
    if data_parts or event_name is not None:
        yield SseEvent(event=event_name, data="\n".join(data_parts))


def assets_from_content(content: Any) -> list[ImageAsset]:
    """按文档记录的结构取图：``content.parts[]`` 里的 ``image_asset_pointer``。"""
    if not isinstance(content, dict):
        return []
    parts = content.get("parts")
    if not isinstance(parts, list):
        return []
    found: list[ImageAsset] = []
    for part in parts:
        asset = ImageAsset.from_part(part)
        if asset is not None:
            found.append(asset)
    return found


def extract_assets(node: Any, *, _depth: int = 0) -> list[ImageAsset]:
    """递归找出任意嵌套位置里的图片资产指针。

    先走文档路径（``content.parts``），再对被扫描到的 dict 做递归兜底。
    结果按出现顺序去重（同一张图可能在多个事件里重复出现）。
    """
    if _depth > MAX_SCAN_DEPTH:
        return []
    found: list[ImageAsset] = []

    if isinstance(node, dict):
        # 1) 文档路径：content.parts[]
        found.extend(assets_from_content(node.get("content")))
        # 2) 兜底：node 本身就是一个 part
        direct = ImageAsset.from_part(node)
        if direct is not None:
            found.append(direct)
        # 3) 继续往子节点走
        for value in node.values():
            found.extend(extract_assets(value, _depth=_depth + 1))
    elif isinstance(node, list):
        for item in node:
            found.extend(extract_assets(item, _depth=_depth + 1))

    return _dedupe(found)


def _dedupe(assets: Iterable[ImageAsset]) -> list[ImageAsset]:
    seen: set[str] = set()
    unique: list[ImageAsset] = []
    for asset in assets:
        if asset.asset_pointer in seen:
            continue
        seen.add(asset.asset_pointer)
        unique.append(asset)
    return unique


@dataclass
class StreamFindings:
    """一次 SSE 流里我们关心的一切。"""

    conversation_id: str | None = None
    title: str | None = None
    assets: list[ImageAsset] = field(default_factory=list)
    done: bool = False
    message_stream_complete: bool = False
    last_assistant_message_id: str | None = None
    events_seen: int = 0
    server_errors: list[str] = field(default_factory=list)

    def merge(self, other: "StreamFindings") -> None:
        if other.conversation_id:
            self.conversation_id = other.conversation_id
        if other.title:
            self.title = other.title
        self.assets = _dedupe([*self.assets, *other.assets])
        self.done = self.done or other.done
        self.message_stream_complete = (self.message_stream_complete
                                        or other.message_stream_complete)
        if other.last_assistant_message_id:
            self.last_assistant_message_id = other.last_assistant_message_id


def _handle_delta(payload: dict[str, Any], findings: StreamFindings) -> None:
    value = payload.get("v")

    # conversation_id 出现在第一个 add 的 v 里（事件 2）
    if isinstance(value, dict):
        candidate = value.get("conversation_id")
        if isinstance(candidate, str) and candidate:
            findings.conversation_id = candidate

        # 服务端错误信息也走 delta（error / error_code）
        for key in ("error", "error_code"):
            error = value.get(key)
            if isinstance(error, str) and error:
                findings.server_errors.append(f"{key}={error}")
            elif isinstance(error, dict) and error:
                findings.server_errors.append(f"{key}={json.dumps(error)[:200]}")

        message = value.get("message")
        if isinstance(message, dict):
            author = message.get("author") or {}
            if isinstance(author, dict) and author.get("role") == "assistant":
                message_id = message.get("id")
                if isinstance(message_id, str) and message_id:
                    findings.last_assistant_message_id = message_id

    findings.assets = _dedupe([*findings.assets, *extract_assets(value)])


def consume_sse(lines: Iterable[str]) -> StreamFindings:
    """消费整条 SSE 流，返回汇总结果。

    对无法解析的事件**不抛异常**：真实流里存在遥测/控制事件，而且抓包本身
    就出现过正文缺失。静默跳过它们、继续找图，比中途炸掉更有用。
    """
    findings = StreamFindings()

    for event in iter_sse(lines):
        findings.events_seen += 1
        data = event.data.strip()
        if not data:
            continue
        if data == "[DONE]":
            findings.done = True
            continue

        try:
            payload = json.loads(data)
        except ValueError:
            continue

        if not isinstance(payload, dict):
            continue

        event_type = payload.get("type")
        if event_type == "title_generation":
            title = payload.get("title")
            if isinstance(title, str) and title:
                findings.title = title
            continue
        if event_type == "message_stream_complete":
            findings.message_stream_complete = True
            conversation_id = payload.get("conversation_id")
            if isinstance(conversation_id, str) and conversation_id:
                findings.conversation_id = conversation_id
            continue
        if event_type == "resume_conversation_token":
            continue

        # delta 事件：既可能是 {"p":..,"o":..,"v":..}，也可能直接带 message
        if "v" in payload or "o" in payload or "p" in payload:
            _handle_delta(payload, findings)
        else:
            findings.assets = _dedupe([*findings.assets, *extract_assets(payload)])

    return findings


def extract_assets_from_conversation(payload: Any) -> list[ImageAsset]:
    """从 ``GET /backend-api/conversations/<id>`` 的响应里找图（兜底路径）。

    该响应既有 ``messages[]``（docs/04 §2.5）也可能有 ``mapping``（原始树），
    这里不假设具体字段，直接递归找 —— 反正 ``extract_assets`` 有去重与深度上限。
    """
    return extract_assets(payload)
