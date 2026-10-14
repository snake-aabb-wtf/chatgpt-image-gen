"""助手只回文字、没画图时不能"卡死"。

用户报的现象：提示词因违规被驳回时，日志一路刷"第 N 次查询：暂无图片资产"，
直到超时（默认 720 秒）—— 看起来就是卡死。

根因：早先的实现**只找图片资产**。找不到就当"图还在生成"，于是去轮询会话详情。
但生图**必然经过工具调用**（``role: "tool"`` 的消息 / ``content_type: "code"``
的工具信封）；没有这些痕迹，就说明这一轮压根没打算画图。

判别点（真实 SSE 结构，见 tests/test_api.py 的 `_real_sse_lines`）：

======================  ==========================  ====================
痕迹                    正常生图                    只有文字
======================  ==========================  ====================
``content_type: code``  ✅ 工具调用信封               ❌
``role: tool`` 的消息    ✅ 带 image_asset_pointer    ❌
助手文本                 可能有（"好的，我来画"）      ✅ 全部内容
======================  ==========================  ====================

所以判据是：**没有工具痕迹 + 有助手文本** → 立刻失败，别等。

两种成因（违规驳回 / 提示词本来就没要求画图）从返回内容上分不开，
因此错误文案两个都提。这也让「让它答个文字题」成了可复现的良性验证方式。
"""

from __future__ import annotations

import json as _json
from pathlib import Path

import pytest

from cgpt.api.client import ChatGptWebClient
from cgpt.api.image import collect_assets, generate_image
from cgpt.api.sse import (
    AnswerSignals,
    answer_signals_from_conversation,
    scan_answer_signals,
)
from cgpt.api.transport import TransportResponse
from cgpt.config import Settings
from cgpt.errors import PromptRejectedError
from cgpt.models import Credentials, SentinelTokens

# --- 构造真实的两种流 ----------------------------------------------------


def _delta(payload: dict) -> str:
    return "data: " + _json.dumps(payload, ensure_ascii=False)


def _text_answer_stream(text: str = "抱歉，我不能帮你生成这类图片。") -> list[str]:
    """被驳回的形态：只有助手的文本，没有任何工具调用。"""
    return [
        "event: delta_encoding",
        "data: v1",
        "",
        "event: delta",
        _delta({"p": "", "o": "add", "v": {"message": {
            "id": "m-0", "author": {"role": "assistant"},
            "content": {"content_type": "text", "parts": [""]}}}}),
        "",
        # 文本是逐段 append 的
        "event: delta",
        _delta({"p": "/message/content/parts/0", "o": "append", "v": text}),
        "",
        "event: delta",
        _delta({"p": "/message/status", "o": "replace",
                "v": "finished_successfully"}),
        "",
        _delta({"type": "message_stream_complete", "conversation_id": "cid-1"}),
        "",
        "data: [DONE]",
        "",
    ]


def _tool_call_then_text_stream() -> list[str]:
    """正常生图的形态：助手说了句话，**但调用过工具**（有 code 信封）。"""
    return [
        "event: delta",
        _delta({"p": "", "o": "add", "v": {"message": {
            "id": "m-0", "author": {"role": "assistant"},
            "content": {"content_type": "text", "parts": ["好的，我来画。"]}}}}),
        "",
        "event: delta",
        _delta({"p": "", "o": "add", "v": {"message": {
            "id": "m-1", "author": {"role": "assistant"},
            "content": {"content_type": "code", "parts": ['{"size":"1024x1024"}']}}}}),
        "",
        _delta({"type": "message_stream_complete", "conversation_id": "cid-1"}),
        "",
        "data: [DONE]",
        "",
    ]


# --- 解析层 -------------------------------------------------------------


def test_scan_detects_assistant_text() -> None:
    node = {"message": {"author": {"role": "assistant"},
                        "content": {"content_type": "text", "parts": ["你好"]}}}
    assert scan_answer_signals(node).text == "你好"


def test_scan_ignores_user_prompt() -> None:
    """用户自己的提示词不能被当成"助手的回复"。"""
    node = {"message": {"author": {"role": "user"},
                        "content": {"content_type": "text", "parts": ["画只猫"]}}}
    signals = scan_answer_signals(node)
    assert signals.text == ""
    assert signals.is_text_answer_without_image() is False


def test_scan_detects_tool_role() -> None:
    node = {"message": {"author": {"role": "tool", "name": "t2uay3k"},
                        "content": {"content_type": "multimodal_text",
                                    "parts": []}}}
    assert scan_answer_signals(node).tool_evidence is True


def test_scan_detects_code_envelope() -> None:
    node = {"message": {"author": {"role": "assistant"},
                        "content": {"content_type": "code", "parts": ["{}"]}}}
    assert scan_answer_signals(node).tool_evidence is True


def test_scan_detects_finished_status() -> None:
    assert scan_answer_signals({"status": "finished_successfully"}).finished is True


def test_scan_is_depth_limited() -> None:
    node: dict = {"author": {"role": "assistant"},
                  "content": {"content_type": "text", "parts": ["深"]}}
    for _ in range(40):
        node = {"nested": node}
    assert scan_answer_signals(node).text == ""


@pytest.mark.parametrize("text,expected", [
    ("抱歉，我不能帮你生成这类图片。", True),
    ("", False),                       # 没文本就谈不上"文字回复"
    ("   \n  ", False),
])
def test_text_answer_predicate(text: str, expected: bool) -> None:
    signals = AnswerSignals(text=text)
    assert signals.is_text_answer_without_image() is expected


def test_text_answer_predicate_false_when_tool_used() -> None:
    """有工具痕迹就**不能**判定为驳回 —— 图可能还在路上。"""
    signals = AnswerSignals(text="好的，我来画。", tool_evidence=True)
    assert signals.is_text_answer_without_image() is False


# --- 端到端：不能卡死 ----------------------------------------------------


class FakeTransport:
    def __init__(self, stream_lines: list[str], conversation: dict | None = None):
        self.stream = stream_lines
        self.conversation = conversation or {}
        self.conversation_calls = 0

    def request(self, method, url, *, headers=None, json=None, data=None,
                timeout=None):
        # 会话详情是走 request()（GET），不是 stream_lines —— 计数挂在这里
        if "conversations/" in url:
            self.conversation_calls += 1
        if "accounts/check" in url:
            payload: object = {"accounts": {"default": {
                "account": {"account_id": "a", "plan_type": "free"},
                "features": ["image_gen_tool_enabled"]}}}
        elif "conversation/init" in url:
            payload = {"limits_progress": []}
        else:
            payload = self.conversation
        return TransportResponse(status_code=200,
                                 content=_json.dumps(payload).encode())

    def stream_lines(self, method, url, *, headers=None, json=None, timeout=None):
        yield from self.stream


def _client(transport, tmp_path: Path) -> ChatGptWebClient:
    credentials = Credentials(
        cookies={"__Secure-next-auth.session-token.0": "x"},
        bearer="b", account_id="a",
        sentinel=SentinelTokens(chat_requirements="cr", proof="pf",
                                turnstile="ts", issued_at=0.0),
        captured_at=0.0)
    return ChatGptWebClient(credentials, transport,
                            Settings(output_dir=tmp_path / "out"))


def test_text_answer_fails_fast_without_polling(tmp_path: Path) -> None:
    """核心：驳回时**一次都不该轮询**，立刻报错。"""
    transport = FakeTransport(_text_answer_stream())

    with pytest.raises(PromptRejectedError) as excinfo:
        generate_image(_client(transport, tmp_path), "违规提示词",
                       timeout=0.05, poll_interval=0.01)

    assert transport.conversation_calls == 0, "不该去轮询会话详情"
    message = str(excinfo.value)
    assert "没有调用生图工具" in message
    assert "没有要求生成图片" in message, "两种成因都要说清"
    assert "我不能帮你生成这类图片" in message, "要把模型原话带出来"


def test_text_answer_error_mentions_no_quota_used(tmp_path: Path) -> None:
    transport = FakeTransport(_text_answer_stream())
    with pytest.raises(PromptRejectedError) as excinfo:
        generate_image(_client(transport, tmp_path), "违规提示词", timeout=0.05)
    assert "不会消耗生图额度" in str(excinfo.value)


def test_tool_evidence_still_polls_for_the_image(tmp_path: Path) -> None:
    """有工具痕迹但流里还没图 → 仍然要轮询（图可能稍后才出现）。"""
    from cgpt.errors import NoImageProducedError

    transport = FakeTransport(_tool_call_then_text_stream(),
                              conversation={"title": "t"})

    with pytest.raises(NoImageProducedError):
        # 超时给得很短，够证明"确实轮询了"
        generate_image(_client(transport, tmp_path), "画只猫",
                       timeout=0.05, poll_interval=0.01)

    assert transport.conversation_calls >= 1, "有工具痕迹就该去轮询"


def test_polling_bails_out_when_conversation_shows_text_answer() -> None:
    """流里看不出名堂、但会话详情显示"只有文字" → 轮询中途就该退出。"""
    conversation = {
        "title": "t",
        "mapping": {"a": {"message": {
            "author": {"role": "assistant"},
            "content": {"content_type": "text",
                        "parts": ["我不能生成这样的内容。"]}}}},
    }
    transport = FakeTransport([], conversation=conversation)
    client = _client(transport, Path("."))

    with pytest.raises(PromptRejectedError):
        collect_assets(client, "cid-1", timeout=30.0, poll_interval=5.0)


def test_polling_reports_elapsed_time() -> None:
    """轮询日志要带已等时长，别让人以为程序死了。"""
    from cgpt.errors import NoImageProducedError

    notes: list[str] = []
    transport = FakeTransport([], conversation={"title": "t"})
    client = _client(transport, Path("."))

    with pytest.raises(NoImageProducedError):
        collect_assets(client, "cid-1", timeout=0.05, poll_interval=0.01,
                       note=notes.append)

    assert any("已等" in line for line in notes)


def test_conversation_with_tool_message_is_not_a_rejection() -> None:
    """会话详情里有工具消息 → 不能误判成驳回。"""
    from cgpt.errors import NoImageProducedError

    conversation = {
        "mapping": {"a": {"message": {
            "author": {"role": "tool"},
            "content": {"content_type": "multimodal_text",
                        "parts": ["sediment://file_x"]}}}},
    }
    signals = answer_signals_from_conversation(conversation)
    assert signals.tool_evidence is True
    assert signals.is_text_answer_without_image() is False

    transport = FakeTransport([], conversation=conversation)
    with pytest.raises(NoImageProducedError):
        collect_assets(_client(transport, Path(".")), "cid-1",
                       timeout=0.05, poll_interval=0.01)
