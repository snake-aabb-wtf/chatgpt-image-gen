"""API 层测试：SSE 解析、资产提取、生图编排、以及"凭据不外泄"这条安全约束。

全部用假传输层（``FakeTransport``）驱动，不联网。SSE 样本按 docs/03 §4.7.1
记录的真实 12 事件结构构造。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

import pytest

from cgpt.api.client import (
    ChatGptWebClient,
    assert_safe_download_url,
    find_assets_in_conversation,
    messages_from_conversation,
)
from cgpt.api.image import (
    collect_assets,
    generate_image,
    probe_image,
)
from cgpt.api.sse import (
    StreamFindings,
    assets_from_content,
    consume_sse,
    extract_assets,
    iter_sse,
)
from cgpt.api.transport import FallbackTransport, TransportResponse
from cgpt.config import Settings
from cgpt.errors import (
    CgptError,
    CloudflareChallengeError,
    ImageGenUnavailableError,
    InvalidPromptError,
    NoImageProducedError,
    QuotaExhaustedError,
    UnsafeDownloadURLError,
)
from cgpt.models import Credentials, ImageAsset, SentinelTokens

REAL_POINTER = "sediment://file_000000009d9881fd99df55e87397a00d"
REAL_FILE_ID = "file_000000009d9881fd99df55e87397a00d"

# 1×1 的合法 PNG（含正确 IHDR），用于验证落盘与自证路径
PNG_1X1 = bytes.fromhex(
    "89504e470d0a1a0a0000000d494844520000000100000001080200000090"
    "7753de0000000c4944415408d763f8cfc000000301010018dd8db0000000"
    "0049454e44ae426082")


def _asset_part(size_bytes: int | None = 1, width: int | None = 1,
                height: int | None = 1) -> dict[str, Any]:
    return {
        "content_type": "image_asset_pointer",
        "asset_pointer": REAL_POINTER,
        "mime_type": "image/png",
        "size_bytes": size_bytes,
        "width": width,
        "height": height,
        "fovea": None,
        "metadata": {"dalle": {"gen_id": "gen-1"}, "gizmo": None,
                     "generation": {"gen_id": "gen-1", "gen_size": "smimage"}},
    }


def _real_sse_lines(asset_part: dict[str, Any] | None = None,
                    extra_events: tuple[tuple[str | None, Any], ...] = ()) -> list[str]:
    """按 docs/03 §4.7.1 的 12 事件结构拼一条 SSE 流。

    ``extra_events`` 会插在收尾事件（title_generation / message_stream_complete
    / ``[DONE]``）之前 —— 直接按切片往末尾塞会把事件拼坏（空行才是事件分隔符）。
    """
    part = asset_part if asset_part is not None else _asset_part()
    events: list[tuple[str | None, Any]] = [
        ("delta_encoding", "v1"),
        (None, {"type": "resume_conversation_token", "kind": "topic",
                "token": "eyJhbGciOiJFUzI1NiJ9.x.y", "conversation_id": "cid-1"}),
        ("delta", {"p": "", "o": "add", "v": {
            "message": {"id": "m-0", "author": {"role": "assistant"},
                        "content": {"content_type": "model_editable_context",
                                    "parts": [""]}},
            "conversation_id": "cid-1", "error": None, "error_code": None}}),
        (None, {"type": "message_marker", "message_id": "m-0", "marker": "x"}),
        ("delta", {"p": "", "o": "add", "v": {
            "message": {"id": "m-1", "author": {"role": "assistant"},
                        "content": {"content_type": "code",
                                    "parts": ['{"skipped_mainline":true}']},
                        "status": "in_progress"}}}),
        ("delta", {"p": "/message/status", "o": "replace",
                   "v": "finished_successfully"}),
        (None, {"type": "title_generation", "title": "生成地球图片"}),
        ("delta", {"p": "", "o": "add", "v": {
            "message": {"id": "m-2", "author": {"role": "tool", "name": "t2uay3k"},
                        "content": {"content_type": "multimodal_text",
                                    "parts": [part]}}}}),
        *extra_events,
        (None, {"type": "title_generation", "title": "生成地球图片"}),
        (None, {"type": "server_ste_metadata", "x": 1}),
        (None, {"type": "message_stream_complete", "conversation_id": "cid-1"}),
        (None, "[DONE]"),
    ]
    lines: list[str] = []
    for name, payload in events:
        if name:
            lines.append(f"event: {name}")
        data = payload if isinstance(payload, str) else json.dumps(payload)
        lines.append(f"data: {data}")
        lines.append("")
    return lines


def _extra_asset_event(part: dict[str, Any], message_id: str = "m-3"
                       ) -> tuple[str, dict[str, Any]]:
    return ("delta", {"p": "", "o": "add", "v": {
        "message": {"id": message_id, "author": {"role": "tool"},
                    "content": {"content_type": "multimodal_text",
                                "parts": [part]}}}})


def _second_asset_part() -> dict[str, Any]:
    part = _asset_part()
    part["asset_pointer"] = "sediment://file_000000003218824383bf262ec925b22e"
    return part


def _send_calls(transport: "FakeTransport") -> list[dict[str, Any]]:
    """只挑真正的发送请求 —— ``f/conversation/prepare`` 的 URL 里也含这个子串。"""
    return [c for c in transport.calls
            if c["method"] == "POST"
            and c["url"].split("?")[0].endswith("/backend-api/f/conversation")]


# --- SSE 解析 ------------------------------------------------------------


def test_iter_sse_parses_event_names_and_data() -> None:
    events = list(iter_sse(["event: delta", "data: {\"a\":1}", "",
                            "data: [DONE]", ""]))
    assert [e.event for e in events] == ["delta", None]
    assert events[0].data == '{"a":1}'
    assert events[1].data == "[DONE]"


def test_iter_sse_joins_multiline_data_and_skips_comments() -> None:
    events = list(iter_sse([": keep-alive", "data: line1", "data: line2", ""]))
    assert len(events) == 1
    assert events[0].data == "line1\nline2"


def test_iter_sse_handles_missing_blank_line_at_eof() -> None:
    events = list(iter_sse(["data: tail"]))
    assert len(events) == 1 and events[0].data == "tail"


def test_consume_sse_extracts_asset_conversation_and_title() -> None:
    findings = consume_sse(_real_sse_lines())
    assert findings.conversation_id == "cid-1"
    assert findings.title == "生成地球图片"
    assert findings.done is True
    assert findings.message_stream_complete is True
    assert [a.asset_pointer for a in findings.assets] == [REAL_POINTER]
    assert findings.assets[0].file_id == REAL_FILE_ID
    assert findings.last_assistant_message_id == "m-2" or \
        findings.last_assistant_message_id == "m-1"


def test_consume_sse_ignores_unparseable_events() -> None:
    findings = consume_sse(["event: delta", "data: {not json", "",
                            "data: [DONE]", ""])
    assert findings.done is True
    assert findings.assets == []


def test_consume_sse_reports_server_errors() -> None:
    payload = json.dumps({"p": "", "o": "add",
                          "v": {"error": "content policy", "error_code": "x"}})
    findings = consume_sse([f"data: {payload}", ""])
    assert findings.server_errors


def test_consume_sse_deduplicates_repeated_asset_events() -> None:
    lines = _real_sse_lines() + _real_sse_lines()
    findings = consume_sse(lines)
    assert len(findings.assets) == 1


def test_consume_sse_finds_multiple_distinct_assets() -> None:
    lines = _real_sse_lines(extra_events=(_extra_asset_event(_second_asset_part()),))
    findings = consume_sse(lines)
    assert len(findings.assets) == 2
    assert {a.file_id for a in findings.assets} == {
        REAL_FILE_ID, "file_000000003218824383bf262ec925b22e"}


# --- 资产提取 ------------------------------------------------------------


def test_assets_from_content_documented_path() -> None:
    content = {"content_type": "multimodal_text", "parts": [_asset_part()]}
    assets = assets_from_content(content)
    assert len(assets) == 1 and assets[0].file_id == REAL_FILE_ID


def test_assets_from_content_ignores_text_parts() -> None:
    assert assets_from_content({"parts": ["hello", None, {"content_type": "text"}]}) == []


def test_extract_assets_respects_depth_limit() -> None:
    node: Any = {"content": {"parts": [_asset_part()]}}
    for _ in range(40):
        node = {"nested": node}
    assert extract_assets(node) == []


def test_extract_assets_finds_deeply_but_validly_nested_asset() -> None:
    node: Any = {"content": {"parts": [_asset_part()]}}
    for _ in range(10):
        node = {"nested": node}
    assert len(extract_assets(node)) == 1


def test_find_assets_in_conversation_from_messages_list() -> None:
    payload = {"messages": [{"author": {"role": "tool"},
                             "content": {"parts": [_asset_part()]}}]}
    assert len(find_assets_in_conversation(payload)) == 1


def test_find_assets_in_conversation_from_mapping() -> None:
    payload = {"mapping": {"a": {"message": {"content": {"parts": [_asset_part()]}}}}}
    assert len(find_assets_in_conversation(payload)) == 1


def test_find_assets_in_conversation_returns_empty_for_text_only() -> None:
    payload = {"messages": [{"content": {"content_type": "text",
                                         "parts": ["不好意思，我不能画这个"]}}]}
    assert find_assets_in_conversation(payload) == []


def test_messages_from_conversation_supports_both_shapes() -> None:
    payload = {"messages": [{"id": "a"}], "mapping": {"k": {"message": {"id": "b"}}}}
    assert sorted(m["id"] for m in messages_from_conversation(payload)) == ["a", "b"]


# --- 下载 URL 安全 -------------------------------------------------------


@pytest.mark.parametrize("url", [
    f"https://chatgpt.com/backend-api/estuary/content?id={REAL_FILE_ID}&sig=x",
    "https://chatgpt.com/x",
])
def test_safe_download_url_accepts_chatgpt_hosts(url: str) -> None:
    assert assert_safe_download_url(url) == url


@pytest.mark.parametrize("url", [
    "https://evil.example.com/steal",
    "https://chatgpt.com.evil.example.com/steal",
    "https://notchatgpt.com/x",
    "http://169.254.169.254/latest/meta-data/",   # SSRF 经典目标
    "file:///etc/passwd",
    "https:///no-host",
])
def test_safe_download_url_rejects_foreign_hosts(url: str) -> None:
    with pytest.raises(UnsafeDownloadURLError):
        assert_safe_download_url(url)


# --- 假传输层与客户端 ----------------------------------------------------


class FakeTransport:
    """按 URL 关键字返回预设响应的假传输层，同时记录收到的请求头。"""

    def __init__(self) -> None:
        self.responses: list[tuple[str, int, Any]] = []
        self.streams: dict[str, list[str]] = {}
        self.calls: list[dict[str, Any]] = []

    def add_json(self, contains: str, status: int, payload: Any) -> None:
        self.responses.append((contains, status, payload))

    def add_stream(self, contains: str, lines: list[str]) -> None:
        self.streams[contains] = lines

    def _match(self, url: str):
        for contains, status, payload in self.responses:
            if contains in url:
                return status, payload
        return 404, None

    def request(self, method: str, url: str, *, headers=None, json=None,
                data=None, timeout=None) -> TransportResponse:
        self.calls.append({"method": method, "url": url,
                           "headers": headers or {}, "json": json})
        status, payload = self._match(url)
        if isinstance(payload, (bytes, bytearray)):
            return TransportResponse(status_code=status,
                                     headers={"content-type": "image/png"},
                                     content=bytes(payload))
        body = b"" if payload is None else json_dumps(payload)
        return TransportResponse(status_code=status,
                                 headers={"content-type": "application/json"},
                                 content=body)

    def stream_lines(self, method: str, url: str, *, headers=None, json=None,
                     timeout=None) -> Iterator[str]:
        self.calls.append({"method": method, "url": url,
                           "headers": headers or {}, "json": json})
        for contains, lines in self.streams.items():
            if contains in url:
                yield from lines
                return
        raise CgptError(f"假传输层没有为 {url} 配置流")


def json_dumps(payload: Any) -> bytes:
    return json.dumps(payload).encode()


def _credentials() -> Credentials:
    import time

    return Credentials(
        cookies={"__Secure-next-auth.session-token.0": "a",
                 "__Secure-next-auth.session-token.1": "b"},
        bearer="bearer-token",
        account_id="acct-1",
        device_id="did-1",
        sentinel=SentinelTokens(chat_requirements="cr", proof="pf",
                                turnstile="ts", issued_at=time.time()),
        captured_at=time.time(),
        user_agent="UA/1.0",
    )


def _client(transport: FakeTransport) -> ChatGptWebClient:
    return ChatGptWebClient(_credentials(), transport, Settings())


def _accounts_check_payload(*, image_gen: bool = True,
                            remaining: int | None = 3) -> list[tuple[str, int, Any]]:
    features = ["gpt5", "mfa"]
    if image_gen:
        features.append("image_gen_tool_enabled")
    limits = []
    if remaining is not None:
        limits.append({"feature_name": "image_gen", "remaining": remaining})
    return [
        ("accounts/check", 200, {
            "accounts": {"default": {
                "account": {"account_id": "acct-1", "plan_type": "free"},
                "features": features}}}),
        ("conversation/init", 200, {"limits_progress": limits,
                                    "default_model_slug": "auto"}),
    ]


# --- 生图编排 ------------------------------------------------------------


def test_generate_image_happy_path_writes_file(tmp_path: Path) -> None:
    transport = FakeTransport()
    for contains, status, payload in _accounts_check_payload():
        transport.add_json(contains, status, payload)
    transport.add_json("f/conversation/prepare", 200,
                       {"status": "ok", "conduit_token": "conduit-jwt"})
    transport.add_stream("f/conversation", _real_sse_lines())
    transport.add_json("files/download", 200, {
        "status": "success",
        "download_url": f"https://chatgpt.com/backend-api/estuary/content"
                        f"?id={REAL_FILE_ID}&sig=deadbeef",
        "file_size_bytes": len(PNG_1X1)})
    transport.add_json("estuary/content", 200, PNG_1X1)

    out = tmp_path / "earth.png"
    result = generate_image(_client(transport), "生成一张地球图片", out=out)

    assert out.read_bytes() == PNG_1X1
    assert result.conversation_id == "cid-1"
    assert result.title == "生成地球图片"
    assert len(result.images) == 1
    image = result.primary
    assert (image.width, image.height) == (1, 1)
    assert image.size_bytes == len(PNG_1X1)
    assert image.mime_type == "image/png"
    assert image.path == out


def test_generate_image_sends_three_sentinel_headers_in_one_piece(tmp_path: Path) -> None:
    transport = FakeTransport()
    for contains, status, payload in _accounts_check_payload():
        transport.add_json(contains, status, payload)
    transport.add_stream("f/conversation", _real_sse_lines())
    transport.add_json("files/download", 200, {
        "download_url": "https://chatgpt.com/backend-api/estuary/content?sig=x"})
    transport.add_json("estuary/content", 200, PNG_1X1)

    generate_image(_client(transport), "画个地球", out=tmp_path / "a.png")

    headers = _send_calls(transport)[0]["headers"]
    assert headers["openai-sentinel-chat-requirements-token"] == "cr"
    assert headers["openai-sentinel-proof-token"] == "pf"
    assert headers["openai-sentinel-turnstile-token"] == "ts"
    assert headers["authorization"] == "Bearer bearer-token"
    assert headers["chatgpt-account-id"] == "acct-1"
    assert headers["oai-did"] == "did-1"


def test_generate_image_request_body_has_no_image_fields(tmp_path: Path) -> None:
    """生图不由客户端声明（docs/03 §4.3）—— 请求体必须干净。"""
    transport = FakeTransport()
    for contains, status, payload in _accounts_check_payload():
        transport.add_json(contains, status, payload)
    transport.add_stream("f/conversation", _real_sse_lines())
    transport.add_json("files/download", 200, {
        "download_url": "https://chatgpt.com/backend-api/estuary/content?sig=x"})
    transport.add_json("estuary/content", 200, PNG_1X1)

    generate_image(_client(transport), "画个地球", out=tmp_path / "a.png")

    body = _send_calls(transport)[0]["json"]
    for forbidden in ("tools", "tool_ids", "image_gen", "image_generation",
                      "dalle", "conversation_mode", "checksum"):
        assert forbidden not in body, f"请求体不该出现 {forbidden}"
    assert body["messages"][0]["content"]["parts"] == ["画个地球"]


def test_generate_image_rejects_blank_prompt_without_network(tmp_path: Path) -> None:
    transport = FakeTransport()
    with pytest.raises(InvalidPromptError):
        generate_image(_client(transport), "   \n\t ", out=tmp_path / "a.png")
    assert transport.calls == []      # 一次请求都没发出去


def test_generate_image_fails_fast_when_feature_disabled(tmp_path: Path) -> None:
    transport = FakeTransport()
    for contains, status, payload in _accounts_check_payload(image_gen=False):
        transport.add_json(contains, status, payload)
    with pytest.raises(ImageGenUnavailableError) as excinfo:
        generate_image(_client(transport), "画个地球", out=tmp_path / "a.png")
    assert "image_gen_tool_enabled" in str(excinfo.value)
    assert not any("f/conversation" in c["url"] for c in transport.calls)


def test_generate_image_detects_exhausted_quota(tmp_path: Path) -> None:
    transport = FakeTransport()
    for contains, status, payload in _accounts_check_payload(remaining=0):
        transport.add_json(contains, status, payload)
    with pytest.raises(QuotaExhaustedError):
        generate_image(_client(transport), "画个地球", out=tmp_path / "a.png")
    assert not any("f/conversation" in c["url"] for c in transport.calls)


def test_generate_image_falls_back_to_conversation_details(tmp_path: Path) -> None:
    """流里没图（抓包真的出现过正文缺失）→ 轮询会话详情兜底。"""
    transport = FakeTransport()
    for contains, status, payload in _accounts_check_payload():
        transport.add_json(contains, status, payload)
    transport.add_stream("f/conversation", [
        "event: delta",
        'data: {"p":"","o":"add","v":{"conversation_id":"cid-9"}}', "",
        "data: [DONE]", ""])
    transport.add_json("conversations/cid-9", 200, {
        "title": "兜底标题",
        "messages": [{"author": {"role": "tool"},
                      "content": {"parts": [_asset_part()]}}]})
    transport.add_json("files/download", 200, {
        "download_url": "https://chatgpt.com/backend-api/estuary/content?sig=x"})
    transport.add_json("estuary/content", 200, PNG_1X1)

    out = tmp_path / "b.png"
    result = generate_image(_client(transport), "画个地球", out=out,
                            poll_interval=0.01)
    assert out.exists()
    assert result.conversation_id == "cid-9"
    assert result.title == "兜底标题"


def test_generate_image_reports_no_image_instead_of_faking_success(tmp_path: Path) -> None:
    transport = FakeTransport()
    for contains, status, payload in _accounts_check_payload():
        transport.add_json(contains, status, payload)
    transport.add_stream("f/conversation", [
        "event: delta",
        'data: {"p":"","o":"add","v":{"conversation_id":"cid-9"}}', "",
        "data: [DONE]", ""])
    transport.add_json("conversations/cid-9", 200, {"messages": [
        {"content": {"content_type": "text", "parts": ["我不能画这个"]}}]})

    with pytest.raises(NoImageProducedError) as excinfo:
        generate_image(_client(transport), "画个地球", out=tmp_path / "c.png",
                       timeout=0.05, poll_interval=0.01)
    assert "cid-9" in str(excinfo.value)
    assert not (tmp_path / "c.png").exists()


def test_collect_assets_rejects_missing_conversation_id() -> None:
    with pytest.raises(CgptError, match="conversation_id"):
        collect_assets(_client(FakeTransport()), None, timeout=0.01,
                       poll_interval=0.01)


def test_generate_image_writes_multiple_files_with_suffixes(tmp_path: Path) -> None:
    transport = FakeTransport()
    for contains, status, payload in _accounts_check_payload():
        transport.add_json(contains, status, payload)
    transport.add_stream(
        "f/conversation",
        _real_sse_lines(extra_events=(_extra_asset_event(_second_asset_part()),)))
    transport.add_json("files/download", 200, {
        "download_url": "https://chatgpt.com/backend-api/estuary/content?sig=x"})
    transport.add_json("estuary/content", 200, PNG_1X1)

    out = tmp_path / "multi.png"
    result = generate_image(_client(transport), "画两张", out=out)
    assert len(result.images) == 2
    assert result.images[0].path == out
    assert result.images[1].path == tmp_path / "multi_2.png"
    assert (tmp_path / "multi_2.png").exists()
    assert out.exists()


def test_generate_image_records_metadata_mismatch_as_note(tmp_path: Path) -> None:
    transport = FakeTransport()
    for contains, status, payload in _accounts_check_payload():
        transport.add_json(contains, status, payload)
    transport.add_stream("f/conversation",
                         _real_sse_lines(_asset_part(size_bytes=99999, width=999,
                                                     height=999)))
    transport.add_json("files/download", 200, {
        "download_url": "https://chatgpt.com/backend-api/estuary/content?sig=x"})
    transport.add_json("estuary/content", 200, PNG_1X1)

    result = generate_image(_client(transport), "画个地球",
                            out=tmp_path / "d.png")
    joined = " | ".join(result.notes)
    assert "字节数与元数据不一致" in joined
    assert "宽度与元数据不一致" in joined


def test_generate_image_rejects_non_image_payload(tmp_path: Path) -> None:
    transport = FakeTransport()
    for contains, status, payload in _accounts_check_payload():
        transport.add_json(contains, status, payload)
    transport.add_stream("f/conversation", _real_sse_lines())
    transport.add_json("files/download", 200, {
        "download_url": "https://chatgpt.com/backend-api/estuary/content?sig=x"})
    transport.add_json("estuary/content", 200, b"<html>not an image</html>")

    with pytest.raises(CgptError, match="不是已知图片格式"):
        generate_image(_client(transport), "画个地球", out=tmp_path / "e.png")


# --- 图片头解析 ----------------------------------------------------------


def test_probe_image_reads_png_ihdr() -> None:
    assert probe_image(PNG_1X1) == ("image/png", 1, 1)


def test_probe_image_rejects_garbage() -> None:
    assert probe_image(b"not an image at all") == ("application/octet-stream",
                                                  None, None)


def test_probe_image_handles_truncated_png() -> None:
    assert probe_image(PNG_1X1[:12]) == ("image/png", None, None)


# --- 传输层回退 ----------------------------------------------------------


def _challenge_response() -> TransportResponse:
    return TransportResponse(status_code=403,
                             headers={"cf-mitigated": "challenge",
                                      "server": "cloudflare"},
                             content=b"<html>Just a moment...</html>")


def test_transport_response_detects_challenge_by_header() -> None:
    assert _challenge_response().looks_like_cloudflare_challenge() is True


def test_transport_response_detects_challenge_by_body() -> None:
    response = TransportResponse(status_code=403, headers={"server": "cloudflare"},
                                 content=b"<html>Just a moment...</html>")
    assert response.looks_like_cloudflare_challenge() is True


def test_transport_response_ignores_plain_403() -> None:
    response = TransportResponse(status_code=403, headers={},
                                 content=b'{"detail":"forbidden"}')
    assert response.looks_like_cloudflare_challenge() is False


class _OnceTransport:
    def __init__(self, response=None, error=None, lines=None):
        self.response = response
        self.error = error
        self.lines = lines or []
        self.calls = 0
        self.yielded_before_error = False

    def request(self, method, url, **kwargs):
        self.calls += 1
        if self.error:
            raise self.error
        return self.response

    def stream_lines(self, method, url, **kwargs):
        self.calls += 1
        if self.yielded_before_error:
            yield "data: partial"
            raise CloudflareChallengeError("mid-stream")
        if self.error:
            raise self.error
        yield from self.lines


def test_fallback_transport_switches_on_challenge() -> None:
    primary = _OnceTransport(response=_challenge_response())
    fallback = _OnceTransport(response=TransportResponse(
        status_code=200, content=b'{"from":"browser"}'))
    transport = FallbackTransport(primary, fallback)

    response = transport.request("GET", "https://chatgpt.com/x")
    assert response.json() == {"from": "browser"}   # 确实用了回退结果
    assert primary.calls == 1 and fallback.calls == 1
    assert transport.fallback_count == 1


def test_fallback_transport_raises_when_browser_context_also_blocked() -> None:
    """回退路径自己也被拦 → 抛可操作的错误，**不能**把 403 漏给业务层。

    早先这里断言的是"原样把结果交回给调用方判断"——那正是 bug 的来源：
    业务层拿到 403 后去 ``json()`` 解析挑战页的 HTML，报出
    "返回的不是 JSON（403）"，完全看不出该干什么。
    现在改为抛 ``CloudflareChallengeError``，消息直接说清"去浏览器完成验证"。
    """
    primary = _OnceTransport(error=CloudflareChallengeError("blocked"))
    fallback = _OnceTransport(response=_challenge_response())
    transport = FallbackTransport(primary, fallback)

    with pytest.raises(CloudflareChallengeError) as excinfo:
        transport.request("GET", "https://chatgpt.com/x")

    assert "人机验证" in str(excinfo.value)
    assert transport.fallback_count == 1


def test_fallback_transport_counts_are_reported_via_callback() -> None:
    seen: list[str] = []
    primary = _OnceTransport(error=CloudflareChallengeError("blocked"))
    fallback = _OnceTransport(response=TransportResponse(status_code=200))
    transport = FallbackTransport(primary, fallback, on_fallback=seen.append)
    transport.request("GET", "https://chatgpt.com/x")
    assert seen == ["https://chatgpt.com/x"]


def test_fallback_transport_does_not_retry_after_stream_started() -> None:
    """流已开始产出后失败，绝不能回退重发 —— 那会重复消耗一次生图额度。"""
    primary = _OnceTransport()
    primary.yielded_before_error = True
    fallback = _OnceTransport(lines=["data: duplicated", ""])
    transport = FallbackTransport(primary, fallback)

    with pytest.raises(CloudflareChallengeError):
        list(transport.stream_lines("POST", "https://chatgpt.com/x"))
    assert fallback.calls == 0
    assert transport.fallback_count == 0


def test_fallback_transport_streams_from_fallback_when_blocked_up_front() -> None:
    primary = _OnceTransport(error=CloudflareChallengeError("blocked"))
    fallback = _OnceTransport(lines=["data: from-browser", ""])
    transport = FallbackTransport(primary, fallback)

    lines = list(transport.stream_lines("POST", "https://chatgpt.com/x"))
    assert lines == ["data: from-browser", ""]
    assert transport.fallback_count == 1


def test_fallback_transport_passes_through_when_primary_succeeds() -> None:
    primary = _OnceTransport(response=TransportResponse(status_code=200,
                                                       content=b'{"ok":true}'))
    fallback = _OnceTransport()
    transport = FallbackTransport(primary, fallback)
    response = transport.request("GET", "https://chatgpt.com/x")
    assert response.json() == {"ok": True}
    assert fallback.calls == 0


def test_client_requires_cookies_to_call_endpoints() -> None:
    """没有会话 Cookie 的凭据不该被用来发请求（空 Cookie 头会暴露问题）。"""
    transport = FakeTransport()
    creds = _credentials()
    creds.cookies = {}
    client = ChatGptWebClient(creds, transport, Settings())
    assert client._headers()["cookie"] == ""


def test_stream_findings_merge_prefers_first_conversation_id() -> None:
    first = StreamFindings(conversation_id="c1", assets=[
        ImageAsset(asset_pointer=REAL_POINTER, file_id=REAL_FILE_ID)])
    second = StreamFindings(conversation_id="c2")
    first.merge(second)
    assert first.conversation_id == "c2"      # 后到的更具体
    assert len(first.assets) == 1
