"""哨兵令牌是**一次性**的。

实测确认的故障现象："第一次生图正常，第二次 403"。

排查过程（三次真实生图）：

======  ==========================  ======
实验    条件                        结果
======  ==========================  ======
A       全新令牌，首次使用            ✅
B       **同一批**令牌，47 秒后再用    ❌ 403
C       **只换了令牌**，49 秒后再来    ✅
======  ==========================  ======

C 是关键对照：与 B 的时间间隔一样近，唯一区别是令牌是新的 ——
所以**不是频率限制**，而是同一批 ``openai-sentinel-*`` 只能用一次。

403 的特征也印证了这一点：``content-type: application/json``、响应体为空、
没有 ``cf-mitigated`` —— 是应用层拒绝，不是 Cloudflare 边缘挑战。

原来的 ``_sentinel_is_fresh()`` 只看 420 秒的时间窗，把令牌当成可复用缓存，
于是第二次必然踩中。这个文件把这个约束钉死。
"""

from __future__ import annotations

import itertools
import json as _json
import time
from pathlib import Path

import pytest

from cgpt.api.client import ChatGptWebClient
from cgpt.api.transport import TransportResponse
from cgpt.client import Client
from cgpt.config import Settings
from cgpt.errors import SentinelRejectedError, TransportError
from cgpt.models import Credentials, SentinelTokens


class FakeBrowser:
    """每次 refresh 都发一批**全新**令牌的假浏览器。

    序号用**跨实例共享**的计数器：``refresh_sentinel`` 用完会关掉会话，
    下一次刷新拿到的是新实例 —— 若用实例级计数器，序号会从头开始，
    就分不清"换了一批"和"复用了同一批"了。
    """

    _serials = itertools.count(1)

    def __init__(self) -> None:
        self.started = False
        self.refresh_count = 0
        self.close_count = 0

    def start(self) -> None:
        self.started = True

    def close(self) -> None:
        self.close_count += 1
        self.started = False

    def refresh_credentials(self, **_kwargs) -> Credentials:
        self.refresh_count += 1
        serial = next(FakeBrowser._serials)
        return Credentials(
            cookies={"__Secure-next-auth.session-token.0": "x"},
            bearer="b", account_id="a",
            sentinel=SentinelTokens(chat_requirements=f"cr-{serial}",
                                    proof=f"pf-{serial}",
                                    turnstile=f"ts-{serial}",
                                    issued_at=time.time()))

    def read_cookies(self) -> list[dict]:
        return [{"name": "__Secure-next-auth.session-token.0", "value": "x"}]

    def fetch_in_context(self, **_kw) -> dict:
        return {"status": 200, "headers": {}, "body": "{}"}


def _credentials(consumed: bool = False) -> Credentials:
    return Credentials(
        cookies={"__Secure-next-auth.session-token.0": "x"},
        bearer="b", account_id="a",
        sentinel=SentinelTokens(chat_requirements="cr", proof="pf",
                                turnstile="ts", issued_at=time.time(),
                                consumed=consumed),
        captured_at=time.time())


def _credentials_without_sentinel() -> Credentials:
    """手上还没有令牌的情况 —— 第一次生图就必须去取。"""
    return Credentials(cookies={"__Secure-next-auth.session-token.0": "x"},
                       bearer="b", account_id="a", captured_at=time.time())


def _client(browser: FakeBrowser | None, logs: list[str], tmp_path: Path,
            credentials: Credentials | None = None) -> Client:
    settings = Settings(credentials_path=tmp_path / "c.json",
                        profile_dir=tmp_path / "p",
                        debug_dir=tmp_path / "d")
    return Client(credentials or _credentials(), settings=settings,
                  browser=browser, log=logs.append)


def _client_via_factory(patch_browser_session, logs: list[str], tmp_path: Path,
                        credentials: Credentials | None = None):
    """不注入会话，让 ``ensure_browser`` 自己去创建（走被替换掉的工厂）。

    为什么需要它：``refresh_sentinel`` 在 finally 里会 ``_release_browser()``，
    所以**第二次**刷新拿到的是**新建**的会话。若只注入一次假件，
    第二次就会去 new 一个真的 BrowserSession。

    返回 ``(client, created)``；``created`` 是按创建顺序收集的假会话列表，
    计数时要跨实例求和（见 ``_total_refreshes``）。
    """
    created = patch_browser_session(FakeBrowser)
    return _client(None, logs, tmp_path, credentials), created


def _total_refreshes(created: list[FakeBrowser]) -> int:
    return sum(browser.refresh_count for browser in created)


# --- 模型层 --------------------------------------------------------------


def test_fresh_tokens_are_fresh() -> None:
    assert SentinelTokens(chat_requirements="a", proof="b", turnstile="c",
                          issued_at=time.time()).is_fresh() is True


def test_consumed_tokens_are_never_fresh_even_within_ttl() -> None:
    """核心：时间窗内也不算新鲜 —— 这是"第二次 403"的根因。"""
    tokens = SentinelTokens(chat_requirements="a", proof="b", turnstile="c",
                            issued_at=time.time(), consumed=True)
    assert tokens.age() < 10, "前提：还在 TTL 窗口内"
    assert tokens.is_fresh() is False


def test_consumed_defaults_to_false() -> None:
    assert SentinelTokens(chat_requirements="a", proof="b",
                          turnstile="c", issued_at=0.0).consumed is False


def test_consumed_survives_serialisation() -> None:
    tokens = SentinelTokens(chat_requirements="a", proof="b", turnstile="c",
                            issued_at=1.0, consumed=True)
    restored = SentinelTokens.model_validate_json(tokens.model_dump_json())
    assert restored.consumed is True


# --- Client 层 -----------------------------------------------------------


def test_ensure_sentinel_refreshes_when_consumed(tmp_path: Path, logs) -> None:
    browser = FakeBrowser()
    client = _client(browser, logs, tmp_path, _credentials(consumed=True))

    client.ensure_sentinel()

    assert browser.refresh_count == 1
    assert any("一次性" in line for line in logs), "日志要说清为什么重取"


def test_ensure_sentinel_skips_refresh_when_unused_and_fresh(tmp_path: Path,
                                                             logs) -> None:
    browser = FakeBrowser()
    client = _client(browser, logs, tmp_path, _credentials(consumed=False))

    client.ensure_sentinel()

    assert browser.refresh_count == 0


def test_refresh_resets_consumed_flag(tmp_path: Path, logs) -> None:
    browser = FakeBrowser()
    client = _client(browser, logs, tmp_path, _credentials(consumed=True))

    client.refresh_sentinel()

    assert client.credentials.sentinel is not None
    assert client.credentials.sentinel.consumed is False
    assert client._sentinel_is_fresh() is True


# --- 两次连续生图必须各取一批令牌 ----------------------------------------


class _Recorder:
    """假传输层：只回必要的响应，让 generate_image 走到"没有图片资产"。"""

    def __init__(self, client: Client) -> None:
        self.client = client
        self.sent_headers: list[dict] = []

    @staticmethod
    def _payload(url: str) -> dict:
        if "accounts/check" in url:
            return {"accounts": {"default": {
                "account": {"account_id": "a", "plan_type": "free"},
                "features": ["image_gen_tool_enabled"]}}}
        if "conversation/init" in url:
            return {"limits_progress": []}
        return {}

    def request(self, method, url, *, headers=None, json=None, data=None,
                timeout=None):
        return TransportResponse(
            status_code=200,
            content=_json.dumps(self._payload(url)).encode())

    def stream_lines(self, method, url, *, headers=None, json=None,
                     timeout=None):
        self.sent_headers.append(dict(headers or {}))
        yield 'data: {"p":"","o":"add","v":{"conversation_id":"cid"}}'
        yield ""
        yield "data: [DONE]"
        yield ""


def _wire(client: Client) -> _Recorder:
    recorder = _Recorder(client)
    client._transport = recorder
    client._web = None
    return recorder


def test_two_generations_each_get_their_own_token_batch(
        tmp_path: Path, logs, patch_browser_session) -> None:
    """这是用户报的那个 bug 的回归测试。

    原来第二次会复用同一批令牌 → 403。现在每次都必须重取。
    """
    from cgpt.errors import NoImageProducedError

    # 起点是"手上没有令牌"，这样两次生图都必须各取一批
    client, created = _client_via_factory(patch_browser_session, logs, tmp_path,
                                          _credentials_without_sentinel())
    recorder = _wire(client)

    for _ in range(2):
        with pytest.raises(NoImageProducedError):
            client.generate_image("画个地球", out=tmp_path / "a.png",
                                  timeout=0.05, poll_interval=0.01)

    assert _total_refreshes(created) == 2, "两次生图必须各取一批新令牌"
    sent = [h["openai-sentinel-chat-requirements-token"]
            for h in recorder.sent_headers]
    assert len(sent) == 2
    assert len(set(sent)) == 2, f"第二次不能复用第一批令牌，实际发了 {sent}"


def test_generation_marks_tokens_consumed_even_on_failure(tmp_path: Path,
                                                          logs) -> None:
    """发过一次就算用掉了 —— 失败也不能留着赌它还有效。"""
    from cgpt.errors import NoImageProducedError

    browser = FakeBrowser()
    client = _client(browser, logs, tmp_path)
    _wire(client)

    with pytest.raises(NoImageProducedError):
        client.generate_image("画个地球", out=tmp_path / "a.png",
                              timeout=0.05, poll_interval=0.01)

    assert client.credentials.sentinel is not None
    assert client.credentials.sentinel.consumed is True


def test_generation_marks_consumed_when_send_is_rejected(tmp_path: Path,
                                                         logs) -> None:
    browser = FakeBrowser()
    client = _client(browser, logs, tmp_path)

    class Rejecting:
        def request(self, method, url, *, headers=None, json=None, data=None,
                    timeout=None):
            payload = _Recorder._payload(url)
            return TransportResponse(status_code=200,
                                     content=_json.dumps(payload).encode())

        def stream_lines(self, method, url, *, headers=None, json=None,
                         timeout=None):
            raise TransportError("boom", status_code=403)
            yield  # pragma: no cover

    client._transport = Rejecting()
    client._web = None

    with pytest.raises(SentinelRejectedError):
        client.generate_image("画个地球", out=tmp_path / "a.png")

    assert client.credentials.sentinel is not None
    assert client.credentials.sentinel.consumed is True


# --- 403 兜底重试 --------------------------------------------------------


def test_403_triggers_one_refresh_and_retry(tmp_path: Path, logs,
                                            patch_browser_session) -> None:
    """万一令牌在不知情时被消耗（比如同一凭据被别的进程用了），
    403 后重取一批再试一次。"""
    from cgpt.errors import NoImageProducedError

    client, created = _client_via_factory(patch_browser_session, logs, tmp_path,
                                          _credentials_without_sentinel())

    attempts = {"n": 0}

    class Flaky:
        def request(self, method, url, *, headers=None, json=None, data=None,
                    timeout=None):
            return TransportResponse(
                status_code=200,
                content=_json.dumps(_Recorder._payload(url)).encode())

        def stream_lines(self, method, url, *, headers=None, json=None,
                         timeout=None):
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise TransportError("rejected", status_code=403)
            yield 'data: {"p":"","o":"add","v":{"conversation_id":"cid"}}'
            yield ""
            yield "data: [DONE]"
            yield ""

    client._transport = Flaky()
    client._web = None

    # 第一次发送被拒 → 重取令牌 → 第二次发送仍然没出图（这里只验证重试发生了）
    with pytest.raises(NoImageProducedError):
        client.generate_image("画个地球", out=tmp_path / "a.png",
                              timeout=0.05, poll_interval=0.01)

    assert attempts["n"] == 2, "应当重试了一次"
    assert _total_refreshes(created) == 2, "首次 ensure + 403 后重取"
    assert any("重取准入令牌后再试一次" in line for line in logs)


def test_retry_does_not_loop_forever(tmp_path: Path, logs,
                                     patch_browser_session) -> None:
    """重试只做一次 —— 不能变成无限重取令牌。"""
    client, created = _client_via_factory(patch_browser_session, logs, tmp_path,
                                          _credentials_without_sentinel())

    class AlwaysRejecting:
        def request(self, method, url, *, headers=None, json=None, data=None,
                    timeout=None):
            return TransportResponse(
                status_code=200,
                content=_json.dumps(_Recorder._payload(url)).encode())

        def stream_lines(self, method, url, *, headers=None, json=None,
                         timeout=None):
            raise TransportError("rejected", status_code=403)
            yield  # pragma: no cover

    client._transport = AlwaysRejecting()
    client._web = None

    with pytest.raises(SentinelRejectedError):
        client.generate_image("画个地球", out=tmp_path / "a.png")

    assert _total_refreshes(created) == 2, "首次 + 一次重试，不该更多"


def test_no_retry_when_refresh_disabled(tmp_path: Path, logs) -> None:
    browser = FakeBrowser()
    client = _client(browser, logs, tmp_path, _credentials_without_sentinel())

    class AlwaysRejecting:
        def request(self, method, url, *, headers=None, json=None, data=None,
                    timeout=None):
            return TransportResponse(
                status_code=200,
                content=_json.dumps(_Recorder._payload(url)).encode())

        def stream_lines(self, method, url, *, headers=None, json=None,
                         timeout=None):
            raise TransportError("rejected", status_code=403)
            yield  # pragma: no cover

    client._transport = AlwaysRejecting()
    client._web = None

    with pytest.raises(SentinelRejectedError):
        client.generate_image("画个地球", out=tmp_path / "a.png",
                              refresh_sentinel=False)

    assert browser.refresh_count == 0


# --- 传输层：状态码要能机器判断 ------------------------------------------


def test_transport_error_carries_status_code() -> None:
    """别再靠匹配错误文本来判断 403。"""
    error = TransportError("x", status_code=403)
    assert error.status_code == 403
    assert TransportError("x").status_code is None


def test_send_message_translates_403_into_sentinel_rejected() -> None:
    class Rejecting:
        def request(self, *a, **kw):
            return TransportResponse(status_code=200, content=b"{}")

        def stream_lines(self, *a, **kw):
            raise TransportError("rejected", status_code=403)
            yield  # pragma: no cover

    client = ChatGptWebClient(_credentials(), Rejecting(), Settings())
    with pytest.raises(SentinelRejectedError) as excinfo:
        client.send_message("画个地球")

    message = str(excinfo.value)
    assert "一次性" in message
    assert "403" in message


def test_send_message_keeps_other_transport_errors_as_is() -> None:
    class Broken:
        def request(self, *a, **kw):
            return TransportResponse(status_code=200, content=b"{}")

        def stream_lines(self, *a, **kw):
            raise TransportError("connection reset", status_code=None)
            yield  # pragma: no cover

    client = ChatGptWebClient(_credentials(), Broken(), Settings())
    with pytest.raises(TransportError) as excinfo:
        client.send_message("画个地球")
    assert not isinstance(excinfo.value, SentinelRejectedError)
