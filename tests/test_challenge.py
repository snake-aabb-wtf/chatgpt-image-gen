"""人机验证（Cloudflare challenge）的交互处理。

背景：用户问过"真被人机验证拦了会留着让我手动去过吗"。当时答案是**不能** ——
窗口虽然留着，但：

* 挑战是以 ``fetch`` **响应体**回来的，页面上不会渲染出可点的 Turnstile 控件，
  用户没有东西可点；
* ``FallbackTransport`` 回退之后没有再检查一次，把 403 原样交给业务层，
  业务层去 ``json()`` 解析那段 HTML，报出"返回的不是 JSON（403）"——
  完全看不出该干什么。

现在改成：两条路都被拦 → 把浏览器**导航**到被拦地址让验证渲染出来 →
等用户点完 → **重读 Cookie**（cf_clearance 是在浏览器里刷新的）→ 自动重试。
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from cgpt.api.transport import (
    FallbackTransport,
    TransportResponse,
    challenge_message,
)
from cgpt.client import Client
from cgpt.config import Settings
from cgpt.errors import CloudflareChallengeError
from cgpt.models import Credentials, SentinelTokens


def _challenge_response() -> TransportResponse:
    return TransportResponse(
        status_code=403,
        headers={"cf-mitigated": "challenge", "server": "cloudflare",
                 "content-type": "text/html"},
        content=b"<html><title>Just a moment...</title></html>")


def _ok_response(payload: bytes = b'{"ok":true}') -> TransportResponse:
    return TransportResponse(status_code=200,
                             headers={"content-type": "application/json"},
                             content=payload)


class ScriptedTransport:
    """按脚本依次返回响应的假传输层。

    脚本用完后**重复最后一个结果** —— 这样"一直被拦的主通道"就真的是一直被拦，
    而不是悄悄变成成功（那会让重试路径的断言变得没有意义）。
    """

    def __init__(self, *outcomes) -> None:
        self.outcomes = list(outcomes)
        self.calls = 0

    def _next(self):
        self.calls += 1
        if not self.outcomes:
            return _ok_response()
        if len(self.outcomes) > 1:
            return self.outcomes.pop(0)
        return self.outcomes[0]          # 最后一个反复使用

    def request(self, *_a, **_kw):
        outcome = self._next()
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def stream_lines(self, *_a, **_kw):
        outcome = self._next()
        if isinstance(outcome, Exception):
            raise outcome
        # 与 BrowserTransport.stream_lines 对齐：挑战响应要抛错，而不是
        # 把挑战页的 HTML 当成"流内容"吐出去
        if outcome.looks_like_cloudflare_challenge():
            raise CloudflareChallengeError("blocked in browser context")
        yield from outcome.text.splitlines()


# --- 传输层：两条路都被拦 --------------------------------------------------


def test_no_solver_raises_instead_of_leaking_403_to_business_layer() -> None:
    """这是修复前的行为：403 漏到业务层，变成"返回的不是 JSON"。"""
    transport = FallbackTransport(
        ScriptedTransport(CloudflareChallengeError("blocked")),
        ScriptedTransport(_challenge_response()))

    with pytest.raises(CloudflareChallengeError) as excinfo:
        transport.request("GET", "https://chatgpt.com/backend-api/me")

    message = str(excinfo.value)
    assert "人机验证" in message
    assert "浏览器窗口已打开" in message
    assert transport.solve_count == 0


def test_solver_is_called_then_request_is_retried() -> None:
    primary = ScriptedTransport(CloudflareChallengeError("blocked"))
    fallback = ScriptedTransport(_challenge_response(), _ok_response())
    solved: list[str] = []

    transport = FallbackTransport(primary, fallback,
                                  challenge_solver=lambda url: solved.append(url) or True)
    response = transport.request("GET", "https://chatgpt.com/backend-api/me")

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert solved == ["https://chatgpt.com/backend-api/me"]
    assert transport.solve_count == 1
    assert fallback.calls == 2          # 被拦一次 + 过验证后重试一次


def test_raises_when_still_challenged_after_solving() -> None:
    primary = ScriptedTransport(CloudflareChallengeError("blocked"))
    fallback = ScriptedTransport(_challenge_response(), _challenge_response())
    transport = FallbackTransport(primary, fallback,
                                  challenge_solver=lambda _url: True)

    with pytest.raises(CloudflareChallengeError) as excinfo:
        transport.request("GET", "https://chatgpt.com/x")
    assert "仍被 Cloudflare 拦截" in str(excinfo.value)


def test_solver_declining_cancel_raises() -> None:
    transport = FallbackTransport(
        ScriptedTransport(CloudflareChallengeError("blocked")),
        ScriptedTransport(_challenge_response()),
        challenge_solver=lambda _url: False)

    with pytest.raises(CloudflareChallengeError):
        transport.request("GET", "https://chatgpt.com/x")
    assert transport.solve_count == 1


def test_solver_not_called_when_primary_succeeds() -> None:
    transport = FallbackTransport(
        ScriptedTransport(_ok_response()), ScriptedTransport(),
        challenge_solver=lambda _url: pytest.fail("不该调用 solver"))
    assert transport.request("GET", "https://chatgpt.com/x").status_code == 200


def test_solver_not_called_when_fallback_succeeds() -> None:
    transport = FallbackTransport(
        ScriptedTransport(CloudflareChallengeError("blocked")),
        ScriptedTransport(_ok_response()),
        challenge_solver=lambda _url: pytest.fail("不该调用 solver"))
    assert transport.request("GET", "https://chatgpt.com/x").status_code == 200


def test_challenge_message_differs_by_state() -> None:
    assert "请在里面完成验证后重试" in challenge_message("u", solved=False)
    assert "仍被 Cloudflare 拦截" in challenge_message("u", solved=True)


# --- 传输层：流式 --------------------------------------------------------


def test_stream_solves_then_retries_when_blocked_up_front() -> None:
    primary = ScriptedTransport(CloudflareChallengeError("blocked"))
    fallback = ScriptedTransport(_challenge_response(), _ok_response(b"data: hi"))
    transport = FallbackTransport(primary, fallback,
                                  challenge_solver=lambda _url: True)

    lines = list(transport.stream_lines("POST", "https://chatgpt.com/f/conversation"))
    assert lines == ["data: hi"]
    assert transport.solve_count == 1


def test_stream_never_retries_after_data_already_yielded() -> None:
    """已开始产出就绝不能重发 —— 那会重复发消息、重复消耗一次生图额度。"""

    class HalfThenFail:
        def request(self, *_a, **_kw):
            raise AssertionError("不该走到这里")

        def stream_lines(self, *_a, **_kw):
            yield "data: partial"
            raise CloudflareChallengeError("mid-stream")

    transport = FallbackTransport(
        HalfThenFail(), ScriptedTransport(_ok_response()),
        challenge_solver=lambda _url: pytest.fail("已产出就不该去求解"))

    with pytest.raises(CloudflareChallengeError):
        list(transport.stream_lines("POST", "https://chatgpt.com/f/conversation"))
    assert transport.solve_count == 0


def test_stream_does_not_fall_back_after_partial_output() -> None:
    """内层也要挡住：primary 产出后再失败，不能退回 fallback 重发。"""

    class HalfThenFail:
        def request(self, *_a, **_kw):
            raise AssertionError

        def stream_lines(self, *_a, **_kw):
            yield "data: partial"
            raise CloudflareChallengeError("mid-stream")

    fallback = ScriptedTransport(_ok_response(b"data: duplicated"))
    transport = FallbackTransport(HalfThenFail(), fallback,
                                  challenge_solver=lambda _url: True)

    with pytest.raises(CloudflareChallengeError):
        list(transport.stream_lines("POST", "https://chatgpt.com/x"))
    assert fallback.calls == 0


# --- Client：求解流程 ----------------------------------------------------


class FakeBrowser:
    def __init__(self, cookies: list[dict] | None = None) -> None:
        self.started = False
        self.navigated: list[str] = []
        self.close_count = 0
        self._cookies = cookies if cookies is not None else [
            {"name": "cf_clearance", "value": "fresh"},
            {"name": "__Secure-next-auth.session-token.0", "value": "s"},
            {"name": "oai-did", "value": "did-new"},
        ]

    def start(self) -> None:
        self.started = True

    def close(self) -> None:
        self.close_count += 1
        self.started = False

    def open_for_challenge(self, url: str) -> None:
        if not self.started:
            raise AssertionError("导航时浏览器未启动")
        self.navigated.append(url)

    def read_cookies(self) -> list[dict]:
        if not self.started:
            raise AssertionError("读 Cookie 时浏览器未启动")
        return list(self._cookies)

    def fetch_in_context(self, **_kw) -> dict:
        return {"status": 200, "headers": {}, "body": "{}"}


def _client(browser: FakeBrowser, prompt, logs: list[str],
            tmp_path: Path) -> Client:
    credentials = Credentials(
        cookies={"cf_clearance": "stale"},
        bearer="b", account_id="a", device_id="did-old",
        sentinel=SentinelTokens(chat_requirements="cr", proof="pf",
                                turnstile="ts", issued_at=time.time()),
        captured_at=time.time())
    settings = Settings(credentials_path=tmp_path / "c.json",
                        profile_dir=tmp_path / "p", debug_dir=tmp_path / "d")
    return Client(credentials, settings=settings, browser=browser,
                  challenge_prompt=prompt, log=logs.append)


def test_solve_challenge_navigates_prompts_and_reloads_cookies(tmp_path: Path,
                                                               logs) -> None:
    browser = FakeBrowser()
    asked: list[str] = []
    client = _client(browser, lambda url: asked.append(url) or True, logs, tmp_path)

    assert client._solve_challenge("https://chatgpt.com/backend-api/me") is True

    assert browser.navigated == ["https://chatgpt.com/backend-api/me"]
    assert asked == ["https://chatgpt.com/backend-api/me"]
    # 关键：cf_clearance 是在浏览器里刷新的，必须重读
    assert client.credentials.cookies["cf_clearance"] == "fresh"
    assert client.credentials.device_id == "did-new"
    assert any("重读" in line for line in logs)


def test_solve_challenge_returns_false_without_prompt(tmp_path: Path, logs) -> None:
    browser = FakeBrowser()
    client = _client(browser, None, logs, tmp_path)
    assert client._solve_challenge("https://chatgpt.com/x") is False
    assert browser.navigated == []          # 不该白开浏览器


def test_solve_challenge_returns_false_when_user_cancels(tmp_path: Path,
                                                         logs) -> None:
    browser = FakeBrowser()
    client = _client(browser, lambda _url: False, logs, tmp_path)

    assert client._solve_challenge("https://chatgpt.com/x") is False
    # 用户取消 → 不重读 Cookie（免得把"其实没刷新"的状态当成刷新了）
    assert client.credentials.cookies["cf_clearance"] == "stale"


def test_solve_challenge_survives_navigation_failure(tmp_path: Path, logs) -> None:
    class BrokenBrowser(FakeBrowser):
        def open_for_challenge(self, url: str) -> None:
            raise RuntimeError("导航炸了")

    client = _client(BrokenBrowser(), lambda _url: True, logs, tmp_path)
    assert client._solve_challenge("https://chatgpt.com/x") is False
    assert any("无法为人工验证打开浏览器" in line for line in logs)


def test_transport_built_by_client_wires_the_solver(tmp_path: Path, logs) -> None:
    browser = FakeBrowser()
    client = _client(browser, lambda _url: True, logs, tmp_path)
    transport = client._build_transport()
    assert transport.challenge_solver == client._solve_challenge


def test_end_to_end_blocked_then_solved_then_succeeds(tmp_path: Path, logs) -> None:
    """把传输层与 Client 串起来跑一遍完整场景。"""
    browser = FakeBrowser()
    client = _client(browser, lambda _url: True, logs, tmp_path)

    primary = ScriptedTransport(CloudflareChallengeError("blocked"))
    fallback = ScriptedTransport(_challenge_response(), _ok_response())
    transport = FallbackTransport(primary, fallback,
                                  challenge_solver=client._solve_challenge)

    response = transport.request("GET", "https://chatgpt.com/backend-api/me")

    assert response.status_code == 200
    assert browser.navigated == ["https://chatgpt.com/backend-api/me"]
    assert client.credentials.cookies["cf_clearance"] == "fresh"
