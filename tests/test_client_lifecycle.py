"""Client 的浏览器生命周期。

这个文件的存在理由是一个真实 bug：``Client.login()`` 会在登录完成后关闭浏览器，
但 ``refresh_sentinel()`` 这条惰性路径**只开不关** —— 用户会发现令牌过期刷新后
浏览器窗口一直挂在那里。

修的时候还牵出一个更隐蔽的问题：``_build_transport()`` 原本在浏览器关闭时
**直接跳过 Cloudflare 回退**。所以"刷新完就关"如果只改一行，会静默丢掉回退能力
（不报错，直到真被 CF 拦住才发现）。因此这里同时钉住两件事：

1. 用完浏览器要关；
2. 关掉之后回退**仍然可用**（会按需重开）。
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from cgpt.api.transport import FallbackTransport, TransportResponse
from cgpt.client import Client
from cgpt.config import Settings
from cgpt.errors import CloudflareChallengeError, NoImageProducedError
from cgpt.models import Credentials, SentinelTokens


class FakeBrowser:
    """记录 start/close 调用的假浏览器会话。"""

    def __init__(self, credentials: Credentials | None = None) -> None:
        self.started = False
        self.close_count = 0
        self.refresh_count = 0
        self.fetch_count = 0
        self._credentials = credentials or Credentials(
            cookies={"__Secure-next-auth.session-token.0": "x"},
            bearer="b",
            account_id="a",
            sentinel=SentinelTokens(chat_requirements="cr", proof="pf",
                                    turnstile="ts", issued_at=time.time()),
            captured_at=time.time(),
        )

    # --- BrowserSession 的接口子集 ---
    def start(self) -> None:
        self.started = True

    def close(self) -> None:
        self.close_count += 1
        self.started = False

    def refresh_credentials(self, **_kwargs) -> Credentials:
        self.refresh_count += 1
        if not self.started:
            raise AssertionError("refresh_credentials 被调用时浏览器未启动")
        return self._credentials

    def fetch_in_context(self, **_kwargs) -> dict:
        self.fetch_count += 1
        if not self.started:
            raise AssertionError("fetch_in_context 被调用时浏览器未启动")
        return {"status": 200, "headers": {}, "body": "{}"}


def _stale_credentials() -> Credentials:
    """哨兵令牌已过期（超过 480-60 秒余量）。"""
    return Credentials(
        cookies={"__Secure-next-auth.session-token.0": "x"},
        bearer="b",
        account_id="a",
        sentinel=SentinelTokens(chat_requirements="old", proof="old",
                                turnstile="old", issued_at=time.time() - 5000),
        captured_at=time.time(),
    )


@pytest.fixture
def logs() -> list[str]:
    return []


def _settings(tmp_path: Path) -> Settings:
    return Settings(credentials_path=tmp_path / "c.json",
                    profile_dir=tmp_path / "p",
                    debug_dir=tmp_path / "d")


def _client(browser: FakeBrowser, logs: list[str], tmp_path: Path) -> Client:
    """注入一个已存在的假会话。"""
    return Client(_stale_credentials(), settings=_settings(tmp_path),
                  browser=browser, log=logs.append)


def _client_without_browser(logs: list[str], tmp_path: Path) -> Client:
    """不注入会话，让 ``ensure_browser()`` 自己去创建（走工厂）。"""
    return Client(_stale_credentials(), settings=_settings(tmp_path),
                  log=logs.append)


@pytest.fixture
def browser_factory(monkeypatch) -> list[FakeBrowser]:
    """把 ``Client.ensure_browser`` 里 new 的 BrowserSession 换成假件。

    ``Client`` 是直接实例化 ``BrowserSession`` 的，没有注入点；测试里替换掉
    这个模块级符号，就能验证"关掉之后按需重开"这条路径而不用真开浏览器。
    返回的列表按创建顺序收集所有假会话。
    """
    created: list[FakeBrowser] = []

    def factory(*_args, **_kwargs) -> FakeBrowser:
        fake = FakeBrowser()
        created.append(fake)
        return fake

    monkeypatch.setattr("cgpt.client.BrowserSession", factory)
    return created


# --- 用完要关 ------------------------------------------------------------


def test_refresh_sentinel_closes_browser_when_done(tmp_path: Path, logs) -> None:
    """核心回归：刷新完不能把窗口留在那儿。"""
    browser = FakeBrowser()
    client = _client(browser, logs, tmp_path)

    client.refresh_sentinel()

    assert browser.refresh_count == 1
    assert browser.close_count == 1
    assert client._browser is None
    assert any("已关闭浏览器窗口" in line for line in logs)


def test_refresh_sentinel_closes_browser_even_on_failure(tmp_path: Path,
                                                         logs) -> None:
    """刷新失败也不能留孤儿窗口。"""
    browser = FakeBrowser()
    browser.refresh_credentials = lambda **_kw: (_ for _ in ()).throw(
        RuntimeError("抓取失败"))
    client = _client(browser, logs, tmp_path)

    with pytest.raises(RuntimeError):
        client.refresh_sentinel()

    assert browser.close_count == 1
    assert client._browser is None


def test_release_browser_is_idempotent(tmp_path: Path, logs) -> None:
    browser = FakeBrowser()
    client = _client(browser, logs, tmp_path)
    client.ensure_browser()
    client._release_browser()
    client._release_browser()
    assert browser.close_count == 1


def test_release_browser_logs_only_once(tmp_path: Path, logs) -> None:
    browser = FakeBrowser()
    client = _client(browser, logs, tmp_path)
    client.ensure_browser()
    client._release_browser()
    client._release_browser()
    assert sum("已关闭浏览器窗口" in line for line in logs) == 1


def test_ensure_sentinel_refreshes_stale_tokens_then_closes(tmp_path: Path,
                                                            logs) -> None:
    browser = FakeBrowser()
    client = _client(browser, logs, tmp_path)

    client.ensure_sentinel()

    assert browser.refresh_count == 1
    assert browser.close_count == 1
    assert client.credentials.sentinel is not None
    assert client.credentials.sentinel.chat_requirements == "cr"


def test_ensure_sentinel_does_not_touch_browser_when_fresh(tmp_path: Path,
                                                           logs) -> None:
    browser = FakeBrowser()
    fresh = Credentials(
        cookies={"__Secure-next-auth.session-token.0": "x"},
        sentinel=SentinelTokens(chat_requirements="cr", proof="pf",
                                turnstile="ts", issued_at=time.time()))
    client = Client(fresh, settings=_settings(tmp_path), browser=browser,
                    log=logs.append)

    client.ensure_sentinel()

    assert browser.refresh_count == 0
    assert browser.close_count == 0
    assert browser.started is False


def test_refresh_sentinel_picks_up_rotated_cookies_and_bearer(tmp_path: Path,
                                                              logs) -> None:
    browser = FakeBrowser()
    client = _client(browser, logs, tmp_path)
    client.credentials.bearer = None
    client.credentials.account_id = None

    client.refresh_sentinel()

    assert client.credentials.bearer == "b"
    assert client.credentials.account_id == "a"
    assert client.credentials.cookies["__Secure-next-auth.session-token.0"] == "x"


# --- 关掉之后回退仍然可用 ------------------------------------------------


def test_browser_fetch_starts_browser_on_demand(tmp_path: Path, logs) -> None:
    browser = FakeBrowser()
    client = _client(browser, logs, tmp_path)
    assert browser.started is False

    result = client._browser_fetch(method="GET", url="/x", headers={}, body=None)

    assert browser.started is True
    assert browser.fetch_count == 1
    assert result["status"] == 200


def test_transport_keeps_fallback_after_browser_closed(tmp_path: Path, logs) -> None:
    """这是那个隐蔽的回归点：浏览器关了，回退不能跟着消失。"""
    browser = FakeBrowser()
    client = _client(browser, logs, tmp_path)
    client.ensure_browser()
    client._release_browser()
    assert client._browser is None

    transport = client._build_transport()

    assert isinstance(transport, FallbackTransport)


def test_fallback_actually_works_after_browser_closed(tmp_path: Path, logs,
                                                      browser_factory) -> None:
    """端到端：主通道被 CF 拦 → 回退按需把浏览器重新拉起来 → 拿到结果。"""
    client = _client_without_browser(logs, tmp_path)
    client.ensure_browser()
    assert len(browser_factory) == 1
    client._release_browser()
    assert client._browser is None

    transport = client._build_transport()

    class _Blocked:
        def request(self, *_a, **_kw):
            raise CloudflareChallengeError("blocked")

        def stream_lines(self, *_a, **_kw):
            raise CloudflareChallengeError("blocked")

    transport.primary = _Blocked()
    response = transport.request("GET", "https://chatgpt.com/backend-api/me")

    assert len(browser_factory) == 2, "回退应当重新创建了一个会话"
    reopened = browser_factory[-1]
    assert reopened.started is True
    assert reopened.fetch_count == 1
    assert response.status_code == 200
    assert transport.fallback_count == 1


def test_fallback_reports_why_browser_appeared(tmp_path: Path, logs,
                                               browser_factory) -> None:
    client = _client_without_browser(logs, tmp_path)
    client.ensure_browser()
    client._release_browser()
    logs.clear()                      # 只看回退这一步产生的日志

    transport = client._build_transport()

    class _Blocked:
        def request(self, *_a, **_kw):
            raise CloudflareChallengeError("blocked")

    transport.primary = _Blocked()
    transport.request("GET", "https://chatgpt.com/x")

    joined = "\n".join(logs)
    assert "启动浏览器" in joined
    assert "被 Cloudflare 拦截" in joined


# --- 与生图编排的配合 ----------------------------------------------------


def test_client_generate_image_refreshes_then_closes_before_sending(
        tmp_path: Path, logs) -> None:
    """生图前若令牌过期：先刷新、关浏览器，**再**发业务请求。

    钉的是顺序：业务请求发出时浏览器必须已经关了（否则用户又会看到
    "刷新完了窗口还挂在那儿"）。
    """
    import json as _json

    browser = FakeBrowser()
    client = _client(browser, logs, tmp_path)

    browser_closed_when_sent: list[bool] = []

    class _Recorder:
        def _payload(self, url: str) -> dict:
            if "accounts/check" in url:
                return {"accounts": {"default": {
                    "account": {"account_id": "a", "plan_type": "free"},
                    "features": ["image_gen_tool_enabled"]}}}
            if "conversation/init" in url:
                return {"limits_progress": []}
            if "files/download" in url:
                return {"download_url": "https://chatgpt.com/e?sig=x"}
            return {}

        def request(self, method, url, *, headers=None, json=None, data=None,
                    timeout=None):
            browser_closed_when_sent.append(client._browser is None)
            return TransportResponse(
                status_code=200,
                content=_json.dumps(self._payload(url)).encode())

        def stream_lines(self, method, url, *, headers=None, json=None,
                         timeout=None):
            browser_closed_when_sent.append(client._browser is None)
            yield 'data: {"p":"","o":"add","v":{"conversation_id":"cid"}}'
            yield ""
            yield "data: [DONE]"
            yield ""

    client._transport = _Recorder()
    client._web = None

    # 流里没有图片资产 → 最终抛 NoImageProducedError；这里只关心顺序
    with pytest.raises(NoImageProducedError):
        client.generate_image("画个地球", out=tmp_path / "a.png",
                              timeout=0.05, poll_interval=0.01)

    assert browser.refresh_count == 1
    assert browser.close_count == 1
    assert browser_closed_when_sent, "应当有业务请求被记录"
    assert all(browser_closed_when_sent), "业务请求发出时浏览器应当已经关闭"
