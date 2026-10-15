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

    def __init__(self, credentials: Credentials | None = None, *,
                 minimized: bool = False, **_kwargs) -> None:
        self.started = False
        self.close_count = 0
        self.refresh_count = 0
        self.fetch_count = 0
        #: 与 BrowserSession 的接口保持一致（``Client.ensure_browser`` 会读它）
        self.minimized = minimized
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


# --- 后台开浏览器时要最小化（别抢焦点） ----------------------------------


def test_background_open_is_minimized(tmp_path: Path, logs,
                                      patch_browser_session) -> None:
    """刷新令牌这类后台用途：窗口最小化，不抢用户焦点。"""
    created = patch_browser_session(FakeBrowser)
    client = _client_without_browser(logs, tmp_path)

    client.ensure_browser()

    assert created and created[0].ctor_kwargs.get("minimized") is True


def test_explicit_visible_open_is_not_minimized(tmp_path: Path, logs,
                                                patch_browser_session) -> None:
    created = patch_browser_session(FakeBrowser)
    client = _client_without_browser(logs, tmp_path)

    client.ensure_browser(minimized=False)

    assert created and created[0].ctor_kwargs.get("minimized") is False


def test_challenge_solver_asks_for_a_visible_window(tmp_path: Path, logs,
                                                    patch_browser_session) -> None:
    """要用户点验证时必须让他看见 —— 最小化了就没法点。"""
    created = patch_browser_session(FakeBrowser)
    client = _client_without_browser(logs, tmp_path)
    client.challenge_prompt = lambda _url: True

    client._solve_challenge("https://chatgpt.com/x")

    assert created, "应当开了浏览器"
    assert all(b.ctor_kwargs.get("minimized") is False for b in created)


def test_visible_need_replaces_a_minimized_session(tmp_path: Path, logs,
                                                   patch_browser_session) -> None:
    """手上是最小化的，但现在要用户看见 → 换一个可见的（而不是凑合用）。"""
    created = patch_browser_session(FakeBrowser)
    client = _client_without_browser(logs, tmp_path)

    client.ensure_browser()                      # 最小化的
    assert created[0].minimized is True
    client.ensure_browser(minimized=False)       # 换成可见的

    assert len(created) == 2, "应当重建了一个会话"
    assert created[0].close_count == 1, "旧的应当被关掉"
    assert created[1].minimized is False
    assert any("重新以可见方式打开浏览器" in line for line in logs)


def test_minimized_need_reuses_a_visible_session(tmp_path: Path, logs,
                                                 patch_browser_session) -> None:
    """反过来不必重建：可见的会话拿来当后台用也没问题。"""
    created = patch_browser_session(FakeBrowser)
    client = _client_without_browser(logs, tmp_path)

    client.ensure_browser(minimized=False)
    client.ensure_browser(minimized=True)

    assert len(created) == 1, "可见的会话可以继续用，不该重建"


# --- 最小化本身的边界（Win32 那部分只在 Windows 生效） -------------------


def test_minimize_is_a_noop_off_windows(monkeypatch) -> None:
    from cgpt.auth import browser as browser_module

    monkeypatch.setattr(browser_module.sys, "platform", "linux")
    session = browser_module.BrowserSession(Settings())
    assert session._minimize_own_window(timeout=0.1) is False


def test_minimize_stops_once_the_session_is_closed(monkeypatch) -> None:
    """已关闭的会话**不能**再去找进程。

    否则它会按 profile 路径找到**下一个**会话的窗口并把它最小化掉 ——
    而下一个会话很可能正需要用户看见（登录 / 人工过人机验证）。
    """
    from cgpt.auth import browser as browser_module

    monkeypatch.setattr(browser_module.sys, "platform", "win32")
    lookups: list[object] = []
    monkeypatch.setattr(browser_module, "_win32_pids_using_profile",
                        lambda path: lookups.append(path) or {1234})

    session = browser_module.BrowserSession(Settings())
    session._closed = True

    assert session._minimize_own_window(timeout=0.5) is False
    assert lookups == [], "已关闭就不该再去查进程"


def test_pid_lookup_survives_subprocess_failure(monkeypatch) -> None:
    """定位进程失败不能把刷新带崩 —— 返回空集合即可。"""
    from cgpt.auth import browser as browser_module

    def boom(*_args, **_kwargs):
        raise OSError("powershell 不见了")

    monkeypatch.setattr(browser_module.subprocess, "run", boom)
    assert browser_module._win32_pids_using_profile(Path(".")) == set()


def test_pid_lookup_hides_the_console_window(monkeypatch) -> None:
    """起 PowerShell 时不能让控制台窗口闪出来 —— 那比抢焦点还烦。"""
    from cgpt.auth import browser as browser_module

    seen: dict = {}

    class Result:
        stdout = "1234\n5678\nnot-a-pid\n"

    def fake_run(cmd, **kwargs):
        seen.update(kwargs)
        seen["cmd"] = cmd
        return Result()

    monkeypatch.setattr(browser_module.subprocess, "run", fake_run)
    pids = browser_module._win32_pids_using_profile(Path("C:/x/profile"))

    assert pids == {1234, 5678}, "非数字行要忽略"
    assert seen.get("creationflags") == browser_module.CREATE_NO_WINDOW
    # 用 resolve() 之后的形式比 —— Windows 上分隔符会变成反斜杠
    marker = str(Path("C:/x/profile").resolve())
    assert marker in seen["cmd"][-1], "查询要按 profile 路径精确匹配"


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
