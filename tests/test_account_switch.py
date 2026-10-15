"""换账号登录必须真的换过去。

用户报的现象：profile 里已有账号 A 时，填账号 B 点「登录」，**还在用 A**，
而且不报任何错。

根因在 ``BrowserSession.login()``：

    if self._is_logged_in():
        self.log("持久化 profile 里已有有效会话，跳过账号密码步骤")
        return self.refresh_credentials()      # ← 拿的是 A 的凭据

持久化 profile 会记住上一个账号，而 ``_is_logged_in()`` 只看**有没有**
会话 Cookie、不看它是谁的 —— 于是新账号被无声地忽略。

修法：登录前先问清楚"当前会话是谁"，不是这个账号就**先退出登录**；
问不出来时**不能赌**，一律走完整登录流程（宁可多走一遍，也不能静默用旧账号）。
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from cgpt.auth import browser as browser_module
from cgpt.auth.browser import (
    BrowserSession,
    _is_kept_on_sign_out,
    _mask_email,
)
from cgpt.config import Settings

# --- 登出时保留哪些 Cookie -------------------------------------------------


@pytest.mark.parametrize("name", [
    "cf_clearance", "__cf_bm", "__cflb", "_cfuvid", "oai-did",
])
def test_cloudflare_and_device_cookies_survive_sign_out(name: str) -> None:
    """清掉这些会平白再撞一次 Cloudflare，甚至被当成新设备。"""
    assert _is_kept_on_sign_out(name) is True


@pytest.mark.parametrize("name", [
    "__Secure-next-auth.session-token.0",
    "__Secure-next-auth.session-token.1",
    "__Host-next-auth.csrf-token",
    "__Secure-next-auth.callback-url",
    "oai-client-auth-info",
    "oai-client-session-epoch",
    "_account",
    "__Host-unified_session_manifest",
    "oai-sc",
])
def test_account_cookies_are_cleared_on_sign_out(name: str) -> None:
    """认证相关的必须清掉 —— 漏一个就会静默地继续用旧账号。"""
    assert _is_kept_on_sign_out(name) is False


def test_unknown_cookies_are_cleared_by_default() -> None:
    """默认清掉，包括我们不认识的新 Cookie。

    理由是不对称的：漏掉一个认证 Cookie 的后果是**静默用旧账号**（就是刚修的
    这个 bug），而多清一个最多是让服务端重发一次。
    """
    assert _is_kept_on_sign_out("__some-brand-new-auth-cookie") is False


# --- 邮箱掩码（日志里不写全） ---------------------------------------------


@pytest.mark.parametrize("email,expected", [
    ("someone@example.com", "so***@example.com"),
    ("abc@x.io", "ab***@x.io"),
    ("ab@x.io", "a***@x.io"),      # 只有两个字符时只留一个
    ("a@x.io", "a***@x.io"),
])
def test_mask_email(email: str, expected: str) -> None:
    assert _mask_email(email) == expected


def test_mask_email_handles_garbage() -> None:
    assert _mask_email("not-an-email") == "***"


# --- login 的决策逻辑 -----------------------------------------------------


class FakePage:
    """够用的假页面：记录 goto，按脚本回答"当前是谁"。"""

    def __init__(self, current_email: str | None = None) -> None:
        self.current_email = current_email
        self.goto_calls: list[str] = []
        self.url = "https://chatgpt.com/"
        self.brought_to_front = 0
        self._interstitial = False

    def goto(self, url, **_kwargs):
        self.goto_calls.append(url)
        self.url = url

    def evaluate(self, script, *_args):
        if "backend-api/me" in script:
            return self.current_email
        # 必须是 _cloudflare_state 认得的**状态字符串**。早先这里返回布尔值，
        # 于是 `== "ready"` 永不成立，_goto 里的等待一路空转到 300 秒超时 ——
        # 把本该 1 秒跑完的测试拖成了 25 分钟。
        return "challenge" if self._interstitial else "ready"

    def wait_for_timeout(self, _ms):
        pass

    def bring_to_front(self):
        self.brought_to_front += 1


def _session(page: FakePage, *, cookies: list[str] | None = None,
             prompt=None) -> BrowserSession:
    session = BrowserSession(Settings(), challenge_prompt=prompt,
                             log=lambda _m: None)
    session._page = page
    session._context = object()          # 让 close() 之类不炸
    names = cookies if cookies is not None else [
        "__Secure-next-auth.session-token.0", "cf_clearance", "oai-did"]
    session.read_cookies = lambda: [{"name": n, "value": "v"} for n in names]
    return session


def test_login_skips_when_session_is_already_this_account(monkeypatch) -> None:
    """同一个账号才允许走捷径（避免反复登录触发风控）。"""
    page = FakePage(current_email="user@example.com")
    session = _session(page)
    signed_out: list[bool] = []
    monkeypatch.setattr(session, "_sign_out", lambda: signed_out.append(True))
    monkeypatch.setattr(session, "refresh_credentials", lambda: "CREDS")

    result = session.login("user@example.com", "pw", "totp")

    assert result == "CREDS"
    assert signed_out == [], "同账号不该退出登录"


def test_login_skips_case_insensitively(monkeypatch) -> None:
    page = FakePage(current_email="User@Example.COM")
    session = _session(page)
    monkeypatch.setattr(session, "_sign_out", lambda: pytest.fail("不该退出"))
    monkeypatch.setattr(session, "refresh_credentials", lambda: "CREDS")

    assert session.login("user@example.com", "pw", "totp") == "CREDS"


def test_login_signs_out_when_a_different_account_is_logged_in(
        monkeypatch) -> None:
    """**这就是用户报的那个 bug**：必须换成新账号，不能继续用旧的。"""
    page = FakePage(current_email="old@example.com")
    session = _session(page)
    signed_out: list[bool] = []
    monkeypatch.setattr(session, "_sign_out", lambda: signed_out.append(True))
    submitted: list[str] = []
    monkeypatch.setattr(session, "_submit_email", submitted.append)
    monkeypatch.setattr(session, "_submit_password", lambda _p: None)
    monkeypatch.setattr(session, "_submit_totp", lambda _t: None)
    monkeypatch.setattr(session, "_wait_for_session", lambda: None)
    monkeypatch.setattr(session, "refresh_credentials", lambda: "CREDS")

    result = session.login("new@example.com", "pw", "totp")

    assert signed_out == [True], "换了账号就必须先退出登录"
    assert submitted == ["new@example.com"], "必须真的走一遍账密流程"
    assert result == "CREDS"


def test_login_signs_out_when_the_current_account_is_unknown(
        monkeypatch) -> None:
    """问不出当前是谁时**不能赌** —— 这正是原来那个 bug 的成因。"""
    page = FakePage(current_email=None)      # 有会话 Cookie，但问不出账号
    session = _session(page)
    signed_out: list[bool] = []
    monkeypatch.setattr(session, "_sign_out", lambda: signed_out.append(True))
    monkeypatch.setattr(session, "_submit_email", lambda _e: None)
    monkeypatch.setattr(session, "_submit_password", lambda _p: None)
    monkeypatch.setattr(session, "_submit_totp", lambda _t: None)
    monkeypatch.setattr(session, "_wait_for_session", lambda: None)
    monkeypatch.setattr(session, "refresh_credentials", lambda: "CREDS")

    session.login("new@example.com", "pw", "totp")

    assert signed_out == [True], "问不出来就该走完整流程，而不是复用旧会话"


def test_login_goes_straight_through_when_not_logged_in(monkeypatch) -> None:
    page = FakePage(current_email="old@example.com")
    session = _session(page, cookies=["cf_clearance"])   # 没有会话 Cookie
    monkeypatch.setattr(session, "_sign_out", lambda: pytest.fail("没会话不该退出"))
    monkeypatch.setattr(session, "_submit_email", lambda _e: None)
    monkeypatch.setattr(session, "_submit_password", lambda _p: None)
    monkeypatch.setattr(session, "_submit_totp", lambda _t: None)
    monkeypatch.setattr(session, "_wait_for_session", lambda: None)
    monkeypatch.setattr(session, "refresh_credentials", lambda: "CREDS")

    assert session.login("new@example.com", "pw", "totp") == "CREDS"


def test_sign_out_clears_only_the_right_cookies() -> None:
    cleared: list[str] = []

    class Context:
        def clear_cookies(self, *, name=None, **_kw):
            cleared.append(name)

    page = FakePage()
    session = _session(page, cookies=[
        "cf_clearance", "oai-did", "__cf_bm",
        "__Secure-next-auth.session-token.0",
        "__Secure-next-auth.session-token.1",
        "__Host-next-auth.csrf-token",
    ])
    session._context = Context()
    session._goto = lambda *_a, **_kw: None

    count = session._sign_out()

    assert sorted(cleared) == sorted([
        "__Secure-next-auth.session-token.0",
        "__Secure-next-auth.session-token.1",
        "__Host-next-auth.csrf-token",
    ])
    assert count == 3
    assert "cf_clearance" not in cleared
    assert "oai-did" not in cleared


# --- Cloudflare 拦截页：需要人点，不能傻等 ---------------------------------


def test_interstitial_detected_by_title(monkeypatch) -> None:
    page = FakePage()
    session = _session(page)
    session._page = page
    page._interstitial = True
    assert session._is_cloudflare_interstitial() is True


def test_wait_returns_immediately_when_not_intercepted() -> None:
    page = FakePage()
    session = _session(page)
    assert session._wait_for_cloudflare(timeout_s=0.1) is True


def test_wait_asks_the_user_instead_of_just_waiting() -> None:
    """这个验证**需要人点**，不会自己过去 —— 必须把窗口提到前台并问用户。"""
    page = FakePage()
    page._interstitial = True
    asked: list[str] = []
    session = _session(page, prompt=lambda url: asked.append(url) or True)

    # 问过之后仍然拦截 → 轮询到超时，如实返回 False
    assert session._wait_for_cloudflare(timeout_s=0.3) is False
    assert asked == ["https://chatgpt.com/"], "必须问用户，而不是干等"
    assert page.brought_to_front >= 1, "得把窗口提到前台，否则用户点不到"


def test_wait_returns_false_when_user_gives_up() -> None:
    page = FakePage()
    page._interstitial = True
    session = _session(page, prompt=lambda _url: False)
    assert session._wait_for_cloudflare(timeout_s=5.0) is False


def test_wait_succeeds_once_the_interstitial_clears() -> None:
    page = FakePage()
    page._interstitial = True
    session = _session(page, prompt=lambda _url: True)

    calls = {"n": 0}
    original = page.evaluate

    def evaluate(script, *args):
        if "backend-api/me" in script:
            return original(script, *args)
        calls["n"] += 1
        # 前两次还是挑战页，第三次开始已经是正常页面
        return "challenge" if calls["n"] < 3 else "ready"

    page.evaluate = evaluate
    assert session._wait_for_cloudflare(timeout_s=5.0) is True


def test_cloudflare_state_rejects_unexpected_values() -> None:
    """假件（或将来页面改版）返回意料之外的值时，按"还没好"处理。

    不能因为拿到一个不认得的值就当成"已通过" —— 那会让流程冲进一个还在
    加载的页面；也不能默默等到超时而不留痕迹。
    """
    page = FakePage()
    session = _session(page)
    for bogus in (True, False, None, 0, "READY", ""):
        page.evaluate = lambda _script, _bogus=bogus, **_kw: _bogus
        assert session._cloudflare_state() == "loading", f"{bogus!r} 应被拒"


def test_cloudflare_state_accepts_the_three_real_values() -> None:
    page = FakePage()
    session = _session(page)
    for value in ("challenge", "loading", "ready"):
        page.evaluate = lambda _script, _value=value, **_kw: _value
        assert session._cloudflare_state() == value


def test_wait_without_prompt_does_not_pretend_to_succeed() -> None:
    """纯库调用（没人可问）时只能等外部有人点，超时就如实报错。"""
    page = FakePage()
    page._interstitial = True
    session = _session(page, prompt=None)
    assert session._wait_for_cloudflare(timeout_s=0.3) is False


# --- 导航默认要等 CF -------------------------------------------------------


def test_goto_waits_for_cloudflare_by_default(monkeypatch) -> None:
    page = FakePage()
    session = _session(page)
    waited: list[bool] = []
    monkeypatch.setattr(session, "_wait_for_cloudflare",
                        lambda **_kw: waited.append(True))

    session._goto("https://chatgpt.com/")

    assert waited == [True]


def test_open_for_challenge_does_not_wait_for_cloudflare(monkeypatch) -> None:
    """用户就是被叫来点这个拦截页的，等它反而挡住了。"""
    page = FakePage()
    session = _session(page)
    waited: list[bool] = []
    monkeypatch.setattr(session, "_wait_for_cloudflare",
                        lambda **_kw: waited.append(True))
    monkeypatch.setattr(session, "log", lambda _m: None)

    session.open_for_challenge("https://chatgpt.com/x")

    assert waited == [], "这里不该等 —— 拦截页正是要给用户看的"


def test_module_exports_the_helpers_we_test() -> None:
    assert callable(browser_module._is_kept_on_sign_out)
    assert Path(browser_module.__file__).exists()


# --- 邮箱提交的"提交态"不能被误判成失败 -----------------------------------


class StatePage(FakePage):
    """按脚本回答"邮箱步骤现在什么状态"的假页面。"""

    def __init__(self, states: list[str]) -> None:
        super().__init__()
        self.states = list(states)
        self.calls = 0

    def wait_for_timeout(self, _ms):
        pass


def _state_session(page: StatePage) -> BrowserSession:
    """让 ``_email_step_state`` 按脚本依次回答，用完就一直重复最后一个。"""
    session = _session(page)

    def state() -> str:
        index = min(page.calls, len(page.states) - 1)
        page.calls += 1
        return page.states[index]

    session._email_step_state = state
    return session


def test_wait_for_email_accepted_when_it_advances() -> None:
    page = StatePage(["submitting", "submitting", "advanced"])
    session = _state_session(page)
    assert session._wait_for_email_accepted(timeout_s=5.0) is True


def test_wait_for_email_tolerates_a_long_submitting_state() -> None:
    """**这就是"卡住"的成因**：提交态会持续几秒，不能当成失败。"""
    page = StatePage(["submitting"] * 20 + ["advanced"])
    session = _state_session(page)
    assert session._wait_for_email_accepted(timeout_s=30.0) is True


def test_wait_for_email_reports_failure_when_form_comes_back() -> None:
    """先提交态、又回到可编辑态 = 页面把表单还回来了，这次真没成。"""
    page = StatePage(["submitting", "submitting", "idle", "idle"])
    session = _state_session(page)
    assert session._wait_for_email_accepted(timeout_s=5.0) is False


def test_wait_for_email_times_out_when_never_submitting() -> None:
    page = StatePage(["idle"])
    session = _state_session(page)
    assert session._wait_for_email_accepted(timeout_s=0.3) is False


def test_email_step_state_recognises_advanced_when_logged_in() -> None:
    page = FakePage()
    session = _session(page)
    session._is_logged_in = lambda: True
    assert session._email_step_state() == "advanced"


def test_email_step_state_recognises_advanced_when_email_field_gone(
        monkeypatch) -> None:
    page = FakePage()
    session = _session(page)
    monkeypatch.setattr(session, "_is_logged_in", lambda: False)
    monkeypatch.setattr(session, "_find_visible", lambda *_a, **_kw: None)
    assert session._email_step_state() == "advanced"


def test_email_step_state_reports_submitting_for_a_disabled_field(
        monkeypatch) -> None:
    class Disabled:
        def is_enabled(self):
            return False

    page = FakePage()
    session = _session(page)
    monkeypatch.setattr(session, "_is_logged_in", lambda: False)

    calls = {"n": 0}

    def find(selectors, **_kw):
        calls["n"] += 1
        return Disabled() if calls["n"] == 3 else None   # 第 3 次是找邮箱框

    monkeypatch.setattr(session, "_find_visible", find)
    assert session._email_step_state() == "submitting"


def test_email_step_state_reports_idle_for_an_enabled_field(monkeypatch) -> None:
    class Enabled:
        def is_enabled(self):
            return True

    page = FakePage()
    session = _session(page)
    monkeypatch.setattr(session, "_is_logged_in", lambda: False)

    calls = {"n": 0}

    def find(selectors, **_kw):
        calls["n"] += 1
        return Enabled() if calls["n"] == 3 else None

    monkeypatch.setattr(session, "_find_visible", find)
    assert session._email_step_state() == "idle"


def test_email_step_still_showing_only_when_idle() -> None:
    page = FakePage()
    session = _session(page)
    for state, expected in (("idle", True), ("submitting", False),
                            ("advanced", False)):
        session._email_step_state = lambda s=state: s
        assert session._email_step_still_showing() is expected


# --- 账号身份必须和 Cookie 成套更新 ---------------------------------------


class RefreshBrowser:
    """refresh_credentials 返回指定账号身份的假浏览器。"""

    minimized = False

    def __init__(self, account_id: str | None, bearer: str | None) -> None:
        self._account_id = account_id
        self._bearer = bearer
        self.close_count = 0

    def start(self) -> None:
        pass

    def close(self) -> None:
        self.close_count += 1

    def refresh_credentials(self, **_kwargs):
        from cgpt.models import Credentials, SentinelTokens
        return Credentials(
            cookies={"__Secure-next-auth.session-token.0": "new"},
            bearer=self._bearer, account_id=self._account_id,
            sentinel=SentinelTokens(chat_requirements="cr", proof="pf",
                                    turnstile="ts", issued_at=time.time()))


def _refresh_client(browser, tmp_path: Path, *, account_id: str,
                    bearer: str | None):
    from cgpt.client import Client
    from cgpt.models import Credentials, SentinelTokens
    credentials = Credentials(
        cookies={"__Secure-next-auth.session-token.0": "old"},
        bearer=bearer, account_id=account_id,
        sentinel=SentinelTokens(chat_requirements="old", proof="old",
                                turnstile="old", issued_at=0.0))
    logs: list[str] = []
    client = Client(credentials, settings=Settings(
        credentials_path=tmp_path / "c.json", profile_dir=tmp_path / "p",
        debug_dir=tmp_path / "d"), browser=browser, log=logs.append)
    return client, logs


def test_refresh_adopts_a_changed_account_id(tmp_path: Path) -> None:
    """**这是真实风险**：account_id 会被当成 chatgpt-account-id 发出去。

    如果 Cookie 换成了新账号、account_id 还留着旧的，请求就打到错误的账号上。
    """
    browser = RefreshBrowser("account-BBBBBBBB", "bearer-B")
    client, logs = _refresh_client(browser, tmp_path,
                                   account_id="account-AAAAAAAA", bearer="bearer-A")

    client.refresh_sentinel()

    assert client.credentials.account_id == "account-BBBBBBBB"
    assert client.credentials.bearer == "bearer-B", "bearer 也是绑账号的"
    assert any("另一个账号" in line for line in logs), "换账号要说出来"


def test_refresh_keeps_account_when_unchanged(tmp_path: Path) -> None:
    browser = RefreshBrowser("account-AAAAAAAA", "bearer-A")
    client, logs = _refresh_client(browser, tmp_path,
                                   account_id="account-AAAAAAAA", bearer="bearer-A")

    client.refresh_sentinel()

    assert client.credentials.account_id == "account-AAAAAAAA"
    assert client.credentials.bearer == "bearer-A"
    assert not any("另一个账号" in line for line in logs)


def test_refresh_fills_in_a_missing_account_id(tmp_path: Path) -> None:
    browser = RefreshBrowser("account-AAAAAAAA", "bearer-A")
    client, logs = _refresh_client(browser, tmp_path, account_id="", bearer=None)

    client.refresh_sentinel()

    assert client.credentials.account_id == "account-AAAAAAAA"
    assert client.credentials.bearer == "bearer-A"


def test_refresh_keeps_bearer_when_browser_has_none(tmp_path: Path) -> None:
    """浏览器这轮没抓到 bearer 时，不能把手上好的那个抹掉。"""
    browser = RefreshBrowser("account-AAAAAAAA", None)
    client, _ = _refresh_client(browser, tmp_path,
                                account_id="account-AAAAAAAA", bearer="bearer-A")

    client.refresh_sentinel()

    assert client.credentials.bearer == "bearer-A"
