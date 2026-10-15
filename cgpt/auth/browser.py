"""阶段 A：真实浏览器登录 + 凭据抓取。

这是整条链路唯一必须用浏览器的地方，原因有两条硬约束（docs/01 §4.3、§4.8.1）：

1. ``cf_clearance`` 带 ``Partitioned``（CHIPS）属性，按顶层站点分区绑定，
   而且 Cloudflare 会同时校验 TLS/JA3 与 HTTP/2 指纹 —— 纯脚本过不去；
2. ``t`` / ``turnstile`` 的 XOR 密钥随未解开的 ``dx`` 下发，**无法自行伪造**，
   所以对话准入令牌只能由真实页面的 SDK 产出。

凭据是"捡"来的，不是"造"来的：监听应用自己的网络流量，把服务端**实际接受**的
那一份 ``Authorization`` / ``chatgpt-account-id`` / 三条哨兵头读出来。
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from cgpt.auth.totp import seconds_remaining, totp_with_skew
from cgpt.config import Settings
from cgpt.errors import LoginBlockedError, TotpRejectedError
from cgpt.models import Credentials, SentinelTokens

LOGIN_URL = "https://chatgpt.com/auth/login"
HOME_URL = "https://chatgpt.com/"
AUTH_HOST = "auth.openai.com"

#: 会话 Cookie 的前缀（NextAuth v5，超过 4 KB 会分片成 .0/.1）
SESSION_COOKIE_PREFIX = "__Secure-next-auth.session-token"

#: 邮箱输入框的候选选择器（登录页改版频繁，多备几个）
EMAIL_SELECTORS = (
    "input#email-input",
    "input[name='email']",
    "input[type='email']",
    "input[autocomplete='username']",
    "input[autocomplete='email']",
)
PASSWORD_SELECTORS = (
    "input#password",
    "input[name='password']",
    "input[type='password']",
    "input[autocomplete='current-password']",
)
CODE_SELECTORS = (
    "input#code",
    "input[name='code']",
    "input[autocomplete='one-time-code']",
    "input[inputmode='numeric']",
    "input[type='tel']",
)
SUBMIT_SELECTORS = (
    "button[type='submit']",
    "button:has-text('Continue')",
    "button:has-text('Log in')",
    "button:has-text('Verify')",
    "button:has-text('继续')",
    "button:has-text('登录')",
    "button:has-text('验证')",
)
COOKIE_SELECTORS = (
    "button:has-text('全部接受')",
    "button:has-text('Accept all')",
    "button:has-text('拒绝非必需')",
    "button:has-text('Reject non-essential')",
)

#: 页面文本里出现这些词，说明是"登录被额外验证拦住"而不是普通失败
BLOCK_MARKERS = (
    "verify your identity", "unusual activity", "suspicious",
    "captcha", "verify you are human", "account has been locked",
    "too many attempts", "try again later",
)
#: 出现这些词说明 TOTP 没被接受
TOTP_REJECT_MARKERS = (
    "incorrect code", "invalid code", "code is incorrect",
    "验证码不正确", "代码不正确", "try again",
)


@dataclass
class _Captured:
    """从页面网络流量里捡到的凭据片段。"""

    authorization: str | None = None
    account_id: str | None = None
    finalize_request: dict[str, Any] | None = None
    finalize_response: dict[str, Any] | None = None
    seen_backend_requests: int = 0
    seen_finalize: int = 0
    notes: list[str] = field(default_factory=list)


#: 把窗口最小化（Win32 ``ShowWindow`` 的 ``SW_MINIMIZE``）
SW_MINIMIZE = 6
#: 别让 PowerShell 弹一个控制台窗口出来
CREATE_NO_WINDOW = 0x08000000

#: 退出登录时**保留**的 Cookie：Cloudflare 放行凭证 + 设备标识。
#: 清掉它们会平白再撞一次 Cloudflare，甚至被当成新设备而触发风控。
#: （``__cf*`` / ``_cf*`` 系列由前缀覆盖，这里只列不满足前缀的两个。）
_SIGN_OUT_KEEP = frozenset({"cf_clearance", "oai-did"})
_SIGN_OUT_KEEP_PREFIXES = ("__cf", "_cf")


def _is_kept_on_sign_out(name: str) -> bool:
    return name in _SIGN_OUT_KEEP or name.startswith(_SIGN_OUT_KEEP_PREFIXES)


def _mask_email(email: str) -> str:
    """``someone@example.com`` → ``so***@example.com``，日志里不写全。"""
    local, _, domain = email.partition("@")
    if not domain:
        return "***"
    head = local[:2] if len(local) > 2 else local[:1]
    return f"{head}***@{domain}"


def _win32_pids_using_profile(profile_dir: Path) -> set[int]:
    """命令行里带该 profile 目录的进程号。

    为什么非要按 profile 路径找：``EnumWindows`` 只能给出 PID，而用户自己
    很可能也开着 Chrome（甚至也开着 chatgpt.com）。只有"命令行里带我们这个
    ``--user-data-dir``"才能精确锁定本会话的浏览器 —— 否则就有把用户自己的
    窗口最小化掉的风险。
    """
    marker = str(profile_dir.resolve()).replace("'", "''")
    script = (
        "Get-CimInstance Win32_Process -Filter \"Name='chrome.exe'\" | "
        f"Where-Object {{ $_.CommandLine -and $_.CommandLine.Contains('{marker}') }} | "
        "Select-Object -ExpandProperty ProcessId")
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, errors="replace", timeout=15,
            creationflags=CREATE_NO_WINDOW)
    except (OSError, subprocess.SubprocessError):
        return set()
    return {int(line) for line in result.stdout.split() if line.strip().isdigit()}


def _win32_visible_windows(pids: set[int]) -> list[tuple[int, bool]]:
    """属于这些进程的可见顶层窗口：``(hwnd, 是否已最小化)``。"""
    import ctypes

    user32 = ctypes.windll.user32
    found: list[tuple[int, bool]] = []

    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    def callback(hwnd, _lparam):  # pragma: no cover - 由 Win32 回调
        pid = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value in pids and user32.IsWindowVisible(hwnd):
            found.append((hwnd, bool(user32.IsIconic(hwnd))))
        return True

    user32.EnumWindows(callback, 0)
    return found


class BrowserSession:
    """Playwright 会话：负责登录、以及后续的凭据刷新与 CF 回退请求。"""

    def __init__(self, settings: Settings | None = None, *,
                 headless: bool | None = None,
                 minimized: bool | None = None,
                 challenge_prompt: Callable[[str], bool] | None = None,
                 log: Callable[[str], None] | None = None) -> None:
        self.settings = settings or Settings()
        self.headless = self.settings.headless if headless is None else headless
        if minimized is None:
            minimized = self.settings.minimize_browser
        self.minimized = minimized
        #: 遇到需要人工完成的 Cloudflare 验证时用它问用户；None 表示没人可问
        self.challenge_prompt = challenge_prompt
        self.log = log or (lambda _message: None)
        self._playwright = None
        self._context = None
        self._page = None
        self._closed = False
        self._captured = _Captured()

    # --- 生命周期 -----------------------------------------------------

    def __enter__(self) -> "BrowserSession":
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def start(self) -> None:
        from playwright.sync_api import sync_playwright

        if self._context is not None:
            return

        profile_dir = Path(self.settings.profile_dir)
        profile_dir.mkdir(parents=True, exist_ok=True)
        self._playwright = sync_playwright().start()
        # 最小化要和启动**并行**跑：窗口是在 launch 过程中就出现的，
        # 等 launch 返回再去查进程，用户已经多被抢了几百毫秒焦点。
        minimizer: threading.Thread | None = None
        if self.minimized and not self.headless:
            minimizer = threading.Thread(target=self._minimize_own_window,
                                         daemon=True)
            minimizer.start()
        self._context = self._playwright.chromium.launch_persistent_context(
            user_data_dir=str(profile_dir),
            headless=self.headless,
            args=[
                # 去掉 CDP 自动化痕迹：默认启动会置 navigator.webdriver = true
                "--disable-blink-features=AutomationControlled",
                "--no-first-run",
                "--no-default-browser-check",
                # 我们每次都是强制关掉浏览器的，Chromium 会认为"上次崩了"，
                # 于是弹一个"要恢复页面吗？"的气泡。实测它会一起冒到前台。
                "--hide-crash-restore-bubble",
            ],
            viewport={"width": 1440, "height": 900},
            locale="zh-CN",
            timezone_id="Asia/Shanghai",
        )
        self._context.set_default_timeout(self.settings.browser_timeout_ms)
        self._context.on("page", self._attach_page)
        self._page = (self._context.pages[0] if self._context.pages
                      else self._context.new_page())
        self._attach_page(self._page)
        if minimizer is not None:
            minimizer.join(timeout=8.0)

    def _minimize_own_window(self, *, timeout: float = 10.0) -> bool:
        """把本会话的浏览器窗口最小化，免得它抢走用户焦点（仅 Windows）。

        为什么不用 ``--start-minimized``：**实测 Playwright 自带的
        "Google Chrome for Testing" 不认这个开关**，窗口照样弹出来并成为前台。

        为什么最小化而不是别的：实测最小化之后

        * 焦点会**自动回到用户原来的窗口**；
        * 页面 JS 照常运行，哨兵令牌照样抓到（7.5s，比不最小化还快）。

        这个方法通常在**独立线程**里、与浏览器启动同时进行：一开始进程还不存在，
        所以要轮询等它出现。全程尽力而为 —— 拿不到就只记一行日志，绝不因此
        让刷新失败。
        """
        if not sys.platform.startswith("win"):
            return False

        import ctypes

        user32 = ctypes.windll.user32
        profile_dir = Path(self.settings.profile_dir)
        deadline = time.monotonic() + timeout
        pids: set[int] = set()
        looked_up = False

        while time.monotonic() < deadline:
            if self._closed:
                # 会话已经关掉了。若还继续按 profile 找进程，就可能把**下一个**
                # 会话的窗口最小化掉 —— 而下一个会话很可能正需要用户看见
                # （登录 / 人工过人机验证）。所以必须在这里收手。
                return False
            if not pids:
                pids = _win32_pids_using_profile(profile_dir)
                looked_up = True
                if not pids:
                    # 每次查询要起一个 PowerShell（约 0.4s），别转得太密
                    time.sleep(0.15)
                    continue
            windows = _win32_visible_windows(pids)
            for hwnd, iconic in windows:
                if not iconic:
                    user32.ShowWindow(hwnd, SW_MINIMIZE)
            if windows and all(iconic for _, iconic in windows):
                self.log("已把浏览器窗口最小化（后台跑，不抢焦点）")
                return True
            time.sleep(0.05)

        if looked_up and not pids:
            self.log("没能定位到浏览器进程，窗口可能仍在前台")
        elif pids:
            self.log("浏览器窗口没能最小化，可能仍在前台")
        return False

    def _attach_page(self, page) -> None:
        page.on("request", self._on_request)
        page.on("response", self._on_response)

    def close(self) -> None:
        # 先立旗：最小化线程可能还在按 profile 找进程，别让它去动下一个会话的窗口
        self._closed = True
        if self._context is not None:
            try:
                self._context.close()
            except Exception:  # noqa: BLE001 - 关闭失败不该掩盖真正的错误
                pass
        if self._playwright is not None:
            try:
                self._playwright.stop()
            except Exception:  # noqa: BLE001
                pass
        self._context = None
        self._playwright = None
        self._page = None

    @property
    def page(self):
        if self._page is None:
            raise RuntimeError("浏览器会话尚未启动，请先调用 start()")
        return self._page

    # --- 网络监听 -----------------------------------------------------

    def _on_request(self, request) -> None:
        try:
            url = request.url
            if "/backend-api/" in url:
                self._captured.seen_backend_requests += 1
                headers = request.headers
                authorization = headers.get("authorization")
                if authorization and not self._captured.authorization:
                    self._captured.authorization = authorization
                account_id = headers.get("chatgpt-account-id")
                if account_id and not self._captured.account_id:
                    self._captured.account_id = account_id

            if "sentinel/chat-requirements/finalize" in url:
                self._captured.seen_finalize += 1
                raw = request.post_data
                if raw:
                    try:
                        self._captured.finalize_request = json.loads(raw)
                    except ValueError:
                        self._captured.notes.append("finalize 请求体不是 JSON")
        except Exception as exc:  # noqa: BLE001 - 监听器绝不能抛
            self._captured.notes.append(f"request 监听异常：{exc!r}")

    def _on_response(self, response) -> None:
        try:
            if "sentinel/chat-requirements/finalize" not in response.url:
                return
            if response.status != 200:
                return
            payload = response.json()
            if isinstance(payload, dict) and payload.get("token"):
                self._captured.finalize_response = payload
        except Exception as exc:  # noqa: BLE001
            self._captured.notes.append(f"response 监听异常：{exc!r}")

    # --- 登录 ---------------------------------------------------------

    def login(self, email: str, password: str, totp_secret: str) -> Credentials:
        """以给定账号登录，返回可直接用于 HTTP 的凭据。

        ⚠️ **必须确认当前会话是不是这个账号**。持久化 profile 会记住上一个账号，
        而早先的实现只要"检测到已登录"就跳过账密步骤 —— 于是用户填了新账号点
        登录，实际还在用旧账号，**而且不报任何错**。
        """
        self.log(f"打开登录页 {LOGIN_URL}")
        self._goto(LOGIN_URL)
        self._dismiss_cookie_banner()

        if self._is_logged_in():
            current = self._current_account_email()
            if current and current.strip().lower() == email.strip().lower():
                self.log(f"当前会话已经是 {_mask_email(current)}，跳过账号密码步骤")
                return self.refresh_credentials()
            if current:
                self.log(f"当前会话属于 {_mask_email(current)}，"
                         f"要登录的是 {_mask_email(email)} —— 先退出登录")
            else:
                # 问不出是哪个账号就**不能赌**：宁可多走一遍登录，也不能静默地
                # 继续用旧账号。这正是这个 bug 的成因。
                self.log("检测到已有会话，但问不出它属于哪个账号；"
                         "为稳妥起见先退出登录再走完整流程")
            self._sign_out()

        self._submit_email(email)
        self._submit_password(password)
        self._submit_totp(totp_secret)

        self._wait_for_session()
        return self.refresh_credentials()

    def _current_account_email(self) -> str | None:
        """当前会话属于哪个账号；没有会话或问不出来时返回 ``None``。

        在**页面里**发这个请求（同源、带浏览器自己的 Cookie），比在外面用
        curl_cffi 更贴近"浏览器现在是谁"。问不出来就返回 None —— 调用方据此
        走完整登录流程，而不是假设一切正常。
        """
        try:
            email = self.page.evaluate(
                """async () => {
                    try {
                        const r = await fetch('/backend-api/me',
                                              {credentials: 'include'});
                        if (!r.ok) return null;
                        const j = await r.json();
                        return (j && j.email) || null;
                    } catch (e) { return null; }
                }""")
        except Exception:  # noqa: BLE001 - 导航中途/页面已关都会抛
            return None
        return email if isinstance(email, str) and email.strip() else None

    def _sign_out(self) -> int:
        """清掉登录态 Cookie，然后回到登录页。

        保留 **Cloudflare 放行凭证**（``cf_clearance`` / ``__cf_bm`` / ``_cfuvid`` …）
        与**设备标识**（``oai-did``）：清掉它们会平白再撞一次 Cloudflare，
        甚至被当成新设备而触发风控。

        其余一律清掉 —— **包括我们不认识的新 Cookie**。理由是不对称的：
        "漏掉一个认证 Cookie"的后果是静默地继续用旧账号（就是刚修的这个 bug），
        而"多清了一个"最多是让服务端重发一次。
        """
        cleared = 0
        for cookie in self.read_cookies():
            name = str(cookie.get("name") or "")
            if not name or _is_kept_on_sign_out(name):
                continue
            try:
                self._context.clear_cookies(name=name)
                cleared += 1
            except Exception:  # noqa: BLE001 - 单个删不掉不该中断
                continue
        self.log(f"已清除 {cleared} 个登录态 Cookie（保留 Cloudflare 放行凭证）")
        self._goto(LOGIN_URL)
        self._dismiss_cookie_banner()
        return cleared

    def _is_logged_in(self) -> bool:
        return any(cookie["name"].startswith(SESSION_COOKIE_PREFIX)
                   for cookie in self.read_cookies())

    def read_cookies(self) -> list[dict[str, Any]]:
        """读出三个域上的全部 Cookie（用于收集凭据 / 刷新后重读）。"""
        cookies: list[dict[str, Any]] = []
        for url in ("https://chatgpt.com", "https://auth.openai.com",
                    "https://sentinel.openai.com"):
            try:
                cookies.extend(self._context.cookies(url))
            except Exception:  # noqa: BLE001
                continue
        return cookies

    def open_for_challenge(self, url: str) -> None:
        """把浏览器**导航**到被拦的地址，让 Cloudflare 的验证页真正渲染出来。

        为什么必须导航、不能沿用页面里的 ``fetch``：``fetch`` 拿回来的是挑战的
        HTML **响应体**，页面上不会出现可点的 Turnstile 控件 —— 用户没有东西可点。
        导航则会走正常的文档加载路径，Cloudflare 的验证页就会显示出来。

        导航到业务 API 地址时，若 CF 不再要求验证，页面会直接显示 JSON ——
        那也说明放行了，调用方随后重试即可。
        """
        absolute = url if url.startswith("http") else HOME_URL.rstrip("/") + url
        self.log(f"把浏览器导航到被拦地址，以便渲染人机验证：{absolute[:100]}")
        # 只试一次：这一步失败就直接交给上层报错，不必再重试。
        # wait_cloudflare=False：这里的拦截页**正是要给用户看的**，
        # 等它消解等于把用户要点的东西挡在门外。
        self._goto(absolute, attempts=1, wait_cloudflare=False)
        try:
            self.page.bring_to_front()
        except Exception:  # noqa: BLE001 - 无头模式或已关闭时忽略
            pass

    # --- 页面就绪与重试 -------------------------------------------------

    def _wait_for_hydration(self, timeout_s: float = 30.0) -> bool:
        """等 React 完成 hydration。

        这一步不是可选的：登录表单的提交靠 React 的 onSubmit。如果 JS 还没接管，
        点"继续"会退化成**浏览器原生 GET 提交** —— 现象是 URL 变成
        ``/auth/login?email=…`` 而流程毫无进展（第一版就踩了这个坑）。
        这里通过检测 DOM 节点上的 React 内部属性判断是否已接管。
        """
        script = """() => {
            const el = document.querySelector('form')
                    || document.querySelector('input')
                    || document.body;
            if (!el) return false;
            return Object.keys(el).some(k => k.startsWith('__react'));
        }"""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                if self.page.evaluate(script):
                    return True
            except Exception:  # noqa: BLE001 - 导航中途 evaluate 会失败
                pass
            self.page.wait_for_timeout(250)
        self.log(f"警告：{timeout_s:.0f} 秒内未检测到 React 接管，仍继续尝试")
        return False

    def _dismiss_cookie_banner(self) -> None:
        locator = self._find_visible(COOKIE_SELECTORS, timeout_ms=1500)
        if locator is None:
            return
        try:
            locator.click()
            self.log("已处理 Cookie 横幅")
            self.page.wait_for_timeout(500)
        except Exception:  # noqa: BLE001 - 关不掉也不该让登录失败
            pass

    def _find_visible(self, selectors: tuple[str, ...], *, timeout_ms: int = 1500):
        """在候选选择器里找第一个可见元素，找不到返回 None。

        **必须轮询到 deadline**：``locator.count()`` 不会等待元素出现，
        早先的实现只在 ``is_visible()`` 上传了 timeout，导致页面还在导航时
        直接返回 None（MFA 输入框就是这么被错过的）。这里改成在超时窗口内
        反复扫描全部候选选择器。
        """
        deadline = time.monotonic() + timeout_ms / 1000.0
        while True:
            for selector in selectors:
                try:
                    locator = self.page.locator(selector).first
                    if locator.count() and locator.is_visible():
                        return locator
                except Exception:  # noqa: BLE001 - 页面导航中途查询会失败
                    continue
            if time.monotonic() >= deadline:
                return None
            self.page.wait_for_timeout(200)

    def _fill_first(self, selectors: tuple[str, ...], value: str):
        locator = self._find_visible(selectors, timeout_ms=8000)
        if locator is None:
            return None
        self._fill_and_verify(locator, value)
        return locator

    def _fill_and_verify(self, locator, value: str) -> bool:
        """填入并**确认值真的进去了**。

        React 受控组件在 hydration 完成的瞬间可能把已填的值清掉；
        ``fill()`` 不保证留下痕迹，所以这里校验 + 用真实按键重试。
        """
        try:
            locator.fill(value)
            if locator.input_value() == value:
                return True
        except Exception:  # noqa: BLE001
            pass
        try:
            locator.click()
            locator.fill("")
            locator.press_sequentially(value, delay=25)
            if locator.input_value() == value:
                return True
        except Exception:  # noqa: BLE001
            pass
        current = ""
        try:
            current = locator.input_value()
        except Exception:  # noqa: BLE001
            pass
        self.log(f"警告：输入框的值未能确认（当前 {current[:12]!r}）")
        return current == value

    def _email_step_state(self) -> str:
        """邮箱步骤现在处于什么状态。

        ==============  ====================================================
        返回值           含义
        ==============  ====================================================
        ``advanced``     已经进到下一步（出现密码框/验证码框，或邮箱框消失，
                         或已经拿到会话）
        ``submitting``   正在提交 —— 输入框和按钮都变灰了
        ``idle``         还停在邮箱步骤，表单可用（= 这次提交没生效）
        ==============  ====================================================
        """
        if self._is_logged_in():
            return "advanced"
        if self._find_visible(PASSWORD_SELECTORS, timeout_ms=300) is not None:
            return "advanced"
        if self._find_visible(CODE_SELECTORS, timeout_ms=300) is not None:
            return "advanced"
        field = self._find_visible(EMAIL_SELECTORS, timeout_ms=300)
        if field is None:
            return "advanced"          # 邮箱框没了，说明页面已经翻篇
        try:
            if not field.is_enabled():
                return "submitting"    # 灰着 = 正在提交，**不是**失败
        except Exception:  # noqa: BLE001 - 查询失败按提交中处理，宁可多等
            return "submitting"
        return "idle"

    def _wait_for_email_accepted(self, *, timeout_s: float = 25.0) -> bool:
        """等邮箱提交生效，返回是否真的推进到了下一步。

        **为什么要这么写**：点「继续」之后，页面会进入一段 **disabled 的提交态**
        （输入框和按钮都变灰），**几秒后**才导航到下一步。早先的实现只等固定
        2.5 秒、再看"邮箱框还在不在"，于是把"正在提交"误判成"没提交成功" ——
        白重试 3 次然后报"邮箱提交连续 3 次都没有推进"，而实际上第一次就成了。
        （实测：点击后约 3 秒页面才导航走。）

        所以这里改成轮询状态机：
        * 变成 ``advanced`` → 成功；
        * 先见到 ``submitting``、后来又回到 ``idle`` → 页面把表单还回来了，
          这次确实没成，返回 False 让上层重试；
        * 一直 ``idle`` 到超时 → 也返回 False。
        """
        started = time.monotonic()
        saw_submitting = False
        while time.monotonic() - started < timeout_s:
            state = self._email_step_state()
            if state == "advanced":
                return True
            if state == "submitting":
                saw_submitting = True
            elif saw_submitting:
                self.log("提交态退回可编辑态 —— 这次提交没生效")
                return False
            self.page.wait_for_timeout(300)
        return False

    def _email_step_still_showing(self) -> bool:
        """判断是否仍停在邮箱这一步（等不到推进时的兜底判断）。

        原生 GET 提交的典型特征是 URL 带上了 ``?email=`` 且邮箱框又变回空的。
        """
        return self._email_step_state() == "idle"

    def _submit_email(self, email: str) -> None:
        self.log("提交邮箱…")
        self._wait_for_hydration()
        for attempt in range(1, 4):
            if attempt > 1:
                self.log(f"邮箱步骤未推进，回到干净登录页重试（第 {attempt}/3 次）…")
                self._goto(LOGIN_URL)
                self._dismiss_cookie_banner()
                self._wait_for_hydration()
            field = self._fill_first(EMAIL_SELECTORS, email)
            if field is None:
                self._dump("email-step")
                raise LoginBlockedError(
                    "找不到邮箱输入框。已把页面截图与 HTML 存到 "
                    f"{self.settings.debug_dir}，请据此判断登录页是否改版或被拦截。")
            self._click_submit(field)
            self._raise_if_blocked("邮箱提交后被拦")
            if self._wait_for_email_accepted():
                self.log("邮箱已接受")
                return
            self.log("仍停在邮箱步骤（疑似提交未生效）")
        self._dump("email-step-stuck")
        raise LoginBlockedError(
            "邮箱提交连续 3 次都没有推进到下一步。\n"
            f"当前 URL：{self.page.url}\n"
            f"页面片段：{self._visible_text()[:300]}\n"
            f"截图与 HTML 已存到 {self.settings.debug_dir}。")

    def _submit_password(self, password: str) -> None:
        if self._is_logged_in() or self._find_visible(CODE_SELECTORS) is not None:
            self.log("没有出现密码步骤（可能免密或直接进入二次验证），跳过")
            return
        self.log("提交密码…")
        field = self._fill_first(PASSWORD_SELECTORS, password)
        if field is None:
            self._dump("password-step")
            self._raise_if_blocked("找不到密码输入框")
            # 没找到密码框且没有风控提示 —— 这是真失败，不能静默继续
            raise LoginBlockedError(
                "找不到密码输入框，登录流程没有推进到密码步骤。\n"
                f"当前 URL：{self.page.url}\n"
                f"页面片段：{self._visible_text()[:300]}\n"
                f"截图与 HTML 已存到 {self.settings.debug_dir}。")
        self._click_submit(field)
        self.page.wait_for_timeout(2500)
        self._raise_if_blocked("提交密码后页面出现风控提示")

    def _submit_totp(self, totp_secret: str) -> None:
        """等待并提交二次验证码。

        这里必须**给足时间**：密码通过后浏览器会跳到 auth.openai.com，而这个域
        本身还要过一次 Cloudflare 的 JSD 挑战（实测它对非浏览器客户端直接回
        ``403 cf-mitigated: challenge``）。早先只等 8 秒，结果 MFA 页面还没渲染
        出来就放弃了，然后干等 90 秒会话 Cookie —— 现象是"没有出现验证码输入框"。
        """
        self.log("等待二次验证（MFA）页面…")
        field = self._find_visible(CODE_SELECTORS, timeout_ms=90_000)
        if field is None:
            if self._is_logged_in():
                self.log("已获得会话，说明这一步不需要二次验证，继续")
                return
            self._dump("mfa-missing")
            raise LoginBlockedError(
                "等待 90 秒仍未出现二次验证输入框，且尚未拿到会话 Cookie。\n"
                f"当前 URL：{self.page.url}\n"
                f"页面片段：{self._visible_text()[:300]}\n"
                f"截图与 HTML 已存到 {self.settings.debug_dir}。")
        self.log("已找到验证码输入框")

        # MFA 页同样是 React 表单（method=post action=/mfa-challenge/<id>），
        # 未完成 hydration 就点击会退化成原生 POST。
        self._wait_for_hydration()
        # 窗口只剩几秒时提交，很可能到服务端就过期了 —— 等下一个窗口更稳
        remaining = seconds_remaining()
        if remaining < 5:
            self.log(f"当前验证码只剩 {remaining:.1f}s，等待下一个窗口…")
            self.page.wait_for_timeout(int((remaining + 1) * 1000))

        attempts = totp_with_skew(totp_secret)     # [上一窗口, 当前, 下一窗口]
        order = [attempts[1], attempts[2], attempts[0]]
        last_error: str | None = None
        for index, code in enumerate(order):
            current = self._find_visible(CODE_SELECTORS, timeout_ms=10_000) or field
            self._fill_and_verify(current, code)
            self._click_submit(current)
            self.page.wait_for_timeout(3000)
            if self._totp_accepted():
                self.log("二次验证通过")
                return
            last_error = self._visible_text()[:200]
            if index < len(order) - 1:
                self.log("验证码被拒，换一个时间窗口重试…")
                self.page.wait_for_timeout(1000)
                self._fill_and_verify(current, "")
        self._dump("totp-rejected")
        raise TotpRejectedError(
            "TOTP 验证码被服务端拒绝（已尝试相邻三个时间窗口）。\n"
            f"页面片段：{last_error}\n"
            "若本机时钟偏差较大，请先校准系统时间。")

    def _totp_accepted(self) -> bool:
        """判断二次验证是否通过。

        只看"没有报错文案"太弱（页面还没渲染出错误时也会为真），
        因此优先看会话 Cookie，其次看验证码输入框是否消失 / URL 是否离开
        mfa-challenge 页面。
        """
        if self._is_logged_in():
            return True
        text = self._visible_text().lower()
        if any(marker in text for marker in TOTP_REJECT_MARKERS):
            return False
        if "mfa-challenge" not in self.page.url:
            return True
        return self._find_visible(CODE_SELECTORS, timeout_ms=500) is None

    # --- 页面操作小工具 -----------------------------------------------

    def _fill_first(self, selectors: tuple[str, ...], value: str):
        for selector in selectors:
            try:
                locator = self.page.locator(selector).first
                if locator.count() == 0:
                    continue
                locator.wait_for(state="visible", timeout=8000)
                locator.fill(value)
                return locator
            except Exception:  # noqa: BLE001 - 逐个候选试，失败就换下一个
                continue
        return None

    def _click_submit(self, field) -> None:
        for selector in SUBMIT_SELECTORS:
            try:
                button = self.page.locator(selector).first
                if button.count() and button.is_visible():
                    button.click()
                    return
            except Exception:  # noqa: BLE001
                continue
        # 没有可用按钮就回车提交
        try:
            field.press("Enter")
        except Exception:  # noqa: BLE001
            self.page.keyboard.press("Enter")

    def _goto(self, url: str, *, attempts: int = 3,
              wait_until: str = "domcontentloaded",
              wait_cloudflare: bool = True) -> None:
        """带重试的导航。

        这个环境到 chatgpt.com 的链路会偶发 ``ERR_CONNECTION_TIMED_OUT``
        （实测过一次），一次失败就放弃会让整个登录流程白跑，所以这里退避重试。

        ``wait_cloudflare``：导航后是否等 Cloudflare 的"请稍候…"拦截页消解。
        默认等 —— 不等的话，后续会在一个还是拦截页的文档里找表单/等挑战，
        报出来的错（"找不到邮箱输入框"）跟真实原因（被 CF 拦了）完全对不上。
        只有"就是要让用户看见拦截页去点它"的场合（``open_for_challenge``）才传 False。
        """
        last_error: Exception | None = None
        for attempt in range(1, attempts + 1):
            try:
                self.page.goto(url, wait_until=wait_until)
                if wait_cloudflare:
                    self._wait_for_cloudflare()
                return
            except Exception as exc:  # noqa: BLE001 - 网络类错误统一重试
                last_error = exc
                if attempt < attempts:
                    delay = 2.0 * attempt
                    self.log(f"打开 {url} 失败（第 {attempt}/{attempts} 次），"
                             f"{delay:.0f}s 后重试：{str(exc)[:120]}")
                    self.page.wait_for_timeout(int(delay * 1000))
        raise LoginBlockedError(
            f"连续 {attempts} 次都无法打开 {url}。\n"
            f"最后一次错误：{last_error}\n"
            "请检查本机网络/代理是否可达 chatgpt.com。")

    def _cloudflare_state(self) -> str:
        """当前文档处于什么状态：``challenge`` / ``loading`` / ``ready``。

        ⚠️ 早先只判"**是不是**挑战页"，于是**导航途中**（标题还空着、挑战标记
        也还没出现）被判成"已通过" —— 我们兴冲冲去提交邮箱，而挑战页下一秒才
        真正加载完。用户看到的现象就是"点了又有"。
        所以这里必须要求**正面证据**：真的加载出内容了才算 ``ready``。
        """
        try:
            state = self.page.evaluate("""() => {
                const title = document.title || '';
                if (/请稍候|Just a moment|Attention Required|Verifying you are human/i
                        .test(title)) return 'challenge';
                if (document.querySelector('script[src*="challenge-platform"]'))
                    return 'challenge';
                const body = document.body;
                if (!body || body.childElementCount === 0) return 'loading';
                return 'ready';
            }""")
        except Exception:  # noqa: BLE001 - 导航中途 evaluate 会失败
            return "loading"          # 查不出来就按"还没好"处理，宁可多等
        # 白名单：拿到意料之外的值（比如假件返回了布尔）一律按"还没好"处理。
        # 否则会静默地一路等到超时 —— 实测这个坑把测试从 1 秒拖到 25 分钟。
        return state if state in ("challenge", "loading", "ready") else "loading"

    def _is_cloudflare_interstitial(self) -> bool:
        """当前文档是不是 Cloudflare 的拦截页。"""
        return self._cloudflare_state() == "challenge"

    def _wait_for_cloudflare(self, *, timeout_s: float = 300.0,
                             reask_after_s: float = 60.0) -> bool:
        """遇到 Cloudflare 拦截页时，**交给用户去点**。

        ⚠️ 这个"请稍候…"是**需要人点一下**的挑战，**不会自己过去**。
        （我一度以为它是托管挑战、浏览器能自己过 —— 那次观测里其实是用户
        手动点掉的，属于把人的操作算到了程序头上。）

        所以这里不能傻等，要做三件事：

        1. 把窗口提到前台 —— 用户得看得见才点得到；
        2. 明确告诉他"去点一下"（GUI 弹框 / CLI 回车确认，走 challenge_prompt）；
        3. 一边等一边轮询**直到页面真正加载出内容**，中途的导航/空文档都算没完。

        挑战有时会**连着来**（过了一个又弹一个），所以用户说"点完了"之后如果
        仍在挑战页，隔一段时间会**再问一次**，而不是默默等超时。

        没有 ``challenge_prompt``（纯库调用）时只能轮询等外部有人点，
        超时就如实报错，不假装成功。
        """
        if self._cloudflare_state() == "ready":
            return True

        self.log("页面被 Cloudflare 拦住 —— 这个验证**需要你亲自点一下**，"
                 "它不会自己过去")
        try:
            self.page.bring_to_front()
        except Exception:  # noqa: BLE001 - 无头/已关闭时忽略
            pass

        started = time.monotonic()
        last_ask: float | None = None
        while time.monotonic() - started < timeout_s:
            if self._cloudflare_state() == "ready":
                self.log(f"Cloudflare 验证已通过（等了 "
                         f"{time.monotonic() - started:.0f} 秒）")
                return True
            now = time.monotonic()
            if (self.challenge_prompt is not None
                    and (last_ask is None or now - last_ask >= reask_after_s)):
                first = last_ask is None
                last_ask = now
                if not first:
                    self.log("仍在 Cloudflare 验证页 —— 可能还需要再点一次")
                if not self.challenge_prompt(self.page.url):
                    self.log("已放弃这次 Cloudflare 验证")
                    return False
            self.page.wait_for_timeout(500)

        self.log(f"警告：{timeout_s:.0f} 秒内 Cloudflare 验证仍未通过")
        return False

    def _reload(self, *, attempts: int = 3,
                wait_until: str = "domcontentloaded") -> None:
        last_error: Exception | None = None
        for attempt in range(1, attempts + 1):
            try:
                self.page.reload(wait_until=wait_until)
                return
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                if attempt < attempts:
                    self.page.wait_for_timeout(2000 * attempt)
        self.log(f"重新加载失败（忽略）：{str(last_error)[:120]}")

    def _visible_text(self) -> str:
        try:
            return self.page.inner_text("body")
        except Exception:  # noqa: BLE001
            return ""

    def _raise_if_blocked(self, prefix: str) -> None:
        text = self._visible_text().lower()
        for marker in BLOCK_MARKERS:
            if marker in text:
                self._dump("blocked")
                raise LoginBlockedError(
                    f"{prefix}：页面出现风控/人机校验提示（命中 {marker!r}）。\n"
                    f"截图与 HTML 已存到 {self.settings.debug_dir}。\n"
                    "建议：加 --headed 观察浏览器实际停在哪一步。")

    def _wait_for_session(self, timeout_s: float = 90.0) -> None:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if self._is_logged_in():
                self.log("已拿到会话 Cookie")
                return
            self._raise_if_blocked("登录未完成")
            self.page.wait_for_timeout(1000)
        self._dump("no-session")
        raise LoginBlockedError(
            f"等待 {timeout_s:.0f} 秒仍未拿到会话 Cookie。\n"
            f"当前 URL：{self.page.url}\n"
            f"页面片段：{self._visible_text()[:300]}\n"
            f"截图与 HTML 已存到 {self.settings.debug_dir}。")

    def _dump(self, name: str) -> None:
        """把现场落盘 —— 登录页改版时这是唯一能自救的东西。"""
        try:
            debug_dir = Path(self.settings.debug_dir)
            debug_dir.mkdir(parents=True, exist_ok=True)
            stamp = time.strftime("%Y%m%d-%H%M%S")
            base = debug_dir / f"{name}-{stamp}"
            self.page.screenshot(path=str(base.with_suffix(".png")),
                                 full_page=True)
            base.with_suffix(".html").write_text(self.page.content(),
                                                 encoding="utf-8")
            (base.with_suffix(".txt")).write_text(
                f"url: {self.page.url}\n\n{self._visible_text()}",
                encoding="utf-8")
            self.log(f"已保存现场：{base}.png / .html / .txt")
        except Exception as exc:  # noqa: BLE001
            self.log(f"保存现场失败：{exc!r}")

    # --- 凭据收集 -----------------------------------------------------

    def refresh_credentials(self, *, wait_sentinel: float | None = None,
                            reload_if_missing: bool = True) -> Credentials:
        """回到首页，等应用自己发起 chat-requirements，然后把凭据收集齐。"""
        if not self._is_logged_in():
            raise LoginBlockedError("当前浏览器会话没有有效的登录 Cookie。")
        wait_sentinel = (self.settings.sentinel_wait if wait_sentinel is None
                         else wait_sentinel)

        self.log(f"打开 {HOME_URL}，等待对话准入挑战…")
        self._goto(HOME_URL)
        self._wait_for_sentinel(wait_sentinel)
        if self._captured.finalize_response is None and reload_if_missing:
            self.log("首次加载没抓到 chat-requirements，重新加载一次…")
            self._reload()
            self._wait_for_sentinel(wait_sentinel)

        return self._collect()

    def _wait_for_sentinel(self, timeout_s: float) -> None:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if self._captured.finalize_response is not None:
                self.log("已抓到 chat-requirements 的准入令牌")
                return
            # 页面刚加载完时应用可能还没发请求，稍等一下再看
            self.page.wait_for_timeout(500)
        self.log(f"等待 {timeout_s:.0f} 秒仍未抓到 chat-requirements 挑战")

    def _collect(self) -> Credentials:
        cookies = {cookie["name"]: cookie["value"]
                   for cookie in self.read_cookies()}
        if not any(name.startswith(SESSION_COOKIE_PREFIX) for name in cookies):
            raise LoginBlockedError("收集凭据时发现会话 Cookie 不见了。")

        sentinel = self._build_sentinel_tokens()
        bearer = self._captured.authorization
        if bearer and bearer.lower().startswith("bearer "):
            bearer = bearer[7:]
        if not bearer:
            bearer = self._fetch_access_token()
        account_id = self._captured.account_id
        if not account_id:
            account_id = self._fetch_account_id()

        credentials = Credentials(
            cookies=cookies,
            bearer=bearer,
            account_id=account_id,
            device_id=cookies.get("oai-did"),
            sentinel=sentinel,
            captured_at=time.time(),
            user_agent=self._user_agent(),
            originator=self.settings.originator,
        )
        self.log(f"凭据收集完成：{len(cookies)} 个 Cookie，"
                 f"Bearer {'有' if bearer else '无'}，"
                 f"account_id={account_id}，"
                 f"哨兵令牌 {'齐' if sentinel else '缺'}")
        if not bearer:
            self.log("提醒：没抓到 Authorization，将只靠 Cookie 请求（可能仍可用）")
        return credentials

    def _build_sentinel_tokens(self) -> SentinelTokens | None:
        request_body = self._captured.finalize_request or {}
        response_body = self._captured.finalize_response or {}
        chat_requirements = response_body.get("token")
        proof = request_body.get("proofofwork")
        turnstile = request_body.get("turnstile")
        if not all(isinstance(v, str) and v
                   for v in (chat_requirements, proof, turnstile)):
            return None
        return SentinelTokens(chat_requirements=chat_requirements,
                              proof=proof, turnstile=turnstile,
                              issued_at=time.time())

    def _user_agent(self) -> str:
        try:
            return self.page.evaluate("() => navigator.userAgent")
        except Exception:  # noqa: BLE001
            return self.settings.user_agent

    def _fetch_access_token(self) -> str | None:
        """兜底：NextAuth 的 session 端点会回显 ``accessToken``。"""
        try:
            result = self.fetch_in_context(method="GET",
                                           url="/api/auth/session",
                                           headers={}, body=None)
            if result.get("status") == 200:
                payload = json.loads(result.get("body") or "{}")
                token = payload.get("accessToken")
                if isinstance(token, str) and token:
                    return token
        except Exception as exc:  # noqa: BLE001
            self._captured.notes.append(f"读取 /api/auth/session 失败：{exc!r}")
        return None

    def _fetch_account_id(self) -> str | None:
        try:
            result = self.fetch_in_context(
                method="GET", url="/backend-api/me", headers={}, body=None)
            if result.get("status") == 200:
                payload = json.loads(result.get("body") or "{}")
                for org in (payload.get("orgs") or {}).get("data") or []:
                    if isinstance(org, dict) and org.get("is_default"):
                        return org.get("id")
                return payload.get("id")
        except Exception as exc:  # noqa: BLE001
            self._captured.notes.append(f"读取 /backend-api/me 失败：{exc!r}")
        return None

    # --- 给 BrowserTransport 用 ---------------------------------------

    def fetch_in_context(self, *, method: str, url: str,
                         headers: dict[str, str], body: str | None,
                         timeout: float | None = None) -> dict[str, Any]:
        """在页面上下文里发 ``fetch``（自带 Cookie、TLS 与 HTTP/2 指纹）。

        这是 Cloudflare 回退路径的实现。返回 ``{status, headers, body}``。
        """
        script = """
        async ({ method, url, headers, body, timeoutMs }) => {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeoutMs);
          try {
            const response = await fetch(url, {
              method, headers,
              body: (body === null ? undefined : body),
              credentials: 'include',
              signal: controller.signal,
            });
            const text = await response.text();
            const out = {};
            response.headers.forEach((v, k) => { out[k] = v; });
            return { status: response.status, headers: out, body: text };
          } finally {
            clearTimeout(timer);
          }
        }
        """
        absolute = url if url.startswith("http") else HOME_URL.rstrip("/") + url
        effective = headers or {}
        if body is not None and not any(k.lower() == "content-type"
                                        for k in effective):
            effective = {**effective, "content-type": "application/json"}
        return self.page.evaluate(script, {
            "method": method.upper(),
            "url": absolute,
            "headers": effective,
            "body": body,
            "timeoutMs": int((timeout or 120.0) * 1000),
        })
