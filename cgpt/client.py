"""库入口：把浏览器凭据获取与 HTTP 业务请求串成一个对象。

典型用法::

    from cgpt import Client

    client = Client.login(email=..., password=..., totp_secret=...)
    client.save(".cgpt/credentials.json")
    result = client.generate_image("生成一张地球图片")
    print(result.primary.path)      # output/<随机名>.png

或者复用已登录的凭据::

    client = Client.from_credentials(".cgpt/credentials.json")
    client.generate_image("...")

输出固定落在 ``Settings.output_dir``（默认 ``output/``）下，文件名随机、
后缀跟图片格式走。需要指定文件名时才传 ``out=``（只给库调用方留的口子）。
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Callable

from cgpt.api.client import ChatGptWebClient
from cgpt.api.image import generate_image as _generate_image
from cgpt.api.transport import (
    BrowserTransport,
    FallbackTransport,
    HttpTransport,
    Transport,
)
from cgpt.auth.browser import BrowserSession
from cgpt.auth.store import (
    load_credentials,
    save_credentials,
)
from cgpt.config import Settings
from cgpt.errors import SentinelRejectedError
from cgpt.models import Credentials, GenerationResult, SentinelTokens

#: 哨兵令牌剩余寿命低于这个值就视为需要刷新（服务端 540 秒，留 60 秒余量）
SENTINEL_REFRESH_MARGIN = 60.0

#: 询问用户"人机验证完成了吗"的回调；返回 True 表示可以重试。
#: 由调用方提供（CLI 用回车确认、GUI 用对话框）。为 None 时不等待，直接报错。
ChallengePrompt = Callable[[str], bool]


class Client:
    """ChatGPT 生图客户端。"""

    def __init__(self, credentials: Credentials, *,
                 settings: Settings | None = None,
                 transport: Transport | None = None,
                 browser: BrowserSession | None = None,
                 challenge_prompt: ChallengePrompt | None = None,
                 log: Callable[[str], None] | None = None) -> None:
        self.credentials = credentials
        self.settings = settings or Settings()
        self.challenge_prompt = challenge_prompt
        self.log = log or (lambda _message: None)
        self._browser = browser
        self._owns_browser = False
        self._transport = transport
        self._web: ChatGptWebClient | None = None

    # --- 构造 ---------------------------------------------------------

    @classmethod
    def login(cls, *, email: str, password: str, totp_secret: str,
              settings: Settings | None = None, headless: bool | None = None,
              challenge_prompt: ChallengePrompt | None = None,
              log: Callable[[str], None] | None = None) -> "Client":
        """用账密 + TOTP 登录并抓取凭据（会启动真实浏览器）。"""
        settings = settings or Settings()
        # 登录是用户主动点的，而且 Cloudflare 可能要他亲自处理 —— 正常显示窗口。
        # challenge_prompt 一路传下去：登录过程中也可能撞上需要人工点的 CF 验证。
        session = BrowserSession(settings, headless=headless, minimized=False,
                                 challenge_prompt=challenge_prompt, log=log)
        session.start()
        client = cls(credentials=Credentials(), settings=settings,
                     browser=session, challenge_prompt=challenge_prompt,
                     log=log)
        client._owns_browser = True
        try:
            client.credentials = session.login(email, password, totp_secret)
        finally:
            # 登录完成后凭据（含刚签发的哨兵令牌）已经在手，浏览器没用了。
            # 放在 finally 里是为了失败时也不留一个孤儿窗口。
            client._release_browser()
        return client

    @classmethod
    def from_credentials(cls, path: Path | str | None = None, *,
                         settings: Settings | None = None,
                         challenge_prompt: ChallengePrompt | None = None,
                         log: Callable[[str], None] | None = None) -> "Client":
        """从磁盘读凭据（不启动浏览器；需要时才惰性启动）。"""
        settings = settings or Settings()
        if path is not None:
            settings = settings.model_copy(update={"credentials_path": Path(path)})
        credentials = load_credentials(settings.credentials_path)
        return cls(credentials=credentials, settings=settings,
                   challenge_prompt=challenge_prompt, log=log)

    # --- 持久化 -------------------------------------------------------

    def save(self, path: Path | str | None = None) -> Path:
        target = Path(path) if path is not None else self.settings.credentials_path
        return save_credentials(self.credentials, target)

    # --- 浏览器（惰性） -----------------------------------------------

    def ensure_browser(self, *, minimized: bool = True) -> BrowserSession:
        """按需启动浏览器。

        ``minimized=True``（默认）用于**后台**用途 —— 刷新准入令牌、Cloudflare
        回退。窗口会立刻最小化，不抢走用户焦点。
        需要用户亲自处理时传 ``minimized=False``（登录、人工过人机验证），
        窗口正常显示。

        ``start()`` 是幂等的（已启动则直接返回），所以这里**无条件调用** ——
        不能假设"``self._browser`` 非空就等于已经在跑"，那是个隐式不变量，
        一旦哪天有人在别处关掉会话却没置 None，就会变成难查的哑失败。
        """
        if self._browser is not None and self._browser.minimized and not minimized:
            # 手上这个是最小化的，但现在需要用户看见 —— 重建一个可见的。
            # 不试图"恢复窗口"是因为那要额外碰 Win32，而这条路径很少走到
            # （刷新完就关了，需要人工验证时通常是新建会话）。
            self.log("需要用户查看，重新以可见方式打开浏览器…")
            self._release_browser()
        if self._browser is None:
            self.log("启动浏览器（用于刷新准入令牌 / Cloudflare 回退）…")
            self._browser = BrowserSession(self.settings, minimized=minimized,
                                           log=self.log)
            self._owns_browser = True
        self._browser.start()
        return self._browser

    def refresh_sentinel(self) -> SentinelTokens:
        """回浏览器重新抓一轮三条哨兵令牌，并更新凭据。

        **用完就把浏览器关掉**：它是可见的重型窗口，令牌到手后就没有存在价值了。
        关掉不会削弱 Cloudflare 回退 —— 回退走 ``_browser_fetch``，会按需重开。
        """
        session = self.ensure_browser()
        try:
            credentials = session.refresh_credentials()
        finally:
            self._release_browser()

        self.credentials.sentinel = credentials.sentinel
        # Cookie 也可能在这轮被轮换，一并更新
        if credentials.cookies:
            self.credentials.cookies = credentials.cookies
        self.credentials.captured_at = time.time()

        # 账号身份必须和 Cookie **成套**更新。
        #
        # 曾经的写法是"只在没有时才填"，于是一旦浏览器 profile 里的会话换了人
        # （比如用户用另一个账号登录过），就会出现"account_id 还是旧的、Cookie
        # 已经是新的"——而 account_id 会被当成 ``chatgpt-account-id`` 请求头发出去，
        # 结果是**拿 A 的账号头配 B 的会话**，请求打到错误的账号上。
        new_account = credentials.account_id
        if new_account and new_account != self.credentials.account_id:
            if self.credentials.account_id:
                self.log(f"注意：浏览器里的会话属于另一个账号"
                         f"（{self.credentials.account_id[:8]}… → "
                         f"{new_account[:8]}…），已跟着换过去")
            self.credentials.account_id = new_account
            # bearer 也是绑定账号的，换了账号就不能留旧的
            self.credentials.bearer = credentials.bearer
        elif not self.credentials.bearer and credentials.bearer:
            self.credentials.bearer = credentials.bearer
        self._web = None                      # 让客户端用新凭据重建
        if self.credentials.sentinel is None:
            self.log("警告：这一轮仍未抓到哨兵令牌，对话请求可能被拒")
        return self.credentials.sentinel or SentinelTokens(
            chat_requirements="", proof="", turnstile="", issued_at=0.0)

    def _release_browser(self) -> None:
        """关闭浏览器窗口（幂等）。

        刻意**不**在这里顺手清掉 ``self._transport``：回退用的是惰性取数函数，
        浏览器关了它照样能在需要时重开，不需要重建传输层。
        """
        if self._browser is None:
            return
        self._browser.close()
        self._browser = None
        self.log("已关闭浏览器窗口（需要时会自动重新打开）")

    def _sentinel_is_fresh(self) -> bool:
        """能否直接拿现有令牌发请求。

        除了过期，还必须检查 ``consumed`` —— 哨兵令牌是**一次性**的
        （见 ``SentinelTokens`` 的说明）。忽略这一点就会"第一次成功、
        第二次 403"，而且看起来像随机故障。
        """
        tokens = self.credentials.sentinel
        if tokens is None or not tokens.chat_requirements:
            return False
        if tokens.consumed:
            return False
        return tokens.age() < (480.0 - SENTINEL_REFRESH_MARGIN)

    def ensure_sentinel(self) -> None:
        if not self._sentinel_is_fresh():
            tokens = self.credentials.sentinel
            if tokens is not None:
                if tokens.consumed:
                    self.log("准入令牌已被上一次发送消耗（令牌是一次性的），"
                             "重新获取…")
                else:
                    self.log(f"准入令牌已过 {tokens.age():.0f} 秒，重新获取…")
            self.refresh_sentinel()

    def _mark_sentinel_consumed(self) -> None:
        """把当前这批令牌标记为已用掉。

        只要向 ``f/conversation`` 发过一次（无论成功与否），服务端就见过它们了，
        不能再赌它还有效 —— 重取的代价只是几秒，猜错的代价是一次 403。
        """
        tokens = self.credentials.sentinel
        if tokens is not None and not tokens.consumed:
            tokens.consumed = True

    # --- 传输层 -------------------------------------------------------

    def _browser_fetch(self, **kwargs):
        """给 Cloudflare 回退用的取数函数：**按需**启动浏览器。

        这里必须是惰性的，不能直接绑 ``self._browser.fetch_in_context``：
        浏览器一关，那种绑法就永久失效了 —— 而且**不会报错**，直到真的被
        Cloudflare 拦住才发现回退早就没了。
        """
        session = self.ensure_browser()
        return session.fetch_in_context(**kwargs)

    def _build_transport(self) -> Transport:
        primary = HttpTransport(impersonate=self.settings.impersonate,
                                proxy=self.settings.proxy)
        # 始终挂上回退：它自己会在被拦时按需启动浏览器
        fallback = BrowserTransport(self._browser_fetch)
        return FallbackTransport(
            primary, fallback,
            on_fallback=lambda url: self.log(
                f"被 Cloudflare 拦截，改用浏览器上下文重发：{url[:80]}"),
            challenge_solver=self._solve_challenge)

    def _solve_challenge(self, url: str) -> bool:
        """两条通道都被拦时：把验证页渲染出来 → 等用户 → 重读 Cookie。

        返回 True 表示"用户说已经过了，可以重试"。任何一步出问题都返回 False，
        让传输层抛出那条说人话的错误，而不是把 403 丢给业务层去猜。

        整个方法都在**持有 Playwright 的那个线程**里执行（CLI 是主线程，
        GUI 是工作线程）—— ``challenge_prompt`` 负责把"问用户"这件事安全地
        转交给主线程。
        """
        if self.challenge_prompt is None:
            return False
        try:
            # 这里**必须**让用户看见：他得在窗口里点验证。所以不最小化。
            session = self.ensure_browser(minimized=False)
            session.open_for_challenge(url)
        except Exception as exc:  # noqa: BLE001 - 打不开浏览器就如实失败
            self.log(f"无法为人工验证打开浏览器：{exc!r}")
            return False

        if not self.challenge_prompt(url):
            self.log("已放弃本次人机验证")
            return False

        self._reload_cookies_from_browser(session)
        return True

    def _reload_cookies_from_browser(self, session: BrowserSession) -> None:
        """把浏览器里的 Cookie 重新读进来。

        这一步不能省：用户在浏览器里过完验证后，``cf_clearance`` 是在**浏览器**
        里被刷新的，我们手里的快照还是旧的 —— 不重读的话，重试会拿旧 Cookie
        再撞一次墙。
        """
        try:
            cookies = {cookie["name"]: cookie["value"]
                       for cookie in session.read_cookies()}
        except Exception as exc:  # noqa: BLE001
            self.log(f"重读 Cookie 失败：{exc!r}")
            return
        if not cookies:
            self.log("浏览器里没读到 Cookie，重试可能仍被拦")
            return
        self.credentials.cookies = cookies
        self.credentials.captured_at = time.time()
        device_id = cookies.get("oai-did")
        if device_id:
            self.credentials.device_id = device_id
        self._web = None                     # 让客户端用新 Cookie 重建
        self.log(f"已从浏览器重读 {len(cookies)} 个 Cookie"
                 f"（含刷新后的 cf_clearance）")

    @property
    def web(self) -> ChatGptWebClient:
        if self._web is None:
            if self._transport is None:
                self._transport = self._build_transport()
            self._web = ChatGptWebClient(self.credentials, self._transport,
                                         self.settings)
        return self._web

    # --- 业务 ---------------------------------------------------------

    def whoami(self) -> dict:
        return self.web.me()

    def generate_image(self, prompt: str, out: Path | str | None = None, *,
                       timeout: float | None = None,
                       poll_interval: float | None = None,
                       refresh_sentinel: bool = True) -> GenerationResult:
        """生成图片并落盘。

        **每次都会取一批新的准入令牌** —— 哨兵令牌是一次性的，不能跨次复用
        （见 ``SentinelTokens``）。所以每跑一次生图都会短暂开一下浏览器。

        若服务端返回会话失效，**不自动重登**（那会反复触发风控），
        而是抛 ``SessionExpiredError`` 让调用方决定。
        """
        if refresh_sentinel:
            self.ensure_sentinel()
        try:
            return _generate_image(self.web, prompt, out, timeout=timeout,
                                   poll_interval=poll_interval, note=self.log)
        except SentinelRejectedError:
            # 兜底：万一令牌在我们不知情的情况下被消耗了（比如同一份凭据被
            # 另一个进程用掉），重取一批再试一次。发送被 403 拒绝说明消息
            # **没有**被受理，重试不会重复消耗额度。
            if not refresh_sentinel:
                raise
            self.log("发送被拒（403），重取准入令牌后再试一次…")
            self.refresh_sentinel()
            return _generate_image(self.web, prompt, out, timeout=timeout,
                                   poll_interval=poll_interval, note=self.log)
        finally:
            # 无论成败都标记消耗 —— 服务端已经见过这批令牌了
            self._mark_sentinel_consumed()

    def close(self) -> None:
        if self._browser is not None and self._owns_browser:
            self._browser.close()
        self._browser = None

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
