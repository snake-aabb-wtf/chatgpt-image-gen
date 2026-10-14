"""库入口：把浏览器凭据获取与 HTTP 业务请求串成一个对象。

典型用法::

    from cgpt import Client

    client = Client.login(email=..., password=..., totp_secret=...)
    client.save(".cgpt/credentials.json")
    result = client.generate_image("生成一张地球图片", out="earth.png")

或者复用已登录的凭据::

    client = Client.from_credentials(".cgpt/credentials.json")
    client.generate_image("...", out="a.png")
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
from cgpt.errors import SessionExpiredError
from cgpt.models import Credentials, GenerationResult, SentinelTokens

#: 哨兵令牌剩余寿命低于这个值就视为需要刷新（服务端 540 秒，留 60 秒余量）
SENTINEL_REFRESH_MARGIN = 60.0


class Client:
    """ChatGPT 生图客户端。"""

    def __init__(self, credentials: Credentials, *,
                 settings: Settings | None = None,
                 transport: Transport | None = None,
                 browser: BrowserSession | None = None,
                 log: Callable[[str], None] | None = None) -> None:
        self.credentials = credentials
        self.settings = settings or Settings()
        self.log = log or (lambda _message: None)
        self._browser = browser
        self._owns_browser = False
        self._transport = transport
        self._web: ChatGptWebClient | None = None

    # --- 构造 ---------------------------------------------------------

    @classmethod
    def login(cls, *, email: str, password: str, totp_secret: str,
              settings: Settings | None = None, headless: bool | None = None,
              log: Callable[[str], None] | None = None) -> "Client":
        """用账密 + TOTP 登录并抓取凭据（会启动真实浏览器）。"""
        settings = settings or Settings()
        session = BrowserSession(settings, headless=headless, log=log)
        session.start()
        client = cls(credentials=Credentials(), settings=settings,
                     browser=session, log=log)
        client._owns_browser = True
        client.credentials = session.login(email, password, totp_secret)
        return client

    @classmethod
    def from_credentials(cls, path: Path | str | None = None, *,
                         settings: Settings | None = None,
                         log: Callable[[str], None] | None = None) -> "Client":
        """从磁盘读凭据（不启动浏览器；需要时才惰性启动）。"""
        settings = settings or Settings()
        if path is not None:
            settings = settings.model_copy(update={"credentials_path": Path(path)})
        credentials = load_credentials(settings.credentials_path)
        return cls(credentials=credentials, settings=settings, log=log)

    # --- 持久化 -------------------------------------------------------

    def save(self, path: Path | str | None = None) -> Path:
        target = Path(path) if path is not None else self.settings.credentials_path
        return save_credentials(self.credentials, target)

    # --- 浏览器（惰性） -----------------------------------------------

    def ensure_browser(self) -> BrowserSession:
        """按需启动浏览器。用于刷新哨兵令牌与 Cloudflare 回退。"""
        if self._browser is None:
            self.log("启动浏览器（用于刷新准入令牌 / Cloudflare 回退）…")
            self._browser = BrowserSession(self.settings, log=self.log)
            self._browser.start()
            self._owns_browser = True
        return self._browser

    def refresh_sentinel(self) -> SentinelTokens:
        """回浏览器重新抓一轮三条哨兵令牌，并更新凭据。"""
        session = self.ensure_browser()
        credentials = session.refresh_credentials()
        self.credentials.sentinel = credentials.sentinel
        # Cookie 也可能在这轮被轮换，一并更新
        if credentials.cookies:
            self.credentials.cookies = credentials.cookies
        self.credentials.captured_at = time.time()
        if not self.credentials.bearer and credentials.bearer:
            self.credentials.bearer = credentials.bearer
        if not self.credentials.account_id and credentials.account_id:
            self.credentials.account_id = credentials.account_id
        self._web = None                      # 让客户端用新凭据重建
        if self.credentials.sentinel is None:
            self.log("警告：这一轮仍未抓到哨兵令牌，对话请求可能被拒")
        return self.credentials.sentinel or SentinelTokens(
            chat_requirements="", proof="", turnstile="", issued_at=0.0)

    def _sentinel_is_fresh(self) -> bool:
        tokens = self.credentials.sentinel
        if tokens is None or not tokens.chat_requirements:
            return False
        return tokens.age() < (480.0 - SENTINEL_REFRESH_MARGIN)

    def ensure_sentinel(self) -> None:
        if not self._sentinel_is_fresh():
            if self.credentials.sentinel is not None:
                self.log(f"准入令牌已过 {self.credentials.sentinel.age():.0f} 秒，"
                         f"重新获取…")
            self.refresh_sentinel()

    # --- 传输层 -------------------------------------------------------

    def _build_transport(self) -> Transport:
        primary = HttpTransport(impersonate=self.settings.impersonate,
                                proxy=self.settings.proxy)
        if self._browser is None:
            return primary
        fallback = BrowserTransport(self._browser.fetch_in_context)
        return FallbackTransport(
            primary, fallback,
            on_fallback=lambda url: self.log(
                f"被 Cloudflare 拦截，改用浏览器上下文重发：{url[:80]}"))

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

        会自动确保准入令牌新鲜；若服务端返回会话失效，**不自动重登**
        （那会反复触发风控），而是抛 ``SessionExpiredError`` 让调用方决定。
        """
        if refresh_sentinel:
            self.ensure_sentinel()
        try:
            return _generate_image(self.web, prompt, out, timeout=timeout,
                                   poll_interval=poll_interval, note=self.log)
        except SessionExpiredError:
            raise

    def close(self) -> None:
        if self._browser is not None and self._owns_browser:
            self._browser.close()
        self._browser = None

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
