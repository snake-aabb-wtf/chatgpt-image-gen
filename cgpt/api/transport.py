"""传输层：curl_cffi 走 HTTP，被 Cloudflare 拦时回退到浏览器上下文。

为什么用 curl_cffi 而不是 requests/httpx：``cf_clearance`` 是按
**顶层站点分区**（CHIPS）绑定，并且 Cloudflare 会同时校验 TLS 指纹
（JA3/JA4）与 HTTP/2 指纹。curl_cffi 能冒充真实 Chrome 的这两层指纹 ——
这是"带上抓来的 Cookie 直接发请求"能成立的前提。

即便如此也不保证一定成功，所以设计了 ``FallbackTransport``：一旦发现
``403 + cf-mitigated: challenge``，就用 ``page.evaluate(fetch)`` 在**真实
浏览器上下文里**重发同一个请求（那里天然带着有效凭据与指纹），
调用方完全无感。

**安全约束**：Cookie 只随显式的请求头传递，传输层绝不自动附加任何凭据。
URL 白名单由 ``ChatGptWebClient`` 负责（见 ``UnsafeDownloadURLError``）。
"""

from __future__ import annotations

import json as json_module
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, Protocol

from cgpt.errors import CloudflareChallengeError, TransportError

#: 判定 Cloudflare 挑战的响应特征
CHALLENGE_HEADER = "cf-mitigated"
CHALLENGE_HEADER_VALUE = "challenge"
_CHALLENGE_BODY_MARKERS = ("Just a moment", "cf-chl", "challenge-platform",
                           "Attention Required")

DEFAULT_CONNECT_TIMEOUT = 15.0
DEFAULT_READ_TIMEOUT = 120.0
DEFAULT_IMPERSONATE = "chrome"

#: 挑战求解回调：收到被拦的 URL，返回 True 表示"用户已完成验证，可以重试"。
#: 由 ``Client`` 提供 —— 它负责把验证页渲染出来、等用户、再重读 Cookie。
ChallengeSolver = Callable[[str], bool]


def challenge_message(url: str, *, solved: bool) -> str:
    """两条通道都被拦时的错误文案。

    措辞刻意写成"下一步该做什么"，而不是把 403 丢出去让上层去猜。
    """
    if solved:
        return (
            f"完成人机验证后重试，{url} 仍被 Cloudflare 拦截。\n"
            f"浏览器窗口保持打开，可以看看里面的页面是否已经正常加载；\n"
            f"若仍显示验证页，请再完成一次，然后重新执行刚才的操作。")
    return (
        f"{url} 被 Cloudflare 人机验证拦住，且用浏览器上下文重发也没过去。\n"
        f"这通常意味着 Cloudflare 要求**人工**完成一次验证（不是指纹问题）。\n"
        f"浏览器窗口已打开在该地址上，请在里面完成验证后重试。")


#: 出错时值得打出来的响应头 —— 判断"边缘挑战 vs 应用层拒绝"全靠它们
_DIAGNOSTIC_HEADERS = ("cf-mitigated", "cf-ray", "server", "content-type",
                       "www-authenticate", "x-request-id")


def describe_response(response: TransportResponse, limit: int = 300) -> str:
    """把响应压成一行可诊断的摘要（状态码 + 关键头 + 正文片段）。

    早先只打正文，而 ``f/conversation`` 被拒时正文是**空的** ——
    结果错误信息成了"返回 403："后面什么都没有，完全没法查。
    """
    bits = [f"{name}={response.header(name)}"
            for name in _DIAGNOSTIC_HEADERS if response.header(name)]
    detail = str(response.status_code)
    if bits:
        detail += " [" + ", ".join(bits) + "]"
    body = response.text[:limit].replace("\n", " ").strip()
    detail += f" {body}" if body else " （空响应体）"
    return detail


@dataclass
class TransportResponse:
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    content: bytes = b""

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json_module.loads(self.text)

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    def looks_like_cloudflare_challenge(self) -> bool:
        if self.status_code not in (403, 503):
            return False
        if (self.header(CHALLENGE_HEADER) or "").lower() == CHALLENGE_HEADER_VALUE:
            return True
        if self.header("server") == "cloudflare":
            body = self.text[:4000]
            return any(marker in body for marker in _CHALLENGE_BODY_MARKERS)
        return False


def _normalize_headers(raw: Any) -> dict[str, str]:
    """把各种 headers 表示统一成小写键的普通 dict。"""
    if raw is None:
        return {}
    if hasattr(raw, "items"):
        return {str(k).lower(): str(v) for k, v in raw.items()}
    return {}


class Transport(Protocol):
    def request(self, method: str, url: str, *, headers: dict[str, str] | None = None,
                json: Any = None, data: bytes | str | None = None,
                timeout: float | None = None) -> TransportResponse:
        ...

    def stream_lines(self, method: str, url: str, *,
                     headers: dict[str, str] | None = None,
                     json: Any = None,
                     timeout: float | None = None) -> Iterator[str]:
        ...


class HttpTransport:
    """curl_cffi 实现：HTTP/2 + Chrome TLS 指纹冒充。"""

    def __init__(self, *, impersonate: str = DEFAULT_IMPERSONATE,
                 proxy: str | None = None) -> None:
        try:
            from curl_cffi import requests as curl_requests
        except ImportError as exc:  # pragma: no cover - 依赖缺失时的清晰报错
            raise TransportError(
                "缺少 curl_cffi 依赖。安装：pip install curl_cffi") from exc

        self._curl = curl_requests
        self.impersonate = impersonate
        self._session = curl_requests.Session(impersonate=impersonate)
        if proxy:
            self._session.proxies = {"http": proxy, "https": proxy}

    # -- 内部 ---------------------------------------------------------

    def _timeout(self, timeout: float | None):
        read = timeout if timeout is not None else DEFAULT_READ_TIMEOUT
        return (DEFAULT_CONNECT_TIMEOUT, read)

    # -- 接口 ---------------------------------------------------------

    def request(self, method: str, url: str, *, headers: dict[str, str] | None = None,
                json: Any = None, data: bytes | str | None = None,
                timeout: float | None = None) -> TransportResponse:
        try:
            response = self._session.request(
                method.upper(), url, headers=headers or {}, json=json, data=data,
                timeout=self._timeout(timeout),
            )
        except Exception as exc:  # curl_cffi 抛的异常类型较多，统一收口
            raise TransportError(f"{method.upper()} {url} 失败：{exc}") from exc
        return TransportResponse(status_code=response.status_code,
                                 headers=_normalize_headers(response.headers),
                                 content=response.content or b"")

    def stream_lines(self, method: str, url: str, *,
                     headers: dict[str, str] | None = None,
                     json: Any = None,
                     timeout: float | None = None) -> Iterator[str]:
        try:
            # 用 session.stream() 而不是 session.request(stream=True)：
            # curl_cffi 的 Response 不是上下文管理器，stream() 才是。
            context = self._session.stream(
                method.upper(), url, headers=headers or {}, json=json,
                timeout=self._timeout(timeout))
        except Exception as exc:
            raise TransportError(f"{method.upper()} {url} 失败：{exc}") from exc

        with context as response:
            if response.status_code >= 400:
                probe = TransportResponse(
                    status_code=response.status_code,
                    headers=_normalize_headers(response.headers),
                    content=response.content or b"")
                if probe.looks_like_cloudflare_challenge():
                    raise CloudflareChallengeError(
                        f"{url} 被 Cloudflare 挑战拦截"
                        f"（{describe_response(probe)}）")
                raise TransportError(
                    f"{url} 返回 {describe_response(probe)}",
                    status_code=response.status_code)
            for line in response.iter_lines():
                yield line.decode("utf-8", errors="replace") \
                    if isinstance(line, bytes) else line


class BrowserTransport:
    """在真实浏览器页面上下文里发请求（Cloudflare 回退路径）。

    ``fetch_in_context`` 由 ``cgpt.auth.browser.BrowserSession`` 提供：
    它调用 ``page.evaluate`` 执行 ``fetch``，因此天然带着该页面的
    Cookie、TLS 指纹与 HTTP/2 指纹。
    """

    def __init__(self, fetch_in_context: Callable[..., dict[str, Any]]) -> None:
        self._fetch = fetch_in_context

    def request(self, method: str, url: str, *, headers: dict[str, str] | None = None,
                json: Any = None, data: bytes | str | None = None,
                timeout: float | None = None) -> TransportResponse:
        body = None
        if json is not None:
            body = json_module.dumps(json, ensure_ascii=False)
        elif data is not None:
            body = data.decode("utf-8") if isinstance(data, bytes) else data

        try:
            result = self._fetch(method=method.upper(), url=url,
                                 headers=headers or {}, body=body, timeout=timeout)
        except Exception as exc:
            raise TransportError(f"浏览器上下文请求失败 {url}：{exc}") from exc

        return TransportResponse(
            status_code=int(result.get("status", 0)),
            headers={str(k).lower(): str(v) for k, v in (result.get("headers") or {}).items()},
            content=str(result.get("body") or "").encode("utf-8"),
        )

    def stream_lines(self, method: str, url: str, *,
                     headers: dict[str, str] | None = None,
                     json: Any = None,
                     timeout: float | None = None) -> Iterator[str]:
        """浏览器里拿到的是一次性完整正文（fetch 不做流式读取），按行产出即可。"""
        response = self.request(method, url, headers=headers, json=json,
                                timeout=timeout)
        if response.looks_like_cloudflare_challenge():
            raise CloudflareChallengeError(
                f"{url} 在浏览器上下文里仍被 Cloudflare 拦截")
        if not response.ok:
            raise TransportError(
                f"{url} 返回 {describe_response(response)}",
                status_code=response.status_code)
        yield from response.text.splitlines()


class FallbackTransport:
    """先走 HTTP，被 Cloudflare 拦就切浏览器上下文重发。

    如果**两条路都被拦**，说明这不是"指纹不像浏览器"的问题，而是 Cloudflare
    真的要求人机验证。此时交给 ``challenge_solver`` 去处理（把验证页渲染出来、
    等用户点完），成功后再重试一次。

    注意：不设 solver 时**必须抛错**，不能把 403 原样交给业务层 ——
    那样业务层会去 ``json()`` 解析挑战页的 HTML，报出"返回的不是 JSON（403）"
    这种完全看不出该干什么的错误。
    """

    def __init__(self, primary: Transport, fallback: Transport, *,
                 on_fallback: Callable[[str], None] | None = None,
                 challenge_solver: ChallengeSolver | None = None) -> None:
        self.primary = primary
        self.fallback = fallback
        self.on_fallback = on_fallback
        self.challenge_solver = challenge_solver
        self.fallback_count = 0
        self.solve_count = 0

    def _note(self, url: str) -> None:
        self.fallback_count += 1
        if self.on_fallback:
            self.on_fallback(url)

    def _attempt(self, method: str, url: str, **kwargs: Any) -> TransportResponse:
        """走一遍「主通道 → 被拦则回退」，返回最后一次的响应（可能仍是挑战）。"""
        try:
            response = self.primary.request(method, url, **kwargs)
        except CloudflareChallengeError:
            self._note(url)
            return self.fallback.request(method, url, **kwargs)
        if response.looks_like_cloudflare_challenge():
            self._note(url)
            return self.fallback.request(method, url, **kwargs)
        return response

    def _solve(self, url: str) -> bool:
        if self.challenge_solver is None:
            return False
        self.solve_count += 1
        return bool(self.challenge_solver(url))

    def request(self, method: str, url: str, *, headers: dict[str, str] | None = None,
                json: Any = None, data: bytes | str | None = None,
                timeout: float | None = None) -> TransportResponse:
        kwargs: dict[str, Any] = {"headers": headers, "json": json, "data": data,
                                  "timeout": timeout}
        response = self._attempt(method, url, **kwargs)
        if not response.looks_like_cloudflare_challenge():
            return response

        if not self._solve(url):
            raise CloudflareChallengeError(challenge_message(url, solved=False))

        response = self._attempt(method, url, **kwargs)
        if response.looks_like_cloudflare_challenge():
            raise CloudflareChallengeError(challenge_message(url, solved=True))
        return response

    def _stream_once(self, method: str, url: str, *,
                     headers: dict[str, str] | None = None,
                     json: Any = None,
                     timeout: float | None = None) -> Iterator[str]:
        produced = False
        try:
            for line in self.primary.stream_lines(method, url, headers=headers,
                                                  json=json, timeout=timeout):
                produced = True
                yield line
            return
        except CloudflareChallengeError:
            if produced:
                raise
            self._note(url)
        yield from self.fallback.stream_lines(method, url, headers=headers,
                                              json=json, timeout=timeout)

    def stream_lines(self, method: str, url: str, *,
                     headers: dict[str, str] | None = None,
                     json: Any = None,
                     timeout: float | None = None) -> Iterator[str]:
        for attempt in range(2):
            yielded = False
            try:
                for line in self._stream_once(method, url, headers=headers,
                                              json=json, timeout=timeout):
                    yielded = True
                    yield line
                return
            except CloudflareChallengeError:
                if yielded:
                    # 流已开始产出：**绝不能**重发。那会重复发送同一条消息、
                    # 重复消耗一次生图额度 —— 宁可失败也不能偷偷多花一次。
                    raise
                if attempt == 1 or not self._solve(url):
                    raise CloudflareChallengeError(
                        challenge_message(url, solved=attempt == 1)) from None
                # 用户过完验证 → 循环再试一次
