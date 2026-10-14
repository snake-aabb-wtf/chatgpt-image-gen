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
                        f"{url} 被 Cloudflare 挑战拦截（{response.status_code}）")
                raise TransportError(
                    f"{url} 返回 {response.status_code}：{probe.text[:300]}")
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
                f"{url} 返回 {response.status_code}：{response.text[:300]}")
        yield from response.text.splitlines()


class FallbackTransport:
    """先走 HTTP，遇到 Cloudflare 挑战就切浏览器上下文重发。"""

    def __init__(self, primary: Transport, fallback: Transport,
                 on_fallback: Callable[[str], None] | None = None) -> None:
        self.primary = primary
        self.fallback = fallback
        self.on_fallback = on_fallback
        self.fallback_count = 0

    def _note(self, url: str) -> None:
        self.fallback_count += 1
        if self.on_fallback:
            self.on_fallback(url)

    def request(self, method: str, url: str, *, headers: dict[str, str] | None = None,
                json: Any = None, data: bytes | str | None = None,
                timeout: float | None = None) -> TransportResponse:
        try:
            response = self.primary.request(method, url, headers=headers, json=json,
                                            data=data, timeout=timeout)
        except CloudflareChallengeError:
            self._note(url)
            return self.fallback.request(method, url, headers=headers, json=json,
                                         data=data, timeout=timeout)
        if response.looks_like_cloudflare_challenge():
            self._note(url)
            return self.fallback.request(method, url, headers=headers, json=json,
                                         data=data, timeout=timeout)
        return response

    def stream_lines(self, method: str, url: str, *,
                     headers: dict[str, str] | None = None,
                     json: Any = None,
                     timeout: float | None = None) -> Iterator[str]:
        yielded = False
        try:
            for line in self.primary.stream_lines(method, url, headers=headers,
                                                  json=json, timeout=timeout):
                yielded = True
                yield line
            return
        except CloudflareChallengeError:
            if yielded:
                # 流已经开始产出再失败，**绝不能**回退重发：那会重复发送同一条
                # 消息、重复消耗一次生图额度。这里如实抛出。
                raise
            self._note(url)
        yield from self.fallback.stream_lines(method, url, headers=headers,
                                              json=json, timeout=timeout)
