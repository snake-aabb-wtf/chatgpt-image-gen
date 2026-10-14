"""chatgpt.com Web 端接口薄封装（对照 docs/04 的接口清单）。

设计取舍：
* 只封装本工具真正用到的端点，不做"全集 API 客户端"—— YAGNI。
* 每个方法只做"发请求 + 解析 + 把异常翻译成领域异常"，不含业务编排
  （编排在 ``cgpt.api.image``）。
* **Cookie 只在同域请求里出现**。下载签名 URL 前强制校验主机名，
  见 ``assert_safe_download_url``。
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Iterator
from urllib.parse import urlparse

from cgpt.api.sse import StreamFindings, consume_sse
from cgpt.api.transport import Transport, TransportResponse
from cgpt.config import FEATURE_IMAGE_GEN, Settings
from cgpt.errors import (
    CgptError,
    ImageGenUnavailableError,
    NoImageProducedError,
    SentinelRejectedError,
    SessionExpiredError,
    TransportError,
    UnsafeDownloadURLError,
)
from cgpt.models import Credentials, ImageAsset, SentinelTokens

BASE_URL = "https://chatgpt.com"

#: 允许携带 Cookie 去下载的主机（含子域）
ALLOWED_DOWNLOAD_HOSTS: tuple[str, ...] = ("chatgpt.com",)

SENTINEL_HEADERS = {
    "chat_requirements": "openai-sentinel-chat-requirements-token",
    "proof": "openai-sentinel-proof-token",
    "turnstile": "openai-sentinel-turnstile-token",
}


def assert_safe_download_url(url: str) -> str:
    """校验下载 URL 的主机名在白名单内，否则抛 ``UnsafeDownloadURLError``。

    这是一条**凭据泄漏防护**：``download_url`` 由服务端下发，如果它指向第三方
    域而我们照样把会话 Cookie 发过去，等同于把账号交给对方。必须在发请求**之前**
    失败，而不是"先发了再说"。
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise UnsafeDownloadURLError(
            f"下载 URL 的协议不受支持：{parsed.scheme!r}（{url[:120]}）")
    host = (parsed.hostname or "").lower()
    if not host:
        raise UnsafeDownloadURLError(f"下载 URL 没有主机名：{url[:120]}")
    if not any(host == allowed or host.endswith("." + allowed)
               for allowed in ALLOWED_DOWNLOAD_HOSTS):
        raise UnsafeDownloadURLError(
            f"下载 URL 指向非白名单主机 {host!r}，拒绝携带会话凭据请求：{url[:120]}\n"
            f"白名单：{', '.join(ALLOWED_DOWNLOAD_HOSTS)}")
    return url


@dataclass
class AccountInfo:
    account_id: str | None
    plan: str | None
    features: set[str]
    raw: dict[str, Any]

    @property
    def can_generate_images(self) -> bool:
        return FEATURE_IMAGE_GEN in self.features


class ChatGptWebClient:
    """把 ``Credentials`` + ``Transport`` 组合成可用的 chatgpt.com 客户端。"""

    def __init__(self, credentials: Credentials, transport: Transport,
                 settings: Settings | None = None) -> None:
        self.credentials = credentials
        self.transport = transport
        self.settings = settings or Settings()

    # --- 请求构造 -----------------------------------------------------

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = self.settings.request_headers(self.credentials)
        headers["cookie"] = self.credentials.cookie_header()
        if extra:
            headers.update(extra)
        return headers

    def sentinel_headers(self, tokens: SentinelTokens | None = None
                         ) -> dict[str, str]:
        """三条 ``openai-sentinel-*`` 头。

        它们**必须成套**（同一次 finalize 产出）—— 混用不同轮的令牌会被拒
        （docs/02 §4.4 专门记过这个坑）。
        """
        tokens = tokens or self.credentials.sentinel
        if tokens is None:
            return {}
        return {
            SENTINEL_HEADERS["chat_requirements"]: tokens.chat_requirements,
            SENTINEL_HEADERS["proof"]: tokens.proof,
            SENTINEL_HEADERS["turnstile"]: tokens.turnstile,
        }

    def _url(self, path: str) -> str:
        return path if path.startswith("http") else BASE_URL + path

    def _get_json(self, path: str, *, extra_headers: dict[str, str] | None = None
                  ) -> dict[str, Any]:
        response = self.transport.request("GET", self._url(path),
                                          headers=self._headers(extra_headers))
        self._raise_for_session(response, path)
        try:
            return response.json()
        except ValueError as exc:
            raise CgptError(
                f"{path} 返回的不是 JSON（{response.status_code}）："
                f"{response.text[:200]}") from exc

    def _post_json(self, path: str, payload: dict[str, Any], *,
                   extra_headers: dict[str, str] | None = None
                   ) -> tuple[dict[str, Any], TransportResponse]:
        response = self.transport.request("POST", self._url(path),
                                          headers=self._headers(extra_headers),
                                          json=payload)
        self._raise_for_session(response, path)
        try:
            return response.json(), response
        except ValueError as exc:
            raise CgptError(
                f"{path} 返回的不是 JSON（{response.status_code}）："
                f"{response.text[:200]}") from exc

    @staticmethod
    def _raise_for_session(response: TransportResponse, path: str) -> None:
        if response.status_code in (401, 403) and not \
                response.looks_like_cloudflare_challenge():
            raise SessionExpiredError(
                f"{path} 返回 {response.status_code}，会话可能已失效。\n"
                f"重新登录：python -m cgpt login --email <邮箱> --password <密码> "
                f"--totp-secret <2FA密钥>\n"
                f"响应片段：{response.text[:200]}")

    # --- 只读端点 -----------------------------------------------------

    def accounts_check(self) -> AccountInfo:
        """``accounts/check`` —— 账号身份与能力开关的唯一来源（docs/03 §3）。"""
        payload = self._get_json("/backend-api/accounts/check/v4-2023-04-27")
        accounts = payload.get("accounts") or {}
        default = accounts.get("default") or {}
        account = default.get("account") or {}
        features = set(default.get("features") or [])
        account_id = account.get("account_id") or self.credentials.account_id
        plan = account.get("plan_type")
        if account_id and not self.credentials.account_id:
            self.credentials.account_id = account_id
        return AccountInfo(account_id=account_id, plan=plan, features=features,
                           raw=payload)

    def require_image_gen(self) -> AccountInfo:
        info = self.accounts_check()
        if not info.can_generate_images:
            raise ImageGenUnavailableError(
                f"该账号没有生图能力：features 里缺少 {FEATURE_IMAGE_GEN!r}。\n"
                f"（这是服务端下发的开关，客户端无法绕过；"
                f"docs/03 §3 记录了它出现在 accounts/check 的响应里）")
        return info

    def me(self) -> dict[str, Any]:
        return self._get_json("/backend-api/me")

    def conversation_init(self) -> dict[str, Any]:
        """会话初始化 / 配额（docs/04 §2.3）。"""
        payload, _ = self._post_json("/backend-api/conversation/init", {
            "conversation_id": None,
            "conversation_origin": None,
            "gizmo_id": None,
            "requested_default_model": None,
            "system_hints": None,
            "timezone": self.settings.timezone,
            "timezone_offset_min": self.settings.timezone_offset_min,
        })
        return payload

    def image_gen_remaining(self) -> int | None:
        """从 ``conversation/init`` 的 ``limits_progress`` 读生图剩余额度。"""
        payload = self.conversation_init()
        for entry in payload.get("limits_progress") or []:
            if isinstance(entry, dict) and entry.get("feature_name") == "image_gen":
                remaining = entry.get("remaining")
                return remaining if isinstance(remaining, int) else None
        return None

    # --- 发送消息 -----------------------------------------------------

    def prepare_conversation(
        self,
        prompt: str | None = None,
        *,
        parent_message_id: str = "client-created-root",
        conversation_id: str | None = None,
    ) -> str | None:
        """草稿预发送，返回 ``conduit_token``（60 秒，可选携带）。

        失败不致命 —— 抓包里 chat 会话就没带它也成功了（docs/02 §4.2），
        所以这里把异常吞掉只返回 None。真正要紧的是别让它拖慢发送。
        """
        body: dict[str, Any] = {
            "action": "next",
            "is_do_not_remember": False,
            "model": self.settings.model,
            "parent_message_id": parent_message_id,
            "timezone": self.settings.timezone,
            "timezone_offset_min": self.settings.timezone_offset_min,
            "client_contextual_info": {
                "app_name": "chatgpt.com",
                "app_surface": "chat",
                "has_web_push_capabilities": False,
                "web_push_notification_permission": "default",
            },
            "supported_encodings": ["v1"],
            "client_prepare_state": "sent",
            "client_prepare_dispatch": "debounced",
            "client_prepare_source": "context_change",
        }
        if prompt:
            body["partial_query"] = {
                "id": str(uuid.uuid4()),
                "author": {"role": "user"},
                "content": {"content_type": "text", "parts": [prompt]},
            }
        if conversation_id:
            body["conversation_id"] = conversation_id
        try:
            payload, _ = self._post_json("/backend-api/f/conversation/prepare", body)
        except CgptError:
            return None
        token = payload.get("conduit_token")
        return token if isinstance(token, str) and token else None

    def send_message(self, prompt: str, *,
                     parent_message_id: str = "client-created-root",
                     conversation_id: str | None = None,
                     conduit_token: str | None = None,
                     sentinel: SentinelTokens | None = None,
                     timeout: float | None = None) -> StreamFindings:
        """``POST /backend-api/f/conversation``（SSE）—— 生图就走这里。

        请求体里**没有**任何 image_gen / tools 字段：是否出图由服务端依据
        feature 开关 + 用户意图决定（docs/03 §4.3）。
        """
        message_id = str(uuid.uuid4())
        body: dict[str, Any] = {
            "turn_attribution": {"turn_trigger": "composer"},
            "action": "next",
            "is_do_not_remember": False,
            "model": self.settings.model,
            "parent_message_id": parent_message_id,
            "timezone": self.settings.timezone,
            "timezone_offset_min": self.settings.timezone_offset_min,
            "client_contextual_info": {
                "app_name": "chatgpt.com",
                "app_surface": "chat",
                "has_web_push_capabilities": False,
                "web_push_notification_permission": "default",
            },
            "messages": [{
                "id": message_id,
                "author": {"role": "user", "name": None, "metadata": {}},
                "content": {"content_type": "text", "parts": [prompt]},
                "create_time": time.time(),
                "recipient": "all",
                "status": "finished_successfully",
                "end_turn": None,
                "weight": 1,
                "channel": None,
                "metadata": {},
            }],
            "supported_encodings": ["v1"],
            "genui_state_snapshots": [],
            "client_prepare_state": "success" if conduit_token else "sent",
        }
        if conversation_id:
            body["conversation_id"] = conversation_id

        extra = self.sentinel_headers(sentinel)
        extra["x-oai-turn-trace-id"] = str(uuid.uuid4())
        if conduit_token:
            extra["x-conduit-token"] = conduit_token

        lines = self.transport.stream_lines(
            "POST", self._url("/backend-api/f/conversation"),
            headers=self._headers(extra), json=body, timeout=timeout)
        try:
            findings = consume_sse(lines)
        except TransportError as exc:
            # 403 且不是 CF 边缘挑战 → 服务端不受理这次发送。
            # 最常见成因就是准入令牌已被上一次请求消耗（令牌是一次性的）。
            if getattr(exc, "status_code", None) == 403:
                raise SentinelRejectedError(
                    "服务端拒绝了这次发送（403）。\n"
                    "最常见的原因是准入令牌已被上一次请求消耗 —— "
                    "三条 openai-sentinel-* 是**一次性**的，同一批只能用一次。\n"
                    f"详情：{exc}") from exc
            raise
        if findings.server_errors:
            raise CgptError(
                "服务端在事件流里报了错：" + "; ".join(findings.server_errors[:3]))
        return findings

    # --- 取图 ---------------------------------------------------------

    def get_conversation(self, conversation_id: str, *,
                         num_turns: int = 10) -> dict[str, Any]:
        """会话详情 —— SSE 正文可能缺失时的兜底找图路径（docs/03 §0 边界 2）。"""
        return self._get_json(
            f"/backend-api/conversations/{conversation_id}"
            f"?num_turns={num_turns}&include_has_versions=true")

    def files_download(self, file_id: str, conversation_id: str, *,
                       include_library_file_state: bool = False) -> str:
        """换取服务端签名的 ``download_url``（docs/03 §4.9 第 1 步）。"""
        query = (f"?conversation_id={conversation_id}"
                 f"&download_intent=false&inline=true")
        if include_library_file_state:
            query += "&include_library_file_state=true"
        payload = self._get_json(f"/backend-api/files/download/{file_id}{query}")
        url = payload.get("download_url")
        if not isinstance(url, str) or not url:
            raise CgptError(
                f"files/download 没有返回 download_url：{json.dumps(payload)[:200]}")
        return url

    def download_bytes(self, url: str, *, timeout: float | None = None) -> bytes:
        """用签名 URL 取字节（docs/03 §4.9 第 2 步）。

        该端点的授权模型是"签名 URL"而非会话头（docs/04 §3.2），但因为我们
        带的是同域 Cookie，所以**必须先校验主机名**。
        """
        assert_safe_download_url(url)
        # 该端点只需要少数几个头（docs/03 §3），不带 oai-did 等设备头
        headers = {
            "accept": "image/avif,image/webp,image/png,image/*,*/*;q=0.8",
            "referer": "https://chatgpt.com/",
            "user-agent": self.credentials.user_agent or self.settings.user_agent,
            "cookie": self.credentials.cookie_header(),
        }
        if self.credentials.account_id:
            headers["chatgpt-account-id"] = self.credentials.account_id
        headers["originator"] = self.settings.originator

        response = self.transport.request("GET", url, headers=headers,
                                          timeout=timeout)
        if not response.ok:
            raise TransportError(
                f"下载图片失败（{response.status_code}）：{response.text[:200]}")
        return response.content


def messages_from_conversation(payload: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """从会话详情里产出消息（``messages[]`` 或 ``mapping`` 两种形态都支持）。"""
    messages = payload.get("messages")
    if isinstance(messages, list):
        yield from (m for m in messages if isinstance(m, dict))
    mapping = payload.get("mapping")
    if isinstance(mapping, dict):
        for node in mapping.values():
            if isinstance(node, dict) and isinstance(node.get("message"), dict):
                yield node["message"]


def find_assets_in_conversation(payload: dict[str, Any]) -> list[ImageAsset]:
    """在会话详情里找图片资产指针，保持出现顺序。"""
    from cgpt.api.sse import extract_assets

    assets = extract_assets(payload)
    if assets:
        return assets
    collected: list[ImageAsset] = []
    for message in messages_from_conversation(payload):
        collected.extend(extract_assets(message))
    return collected


__all__ = [
    "ALLOWED_DOWNLOAD_HOSTS",
    "BASE_URL",
    "SENTINEL_HEADERS",
    "AccountInfo",
    "ChatGptWebClient",
    "NoImageProducedError",
    "assert_safe_download_url",
    "find_assets_in_conversation",
    "messages_from_conversation",
]
