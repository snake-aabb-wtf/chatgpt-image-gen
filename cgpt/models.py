"""领域模型。

全部用 pydantic，好处有两个：
1. 从磁盘读回凭据时自动校验，坏文件在**入口**就报错，而不是深入到协议代码里
   某个 KeyError；
2. `model_dump_json()` 直接就是可持久化格式，不需要手写序列化。
"""

from __future__ import annotations

import time
from pathlib import Path

from pydantic import BaseModel, Field

#: 服务端签发的哨兵令牌 TTL 是 540 秒（docs/02 §4.5），本地留 60 秒余量。
SENTINEL_TTL_SECONDS = 480.0

#: OIDC 访问令牌的 `exp - iat` 是 10 天（docs/01 §4.12.1），本地按 9 天判过期。
BEARER_TTL_SECONDS = 9 * 24 * 3600

#: `sediment://` 是 ChatGPT 内部资产 URI 方案（docs/03 §4.7）。
SEDIMENT_SCHEME = "sediment://"


class SentinelTokens(BaseModel):
    """三条 `openai-sentinel-*` 请求头的值。

    它们**必须成套使用**——同一次 `chat-requirements/finalize` 产出，
    混用不同轮的令牌会被服务端拒绝（docs/02 §4.4 专门记录过这个坑）。
    """

    chat_requirements: str  # → openai-sentinel-chat-requirements-token
    proof: str              # → openai-sentinel-proof-token
    turnstile: str          # → openai-sentinel-turnstile-token
    issued_at: float        # 本地记录时刻（服务端 expire_at 未落盘，用 TTL 近似）

    def is_fresh(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return (now - self.issued_at) < SENTINEL_TTL_SECONDS

    def age(self, now: float | None = None) -> float:
        now = time.time() if now is None else now
        return now - self.issued_at


class Credentials(BaseModel):
    """阶段 A（浏览器）抓到、阶段 B（HTTP）要用的全部凭据。"""

    cookies: dict[str, str] = Field(default_factory=dict)
    bearer: str | None = None
    account_id: str | None = None
    device_id: str | None = None          # oai-did
    sentinel: SentinelTokens | None = None
    captured_at: float = 0.0
    user_agent: str = ""
    originator: str = "chatgpt.com"

    def cookie_header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def is_bearer_expired(self, now: float | None = None) -> bool:
        if not self.bearer:
            return True
        now = time.time() if now is None else now
        return (now - self.captured_at) >= BEARER_TTL_SECONDS

    def has_session_cookie(self) -> bool:
        """NextAuth v5 的会话 Cookie 会因超过 4 KB 被分片成 .0/.1（docs/01 §4.12.2）。"""
        return any(k.startswith("__Secure-next-auth.session-token")
                   for k in self.cookies)


class ImageAsset(BaseModel):
    """一条 `image_asset_pointer` 内容项（服务端产物，客户端不可伪造）。"""

    asset_pointer: str                 # sediment://file_<id>
    file_id: str                       # file_<id>
    width: int | None = None
    height: int | None = None
    size_bytes: int | None = None
    mime_type: str | None = None
    gen_id: str | None = None

    @classmethod
    def from_part(cls, part: object) -> "ImageAsset | None":
        """从消息的 `content.parts[]` 元素构造；不是图片资产则返回 None。

        SSE 与 `GET /conversations/<id>` 两处的结构完全一致，所以复用同一个映射。
        """
        if not isinstance(part, dict):
            return None
        if part.get("content_type") != "image_asset_pointer":
            return None
        pointer = part.get("asset_pointer")
        if not isinstance(pointer, str) or not pointer:
            return None
        file_id = pointer[len(SEDIMENT_SCHEME):] if pointer.startswith(
            SEDIMENT_SCHEME) else pointer
        metadata = part.get("metadata") or {}
        dalle = metadata.get("dalle") or {}
        return cls(
            asset_pointer=pointer,
            file_id=file_id,
            width=part.get("width"),
            height=part.get("height"),
            size_bytes=part.get("size_bytes"),
            mime_type=part.get("mime_type"),
            gen_id=dalle.get("gen_id"),
        )


class ImageResult(BaseModel):
    """一张已落盘的图片。"""

    path: Path
    width: int
    height: int
    size_bytes: int
    asset_pointer: str
    mime_type: str


class GenerationResult(BaseModel):
    """一次生图请求的完整结果。

    一轮可能产出多张图，因此返回列表而非单张；``images[0]`` 是主图。
    ``notes`` 记录"下到了图但元数据对不上"这类非致命差异 —— 如实记下，
    不静默吞掉。
    """

    conversation_id: str
    title: str | None = None
    images: list[ImageResult] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    @property
    def primary(self) -> ImageResult:
        if not self.images:
            raise IndexError("本次生成没有任何图片")
        return self.images[0]
