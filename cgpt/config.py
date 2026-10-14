"""运行配置。

默认值刻意取自抓包（docs/01 §2.1、docs/02 §3）—— 客户端标识头必须与服务端
见到的一致，否则容易被风控区别对待。

关于 ``originator``：抓包里的值是 ``Codex Browser``，因为那些流量来自 Codex
内嵌浏览器。普通网页端是另一个取值，所以这里做成可配置，默认用网页端的
``chatgpt.com``，联网若被拒可回退到抓包观测值（见设计文档 §8 风险表）。
"""

from __future__ import annotations

import time
from pathlib import Path

from pydantic import BaseModel, Field

from cgpt.auth.store import DEFAULT_CREDENTIALS_PATH, DEFAULT_PROFILE_DIR

#: 兜底 UA。真正的请求会优先用 ``Credentials.user_agent``（登录时从真实
#: 浏览器抓下来的那一个），以保证 HTTP 与浏览器的 UA 完全一致。
FALLBACK_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
)

#: 生图能力的 feature 开关名（docs/03 §3）
FEATURE_IMAGE_GEN = "image_gen_tool_enabled"


def local_timezone() -> tuple[str, int]:
    """返回 (IANA 风格的时区名, 相对 UTC 的分钟偏移)。

    取不到 IANA 名时退回 ``UTC±HH:MM`` 形式 —— 服务端只是做时区提示，
    不要求严格合法。
    """
    offset_seconds = -time.timezone if not time.localtime().tm_isdst \
        else -time.altzone
    offset_min = offset_seconds // 60
    name = time.tzname[time.localtime().tm_isdst] if time.tzname else "UTC"
    if not name or name.startswith(("UTC", "GMT")) and "+" not in name:
        sign = "+" if offset_min >= 0 else "-"
        hours, minutes = divmod(abs(offset_min), 60)
        name = f"UTC{sign}{hours:02d}:{minutes:02d}"
    return name, offset_min


class Settings(BaseModel):
    """一次运行的全部可调参数。"""

    # --- 凭据与浏览器 profile 位置 ---
    credentials_path: Path = DEFAULT_CREDENTIALS_PATH
    profile_dir: Path = DEFAULT_PROFILE_DIR

    # --- 客户端标识头 ---
    originator: str = "chatgpt.com"
    oai_language: str = "zh-CN"
    user_agent: str = FALLBACK_USER_AGENT
    extra_headers: dict[str, str] = Field(default_factory=dict)

    # --- 传输层 ---
    impersonate: str = "chrome"
    proxy: str | None = None
    connect_timeout: float = 15.0
    read_timeout: float = 120.0

    # --- 业务请求体 ---
    timezone: str = Field(default_factory=lambda: local_timezone()[0])
    timezone_offset_min: int = Field(default_factory=lambda: local_timezone()[1])
    model: str = "auto"

    # --- 浏览器 ---
    headless: bool = False
    browser_timeout_ms: int = 60_000
    debug_dir: Path = Path(".cgpt") / "debug"

    # --- 超时与轮询 ---
    #: 图片生成可能耗时较久（抓包里一轮 18 秒，但排队/重试会更长）
    generation_timeout: float = 720.0
    poll_interval: float = 5.0
    #: 登录后等待应用自行发起 chat-requirements 的最长时间
    sentinel_wait: float = 45.0

    def request_headers(self, credentials) -> dict[str, str]:
        """组装 ``/backend-api/*`` 的通用请求头。

        Cookie 不在这里 —— 由调用方显式加入，避免任何"自动带凭据"的路径。
        """
        headers = {
            "accept": "*/*",
            "accept-language": f"{self.oai_language},en;q=0.9",
            "content-type": "application/json",
            "oai-language": self.oai_language,
            "originator": self.originator,
            "user-agent": credentials.user_agent or self.user_agent,
            "referer": "https://chatgpt.com/",
        }
        if credentials.bearer:
            headers["authorization"] = f"Bearer {credentials.bearer}"
        if credentials.account_id:
            headers["chatgpt-account-id"] = credentials.account_id
        if credentials.device_id:
            headers["oai-did"] = credentials.device_id
        headers.update(self.extra_headers)
        return headers
