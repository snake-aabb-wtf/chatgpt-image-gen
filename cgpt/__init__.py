"""ChatGPT 账密 + 2FA 登录并请求生图。

用法（库）：::

    from cgpt import Client

    client = Client.from_credentials(".cgpt/credentials.json")
    result = client.generate_image("生成一张地球图片", out="earth.png")

用法（CLI）：``python -m cgpt --help``
"""

from __future__ import annotations

from cgpt.errors import (
    CgptError,
    CloudflareChallengeError,
    CredentialsNotFoundError,
    ImageGenUnavailableError,
    InvalidPromptError,
    LoginBlockedError,
    LoginError,
    NoImageProducedError,
    QuotaExhaustedError,
    SessionExpiredError,
    TotpRejectedError,
    UnsafeDownloadURLError,
)
from cgpt.models import (
    Credentials,
    GenerationResult,
    ImageAsset,
    ImageResult,
    SentinelTokens,
)

__version__ = "0.1.0"

__all__ = [
    "Client",
    "CgptError",
    "CloudflareChallengeError",
    "Credentials",
    "CredentialsNotFoundError",
    "GenerationResult",
    "ImageAsset",
    "ImageGenUnavailableError",
    "ImageResult",
    "InvalidPromptError",
    "LoginBlockedError",
    "LoginError",
    "NoImageProducedError",
    "QuotaExhaustedError",
    "SentinelTokens",
    "SessionExpiredError",
    "TotpRejectedError",
    "UnsafeDownloadURLError",
    "__version__",
]


def __getattr__(name: str):
    """惰性导出 ``Client``。

    这样 ``import cgpt`` 不必连带加载 playwright / curl_cffi —— 只想用
    ``cgpt.sentinel`` 做离线取证的使用者不该被迫装浏览器。
    """
    if name == "Client":
        from cgpt.client import Client

        return Client
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
