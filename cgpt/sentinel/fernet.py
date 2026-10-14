"""Fernet 令牌头解析（docs/01 §4.9）。

布局（服务端密钥加密的不透明令牌，客户端**只能缓存与回传**）::

    version   = 0x80                     1 字节
    timestamp = 大端 Unix 秒              8 字节
    iv        = 16 字节
    body      = 密文                      N 字节
    hmac      = HMAC-SHA256 校验          32 字节（末尾）

解析它的唯一实际用途是**核对签发时刻**：`c` 与 `/sentinel/req` 响应的 `token`
必须逐字节相同，而内嵌时间戳可以与抓包的 HTTP `date` 相互印证。
密文本身无法解开 —— 那需要服务端密钥。
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from datetime import datetime, timezone

FERNET_VERSION = 0x80
_HEADER_LEN = 1 + 8 + 16      # version + timestamp + iv
_HMAC_LEN = 32
_MIN_LEN = _HEADER_LEN + _HMAC_LEN


@dataclass
class FernetInfo:
    version: int
    timestamp: int
    iv: bytes
    ciphertext: bytes
    hmac: bytes
    total_len: int

    @property
    def timestamp_iso(self) -> str | None:
        """内嵌时间戳的 ISO 表示；取值不合理（非 Unix 秒量级）时为 None。"""
        if not (1_000_000_000 < self.timestamp < 4_000_000_000):
            return None
        return datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat()

    @property
    def iv_hex(self) -> str:
        return self.iv.hex()

    @property
    def hmac_hex(self) -> str:
        return self.hmac.hex()


def parse_fernet_bytes(raw: bytes) -> FernetInfo:
    """从已解码的字节解析 Fernet 头。调用方需自行确认首字节是 0x80。"""
    if len(raw) < _MIN_LEN:
        raise ValueError(
            f"Fernet 令牌太短：{len(raw)} 字节（至少需要 {_MIN_LEN} 字节）")
    if raw[0] != FERNET_VERSION:
        raise ValueError(f"不是 Fernet：版本字节 0x{raw[0]:02x}，期望 0x80")

    timestamp = int.from_bytes(raw[1:9], "big")
    iv = raw[9:25]
    ciphertext = raw[25:-_HMAC_LEN]
    hmac = raw[-_HMAC_LEN:]
    return FernetInfo(version=raw[0], timestamp=timestamp, iv=iv,
                      ciphertext=ciphertext, hmac=hmac, total_len=len(raw))


def parse_fernet(token: str) -> FernetInfo | None:
    """解析 Fernet 形态的令牌；不是 Fernet 时返回 None（而不是抛错）。

    返回 None 而非抛异常，是因为调用方通常在做"这是哪种令牌"的分流判断。

    ⚠️ **必须排除 Sentinel 载荷**：载荷的 7 字符字面前缀 ``gAAAAAB`` 恰好
    让整串 base64 解码后也是 ``0x80`` 开头（docs/01 §4.5.2 记录过这个现象），
    所以"首字节 0x80"不足以判定 Fernet。真正的判别条件是：去掉 7 字符后
    **能否解出 UTF-8 JSON** —— 能，就是载荷，不是 Fernet。
    """
    if not isinstance(token, str):
        return None
    text = token.strip()
    if text.endswith("~S"):
        text = text[:-2]
    if _looks_like_sentinel_payload(text):
        return None
    text = text.replace("-", "+").replace("_", "/")
    text += "=" * ((-len(text)) % 4)
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) < _MIN_LEN or raw[0] != FERNET_VERSION:
        return None
    return parse_fernet_bytes(raw)


def _looks_like_sentinel_payload(text: str) -> bool:
    """去掉 7 字符前缀后能否解出 UTF-8 JSON（是则说明这是载荷而非 Fernet）。"""
    if len(text) <= 7:
        return False
    body = text[7:].replace("-", "+").replace("_", "/")
    body += "=" * ((-len(body)) % 4)
    try:
        decoded = base64.b64decode(body, validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return False
    try:
        return isinstance(json.loads(decoded), (list, dict))
    except ValueError:
        return False
