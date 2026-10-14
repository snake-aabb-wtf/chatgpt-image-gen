"""RFC 6238 TOTP（仅用标准库）。

刻意不引入 pyotp：算法只有二十行，少一个依赖就少一处供应链风险，
而且可以用 RFC 6238 附录 B 的官方向量离线自证。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import struct
import time

DEFAULT_DIGITS = 6
DEFAULT_PERIOD = 30
DEFAULT_ALGORITHM = "sha1"

#: RFC 6238 附录 B 官方向量：(unix 秒, SHA1, SHA256, SHA512)，均为 8 位码。
#: 放在模块里而不是测试里，是为了让 tests/ 与 cgpt/selftest.py 共用**同一份**
#: 常量 —— 两处各写一份曾导致 SHA512 密钥少写 10 个字符，自证凭空变红。
RFC6238_VECTORS: tuple[tuple[int, str, str, str], ...] = (
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
)

#: RFC 6238 各算法使用的 ASCII 密钥（长度必须分别是 20 / 32 / 64 字节）
RFC6238_SECRETS: dict[str, str] = {
    "sha1": "12345678901234567890",
    "sha256": "12345678901234567890123456789012",
    "sha512": ("12345678901234567890123456789012"
               "34567890123456789012345678901234"),
}


def normalize_secret(secret: str) -> str:
    """把用户粘贴的 2FA 密钥整理成可解码的 base32。

    容忍：空格、连字符分组（``abcd-efgh``）、小写、缺失的 ``=`` 补齐。
    """
    s = "".join(secret.split()).replace("-", "").replace(" ", "").upper()
    if not s:
        raise ValueError("TOTP 密钥为空")
    s += "=" * ((-len(s)) % 8)
    return s


def decode_secret(secret: str) -> bytes:
    """base32 解码，失败时给出人话错误。"""
    normalized = normalize_secret(secret)
    try:
        return base64.b32decode(normalized, casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(
            f"TOTP 密钥不是合法 base32：{secret[:8]}…（{exc}）。"
            "请确认复制的是 2FA 设置页给出的密钥，而不是恢复码。"
        ) from exc


def hotp(key: bytes, counter: int, digits: int = DEFAULT_DIGITS,
         algorithm: str = DEFAULT_ALGORITHM) -> str:
    """RFC 4226 HOTP：HMAC → 动态截断 → 取模。"""
    digest = hmac.new(key, struct.pack(">Q", counter),
                      getattr(hashlib, algorithm)).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10 ** digits)).zfill(digits)


def totp(secret: str, at: float | None = None, digits: int = DEFAULT_DIGITS,
         period: int = DEFAULT_PERIOD,
         algorithm: str = DEFAULT_ALGORITHM) -> str:
    """按时间戳生成 TOTP。``at`` 省略时用当前时间。"""
    key = decode_secret(secret)
    timestamp = time.time() if at is None else at
    return hotp(key, int(timestamp // period), digits, algorithm)


def totp_with_skew(secret: str, at: float | None = None,
                   digits: int = DEFAULT_DIGITS, period: int = DEFAULT_PERIOD,
                   algorithm: str = DEFAULT_ALGORITHM) -> list[str]:
    """返回 [上一窗口, 当前窗口, 下一窗口] 三个候选项。

    登录页的校验发生在服务端，客户端时钟偏差 ±30s 时当前窗口会算错；
    提交时按顺序逐个试即可，不必让用户改系统时间。
    """
    timestamp = time.time() if at is None else at
    base = int(timestamp // period)
    return [hotp(decode_secret(secret), base + delta, digits, algorithm)
            for delta in (-1, 0, 1)]


def seconds_remaining(at: float | None = None, period: int = DEFAULT_PERIOD) -> float:
    """当前验证码还剩多少秒失效。

    调用方用它决定"直接提交"还是"等下一个窗口再提交"——
    在窗口只剩 1 秒时提交，很可能到达服务端时已经过期。
    """
    timestamp = time.time() if at is None else at
    return period - (timestamp % period)
