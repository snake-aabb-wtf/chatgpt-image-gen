"""TOTP —— 用 RFC 6238 附录 B 的官方向量自证。

这是全部离线自证里唯一有"权威标准答案"的一项：另外几项（PoW/指纹/XOR）
没有公开标准，只能拿本项目 `legacy/har/` 里的真实抓包当真值。
"""

from __future__ import annotations

import base64

import pytest

from cgpt.auth.totp import (
    RFC6238_SECRETS,
    RFC6238_VECTORS,
    decode_secret,
    hotp,
    normalize_secret,
    seconds_remaining,
    totp,
    totp_with_skew,
)


def _b32(ascii_secret: str) -> str:
    """把 RFC 里的 ASCII 密钥转成用户实际会粘贴的 base32 形式。

    刻意用 b32encode 现算而不是抄字面量 —— 抄错一个字符会让测试从
    "验证实现"退化成"验证抄写"。
    """
    return base64.b32encode(ascii_secret.encode("ascii")).decode("ascii")


@pytest.mark.parametrize("at,sha1,sha256,sha512", RFC6238_VECTORS)
def test_rfc6238_appendix_b(at: int, sha1: str, sha256: str, sha512: str) -> None:
    expected = {"sha1": sha1, "sha256": sha256, "sha512": sha512}
    for algorithm, want in expected.items():
        got = totp(_b32(RFC6238_SECRETS[algorithm]), at=at, digits=8,
                   algorithm=algorithm)
        assert got == want, f"{algorithm} @ t={at}"


def test_hotp_counter_zero_matches_rfc4226() -> None:
    # RFC 4226 附录 D 的第一个值（同一密钥、6 位）
    assert hotp(decode_secret(_b32("12345678901234567890")), 0) == "755224"


@pytest.mark.parametrize(
    "raw,want",
    [
        ("JBSWY3DPEHPK3PXP", "JBSWY3DPEHPK3PXP"),
        ("jbsw y3dp ehpk 3pxp", "JBSWY3DPEHPK3PXP"),
        ("JBSW-Y3DP-EHPK-3PXP", "JBSWY3DPEHPK3PXP"),
        ("  JBSWY3DPEHPK3PXP\n", "JBSWY3DPEHPK3PXP"),
    ],
)
def test_normalize_secret_tolerates_pasted_formatting(raw: str, want: str) -> None:
    assert normalize_secret(raw).rstrip("=") == want


def test_normalize_secret_pads_to_multiple_of_eight() -> None:
    assert len(normalize_secret("ABCDEF")) % 8 == 0


def test_normalize_secret_rejects_empty() -> None:
    with pytest.raises(ValueError, match="为空"):
        normalize_secret("   ")


def test_decode_secret_error_mentions_base32_and_recovery_codes() -> None:
    with pytest.raises(ValueError) as excinfo:
        decode_secret("0189!!!not-base32!!!")
    message = str(excinfo.value)
    assert "base32" in message
    assert "恢复码" in message


def test_totp_is_six_digits_and_stable_within_period() -> None:
    secret = "JBSWY3DPEHPK3PXP"
    base = 1_791_970_980.0            # 30 的整数倍，确保 +29 不跨窗口
    assert base % 30 == 0
    code = totp(secret, at=base)
    assert len(code) == 6 and code.isdigit()
    # 同一 30 秒窗口内必须稳定，否则登录会随机失败
    assert totp(secret, at=base + 29) == code
    # 跨到下一窗口则必须变（否则就不是 TOTP 了）
    assert totp(secret, at=base + 30) != code


def test_totp_with_skew_returns_prev_current_next() -> None:
    secret = "JBSWY3DPEHPK3PXP"
    at = 1_791_971_000.0
    codes = totp_with_skew(secret, at=at)
    assert len(codes) == 3
    assert codes[1] == totp(secret, at=at)
    assert codes[0] == totp(secret, at=at - 30)
    assert codes[2] == totp(secret, at=at + 30)


def test_seconds_remaining_counts_down_within_period() -> None:
    assert seconds_remaining(at=1_791_971_000.0) == pytest.approx(
        30 - (1_791_971_000.0 % 30))
    assert 0 < seconds_remaining(at=1_791_971_000.0) <= 30
