"""Sentinel 各模块的边界与单元行为（真值自证之外的部分）。"""

from __future__ import annotations

import json

import pytest

from cgpt.sentinel.fernet import parse_fernet, parse_fernet_bytes
from cgpt.sentinel.payload import (
    KIND_SENTINEL_PAYLOAD,
    KIND_UNKNOWN,
    PREFIX_ANSWER,
    PREFIX_REQUIREMENTS,
    SOLVED_SUFFIX,
    answer_counter,
    build_fingerprint,
    decode_payload,
    encode_answer,
    js_date_string,
    json_to_b64,
)
from cgpt.sentinel.pow import (
    PowExhaustedError,
    digest_for,
    fnv1a_mix,
    meets_difficulty,
    solve,
    verify,
)
from cgpt.sentinel.xor import (
    b64_to_latin1,
    codec_roundtrip_matches,
    crack,
    decode,
    encode,
    looks_like_blob,
    probe_key_shape_ok,
    xor_latin1,
)

# --- payload -------------------------------------------------------------


def test_json_to_b64_keeps_non_ascii_as_utf8_bytes() -> None:
    """``ensure_ascii=True`` 会输出 \\uXXXX 转义，与抓包原文不一致。"""
    encoded = json_to_b64(["中国标准时间"])
    assert "中国标准时间".encode("utf-8").decode("latin-1") not in encoded
    import base64

    assert base64.b64decode(encoded).decode("utf-8") == '["中国标准时间"]'


def test_fingerprint_has_25_fields_with_expected_anchors() -> None:
    fields = build_fingerprint("UA/1.0", counter=7, elapsed_ms=4)
    assert len(fields) == 25
    assert fields[0] == 3000
    assert fields[3] == 7                # PoW 计数器
    assert fields[4] == "UA/1.0"
    assert fields[6] == "132f33eb272ff65e6bd412b5f3578ab9b3f322cb"
    assert fields[9] == 4
    assert fields[15] == ""
    assert fields[16] == 8
    assert fields[18:] == [0] * 7


def test_fingerprint_random_fields_differ_between_calls() -> None:
    """字段 10~14 是刻意的反指纹稳定性设计，两次调用不该相同。"""
    first = build_fingerprint("UA")[10:15]
    second = build_fingerprint("UA")[10:15]
    assert first != second


def test_decode_rejects_non_string() -> None:
    assert decode_payload(None).kind == KIND_UNKNOWN
    assert decode_payload(12345).kind == KIND_UNKNOWN


def test_decode_returns_unknown_for_short_garbage() -> None:
    info = decode_payload("gAAAAABnot-base64!!!")
    assert info.kind == KIND_UNKNOWN


def test_answer_counter_none_for_fernet() -> None:
    assert answer_counter("bm90IGZlcm5ldA==") is None


def test_encode_decode_roundtrip_for_requirements_prefix() -> None:
    fields = build_fingerprint("UA", counter=1)
    token = encode_answer(fields, PREFIX_REQUIREMENTS, solved=False)
    assert not token.endswith(SOLVED_SUFFIX)
    info = decode_payload(token)
    assert info.prefix == PREFIX_REQUIREMENTS
    assert info.solved is False
    assert info.fields == fields


def test_encode_answer_default_prefix_is_answer_form() -> None:
    token = encode_answer(build_fingerprint("UA"))
    assert token.startswith(PREFIX_ANSWER)
    assert token.endswith(SOLVED_SUFFIX)


def test_js_date_string_shape() -> None:
    text = js_date_string()
    assert "GMT" in text
    assert text[:3] in ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


# --- pow -----------------------------------------------------------------


def test_fnv1a_mix_is_eight_lowercase_hex() -> None:
    digest = fnv1a_mix("hello")
    assert len(digest) == 8
    assert digest == digest.lower()
    int(digest, 16)


def test_fnv1a_mix_handles_astral_plane_like_js_char_code_at() -> None:
    """JS 的 charCodeAt 对星平面字符返回两个代理项，Python 必须对齐。"""
    emoji = "\U0001F600"
    assert fnv1a_mix(emoji) == fnv1a_mix("\ud83d\ude00")


def test_meets_difficulty_uses_lexicographic_prefix() -> None:
    assert meets_difficulty("009b70bc", "06b983") is True
    # '0' == '0', '6' == '6', 'c' > 'b' → 超过阈值
    assert meets_difficulty("06c983ff", "06b983") is False
    # 相等也算通过（≤ 而非 <）
    assert meets_difficulty("06b983ff", "06b983") is True
    # 十六进制里 '9' < 'b'，所以 069b70 反而**通过** —— 这正是"字典序"的坑
    assert meets_difficulty("069b70bc", "06b983") is True


def test_digest_for_is_seed_plus_payload_without_prefix_or_suffix() -> None:
    payload_b64 = json_to_b64([1, 2, 3])
    assert digest_for("0.5", payload_b64) == fnv1a_mix("0.5" + payload_b64)


def test_solve_produces_verifiable_answer() -> None:
    # 难度取满 8 位会让期望尝试数过大，这里用 4 位保证测试稳定快速
    fields = build_fingerprint("UA", counter=0, elapsed_ms=0)
    answer, counter = solve("0.123", "0fff", fields, elapsed_ms=None)
    assert answer.startswith(PREFIX_ANSWER)
    assert answer.endswith(SOLVED_SUFFIX)
    assert answer_counter(answer) == counter
    assert verify("0.123", "0fff", answer) is True


def test_solve_writes_counter_into_field_three() -> None:
    fields = build_fingerprint("UA", elapsed_ms=0)
    answer, counter = solve("0.5", "ffff", fields, elapsed_ms=0)
    info = decode_payload(answer)
    assert info.fields is not None
    assert info.fields[3] == counter


def test_solve_pins_elapsed_ms_when_given() -> None:
    fields = build_fingerprint("UA")
    answer, _ = solve("0.5", "ffff", fields, elapsed_ms=42)
    info = decode_payload(answer)
    assert info.fields is not None
    assert info.fields[9] == 42


def test_solve_raises_when_difficulty_impossible() -> None:
    fields = build_fingerprint("UA", elapsed_ms=0)
    with pytest.raises(PowExhaustedError):
        solve("0.5", "000000", fields, max_attempts=3, elapsed_ms=0)


def test_verify_rejects_non_payload() -> None:
    assert verify("0.5", "06b983", "not-a-token") is False


# --- xor -----------------------------------------------------------------


def test_xor_latin1_is_involutive() -> None:
    assert xor_latin1(xor_latin1("hello world", "17.41"), "17.41") == "hello world"


def test_xor_latin1_rejects_empty_key() -> None:
    with pytest.raises(ValueError):
        xor_latin1("abc", "")


def test_encode_decode_roundtrip() -> None:
    plaintext = '{"41.05":{"availWidth":1920}}'
    blob = encode(plaintext, "17.41")
    assert decode(blob, "17.41") == json.loads(plaintext)
    assert codec_roundtrip_matches(blob, "17.41") is True


def test_codec_roundtrip_holds_even_for_wrong_key() -> None:
    """记录一个**反直觉但重要**的事实：这个回环对任意密钥都成立。

    XOR 是对合运算，``xor(xor(x, k), k) == x``，所以
    ``encode(decode(blob, k), k) == blob`` 与 k 是否正确无关。
    它只能证明编解码器互为逆运算，**不能**当密钥正确性的证据。
    密钥正确性靠 ``crack`` 的 JSON 约束 + ``probe_key_shape_ok`` 的结构约束。
    """
    blob = encode('{"a":1}', "17.41")
    assert codec_roundtrip_matches(blob, "17.41") is True
    assert codec_roundtrip_matches(blob, "99.99") is True     # ← 错误密钥也 True


def test_probe_key_shape_accepts_real_probe_table() -> None:
    assert probe_key_shape_ok({"41.05": 1, "98.82": [1, 2], "3.7": "x"}) is True


def test_probe_key_shape_rejects_other_json_shapes() -> None:
    assert probe_key_shape_ok({"hello": 1}) is False
    assert probe_key_shape_ok([1, 2, 3]) is False
    assert probe_key_shape_ok({}) is False
    assert probe_key_shape_ok("a string") is False
    assert probe_key_shape_ok({"41.05": 1, "not-a-probe": 2}) is False


def test_probe_key_shape_allows_partial_ratio() -> None:
    value = {"41.05": 1, "98.82": 2, "junk": 3}
    assert probe_key_shape_ok(value) is False
    assert probe_key_shape_ok(value, min_ratio=0.6) is True


def test_crack_returns_none_for_non_base64() -> None:
    assert crack("!!!not base64!!!") is None


def test_crack_returns_none_for_random_bytes() -> None:
    import base64
    import os

    blob = base64.b64encode(os.urandom(400)).decode()
    assert crack(blob) is None


def test_crack_handles_base64url_alphabet() -> None:
    plaintext = '{"1.1":"a","2.2":"b","3.3":{"x":1,"y":2},"4.4":[1,2,3]}'
    blob = encode(plaintext, "12.34")
    assert crack(blob) is not None


def test_crack_single_byte_key() -> None:
    plaintext = '{"a":1,"b":2,"c":3}'
    blob = encode(plaintext, "k")
    result = crack(blob)
    assert result is not None
    assert result.key == "k"


def test_looks_like_blob_thresholds() -> None:
    assert looks_like_blob("A" * 60) is True
    assert looks_like_blob("A" * 59) is False
    assert looks_like_blob("not valid!!! " * 10) is False
    assert looks_like_blob(None) is False


def test_b64_to_latin1_strips_solved_suffix() -> None:
    import base64

    raw = "hello"
    assert b64_to_latin1(base64.b64encode(raw.encode()).decode() + "~S") == raw


# --- fernet --------------------------------------------------------------


def test_parse_fernet_returns_none_for_payload_token() -> None:
    """载荷的整串 base64 解码后也是 0x80 开头，必须靠 JSON 判别排除。"""
    token = encode_answer(build_fingerprint("UA"))
    assert parse_fernet(token) is None
    assert decode_payload(token).kind == KIND_SENTINEL_PAYLOAD


def test_decode_payload_prefers_json_form_over_fernet_form() -> None:
    """两种形态都可能以 0x80 开头，判别顺序不能反。"""
    token = encode_answer(build_fingerprint("UA"), PREFIX_REQUIREMENTS,
                          solved=False)
    assert decode_payload(token).kind == KIND_SENTINEL_PAYLOAD


def test_parse_fernet_bytes_rejects_wrong_version() -> None:
    with pytest.raises(ValueError, match="不是 Fernet"):
        parse_fernet_bytes(b"\x81" + b"\x00" * 100)


def test_parse_fernet_bytes_rejects_short_input() -> None:
    with pytest.raises(ValueError, match="太短"):
        parse_fernet_bytes(b"\x80" + b"\x00" * 10)


def test_parse_fernet_layout_is_one_plus_eight_plus_sixteen() -> None:
    import base64
    import struct

    timestamp = 1_791_970_793
    body = struct.pack(">Q", timestamp)
    raw = b"\x80" + body + b"\x11" * 16 + b"\x22" * 50 + b"\x33" * 32
    info = parse_fernet_bytes(raw)
    assert info.timestamp == timestamp
    assert info.iv == b"\x11" * 16
    assert info.ciphertext == b"\x22" * 50
    assert info.hmac == b"\x33" * 32
    assert info.total_len == len(raw)
    # 整串 base64 后应能被 parse_fernet 还原
    assert parse_fernet(base64.b64encode(raw).decode()).timestamp == timestamp
