"""工作量证明（docs/01 §4.7）。

算法：``H(seed + base64载荷)`` 的前 ``len(difficulty)`` 位十六进制
字典序 ≤ ``difficulty``。因为两边都是**定长小写十六进制**，字典序比较
等价于数值比较。

哈希是 FNV-1a 32 位再叠三轮 murmur 风格雪崩混合，输出 8 位小写十六进制。

一个容易被忽略的细节：**字段 [9]（已耗时 ms）也参与哈希**，而它每次尝试
都在变，所以"最小通过计数器"无法脱离时间戳复现。这也是该设计巧妙的地方
—— 服务端重算时必须拿到我们提交的那一份载荷，而不是自己重跑。
"""

from __future__ import annotations

from typing import Callable

from cgpt.errors import CgptError
from cgpt.sentinel.payload import (
    PREFIX_ANSWER,
    SOLVED_SUFFIX,
    encode_answer,
    json_to_b64,
)

#: SDK 源码里的上限（`maxAttempts = 5e5`）
MAX_ATTEMPTS = 500_000


class PowExhaustedError(CgptError):
    """在尝试上限内没有找到满足难度的计数器。"""


def _utf16_code_units(text: str):
    """按 UTF-16 码元迭代，与 JS 的 ``charCodeAt`` 完全一致。

    载荷里含中文（字段 [1] 的时区名），属于 BMP，`ord()` 与 `charCodeAt`
    结果相同；但星平面字符（emoji 等）在 JS 里是两个代理项，若直接用
    `ord()` 会算出不同的哈希。这里做严格对齐，成本几乎为零。
    """
    for ch in text:
        cp = ord(ch)
        if cp > 0xFFFF:
            cp -= 0x10000
            yield 0xD800 + (cp >> 10)
            yield 0xDC00 + (cp & 0x3FF)
        else:
            yield cp


def fnv1a_mix(text: str) -> str:
    """FNV-1a 32 位 + murmur 风格雪崩混合 → 8 位小写十六进制。"""
    e = 2166136261
    for unit in _utf16_code_units(text):
        e ^= unit
        e = (e * 16777619) & 0xFFFFFFFF
    e ^= e >> 16
    e = (e * 2246822507) & 0xFFFFFFFF
    e ^= e >> 13
    e = (e * 3266489909) & 0xFFFFFFFF
    e ^= e >> 16
    return format(e & 0xFFFFFFFF, "08x")


def digest_for(seed: str, payload_b64: str) -> str:
    """哈希输入是 ``seed`` 字符串 **拼接** base64 载荷（不含前缀、不含 ``~S``）。"""
    return fnv1a_mix(seed + payload_b64)


def meets_difficulty(digest: str, difficulty: str) -> bool:
    return digest[: len(difficulty)] <= difficulty


def solve(
    seed: str,
    difficulty: str,
    fields: list,
    *,
    max_attempts: int = MAX_ATTEMPTS,
    elapsed_ms: int | None = None,
    clock: Callable[[], float] | None = None,
) -> tuple[str, int]:
    """就地改写 ``fields`` 直到哈希满足难度，返回 ``(答案令牌, 命中计数器)``。

    :param elapsed_ms: 固定写入字段 [9] 的值；None 表示用 ``clock`` 实测
        （更贴近真实客户端的行为，但结果不确定）。
    :param clock: 返回秒的单调时钟，默认 ``time.perf_counter``。
    """
    import time

    clock = clock or time.perf_counter
    started = clock()
    for counter in range(max_attempts):
        fields[3] = counter
        if elapsed_ms is None:
            fields[9] = int(round((clock() - started) * 1000))
        else:
            fields[9] = elapsed_ms
        payload_b64 = json_to_b64(fields)
        if meets_difficulty(digest_for(seed, payload_b64), difficulty):
            return encode_answer(fields, PREFIX_ANSWER, solved=True), counter
    raise PowExhaustedError(
        f"尝试 {max_attempts} 次仍未满足难度 {difficulty}（seed={seed}）。"
        f"这通常意味着难度被显著调高，或指纹载荷与服务端期望的不一致。")


def verify(seed: str, difficulty: str, answer: str) -> bool:
    """独立复算一条答案是否满足难度（用于离线自证与取证）。

    刻意不依赖 ``solve`` 的任何状态：把答案里的载荷原样取出重新哈希，
    这是服务端会做的事。
    """
    from cgpt.sentinel.payload import decode_payload

    info = decode_payload(answer)
    if not info.is_payload:
        return False
    body = answer[: -len(SOLVED_SUFFIX)] if answer.endswith(SOLVED_SUFFIX) else answer
    payload_b64 = body[len(PREFIX_ANSWER):] if body.startswith(PREFIX_ANSWER) \
        else body[7:]
    return meets_difficulty(digest_for(seed, payload_b64), difficulty)
