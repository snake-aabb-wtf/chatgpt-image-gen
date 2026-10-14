"""`t` / `turnstile` 的 XOR 混淆（docs/01 §4.8.1）。

SDK 的编码方式（源码还原）::

    value = base64( XOR( JSON 字符串, 密钥 ) )        # 逐字符 String.fromCharCode(ct[i] ^ key[i % L])
    JSON.parse( xor( atob(value), key ) )

它不是 Fernet（没有 ``0x80`` 头），也**不是** Cloudflare Turnstile 令牌 ——
明文是"探针编号.答案编号 → 采集值"的答案表。

密钥形如 ``NN.NN`` 的短十进制数，**每轮都不同**，来源仍未确定（推测随未解开的
``dx`` 一并下发）。好消息是：**工具不需要知道来源**，可以用"已知明文推导"
直接从密文还原密钥 —— 明文是 JSON，因此首字符必为 ``{``/``[``，末字符必为
``}``/``]``，且明文是纯 ASCII，这三条约束足以让错误的密钥长度无解。

⚠️ 注意：能**解密**不等于能**伪造**。要生成一份服务端能接受的新 ``t``，
必须用它期望的那把密钥；既然密钥随 ``dx`` 下发而 ``dx`` 未解开，
本工具的生图链路改为从真实浏览器 SDK 取令牌（见设计文档 §2 约束 2）。
本模块在工具里的用途是**离线取证与自证**。
"""

from __future__ import annotations

import base64
import binascii
import itertools
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

ASCII_MIN, ASCII_MAX = 0x20, 0x7E

#: 明文是 JSON，可能的起始字符
DEFAULT_HEADS = ('{"', "[{", '["', '{"t', '{"c', '{"s')
#: 明文是 JSON，可能的结束字符
DEFAULT_TAILS = ("}", "]")
#: 组合爆炸时的上限（与 tools/sentinel-hook.js 的 combineCols cap 一致）
DEFAULT_COMBO_CAP = 20_000

_BLOB_RE = re.compile(r"^[A-Za-z0-9+/_=-]+~?S?$")

#: 文档已独立解出的 10 个样本（用于离线自证的期望值，docs/01 §4.8.1 + tools/README.md）
KNOWN_KEYS: tuple[str, ...] = (
    "17.41", "46.46", "70.41", "27.27", "90.31",
    "64.8", "97.63", "31.99", "3.74", "4.07",
)


@dataclass
class CrackResult:
    key: str
    source: str
    plaintext: str
    blob_length: int

    @property
    def parsed(self) -> Any:
        return json.loads(self.plaintext)

    @property
    def item_count(self) -> int:
        value = self.parsed
        return len(value) if isinstance(value, (dict, list)) else 0


def xor_latin1(text: str, key: str) -> str:
    """与 SDK 内部实现逐字符一致：``chr(ct[i] ^ key[i % len(key)])``。"""
    if not key:
        raise ValueError("XOR 密钥不能为空")
    return "".join(chr(ord(ch) ^ ord(key[i % len(key)]))
                   for i, ch in enumerate(text))


def b64_to_latin1(blob: str) -> str:
    """解码成"每字符 = 一个字节"的 latin-1 字符串，对应 JS 的 ``atob`` 输出。"""
    text = blob.strip()
    if text.endswith("~S"):
        text = text[:-2]
    text = text.replace("-", "+").replace("_", "/")
    text += "=" * ((-len(text)) % 4)
    # validate=True 与 JS 的 atob 语义一致：遇到字母表外的字符就报错，
    # 而不是静默丢弃（默认的 validate=False 会把垃圾数据也"解"出东西来）
    return base64.b64decode(text, validate=True).decode("latin-1")


def looks_like_blob(value: object) -> bool:
    return (isinstance(value, str) and len(value) >= 60
            and bool(_BLOB_RE.match(value)))


def _try_json(text: str) -> Any | None:
    try:
        parsed = json.loads(text)
    except ValueError:
        return None
    return parsed if isinstance(parsed, (dict, list)) else None


# --- 三条还原路径 ---------------------------------------------------------


def crack_with_candidates(ct: str,
                          candidates: Mapping[str, str]) -> CrackResult | None:
    """路径 ①：拿 cookie/storage 里的值当候选密钥逐个试。"""
    for source, value in candidates.items():
        if not value:
            continue
        plaintext = xor_latin1(ct, value)
        if _try_json(plaintext) is not None:
            return CrackResult(key=value, source=f"candidate:{source}",
                               plaintext=plaintext, blob_length=len(ct))
    return None


def crack_single_byte(ct: str) -> CrackResult | None:
    """路径 ②：单字节密钥暴力（256 次）。"""
    for b in range(256):
        key = chr(b)
        plaintext = xor_latin1(ct, key)
        if _try_json(plaintext) is not None:
            return CrackResult(key=key, source=f"brute:单字节(0x{b:02x})",
                               plaintext=plaintext, blob_length=len(ct))
    return None


def _column_candidates(ct: str, length: int, head: str) -> list[list[int]] | None:
    """逐列求密钥字节候选；任一一列无解则返回 None。"""
    columns: list[list[int] | None] = [None] * length

    # 首字符约束：明文以 head 开头
    for pos, head_char in enumerate(head):
        if pos >= length:
            break
        columns[pos] = [ord(ct[pos]) ^ ord(head_char)]

    # 末字符约束：明文以 } 或 ] 结尾。这条约束把大量错误密钥长度直接排除，
    # 是让"已知明文推导"实用的关键。
    tail_index = len(ct) - 1
    tail_col = tail_index % length
    tail_plain = ord(ct[tail_index])
    tail_allowed = [tail_plain ^ ord(ch) for ch in DEFAULT_TAILS]
    columns[tail_col] = (tail_allowed if columns[tail_col] is None
                         else [v for v in columns[tail_col] if v in tail_allowed])
    if not columns[tail_col]:
        return None

    for col in range(length):
        allowed = columns[col]
        for i in range(col, len(ct), length):
            byte = ord(ct[i])
            if allowed is None:
                allowed = [byte ^ v for v in range(ASCII_MIN, ASCII_MAX + 1)]
            else:
                allowed = [a for a in allowed
                           if ASCII_MIN <= (byte ^ a) <= ASCII_MAX]
            if not allowed:
                return None
        columns[col] = allowed
    return columns  # type: ignore[return-value]


def _combine(columns: list[list[int]], cap: int) -> Iterable[str]:
    total = 1
    for column in columns:
        total *= len(column)
        if total > cap:
            break
    product = itertools.product(*columns)
    for combo in itertools.islice(product, cap):
        yield "".join(chr(v) for v in combo)


def crack_known_prefix(ct: str, *, max_key_len: int = 64,
                       cap: int = DEFAULT_COMBO_CAP) -> CrackResult | None:
    """路径 ③：已知明文（JSON 首尾字符 + 纯 ASCII）推导密钥。

    **不依赖任何候选字典**，因此是本工具的主力路径。
    """
    for head in DEFAULT_HEADS:
        for length in range(2, min(max_key_len, len(ct)) + 1):
            columns = _column_candidates(ct, length, head)
            if columns is None:
                continue
            tried = 0
            for key in _combine(columns, cap):
                tried += 1
                plaintext = xor_latin1(ct, key)
                if _try_json(plaintext) is not None:
                    source = f"derive:已知前缀推导(L={length}"
                    if tried > 1:
                        source += f", 尝试 {tried}"
                    source += ")"
                    return CrackResult(key=key, source=source,
                                       plaintext=plaintext, blob_length=len(ct))
    return None


def crack(blob: str, candidates: Mapping[str, str] | None = None,
          *, max_key_len: int = 64) -> CrackResult | None:
    """依次走三条路径，返回第一个成功的结果。"""
    try:
        ct = b64_to_latin1(blob)
    except (binascii.Error, ValueError):
        return None
    if not ct:
        return None
    return (crack_with_candidates(ct, candidates or {})
            or crack_single_byte(ct)
            or crack_known_prefix(ct, max_key_len=max_key_len))


# --- 已知密钥下的解 / 封 --------------------------------------------------


def decode(blob: str, key: str) -> Any:
    """已知密钥时直接解出 JSON。"""
    return json.loads(xor_latin1(b64_to_latin1(blob), key))


def encode(plaintext: str, key: str) -> str:
    """把明文 JSON 字符串按同样的方式混淆（自证的"编码→解码"回环用）。"""
    ciphertext = xor_latin1(plaintext, key)
    return base64.b64encode(ciphertext.encode("latin-1")).decode("ascii")


def codec_roundtrip_matches(blob: str, key: str) -> bool:
    """编解码自洽性检查：``encode(decode(x)) == x``。

    ⚠️ **这不是密钥正确性的证据**。XOR 是对合运算，``xor(xor(x, k), k) == x``
    对**任意** k 都成立，因此拿错误密钥跑这个函数同样返回 True。
    它只能证明"解码与编码两条路径互为逆运算"，即编解码器没写歪。

    判断密钥是否正确，靠的是 ``crack`` 里"明文必须能 JSON 解析"这条约束，
    以及 ``probe_key_shape_ok`` 对明文结构的检查。
    """
    try:
        plaintext = xor_latin1(b64_to_latin1(blob), key)
    except (binascii.Error, ValueError):
        return False
    return encode(plaintext, key) == blob


#: 探针答案表的键形如 "探针号.答案号"（docs/01 §4.8.1）
_PROBE_KEY_RE = re.compile(r"^\d+\.\d+$")


def probe_key_shape_ok(value: Any, *, min_ratio: float = 1.0) -> bool:
    """明文的键是否符合"探针编号.答案编号"的结构。

    这是**密钥正确性的真实旁证**：用一个恰好也能解出 JSON 的错误密钥，
    几乎不可能同时让所有键都落在这个形状上。
    """
    if isinstance(value, dict):
        keys = [str(k) for k in value]
    elif isinstance(value, list):
        keys = [str(v) for v in value]
    else:
        return False
    if not keys:
        return False
    matched = sum(1 for k in keys if _PROBE_KEY_RE.match(k))
    return matched >= len(keys) * min_ratio
