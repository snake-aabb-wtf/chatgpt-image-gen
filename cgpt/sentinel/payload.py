"""Sentinel 指纹载荷的编解码（docs/01 §4.5）。

关键格式（已对 5 处真实提交值逐字节验证）：

    p = <7 字符前缀> + <标准 base64> [+ "~S"]
                     └─ base64(UTF-8(JSON.stringify(25 元素数组)))

两个容易踩的坑：

1. **前缀不是 base64 流的一部分**。SDK 是用字符串拼接把 7 字符常量前置到
   一份**独立**编码的 base64 之上（``"gAAAAAC" + b64(json)``），而不是
   "二进制头 + JSON 一起编码"。所以解析时必须**先去掉 7 个字符**再解码；
   整个字符串单独解码会失败（7 不是 4 的倍数）。

2. **JSON 必须用 ``ensure_ascii=False``**。载荷字段 [1] 是
   ``new Date().toString()``，在中文环境下含「中国标准时间」这类非 ASCII 字符。
   SDK 走的是 ``btoa(String.fromCharCode(...new TextEncoder().encode(t)))``，
   即真正的 UTF-8 字节；若用 ``ensure_ascii=True`` 会输出 ``\\uXXXX`` 转义，
   重编码后与抓包原文**逐字节不同**。
"""

from __future__ import annotations

import base64
import binascii
import json
import random
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

#: 缓存读取的 requirements token（`getRequirementsToken()`）
PREFIX_REQUIREMENTS = "gAAAAAC"
#: 本次新解出的答案（`getRequirementsTokenBlocking()`）
PREFIX_ANSWER = "gAAAAAB"
#: "已解出（solved）"后缀标记，只有经过 PoW 求解的载荷才带
SOLVED_SUFFIX = "~S"
#: 前缀长度固定为 7，因此去掉它之后剩余部分长度才是 4 的倍数
PREFIX_LENGTH = 7

_B64_WHOLE_RE = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")
_ASCII_MIN, _ASCII_MAX = 0x20, 0x7E

KIND_SENTINEL_PAYLOAD = "sentinel-payload"
KIND_FERNET = "fernet"
KIND_BINARY = "binary"
KIND_UNKNOWN = "unknown"

#: 指纹数组长度（docs/01 §4.5.3）
FINGERPRINT_FIELD_COUNT = 25


@dataclass
class PayloadInfo:
    """``decode_payload`` 的结果。"""

    kind: str
    prefix: str | None = None
    solved: bool = False
    fields: list[Any] | None = None
    raw: str | None = None
    byte_length: int | None = None
    head_hex: str | None = None
    note: str | None = None

    @property
    def is_payload(self) -> bool:
        return self.kind == KIND_SENTINEL_PAYLOAD


def b64_to_bytes(value: str) -> bytes:
    """按 SDK 的 ``b64ToBytes`` 语义解码：容忍 ``~S`` 后缀、base64url 字母表、缺失补齐。

    用 ``validate=True`` 与 JS 的 ``atob`` 对齐 —— 后者遇到字母表外的字符会抛错，
    而不是静默丢弃。这一点对取证工具很重要：静默丢弃会把垃圾也"解"成东西。
    """
    text = value.strip()
    if text.endswith(SOLVED_SUFFIX):
        text = text[: -len(SOLVED_SUFFIX)]
    text = text.replace("-", "+").replace("_", "/")
    text += "=" * ((-len(text)) % 4)
    return base64.b64decode(text, validate=True)


def json_to_b64(obj: Any) -> str:
    """与 SDK 的 ``btoa(String.fromCharCode(...TextEncoder().encode(JSON.stringify(x))))`` 等价。

    ``separators`` 与 ``ensure_ascii`` 两个参数都必须与 ``JSON.stringify`` 对齐，
    否则重编码结果与抓包原文不一致（见模块 docstring 第 2 点）。
    """
    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    return base64.b64encode(raw.encode("utf-8")).decode("ascii")


def encode_answer(fields: list[Any], prefix: str = PREFIX_ANSWER,
                  solved: bool = True) -> str:
    """把 25 字段数组编成 ``openai-sentinel-*`` 头的形态。"""
    token = prefix + json_to_b64(fields)
    return token + SOLVED_SUFFIX if solved else token


def _try_form_b(body: str, solved: bool) -> PayloadInfo | None:
    """形态 B：7 字符前缀 + 独立 base64；解出 JSON 数组才算命中。"""
    prefix, remainder = body[:PREFIX_LENGTH], body[PREFIX_LENGTH:]
    try:
        raw_bytes = b64_to_bytes(remainder)
    except (binascii.Error, ValueError) as exc:
        return PayloadInfo(kind=KIND_UNKNOWN, prefix=prefix, solved=solved,
                           note=f"去掉 7 字符后 base64 解码失败：{exc}")

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return PayloadInfo(
            kind=KIND_BINARY, prefix=prefix, solved=solved,
            byte_length=len(raw_bytes), head_hex=raw_bytes[:12].hex(),
            note="去掉 7 字符后不是 UTF-8（未识别形态）",
        )

    try:
        parsed = json.loads(text)
    except ValueError:
        return PayloadInfo(kind=KIND_UNKNOWN, prefix=prefix, solved=solved,
                           byte_length=len(raw_bytes), raw=text[:120],
                           note="解码结果不是合法 JSON")

    if not isinstance(parsed, list):
        return PayloadInfo(kind=KIND_UNKNOWN, prefix=prefix, solved=solved,
                           byte_length=len(raw_bytes), raw=text[:120],
                           note="解码结果不是数组")

    return PayloadInfo(kind=KIND_SENTINEL_PAYLOAD, prefix=prefix, solved=solved,
                       fields=parsed, raw=text, byte_length=len(raw_bytes))


def _try_form_a(body: str, solved: bool) -> PayloadInfo | None:
    """形态 A：整串就是一个 base64，且解码后首字节是 0x80（Fernet）。"""
    if len(body) % 4 != 0 or not _B64_WHOLE_RE.match(body):
        return None
    try:
        whole = base64.b64decode(body.replace("-", "+").replace("_", "/"),
                                 validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(whole) <= 40 or whole[0] != 0x80:
        return None

    from cgpt.sentinel.fernet import parse_fernet_bytes

    info = parse_fernet_bytes(whole)
    return PayloadInfo(
        kind=KIND_FERNET, solved=solved, byte_length=len(whole),
        note=(f"服务端 Fernet 不透明令牌（内嵌时间戳 {info.timestamp}）；"
              f"客户端只能缓存与回传，无法解析或伪造"),
    )


def decode_payload(token: str) -> PayloadInfo:
    """识别 ``gAAAAA…`` 串的两种形态。

    **判别顺序很重要**：这里先试形态 B（能否解出 JSON 数组），失败才试形态 A。

    为什么不能像 SDK 那样先判形态 A：两种形态的字符串整串 base64 解码后
    **前 5 字节都是** ``80 00 00 00 00``（docs/01 §4.5.2 已记录），
    因此"首字节 0x80"根本不是判别条件。真正的判别条件是
    **去掉 7 字符后能否解出 UTF-8 JSON** —— 载荷可以，Fernet 不行。
    """
    if not isinstance(token, str):
        return PayloadInfo(kind=KIND_UNKNOWN, note="不是字符串")

    solved = token.endswith(SOLVED_SUFFIX)
    body = token[: -len(SOLVED_SUFFIX)] if solved else token

    form_b = _try_form_b(body, solved)
    if form_b is not None and form_b.kind == KIND_SENTINEL_PAYLOAD:
        return form_b

    form_a = _try_form_a(body, solved)
    if form_a is not None:
        return form_a

    return form_b or PayloadInfo(kind=KIND_UNKNOWN, solved=solved,
                                 note="无法识别形态")


def answer_counter(token: str) -> int | None:
    """取出载荷里的 PoW 计数器（字段 [3]），非载荷则返回 None。"""
    info = decode_payload(token)
    if not info.is_payload or not info.fields or len(info.fields) < 4:
        return None
    counter = info.fields[3]
    return counter if isinstance(counter, int) else None


# --- 指纹构造 ------------------------------------------------------------

#: 字段 [6]：样本中恒定的常量指纹串（疑为构建/版本标识）
CONSTANT_FINGERPRINT = "132f33eb272ff65e6bd412b5f3578ab9b3f322cb"
#: 字段 [2]：样本中恒定的屏幕相关常量
CONSTANT_SCREEN = 4377018368
#: 字段 [0]：格式版本号
PAYLOAD_VERSION = 3000

#: 反指纹稳定性设计：字段 10~12 每次调用从大池子里随机抽取（docs/01 §4.5.3）
_ENV_ATTRIBUTE_POOL = [
    "login", "hardwareConcurrency", "deviceMemory", "maxTouchPoints",
    "pdfViewerEnabled", "webdriver", "vendor", "platform", "product",
    "appVersion", "appName", "onLine", "doNotTrack", "cookieEnabled",
]
_DOM_PROPERTY_POOL = [
    "length", "onslotchange", "customElements", "ontransitionend",
    "onwebkitanimationend", "onpointerrawupdate", "onbeforetoggle",
]
_EVENT_NAME_POOL = [
    "customElements", "onslotchange", "onvisibilitychange",
    "ondeviceorientation", "onpointerdown",
]


def js_date_string(moment: datetime | None = None, tz_name: str | None = None) -> str:
    """近似 ``new Date().toString()``。

    浏览器输出形如 ``Wed Oct 14 2026 17:42:03 GMT+0800 (中国标准时间)``。
    括号里是**本地化时区名**，Python 无法在所有平台上完全复现，
    因此允许调用方显式传入；拿不到时退化为不带的 UTC 偏移写法。
    """
    moment = datetime.now().astimezone() if moment is None else moment
    offset = moment.strftime("%z")
    core = moment.strftime("%a %b %d %Y %H:%M:%S")
    if tz_name:
        return f"{core} GMT{offset} ({tz_name})"
    return f"{core} GMT{offset}"


def build_fingerprint(
    user_agent: str,
    *,
    language: str = "zh-CN",
    languages: str | None = None,
    hardware_concurrency: int = 8,
    time_origin: float | None = None,
    counter: int = 0,
    elapsed_ms: int = 0,
    moment: datetime | None = None,
    tz_name: str | None = None,
    rng: random.Random | None = None,
) -> list[Any]:
    """构造 25 字段指纹数组（字段序号含义见 docs/01 §4.5.3）。"""
    rng = rng or random.Random()
    time_origin = (datetime.now(timezone.utc).timestamp() * 1000
                   if time_origin is None else time_origin)
    fields: list[Any] = [None] * FINGERPRINT_FIELD_COUNT
    fields[0] = PAYLOAD_VERSION
    fields[1] = js_date_string(moment, tz_name)
    fields[2] = CONSTANT_SCREEN
    fields[3] = counter                                   # PoW 计数器
    fields[4] = user_agent
    fields[5] = None
    fields[6] = CONSTANT_FINGERPRINT
    fields[7] = language
    fields[8] = languages if languages is not None else language
    fields[9] = elapsed_ms                                # 已耗时(ms)
    fields[10] = f"{rng.choice(_ENV_ATTRIBUTE_POOL)}−[object Navigator]"
    fields[11] = f"__reactContainer${uuid.UUID(int=rng.getrandbits(128)).hex[:12]}"
    fields[12] = rng.choice(_DOM_PROPERTY_POOL)
    fields[13] = round(rng.uniform(1000.0, 120000.0), 7)
    fields[14] = str(uuid.UUID(int=rng.getrandbits(128)))
    fields[15] = ""
    fields[16] = hardware_concurrency
    fields[17] = time_origin
    for i in range(18, FINGERPRINT_FIELD_COUNT):
        fields[i] = 0
    return fields
