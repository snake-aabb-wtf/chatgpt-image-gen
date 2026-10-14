"""从 legacy/har/ 里的真实抓包提取离线自证用的真值向量。

为什么要单独一个脚本：

* 自证测试不该"抄"分析文档里的数字 —— 那样只是验证抄写。这里把真值
  **从抓包现场提取**并连同文档给出的期望值一起落盘，测试再拿实现去对。
  两者不一致时，能立刻知道是"实现错了"还是"文档错了"。
* 大抓包（117 MB / 83 MB）只读一次，之后自证跑的是小 JSON，秒级完成。

用法::

    python tools/build_har_vectors.py            # 写入 cgpt/data/har_vectors.json
    python tools/build_har_vectors.py --probe    # 只打印摘要，不写文件
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cgpt.har import HarEntry, load_har_entries  # noqa: E402

#: 抓包原始文件现在归档在 legacy/ 下（它们是 cgpt 项目之前就存在的分析素材）
HAR_DIR = REPO_ROOT / "legacy" / "har"
#: 真值随包发布（39 KB），这样 `python -m cgpt selftest` 在任何安装方式下都能找到它
FIXTURE_PATH = REPO_ROOT / "cgpt" / "data" / "har_vectors.json"

#: 每个抓包文件里我们关心的 entry 序号（序号语义 = entries 数组下标，0 起）
TARGET_ENTRIES: dict[str, set[int]] = {
    "chatgpt_chat.har": {4, 27, 31},
    "chatgpt_generate_image.har": {8, 12, 14},
    "chatgpt_login.har": {275, 285, 440, 449, 674, 712},
    "chatgpt_login_包含敏感数据.har": {288},
    "chatgpt_chat_包含敏感数据.har": {6},
    "chatgpt_image_包含敏感数据.har": {4},
    "chatgpt_多轮对话_包含敏感数据.har": {4, 12},
}

#: 文档已独立解出的 XOR 密钥（docs/01 §4.8.1 + tools/README.md）。
#: 三元组 = (文件, entry 序号, 取值位置)；值是 (期望密钥, 期望条目数)。
EXPECTED_XOR: dict[tuple[str, int, str], tuple[str, int]] = {
    ("chatgpt_login.har", 285, "header.openai-sentinel-token.t"): ("17.41", 16),
    ("chatgpt_login.har", 449, "header.openai-sentinel-token.t"): ("46.46", 15),
    ("chatgpt_login.har", 712, "body.turnstile"): ("70.41", 24),
    ("chatgpt_chat.har", 31, "body.turnstile"): ("27.27", 24),
    ("chatgpt_generate_image.har", 14, "body.turnstile"): ("90.31", 22),
    ("chatgpt_chat_包含敏感数据.har", 6,
     "header.openai-sentinel-turnstile-token"): ("64.8", 23),
    ("chatgpt_image_包含敏感数据.har", 4, "body.turnstile"): ("97.63", 21),
    ("chatgpt_多轮对话_包含敏感数据.har", 4, "body.turnstile"): ("31.99", 23),
    ("chatgpt_多轮对话_包含敏感数据.har", 12, "body.turnstile"): ("3.74", 22),
    ("chatgpt_login_包含敏感数据.har", 288,
     "header.openai-sentinel-token.t"): ("4.07", 15),
}

#: 文档已复算通过的 PoW 样本（docs/01 §4.7.2）。
#: 五元组 = (文件, 答案位置, 挑战位置, 期望计数器, 期望哈希前缀)
EXPECTED_POW: list[tuple[str, str, str, int, str]] = [
    ("chatgpt_chat.har", "31:body.proofofwork", "27:resp.proofofwork", 40, "009b70"),
    ("chatgpt_generate_image.har", "14:body.proofofwork", "12:resp.proofofwork",
     13, "025bd1"),
    ("chatgpt_login.har", "712:body.proofofwork", "674:resp.proofofwork",
     11, "001e37"),
    ("chatgpt_login.har", "285:header.openai-sentinel-token.p",
     "275:resp.proofofwork", 21, "057ce0"),
    ("chatgpt_login.har", "449:header.openai-sentinel-token.p",
     "440:resp.proofofwork", 42, "03dad0"),
]

#: 需要识别形态的令牌（docs/01 §4.5.2 与 tools/sentinel-hook.js 的 decodePayload）
EXPECTED_KINDS: list[tuple[str, str, str]] = [
    # 客户端 PoW 答案：7 字符前缀(gAAAAAB) + 独立 base64，带 ~S
    ("chatgpt_chat.har", "4:header.openai-sentinel-proof-token", "sentinel-payload"),
    ("chatgpt_chat.har", "31:body.proofofwork", "sentinel-payload"),
    # 未解题的缓存 requirements token：前缀 gAAAAAC，不带 ~S
    ("chatgpt_chat.har", "27:body.p", "sentinel-payload"),
    # 服务端 Fernet：整串 base64，首字节 0x80
    ("chatgpt_chat.har", "4:header.openai-sentinel-chat-requirements-token", "fernet"),
    ("chatgpt_chat.har", "31:body.prepare_token", "fernet"),
    ("chatgpt_chat.har", "31:resp.token", "fernet"),
    ("chatgpt_login.har", "449:header.openai-sentinel-token.c", "fernet"),
]

#: 跨抓包"逐字节复用"断言（docs/02 §4.5）—— 这些是最容易被只看前缀就下结论而搞错的地方
EXPECTED_IDENTICAL: list[tuple[str, str, bool]] = [
    # c 必须逐字节等于 /sentinel/req 响应里的 token（docs/01 §4.8）
    ("chatgpt_login.har:285:header.openai-sentinel-token.c",
     "chatgpt_login.har:275:resp.token", True),
    ("chatgpt_login.har:449:header.openai-sentinel-token.c",
     "chatgpt_login.har:440:resp.token", True),
    # chat[4] 用的是上一轮（login[712]）签发的三条令牌 —— 来自登录抓包，不是本轮 chat[31]
    ("chatgpt_chat.har:4:header.openai-sentinel-chat-requirements-token",
     "chatgpt_login.har:712:resp.token", True),
    ("chatgpt_chat.har:4:header.openai-sentinel-proof-token",
     "chatgpt_login.har:712:body.proofofwork", True),
    ("chatgpt_chat.har:4:header.openai-sentinel-turnstile-token",
     "chatgpt_login.har:712:body.turnstile", True),
    # 而 chat[31] 本轮新签发的那一套，被图片会话 [8] 逐字节复用
    ("chatgpt_generate_image.har:8:header.openai-sentinel-chat-requirements-token",
     "chatgpt_chat.har:31:resp.token", True),
    ("chatgpt_generate_image.har:8:header.openai-sentinel-proof-token",
     "chatgpt_chat.har:31:body.proofofwork", True),
    ("chatgpt_generate_image.har:8:header.openai-sentinel-turnstile-token",
     "chatgpt_chat.har:31:body.turnstile", True),
    # 反例：chat[4] 用的**不是**本轮 chat[31] 新签发的那一套（长度都不同）
    ("chatgpt_chat.har:4:header.openai-sentinel-chat-requirements-token",
     "chatgpt_chat.har:31:resp.token", False),
]


def _load(filenames: set[str]) -> dict[str, dict[int, HarEntry]]:
    loaded: dict[str, dict[int, HarEntry]] = {}
    for name in sorted(filenames):
        path = HAR_DIR / name
        if not path.exists():
            print(f"  !! 缺少抓包文件，跳过：{name}", file=sys.stderr)
            continue
        started = time.time()
        entries = load_har_entries(path, only=TARGET_ENTRIES[name])
        loaded[name] = entries
        missing = TARGET_ENTRIES[name] - set(entries)
        note = f"，缺 {sorted(missing)}" if missing else ""
        print(f"  {name}: {len(entries)} 条 / {time.time() - started:.1f}s{note}")
    return loaded


def get_value(entry: HarEntry | None, location: str) -> Any:
    """按 ``header.<名>`` / ``body.<字段>`` / ``resp.<字段>`` 取值。

    ``header`` 若指向一个 JSON 字符串（如 ``openai-sentinel-token``），
    支持再往下点一层，例如 ``header.openai-sentinel-token.t``。
    """
    if entry is None:
        return None
    parts = location.split(".")
    if parts[0] == "header":
        data: Any = entry.request_header(parts[1])
        rest = parts[2:]
        if rest and isinstance(data, str):
            try:
                data = json.loads(data)
            except ValueError:
                return None
    elif parts[0] == "body":
        data, rest = entry.request_json(), parts[1:]
    elif parts[0] == "resp":
        data, rest = entry.response_json(), parts[1:]
    else:
        raise ValueError(f"未知位置前缀：{location}")

    for key in rest:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def resolve(loaded: dict[str, dict[int, HarEntry]], ref: str) -> Any:
    """``文件:entry:位置`` → 值。"""
    filename, index, location = ref.split(":", 2)
    return get_value((loaded.get(filename) or {}).get(int(index)), location)


def build() -> dict[str, Any]:
    print("读取抓包（只保留关心的 entry）…")
    loaded = _load(set(TARGET_ENTRIES))

    vectors: dict[str, Any] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "note": ("由 tools/build_har_vectors.py 从 legacy/har/ 现场提取。"
                 "expected_* 来自 docs/ 的独立分析结论，用作自证的对照真值。"),
        "pow": [],
        "xor": [],
        "kinds": [],
        "identical": [],
    }

    for filename, answer_ref, challenge_ref, counter, digest in EXPECTED_POW:
        answer = resolve(loaded, f"{filename}:{answer_ref}")
        challenge = resolve(loaded, f"{filename}:{challenge_ref}") or {}
        if not answer or not challenge.get("seed"):
            print(f"  !! PoW 样本缺失：{filename} {answer_ref}", file=sys.stderr)
            continue
        vectors["pow"].append({
            "source": f"{filename}:{answer_ref}",
            "seed": challenge.get("seed"),
            "difficulty": challenge.get("difficulty"),
            "answer": answer,
            "expected_counter": counter,
            "expected_digest_prefix": digest,
        })

    for (filename, index, location), (key, count) in EXPECTED_XOR.items():
        blob = get_value((loaded.get(filename) or {}).get(index), location)
        if not blob:
            print(f"  !! XOR 样本缺失：{filename}[{index}] {location}", file=sys.stderr)
            continue
        vectors["xor"].append({
            "source": f"{filename}:{index}:{location}",
            "blob": blob,
            "expected_key": key,
            "expected_items": count,
        })

    for filename, reference, kind in EXPECTED_KINDS:
        token = resolve(loaded, f"{filename}:{reference}")
        if not token:
            print(f"  !! 令牌缺失：{filename} {reference}", file=sys.stderr)
            continue
        vectors["kinds"].append({
            "source": f"{filename}:{reference}",
            "token": token,
            "expect_kind": kind,
        })

    for left, right, identical in EXPECTED_IDENTICAL:
        left_value = resolve(loaded, left)
        right_value = resolve(loaded, right)
        if left_value is None or right_value is None:
            print(f"  !! 复用断言缺值：{left} / {right}", file=sys.stderr)
            continue
        vectors["identical"].append({
            "left": left,
            "right": right,
            "expect_identical": identical,
            # 现场观测结果 + 两侧哈希：既是证据，也让自证能复核"文档的说法还成立吗"
            "observed_identical": left_value == right_value,
            "left_sha256": hashlib.sha256(left_value.encode()).hexdigest(),
            "right_sha256": hashlib.sha256(right_value.encode()).hexdigest(),
            "left_len": len(left_value),
            "right_len": len(right_value),
        })

    return vectors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", action="store_true", help="只打印摘要，不写文件")
    args = parser.parse_args()

    started = time.time()
    vectors = build()
    summary = {key: len(value) for key, value in vectors.items()
               if isinstance(value, list)}
    print(f"\n提取完成（{time.time() - started:.1f}s）：{summary}")

    if args.probe:
        return 0

    FIXTURE_PATH.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE_PATH.write_text(json.dumps(vectors, ensure_ascii=False, indent=2),
                            encoding="utf-8")
    print(f"已写入 {FIXTURE_PATH.relative_to(REPO_ROOT)} "
          f"({FIXTURE_PATH.stat().st_size / 1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
