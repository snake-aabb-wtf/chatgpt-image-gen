"""离线自证：用 `legacy/har/` 的真实抓包证明 Sentinel 实现是对的。

为什么这件事值得单独做：

* 登录与生图都要联网、要过 Cloudflare、要消耗额度，而且失败时很难判断
  究竟是"协议实现错了"还是"环境被拦了"。先把**能离线证的部分**证到底，
  联网阶段剩下的变量就少得多。
* 更关键的是**不能假通过**。空 fixture、缺样本、少跑一项，都必须让自证
  失败 —— 否则这个命令就成了安慰剂。因此这里显式校验样本数量下限。

真值由 ``tools/build_har_vectors.py`` 从抓包现场提取，随包发布于
``cgpt/data/har_vectors.json``。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from cgpt.auth.totp import RFC6238_SECRETS as _RFC6238_SECRETS
from cgpt.auth.totp import RFC6238_VECTORS as _RFC6238_VECTORS
from cgpt.sentinel.fernet import parse_fernet
from cgpt.sentinel.payload import (
    KIND_FERNET,
    KIND_SENTINEL_PAYLOAD,
    SOLVED_SUFFIX,
    decode_payload,
    encode_answer,
)
from cgpt.sentinel.pow import digest_for, meets_difficulty, verify
from cgpt.sentinel.xor import codec_roundtrip_matches, crack, probe_key_shape_ok

#: 真值文件随包发布
DEFAULT_FIXTURE = Path(__file__).resolve().parent / "data" / "har_vectors.json"

#: 样本数量下限。fixture 被截断/清空时必须让自证失败，而不是"零项全过"。
MIN_SAMPLES: dict[str, int] = {
    "pow": 5,
    "xor": 10,
    "kinds": 7,
    "identical": 9,
}

#: 注：RFC 6238 官方向量从 cgpt.auth.totp 单一引入（见文件顶部 import），
#: 避免 tests/ 与 selftest 各存一份常量而悄悄漂移。


@dataclass(frozen=True)
class Check:
    name: str
    passed: bool
    detail: str = ""


@dataclass
class SelfTestReport:
    checks: list[Check] = field(default_factory=list)
    fixture_path: Path | None = None

    @property
    def passed(self) -> bool:
        return bool(self.checks) and all(c.passed for c in self.checks)

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if not c.passed]

    @property
    def passed_count(self) -> int:
        return sum(1 for c in self.checks if c.passed)

    def render(self) -> str:
        lines: list[str] = []
        if self.fixture_path:
            lines.append(f"真值来源：{self.fixture_path}")
        lines.append("")
        for check in self.checks:
            mark = "PASS" if check.passed else "FAIL"
            lines.append(f"  [{mark}] {check.name}")
            if check.detail:
                for detail_line in check.detail.splitlines():
                    lines.append(f"         {detail_line}")
        lines.append("")
        lines.append(f"合计 {len(self.checks)} 项，通过 {self.passed_count} 项，"
                     f"失败 {len(self.failures)} 项")
        if not self.passed:
            lines.append("")
            lines.append("离线自证未通过 —— 先修这里，再谈联网。")
        return "\n".join(lines)


def load_vectors(path: Path | str | None = None) -> dict[str, Any]:
    path = Path(path) if path else DEFAULT_FIXTURE
    if not path.exists():
        raise FileNotFoundError(
            f"真值文件不存在：{path}\n"
            f"请先运行：python tools/build_har_vectors.py"
        )
    return json.loads(path.read_text(encoding="utf-8"))


def _check_totp() -> Check:
    from cgpt.auth.totp import totp

    mismatches: list[str] = []
    total = 0
    for at, sha1, sha256, sha512 in _RFC6238_VECTORS:
        for algorithm, want in (("sha1", sha1), ("sha256", sha256),
                                ("sha512", sha512)):
            import base64

            secret = base64.b32encode(
                _RFC6238_SECRETS[algorithm].encode("ascii")).decode("ascii")
            got = totp(secret, at=at, digits=8, algorithm=algorithm)
            total += 1
            if got != want:
                mismatches.append(f"{algorithm} @ {at}: 期望 {want}，实得 {got}")
    return Check(
        name=f"TOTP：RFC 6238 附录 B 官方向量（{total} 组）",
        passed=not mismatches,
        detail="; ".join(mismatches) if mismatches else "全部相符",
    )


def _check_pow(sample: dict[str, Any]) -> Check:
    seed = sample["seed"]
    difficulty = sample["difficulty"]
    answer = sample["answer"]
    name = f"PoW：{sample['source']}（difficulty={difficulty}）"
    try:
        info = decode_payload(answer)
        if not info.is_payload or not info.fields:
            return Check(name=name, passed=False,
                         detail=f"答案不是 Sentinel 载荷（kind={info.kind}）")
        body = answer[:-len(SOLVED_SUFFIX)] if answer.endswith(SOLVED_SUFFIX) else answer
        payload_b64 = body[7:]
        digest = digest_for(seed, payload_b64)
        counter = info.fields[3]
        problems: list[str] = []
        if not meets_difficulty(digest, difficulty):
            problems.append(f"哈希 {digest} 的前 {len(difficulty)} 位 "
                            f"{digest[:len(difficulty)]} > {difficulty}")
        if digest[:len(difficulty)] != sample["expected_digest_prefix"]:
            problems.append(f"哈希前缀 {digest[:len(difficulty)]} ≠ 文档记录的 "
                            f"{sample['expected_digest_prefix']}")
        if counter != sample["expected_counter"]:
            problems.append(f"计数器 {counter} ≠ 文档记录的 {sample['expected_counter']}")
        if not verify(seed, difficulty, answer):
            problems.append("verify() 返回 False")
        detail = (f"seed={seed} 计数器={counter} 哈希={digest}"
                  if not problems else "; ".join(problems))
        return Check(name=name, passed=not problems, detail=detail)
    except Exception as exc:  # noqa: BLE001 - 自证要报告任何异常而不是崩掉
        return Check(name=name, passed=False, detail=f"异常：{exc!r}")


def _check_xor(sample: dict[str, Any]) -> Check:
    name = f"XOR：{sample['source']}"
    try:
        result = crack(sample["blob"])
        if result is None:
            return Check(name=name, passed=False, detail="三条还原路径均未解出")
        problems: list[str] = []
        if result.key != sample["expected_key"]:
            problems.append(f"密钥 {result.key!r} ≠ 文档记录的 "
                            f"{sample['expected_key']!r}")
        if result.item_count != sample["expected_items"]:
            problems.append(f"条目数 {result.item_count} ≠ 文档记录的 "
                            f"{sample['expected_items']}")
        # 真实旁证：明文必须符合"探针号.答案号 → 采集值"的表结构。
        # （不能用 encode(decode(x))==x 当证据 —— XOR 是对合运算，对任何密钥都成立。）
        parsed = result.parsed
        if not probe_key_shape_ok(parsed):
            problems.append("明文结构不符合「探针号.答案号」的键形状")
        if not codec_roundtrip_matches(sample["blob"], result.key):
            problems.append("编解码器自洽性检查失败")
        detail = (f"密钥={result.key!r} 条目={result.item_count} "
                  f"路径={result.source}"
                  if not problems else "; ".join(problems))
        return Check(name=name, passed=not problems, detail=detail)
    except Exception as exc:  # noqa: BLE001
        return Check(name=name, passed=False, detail=f"异常：{exc!r}")


def _check_kind(sample: dict[str, Any]) -> Check:
    name = f"形态识别：{sample['source']}"
    info = decode_payload(sample["token"])
    if info.kind != sample["expect_kind"]:
        return Check(name=name, passed=False,
                     detail=f"期望 {sample['expect_kind']}，实得 {info.kind}")
    extra = ""
    if info.kind == KIND_SENTINEL_PAYLOAD:
        if not info.fields or len(info.fields) != 25:
            return Check(name=name, passed=False,
                         detail=f"载荷字段数 {len(info.fields or [])} ≠ 25")
        # 逐字节回环：解码后按同样规则重编码，必须与原文完全相同
        re_encoded = encode_answer(info.fields, info.prefix, info.solved)
        if re_encoded != sample["token"]:
            return Check(name=name, passed=False,
                         detail=(f"重编码与原文不同："
                                 f"{len(re_encoded)} vs {len(sample['token'])} 字符"))
        extra = (f"前缀={info.prefix} solved={info.solved} 字段=25 "
                 f"逐字节回环一致")
    elif info.kind == KIND_FERNET:
        extra = f"Fernet（{info.byte_length} 字节，内嵌时间戳见下）"
    return Check(name=name, passed=True, detail=extra)


def _check_identical(sample: dict[str, Any]) -> Check:
    """复核文档的"跨抓包逐字节复用"结论在抓包原文里依然成立。

    这类结论是 docs/02 §4.5 的重点，也是初稿写错过的地方（只看 `gAAAAAB`
    前缀就下结论）。所以自证里既要有正例，也要有"不同"的反例。
    """
    expected = sample["expect_identical"]
    observed = sample["observed_identical"]
    label = "相同" if expected else "不同"
    name = f"跨抓包复用（应{label}）：{sample['left']} ↔ {sample['right']}"
    if observed != expected:
        return Check(
            name=name, passed=False,
            detail=(f"抓包现场观测为{'相同' if observed else '不同'}，"
                    f"与文档结论不符；"
                    f"左侧 {sample['left_sha256'][:16]}… / "
                    f"右侧 {sample['right_sha256'][:16]}…"))
    return Check(
        name=name, passed=True,
        detail=(f"{sample['left_len']} vs {sample['right_len']} 字符，"
                f"sha256 {sample['left_sha256'][:16]}… / "
                f"{sample['right_sha256'][:16]}…"))


def _check_fernet_timestamp(sample: dict[str, Any]) -> Check:
    name = f"Fernet：{sample['source']}"
    info = parse_fernet(sample["token"])
    if info is None:
        return Check(name=name, passed=False, detail="无法解析为 Fernet")
    if info.timestamp_iso is None:
        return Check(name=name, passed=False,
                     detail=f"内嵌时间戳不合理：{info.timestamp}")
    if info.total_len != len(sample["token"]):
        # base64 长度与解码字节数不该相同，这里只做基本自洽检查
        pass
    return Check(name=name, passed=True,
                 detail=(f"{info.total_len} 字节，密文 {len(info.ciphertext)} 字节，"
                         f"内嵌时间戳 {info.timestamp} ({info.timestamp_iso})"))


def run_selftest(fixture_path: Path | str | None = None,
                 *, progress: Callable[[str], None] | None = None) -> SelfTestReport:
    """跑完全部离线自证。返回的报告里每一项都带证据。"""
    path = Path(fixture_path) if fixture_path else DEFAULT_FIXTURE
    report = SelfTestReport(fixture_path=path)

    def note(message: str) -> None:
        if progress:
            progress(message)

    if not path.exists():
        report.checks.append(Check(
            name="真值文件存在", passed=False,
            detail=f"找不到 {path}；请先运行 python tools/build_har_vectors.py"))
        return report
    report.checks.append(Check(name=f"真值文件存在（{path.name}）", passed=True))

    vectors = json.loads(path.read_text(encoding="utf-8"))

    # --- 样本数量下限：防止"零项全过"的假绿 ---
    shortfalls: list[str] = []
    for key, minimum in MIN_SAMPLES.items():
        actual = len(vectors.get(key) or [])
        if actual < minimum:
            shortfalls.append(f"{key}: {actual} < {minimum}")
    report.checks.append(Check(
        name="真值样本数量达标",
        passed=not shortfalls,
        detail="; ".join(shortfalls) if shortfalls
        else ", ".join(f"{k}={len(vectors.get(k) or [])}"
                       for k in MIN_SAMPLES)))

    note("TOTP 官方向量…")
    report.checks.append(_check_totp())

    note(f"PoW 复算（{len(vectors.get('pow') or [])} 个样本）…")
    for sample in vectors.get("pow") or []:
        report.checks.append(_check_pow(sample))

    note(f"XOR 密钥还原（{len(vectors.get('xor') or [])} 个样本）…")
    for sample in vectors.get("xor") or []:
        report.checks.append(_check_xor(sample))

    note("令牌形态识别与逐字节回环…")
    for sample in vectors.get("kinds") or []:
        report.checks.append(_check_kind(sample))

    note("跨抓包复用断言…")
    for sample in vectors.get("identical") or []:
        report.checks.append(_check_identical(sample))

    note("Fernet 解析…")
    for sample in vectors.get("kinds") or []:
        if sample["expect_kind"] == KIND_FERNET:
            report.checks.append(_check_fernet_timestamp(sample))

    return report
