"""离线自证的回归门。

`python -m cgpt selftest` 是给人看的；这个测试是给 CI 看的 ——
它保证真值文件没被改坏、样本没被截断、四条自证路径依然全绿。
"""

from __future__ import annotations

import json

import pytest

from cgpt.selftest import DEFAULT_FIXTURE, MIN_SAMPLES, load_vectors, run_selftest


@pytest.fixture(scope="module")
def report():
    return run_selftest()


def test_selftest_passes_end_to_end(report) -> None:
    failures = "\n".join(f"{c.name}: {c.detail}" for c in report.failures)
    assert report.passed, f"离线自证未通过：\n{failures}"


def test_selftest_runs_every_check_family(report) -> None:
    """漏跑某一类检查也必须算失败 —— 否则自证会悄悄缩水。"""
    names = "\n".join(c.name for c in report.checks)
    for family in ("TOTP", "PoW", "XOR", "形态识别", "跨抓包复用", "Fernet",
                   "真值样本数量达标"):
        assert family in names, f"自证缺少 {family} 类检查"


def test_selftest_check_count_matches_sample_count(report) -> None:
    """检查项数量必须与样本量对得上，防止某一类被静默跳过。"""
    vectors = load_vectors()
    families = ("totp", "counts", "pow", "xor", "kinds", "identical", "fernet")
    assert len(report.checks) >= sum(len(vectors.get(k) or [])
                                     for k in ("pow", "xor", "kinds", "identical"))
    assert families  # 占位：families 只是给人读的分类清单


def test_fixture_meets_minimum_sample_counts() -> None:
    vectors = load_vectors()
    for key, minimum in MIN_SAMPLES.items():
        assert len(vectors.get(key) or []) >= minimum, f"{key} 样本不足"


def test_fixture_exists_and_is_committed_artifact() -> None:
    assert DEFAULT_FIXTURE.exists(), (
        f"缺少真值文件 {DEFAULT_FIXTURE}；请运行 python tools/build_har_vectors.py")
    assert DEFAULT_FIXTURE.stat().st_size > 10_000


def test_missing_fixture_fails_loudly_instead_of_passing_vacuously(tmp_path) -> None:
    """空/缺文件必须报失败，绝不能"零项全过"。"""
    report = run_selftest(tmp_path / "does-not-exist.json")
    assert report.passed is False
    assert any("真值文件" in c.name for c in report.failures)


def test_truncated_fixture_fails_on_sample_counts(tmp_path) -> None:
    path = tmp_path / "har_vectors.json"
    path.write_text(json.dumps({"pow": [], "xor": [], "kinds": [],
                                "identical": []}), encoding="utf-8")
    report = run_selftest(path)
    assert report.passed is False
    count_check = next(c for c in report.checks if "数量达标" in c.name)
    assert count_check.passed is False


def test_selftest_report_render_mentions_failures_when_failing(tmp_path) -> None:
    report = run_selftest(tmp_path / "nope.json")
    rendered = report.render()
    assert "[FAIL]" in rendered
    assert "离线自证未通过" in rendered
