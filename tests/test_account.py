"""账号串解析与本地记忆 —— 重点是"粘错了要能说清哪里错"。"""

from __future__ import annotations

from pathlib import Path

import pytest

from cgpt.account import (
    DEFAULT_ACCOUNT_PATH,
    SEPARATOR,
    forget_account,
    load_account,
    parse_account_line,
    save_account,
)

#: 测试用占位值（刻意不是真实凭据 —— 仓库里不该出现可用的密钥）
EMAIL = "user@example.com"
PASSWORD = "Example-Passw0rd!"
TOTP = "JBSWY3DPEHPK3PXP"
LINE = f"{EMAIL}{SEPARATOR}{PASSWORD}{SEPARATOR}{TOTP}"


def test_parses_the_exact_format_the_user_was_given() -> None:
    secret = parse_account_line(LINE)
    assert secret.email == EMAIL
    assert secret.password == PASSWORD
    assert secret.totp_secret == TOTP


def test_roundtrips_through_to_line() -> None:
    assert parse_account_line(LINE).to_line() == LINE


@pytest.mark.parametrize("raw", [
    f"  {LINE}  ",
    f"{LINE}\n",
    f"\n{LINE}\n",
    f"\t{LINE}\t",
])
def test_tolerates_surrounding_whitespace(raw: str) -> None:
    assert parse_account_line(raw).email == EMAIL


def test_tolerates_newline_separators_from_copy_paste() -> None:
    """从别处复制时字段常被拆成多行。"""
    secret = parse_account_line(f"{EMAIL}\n{PASSWORD}\n{TOTP}")
    assert secret == parse_account_line(LINE)


def test_password_containing_separator_still_parses() -> None:
    """左取第一段、右取最后一段 —— 密码里含 ---- 也不会切错。"""
    secret = parse_account_line(f"{EMAIL}----ab----cd----{TOTP}")
    assert secret.password == "ab----cd"
    assert secret.totp_secret == TOTP


def test_totp_secret_case_and_grouping_are_tolerated() -> None:
    lower = parse_account_line(
        f"{EMAIL}----{PASSWORD}----jbsw y3dp ehpk 3pxp")
    assert lower.totp_secret.replace(" ", "").upper() == TOTP


@pytest.mark.parametrize("raw,expect", [
    ("", "为空"),
    ("   ", "为空"),
    (f"{EMAIL}----{PASSWORD}", "只找到 2 段"),
    (f"{EMAIL}{PASSWORD}{TOTP}", "没有找到分隔符"),
    (f"----{PASSWORD}----{TOTP}", "邮箱为空"),
    (f"not-an-email----{PASSWORD}----{TOTP}", "邮箱看起来不对"),
    (f"{EMAIL}--------{TOTP}", "密码为空"),
    (f"{EMAIL}----{PASSWORD}----", "2FA 密钥为空"),
    (f"{EMAIL}----{PASSWORD}----0189!!!bad!!!", "2FA 密钥不合法"),
])
def test_error_messages_are_actionable(raw: str, expect: str) -> None:
    with pytest.raises(ValueError, match=expect):
        parse_account_line(raw)


def test_missing_totp_error_explains_secret_vs_code() -> None:
    """常见误解：把 6 位验证码填进密钥位。"""
    with pytest.raises(ValueError) as excinfo:
        parse_account_line(f"{EMAIL}----{PASSWORD}----")
    message = str(excinfo.value)
    assert "base32" in message and "不是 6 位验证码" in message


def test_none_input_is_rejected() -> None:
    with pytest.raises(ValueError, match="为空"):
        parse_account_line(None)  # type: ignore[arg-type]


def test_masked_hides_secrets_but_keeps_email() -> None:
    masked = parse_account_line(LINE).masked()
    assert EMAIL in masked
    assert PASSWORD not in masked
    assert TOTP not in masked


def test_save_then_load_roundtrip(tmp_path: Path) -> None:
    path = save_account(parse_account_line(LINE), tmp_path / "account.txt")
    assert load_account(path) == parse_account_line(LINE)


def test_save_creates_parent_dir_and_leaves_no_tmp(tmp_path: Path) -> None:
    path = save_account(parse_account_line(LINE),
                        tmp_path / "nested" / "account.txt")
    assert path.exists()
    assert list(path.parent.glob("*.tmp")) == []


def test_load_returns_none_when_missing(tmp_path: Path) -> None:
    assert load_account(tmp_path / "nope.txt") is None


def test_load_returns_none_for_garbage_instead_of_raising(tmp_path: Path) -> None:
    path = tmp_path / "account.txt"
    path.write_text("这不是账号串", encoding="utf-8")
    assert load_account(path) is None


def test_forget_account_removes_file(tmp_path: Path) -> None:
    path = save_account(parse_account_line(LINE), tmp_path / "account.txt")
    assert forget_account(path) is True
    assert not path.exists()
    assert forget_account(path) is False


def test_default_path_lives_under_gitignored_cgpt_dir() -> None:
    """明文密码不能落在会被提交的位置。"""
    assert DEFAULT_ACCOUNT_PATH.parts[0] == ".cgpt"
