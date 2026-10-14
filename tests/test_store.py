"""凭据持久化 —— 重点是"坏输入给出可操作的报错"，不是 happy path。"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from cgpt.auth.store import load_credentials, save_credentials
from cgpt.errors import CredentialsNotFoundError
from cgpt.models import Credentials, SentinelTokens


def _sample() -> Credentials:
    return Credentials(
        cookies={"__Secure-next-auth.session-token.0": "abc",
                 "__Secure-next-auth.session-token.1": "def",
                 "cf_clearance": "xyz"},
        bearer="eyJhbGciOiJSUzI1NiJ9.payload.sig",
        account_id="edebbcbb-3f1d-4963-8ec1-54810e3f2c44",
        device_id="57cab66a-0ad5-42c6-8d2d-2f2e9b2a8d28",
        sentinel=SentinelTokens(chat_requirements="gAAAAAB" + "x" * 100,
                                proof="gAAAAAB" + "y" * 50,
                                turnstile="SRUZABk" + "z" * 50,
                                issued_at=time.time()),
        captured_at=time.time(),
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/154.0.0.0",
        originator="chatgpt.com",
    )


def test_roundtrip_preserves_every_field(tmp_path: Path) -> None:
    creds = _sample()
    path = save_credentials(creds, tmp_path / "credentials.json")
    assert load_credentials(path) == creds


def test_save_creates_parent_directory(tmp_path: Path) -> None:
    path = save_credentials(_sample(), tmp_path / "nested" / "deep" / "credentials.json")
    assert path.exists()


def test_save_leaves_no_tmp_file_behind(tmp_path: Path) -> None:
    path = save_credentials(_sample(), tmp_path / "credentials.json")
    assert list(tmp_path.glob("*.tmp")) == []
    assert path.exists()


def test_missing_file_error_tells_user_the_login_command(tmp_path: Path) -> None:
    with pytest.raises(CredentialsNotFoundError) as excinfo:
        load_credentials(tmp_path / "nope.json")
    message = str(excinfo.value)
    assert "不存在" in message
    assert "python -m cgpt login" in message


def test_corrupt_json_error_says_delete_and_relogin(tmp_path: Path) -> None:
    path = tmp_path / "credentials.json"
    path.write_text("{not json at all", encoding="utf-8")
    with pytest.raises(CredentialsNotFoundError) as excinfo:
        load_credentials(path)
    assert "无法解析" in str(excinfo.value)


def test_missing_required_field_is_reported_not_keyerror(tmp_path: Path) -> None:
    # 合法 JSON，但没有会话 Cookie —— 半成品凭据文件
    path = tmp_path / "credentials.json"
    path.write_text(json.dumps({"bearer": "x"}), encoding="utf-8")
    with pytest.raises(CredentialsNotFoundError) as excinfo:
        load_credentials(path)
    assert "缺少必需字段" in str(excinfo.value)
    assert "cookies" in str(excinfo.value)


@pytest.mark.skipif(os.name == "nt", reason="Windows 的 chmod 不表达 POSIX 权限位")
def test_file_mode_is_owner_only(tmp_path: Path) -> None:
    path = save_credentials(_sample(), tmp_path / "credentials.json")
    assert (path.stat().st_mode & 0o777) == 0o600
