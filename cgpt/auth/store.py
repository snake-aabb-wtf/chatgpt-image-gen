"""凭据持久化。

安全约定：
* 文件权限尽力设为 0600（Windows 上 chmod 只影响只读位，真正的保护来自
  用户目录 ACL —— 因此这里不把 chmod 失败当作错误，但也不假装它生效了）；
* 凭据内容**永不**整体写进日志，只打印长度与关键字段的存在性。
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from pydantic import ValidationError

from cgpt.errors import CredentialsNotFoundError
from cgpt.models import Credentials

DEFAULT_CREDENTIALS_PATH = Path(".cgpt") / "credentials.json"
DEFAULT_PROFILE_DIR = Path(".cgpt") / "profile"


def save_credentials(creds: Credentials, path: Path | str = DEFAULT_CREDENTIALS_PATH) -> Path:
    """原子写入凭据（先写临时文件再替换，避免中途失败留下半截 JSON）。"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(creds.model_dump_json(indent=2), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass  # Windows 上 chmod 语义有限，不作为失败
    tmp.replace(path)
    return path


def load_credentials(path: Path | str = DEFAULT_CREDENTIALS_PATH) -> Credentials:
    """读取凭据；任何问题都转成带操作指引的 ``CredentialsNotFoundError``。

    分三步报错，因为三种坏法的"下一步"不一样：文件不存在 → 去登录；
    不是 JSON → 删文件重登；是 JSON 但没有会话 Cookie → 说明这份文件是
    半成品（比如上次登录中途失败），同样重登。
    """
    path = Path(path)
    if not path.exists():
        raise CredentialsNotFoundError(
            f"凭据文件不存在：{path}\n"
            f"请先登录：python -m cgpt login --email <邮箱> --password <密码> "
            f"--totp-secret <2FA密钥>"
        )

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CredentialsNotFoundError(f"凭据文件无法读取：{path}\n{exc}") from exc

    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise CredentialsNotFoundError(
            f"凭据文件无法解析（不是合法 JSON）：{path}\n{exc}\n"
            f"删除该文件后重新登录。"
        ) from exc

    try:
        creds = Credentials.model_validate(data)
    except ValidationError as exc:
        raise CredentialsNotFoundError(
            f"凭据文件损坏或缺少必需字段：{path}\n{exc}\n"
            f"重新登录即可覆盖：python -m cgpt login --email <邮箱> "
            f"--password <密码> --totp-secret <2FA密钥>"
        ) from exc

    if not creds.cookies:
        raise CredentialsNotFoundError(
            f"凭据文件缺少必需字段：cookies（会话 Cookie 为空）：{path}\n"
            f"这通常意味着上次登录中途失败。重新登录即可覆盖："
            f"python -m cgpt login --email <邮箱> --password <密码> "
            f"--totp-secret <2FA密钥>"
        )
    return creds
