"""账号串的解析与（可选的）本地记忆。

格式就是用户手上那一行的样子（下面用占位值举例）::

    user@example.com----Example-Passw0rd!----JBSWY3DPEHPK3PXP

**安全提醒**：``save_account`` 会把密码与 2FA 密钥以**明文**写到磁盘。
这是用户显式选择的便利性取舍（会话 Cookie 本身也有 90 天寿命，正常情况下
根本不需要重新登录）。文件权限尽力设 0600，且 ``.cgpt/`` 已在 .gitignore 里。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from cgpt.auth.totp import decode_secret

#: 字段分隔符（用户给的格式）
SEPARATOR = "----"

DEFAULT_ACCOUNT_PATH = Path(".cgpt") / "account.txt"

FORMAT_HINT = "邮箱----密码----2FA密钥"


@dataclass
class AccountSecret:
    """一条账号凭据。"""

    email: str
    password: str
    totp_secret: str

    def to_line(self) -> str:
        return SEPARATOR.join((self.email, self.password, self.totp_secret))

    def masked(self) -> str:
        """给界面/日志用的脱敏形式。"""
        return f"{self.email}{SEPARATOR}****{SEPARATOR}****"


def parse_account_line(text: str) -> AccountSecret:
    """解析 ``邮箱----密码----2FA``。

    切分策略是**左边取第一段、右边取最后一段**（而不是从左往右切三段）：
    这样即使密码里含有 ``----``，也能正确解析 —— 因为 2FA 密钥是 base32，
    不可能包含连字符。容错首尾空白与换行。
    """
    if text is None:
        raise ValueError(f"账号为空。格式：{FORMAT_HINT}")

    cleaned = text.strip()
    if not cleaned:
        raise ValueError(f"账号为空。格式：{FORMAT_HINT}")

    # 粘贴多行时把换行也当作分隔（用户从别处复制常见）
    cleaned = cleaned.replace("\r\n", "\n").replace("\n", SEPARATOR)

    if SEPARATOR not in cleaned:
        raise ValueError(
            f"账号格式不对：没有找到分隔符 {SEPARATOR!r}。格式：{FORMAT_HINT}")

    email, rest = cleaned.split(SEPARATOR, 1)
    if SEPARATOR not in rest:
        raise ValueError(
            f"账号格式不对：只找到 2 段，需要 3 段。格式：{FORMAT_HINT}")
    password, totp_secret = rest.rsplit(SEPARATOR, 1)

    email, password, totp_secret = (email.strip(), password.strip(),
                                    totp_secret.strip())

    if not email:
        raise ValueError(f"邮箱为空。格式：{FORMAT_HINT}")
    if "@" not in email:
        raise ValueError(f"邮箱看起来不对：{email!r}")
    if not password:
        raise ValueError(f"密码为空。格式：{FORMAT_HINT}")
    if not totp_secret:
        raise ValueError(
            "2FA 密钥为空。注意这里要填 2FA 设置页给出的 base32 密钥，"
            "不是 6 位验证码，也不是恢复码。")

    # 提前校验 base32，避免登录跑到一半才因为密钥非法失败。
    # 注意必须用 decode_secret —— normalize_secret 只做大小写/补齐，
    # 对非法字符不会报错（这里曾错用后者，导致校验形同虚设）。
    try:
        decode_secret(totp_secret)
    except ValueError as exc:
        raise ValueError(f"2FA 密钥不合法：{exc}") from exc

    return AccountSecret(email=email, password=password,
                         totp_secret=totp_secret)


def save_account(secret: AccountSecret,
                 path: Path | str = DEFAULT_ACCOUNT_PATH) -> Path:
    """明文保存账号串（原子写入 + 尽力 0600）。"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(secret.to_line() + "\n", encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass  # Windows 上 chmod 语义有限，不作为失败
    tmp.replace(path)
    return path


def load_account(path: Path | str = DEFAULT_ACCOUNT_PATH) -> AccountSecret | None:
    """读取已保存的账号；文件不存在或内容非法都返回 None（不抛错）。

    界面启动时会调用它做自动填充，因此"没有"是正常情况而不是错误。
    """
    path = Path(path)
    if not path.exists():
        return None
    try:
        return parse_account_line(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def forget_account(path: Path | str = DEFAULT_ACCOUNT_PATH) -> bool:
    """删除已保存的账号串。返回是否真的删掉了。"""
    path = Path(path)
    if not path.exists():
        return False
    try:
        path.unlink()
        return True
    except OSError:
        return False
