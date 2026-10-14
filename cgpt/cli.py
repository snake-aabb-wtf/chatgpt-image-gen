"""命令行入口。

命令一览::

    python -m cgpt login     --email … --password … --totp-secret …
    python -m cgpt whoami
    python -m cgpt generate  "生成一张地球图片" --out earth.png
    python -m cgpt sentinel  decode <令牌>
    python -m cgpt sentinel  crack  <blob>
    python -m cgpt selftest

安全约定：**密码与 2FA 密钥不进日志、不进 shell 历史**。
优先从环境变量或 ``--password-stdin`` 读取，命令行参数只作为最后手段。
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import click

from cgpt import __version__
from cgpt.config import Settings
from cgpt.errors import CgptError

ENV_EMAIL = "CGPT_EMAIL"
ENV_PASSWORD = "CGPT_PASSWORD"
ENV_TOTP_SECRET = "CGPT_TOTP_SECRET"


def _echo(message: str) -> None:
    click.echo(message, err=True)


def _resolve_secret(value: str | None, env_name: str, prompt: str,
                    *, hide_input: bool = True) -> str:
    """按 环境变量 → 命令行参数 → 交互输入 的顺序取敏感值。"""
    from_env = os.environ.get(env_name)
    if from_env:
        return from_env
    if value:
        return value
    if not sys.stdin.isatty():
        raise click.UsageError(
            f"缺少 {env_name}。非交互环境下请用环境变量提供："
            f"$env:{env_name}='…'")
    return click.prompt(prompt, hide_input=hide_input)


def _settings(ctx: click.Context) -> Settings:
    return Settings(
        credentials_path=Path(ctx.obj["credentials"]),
        profile_dir=Path(ctx.obj["profile"]),
        debug_dir=Path(ctx.obj["debug_dir"]),
        headless=ctx.obj["headless"],
        originator=ctx.obj["originator"],
    )


def _challenge_prompt(url: str) -> bool:
    """命令行下的人机验证交互：把验证页开出来，等用户点完。

    返回 True 表示"已经过验证了，可以重试"。
    """
    _echo("")
    _echo("⚠ 被 Cloudflare 人机验证拦住，自动用浏览器重发也没过去。")
    _echo(f"  浏览器窗口已打开在：{url}")
    _echo("  请在浏览器里完成验证（一般点一下复选框就行），")
    _echo("  然后回到这里按回车 —— 我会重读 Cookie 并自动重试。")
    if not sys.stdin.isatty():
        _echo("  当前不是交互终端，无法等待人工验证。")
        return False
    answer = click.prompt("  完成了吗（回车=是，输入 n=放弃）", default="",
                          show_default=False)
    return answer.strip().lower() not in ("n", "no", "否")


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--credentials", default=".cgpt/credentials.json", show_default=True,
              help="凭据文件路径")
@click.option("--profile", default=".cgpt/profile", show_default=True,
              help="浏览器持久化 profile 目录（复用设备指纹）")
@click.option("--debug-dir", default=".cgpt/debug", show_default=True,
              help="登录失败时保存截图/HTML 的目录")
@click.option("--headed/--headless", "headless", default=False,
              help="是否显示浏览器窗口（登录建议显示，便于人工介入）")
@click.option("--originator", default="chatgpt.com", show_default=True,
              help="客户端来源标识头（抓包中为 'Codex Browser'）")
@click.version_option(__version__, prog_name="cgpt")
@click.pass_context
def main(ctx: click.Context, credentials: str, profile: str, debug_dir: str,
         headless: bool, originator: str) -> None:
    """用 ChatGPT 账密 + 2FA 登录并请求生图。"""
    ctx.ensure_object(dict)
    ctx.obj.update(credentials=credentials, profile=profile, debug_dir=debug_dir,
                   headless=headless, originator=originator)


# --- login ---------------------------------------------------------------

@main.command()
@click.option("--email", default=None, help=f"账号邮箱（或设 ${ENV_EMAIL}）")
@click.option("--password", default=None,
              help=f"密码（或设 ${ENV_PASSWORD}；不建议写在命令行）")
@click.option("--totp-secret", default=None,
              help=f"2FA 的 base32 密钥（或设 ${ENV_TOTP_SECRET}）")
@click.pass_context
def login(ctx: click.Context, email: str | None, password: str | None,
          totp_secret: str | None) -> None:
    """登录并把凭据写入凭据文件。"""
    from cgpt.client import Client

    email = email or os.environ.get(ENV_EMAIL)
    if not email:
        if not sys.stdin.isatty():
            raise click.UsageError(f"缺少邮箱：请用 --email 或 ${ENV_EMAIL}")
        email = click.prompt("邮箱")
    password = _resolve_secret(password, ENV_PASSWORD, "密码")
    totp_secret = _resolve_secret(totp_secret, ENV_TOTP_SECRET, "2FA 密钥")

    settings = _settings(ctx)
    try:
        with Client.login(email=email, password=password,
                          totp_secret=totp_secret, settings=settings,
                          headless=settings.headless, log=_echo) as client:
            path = client.save()
            credentials = client.credentials
    except CgptError as exc:
        _echo("")
        _echo(f"登录失败：{exc}")
        raise SystemExit(2) from exc

    _echo("")
    _echo(f"凭据已保存到 {path}")
    _echo(f"  Cookie      : {len(credentials.cookies)} 个"
          f"（会话 Cookie {'有' if credentials.has_session_cookie() else '无'}）")
    if credentials.bearer:
        _echo(f"  Bearer      : 有（{len(credentials.bearer)} 字符）")
    else:
        _echo("  Bearer      : 无（仅靠 Cookie 请求，可能仍可用）")
    _echo(f"  account_id  : {credentials.account_id}")
    _echo(f"  oai-did     : {credentials.device_id}")
    if credentials.sentinel:
        _echo("  哨兵令牌    : 齐（三条，TTL 540 秒）")
    else:
        _echo("  哨兵令牌    : 缺 —— 生图时会自动重新获取")


# --- whoami --------------------------------------------------------------

@main.command()
@click.pass_context
def whoami(ctx: click.Context) -> None:
    """校验会话是否有效，并打印账号与生图能力。"""
    from cgpt.client import Client

    settings = _settings(ctx)
    try:
        with Client.from_credentials(settings=settings, log=_echo,
                                     challenge_prompt=_challenge_prompt) as client:
            info = client.web.accounts_check()
            me = client.whoami()
    except CgptError as exc:
        _echo(f"会话不可用：{exc}")
        raise SystemExit(2) from exc

    click.echo(json.dumps({
        "email": me.get("email"),
        "user_id": me.get("id"),
        "name": me.get("name"),
        "amr": me.get("amr"),
        "account_id": info.account_id,
        "plan": info.plan,
        "image_gen_tool_enabled": info.can_generate_images,
        "features_count": len(info.features),
    }, ensure_ascii=False, indent=2))


# --- generate ------------------------------------------------------------

@main.command()
@click.argument("prompt")
@click.option("--out", default=None, help="输出文件路径（默认按会话 id 命名）")
@click.option("--timeout", default=None, type=float,
              help="等待出图的总秒数（默认 720）")
@click.option("--no-refresh-sentinel", is_flag=True,
              help="不自动刷新准入令牌（调试用）")
@click.pass_context
def generate(ctx: click.Context, prompt: str, out: str | None,
             timeout: float | None, no_refresh_sentinel: bool) -> None:
    """请求生成图片并落盘。"""
    from cgpt.client import Client

    settings = _settings(ctx)
    try:
        with Client.from_credentials(settings=settings, log=_echo,
                                     challenge_prompt=_challenge_prompt) as client:
            result = client.generate_image(
                prompt, out=out, timeout=timeout,
                refresh_sentinel=not no_refresh_sentinel)
            client.save()          # 刷新后的哨兵令牌一并存下
    except CgptError as exc:
        _echo("")
        _echo(f"生图失败：{exc}")
        raise SystemExit(2) from exc

    payload = {
        "conversation_id": result.conversation_id,
        "title": result.title,
        "images": [{"path": str(image.path), "width": image.width,
                    "height": image.height, "size_bytes": image.size_bytes,
                    "mime_type": image.mime_type,
                    "asset_pointer": image.asset_pointer}
                   for image in result.images],
        "notes": result.notes,
    }
    click.echo(json.dumps(payload, ensure_ascii=False, indent=2))


# --- sentinel ------------------------------------------------------------

@main.group()
def sentinel() -> None:
    """离线取证：解码 Sentinel 令牌（不需要网络）。"""


@sentinel.command("decode")
@click.argument("token")
def sentinel_decode(token: str) -> None:
    """识别令牌形态并解码（指纹载荷 / Fernet）。"""
    from cgpt.sentinel import decode_payload

    info = decode_payload(token)
    click.echo(f"形态      : {info.kind}")
    click.echo(f"前缀      : {info.prefix}")
    click.echo(f"已解出(~S): {info.solved}")
    click.echo(f"解码字节数: {info.byte_length}")
    if info.note:
        click.echo(f"说明      : {info.note}")
    if info.fields:
        click.echo(f"字段数    : {len(info.fields)}")
        for index, value in enumerate(info.fields):
            click.echo(f"  [{index:2d}] {json.dumps(value, ensure_ascii=False)}")


@sentinel.command("crack")
@click.argument("blob")
def sentinel_crack(blob: str) -> None:
    """还原 XOR 混淆的 t / turnstile 答案表。"""
    from cgpt.sentinel import crack

    result = crack(blob)
    if result is None:
        click.echo("三条还原路径均未解出（候选密钥 / 单字节 / 已知前缀推导）")
        raise SystemExit(1)
    click.echo(f"XOR 密钥  : {result.key!r}")
    click.echo(f"还原路径  : {result.source}")
    click.echo(f"条目数    : {result.item_count}")
    click.echo("明文      :")
    click.echo(json.dumps(result.parsed, ensure_ascii=False, indent=2)[:4000])


# --- gui -----------------------------------------------------------------

@main.command()
@click.pass_context
def gui(ctx: click.Context) -> None:
    """打开图形界面（粘贴「邮箱----密码----2FA密钥」即可登录并生图）。"""
    from cgpt.gui import launch

    try:
        launch(_settings(ctx))
    except CgptError as exc:
        _echo(str(exc))
        raise SystemExit(2) from exc


# --- selftest ------------------------------------------------------------

@main.command()
def selftest() -> None:
    """用 legacy/har/ 提取的真值离线自证 Sentinel 实现（不联网）。"""
    from cgpt.selftest import run_selftest

    report = run_selftest(progress=_echo)
    click.echo(report.render())
    raise SystemExit(0 if report.passed else 1)


if __name__ == "__main__":
    main()
