"""生图编排：一次性把"发提示词 → 拿图 → 落盘 → 自证"跑完。

生图**没有独立接口**（docs/04 §0）：它复用 ``POST /backend-api/f/conversation``，
是否调用图像工具完全由服务端依据 ``image_gen_tool_enabled`` 开关 + 用户意图
决定。因此本模块必须能如实处理"请求成功但没出图"这一正常分支 ——
那是 ``NoImageProducedError``，而不是伪造一个成功。
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from cgpt.api.client import ChatGptWebClient, find_assets_in_conversation
from cgpt.errors import (
    CgptError,
    InvalidPromptError,
    NoImageProducedError,
    QuotaExhaustedError,
)
from cgpt.models import GenerationResult, ImageAsset, ImageResult

#: 常见图片容器的魔数
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
JPEG_MAGIC = b"\xff\xd8\xff"
WEBP_RIFF = b"RIFF"
WEBP_TAG = b"WEBP"

_EXTENSION_BY_MIME = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/webp": ".webp",
    "image/gif": ".gif",
}
_MIME_BY_EXTENSION = {v: k for k, v in _EXTENSION_BY_MIME.items()}


def probe_image(data: bytes) -> tuple[str, int | None, int | None]:
    """从字节里读出 (mime, width, height)。

    刻意不依赖 Pillow：只需要读几个固定偏移的头部字段，用标准库就够，
    少一个依赖少一处风险。

    PNG 的 IHDR 布局（docs/03 §4.9 记录过）::

        偏移 0   8 字节  89 50 4E 47 0D 0A 1A 0A
        偏移 8   4 字节  块长度（0x0000000D）
        偏移 12  4 字节  b"IHDR"
        偏移 16  4 字节  宽（大端）
        偏移 20  4 字节  高（大端）
    """
    if data.startswith(PNG_MAGIC):
        if len(data) >= 24 and data[12:16] == b"IHDR":
            width = int.from_bytes(data[16:20], "big")
            height = int.from_bytes(data[20:24], "big")
            return "image/png", width, height
        return "image/png", None, None

    if data.startswith(JPEG_MAGIC):
        width, height = _probe_jpeg(data)
        return "image/jpeg", width, height

    if data[:4] == WEBP_RIFF and data[8:12] == WEBP_TAG:
        return "image/webp", *_probe_webp(data)

    return "application/octet-stream", None, None


def _probe_jpeg(data: bytes) -> tuple[int | None, int | None]:
    """遍历 JPEG 段找 SOF0/SOF2（含宽高）。"""
    index = 2
    length = len(data)
    sof_markers = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
                   0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
    while index + 9 < length:
        if data[index] != 0xFF:
            index += 1
            continue
        marker = data[index + 1]
        if marker in sof_markers:
            height = int.from_bytes(data[index + 5:index + 7], "big")
            width = int.from_bytes(data[index + 7:index + 9], "big")
            return width, height
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            index += 2
            continue
        segment_length = int.from_bytes(data[index + 2:index + 4], "big")
        index += 2 + max(segment_length, 2)
    return None, None


def _probe_webp(data: bytes) -> tuple[int | None, int | None]:
    if len(data) < 30:
        return None, None
    chunk = data[12:16]
    if chunk == b"VP8 " and len(data) >= 30:
        width = int.from_bytes(data[26:28], "little") & 0x3FFF
        height = int.from_bytes(data[28:30], "little") & 0x3FFF
        return width, height
    if chunk == b"VP8L" and len(data) >= 25:
        bits = int.from_bytes(data[21:25], "little")
        return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
    if chunk == b"VP8X" and len(data) >= 30:
        width = int.from_bytes(data[24:27], "little") + 1
        height = int.from_bytes(data[27:30], "little") + 1
        return width, height
    return None, None


#: 随机文件名的熵：8 字节 = 16 个十六进制字符。64 位空间下碰撞概率可忽略，
#: 但仍然会检查一次重名（见 ``random_output_path``）—— 便宜且让保证显式。
#: 默认目录由 ``Settings.output_dir``（默认 ``output/``）决定。
RANDOM_NAME_BYTES = 8


def random_output_path(output_dir: Path | str, mime: str) -> Path:
    """在 ``output_dir`` 下生成一个随机文件名，后缀跟 MIME 走。

    文件名刻意不带语义（不含提示词、会话 id、时间戳）：提示词可能很长或含
    不适合做文件名的字符，而随机会话 id 既不美观也不比随机数更好认。
    需要按时间排序的话，用文件系统的修改时间即可。
    """
    extension = _EXTENSION_BY_MIME.get(mime or "", ".bin")
    directory = Path(output_dir)
    for _ in range(10):
        candidate = directory / f"{secrets.token_hex(RANDOM_NAME_BYTES)}{extension}"
        if not candidate.exists():
            return candidate
    # 64 位空间连撞 10 次基本不可能；真到了这里就加时间戳兜底，而不是抛错
    return directory / (f"{secrets.token_hex(RANDOM_NAME_BYTES)}"
                        f"-{int(time.time())}{extension}")


def _explicit_path(base: Path, index: int, mime: str) -> Path:
    """调用方显式给了路径时的命名：第 0 张用它，多张时加序号后缀。"""
    extension = _EXTENSION_BY_MIME.get(mime or "", "")
    if not extension:
        extension = base.suffix or ".bin"
    if index == 0:
        return base if base.suffix else base.with_suffix(extension)
    return base.with_name(f"{base.stem}_{index + 1}{extension}")


def _verify(data: bytes, asset: ImageAsset) -> tuple[list[str], str, int, int]:
    """下载后自证。返回 (提示信息, mime, width, height)。

    魔数不对是**硬错误**（那说明下的不是图片）；元数据不一致只记录，
    因为服务端给的 `size_bytes`/宽高有可能是缩略图规格。
    """
    notes: list[str] = []
    mime, width, height = probe_image(data)

    if mime == "application/octet-stream":
        raise CgptError(
            f"下载到的内容不是已知图片格式（前 16 字节：{data[:16].hex()}）。"
            f"asset={asset.asset_pointer}")

    if asset.size_bytes is not None and asset.size_bytes != len(data):
        notes.append(f"字节数与元数据不一致：下载 {len(data)}，"
                     f"元数据 {asset.size_bytes}")
    if asset.width is not None and width is not None and asset.width != width:
        notes.append(f"宽度与元数据不一致：实际 {width}，元数据 {asset.width}")
    if asset.height is not None and height is not None and asset.height != height:
        notes.append(f"高度与元数据不一致：实际 {height}，元数据 {asset.height}")
    if asset.mime_type and mime and asset.mime_type != mime:
        notes.append(f"MIME 与元数据不一致：实际 {mime}，元数据 {asset.mime_type}")

    return notes, mime, int(width or 0), int(height or 0)


def _validate_prompt(prompt: str) -> str:
    if not isinstance(prompt, str) or not prompt.strip():
        raise InvalidPromptError(
            "提示词为空或纯空白。这会在服务端浪费一次生图额度，因此本地拦截。")
    return prompt.strip()


@dataclass
class ConversationAssets:
    """会话详情兜底查询的结果。"""

    conversation_id: str
    assets: list[ImageAsset]
    title: str | None = None


def collect_assets(client: ChatGptWebClient, conversation_id: str | None,
                   *, timeout: float, poll_interval: float,
                   note: Callable[[str], None] | None = None) -> ConversationAssets:
    """轮询会话详情，直到出现图片资产指针或超时。

    需要这条兜底路径的原因：抓包本身出现过 SSE 正文未落盘的情况
    （docs/03 §0 边界 2），说明"流里没有图"不等于"没出图"。
    标题也一并取回 —— 兜底路径下 SSE 里那个 `title_generation` 事件是缺失的。
    """
    if not conversation_id:
        raise CgptError(
            "事件流里没有给出 conversation_id，无法查询会话详情。\n"
            "这通常意味着服务端在流里报了错 —— 请检查提示词是否被内容策略拦截。")

    deadline = time.monotonic() + timeout
    attempt = 0
    last_title: str | None = None
    while time.monotonic() < deadline:
        attempt += 1
        try:
            payload = client.get_conversation(conversation_id)
        except CgptError as exc:
            if note:
                note(f"第 {attempt} 次查询会话详情失败：{exc}")
            time.sleep(poll_interval)
            continue
        title = payload.get("title")
        if isinstance(title, str) and title:
            last_title = title
        assets = find_assets_in_conversation(payload)
        if assets:
            return ConversationAssets(conversation_id=conversation_id,
                                      assets=assets, title=last_title)
        if note:
            note(f"第 {attempt} 次查询：暂无图片资产，{poll_interval:.0f}s 后重试")
        time.sleep(poll_interval)

    raise NoImageProducedError(
        f"等待 {timeout:.0f} 秒后仍未在会话 {conversation_id} 里发现任何图片资产。\n"
        f"可能原因：模型这一轮没有调用图像工具（生图由服务端意图判断决定，"
        f"客户端无法强制），或账号额度已耗尽。\n"
        f"该会话可以打开 https://chatgpt.com/c/{conversation_id} 人工确认。")


def generate_image(
    client: ChatGptWebClient,
    prompt: str,
    out: Path | str | None = None,
    *,
    timeout: float | None = None,
    poll_interval: float | None = None,
    parent_message_id: str = "client-created-root",
    conversation_id: str | None = None,
    note: Callable[[str], None] | None = None,
) -> GenerationResult:
    """跑完一次生图。

    ``out`` 省略时（默认）落到 ``Settings.output_dir``（默认 ``output/``）下，
    文件名随机、后缀由图片 MIME 决定。显式传 ``out`` 只是给库调用方留的覆盖口，
    CLI 与 GUI 都不暴露。
    """
    settings = client.settings
    timeout = settings.generation_timeout if timeout is None else timeout
    poll_interval = settings.poll_interval if poll_interval is None else poll_interval
    say = note or (lambda _message: None)

    prompt = _validate_prompt(prompt)

    # ① 先确认账号有生图能力，避免白跑一轮（也避免白花额度）
    say("检查账号能力（accounts/check）…")
    info = client.require_image_gen()
    say(f"账号 {info.account_id} 计划 {info.plan}，生图开关已启用")

    # ② 额度预检
    remaining = client.image_gen_remaining()
    if remaining == 0:
        raise QuotaExhaustedError(
            "账号的生图额度已用尽（conversation/init 的 limits_progress 里 "
            "image_gen.remaining = 0）。")
    if remaining is not None:
        say(f"生图剩余额度：{remaining}")

    # ③ 预热拿 conduit_token（可选；拿不到也继续）
    say("预热会话（f/conversation/prepare）…")
    conduit_token = client.prepare_conversation(
        prompt, parent_message_id=parent_message_id,
        conversation_id=conversation_id)
    say("已拿到 conduit_token" if conduit_token else "未拿到 conduit_token（可选，继续）")

    # ④ 发送（SSE）
    say(f"发送提示词：{prompt}")
    findings = client.send_message(
        prompt, parent_message_id=parent_message_id,
        conversation_id=conversation_id, conduit_token=conduit_token,
        timeout=timeout)
    say(f"事件流结束：{findings.events_seen} 个事件，"
        f"会话 {findings.conversation_id}")

    # ⑤ 找图：流里有就用，没有就轮询会话详情
    assets = list(findings.assets)
    cid = findings.conversation_id
    title = findings.title
    if not assets:
        say("事件流里没有图片资产，转向会话详情轮询…")
        collected = collect_assets(client, cid, timeout=timeout,
                                   poll_interval=poll_interval, note=say)
        cid, assets = collected.conversation_id, collected.assets
        title = title or collected.title

    # ⑥ 逐张下载落盘
    # 默认不询问路径：一律落到 output/ 下，文件名随机、后缀跟 MIME 走。
    # ``out`` 只作为**库调用方**的显式覆盖保留，CLI 与 GUI 都不暴露它。
    output_dir = Path(settings.output_dir)
    explicit = Path(out) if out is not None else None
    results: list[ImageResult] = []
    notes: list[str] = []
    for index, asset in enumerate(assets):
        say(f"取图 {index + 1}/{len(assets)}：{asset.asset_pointer}")
        download_url = client.files_download(asset.file_id, cid)
        data = client.download_bytes(download_url)
        asset_notes, mime, width, height = _verify(data, asset)
        notes.extend(f"{asset.asset_pointer}: {n}" for n in asset_notes)

        path = (_explicit_path(explicit, index, mime) if explicit is not None
                else random_output_path(output_dir, mime))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        say(f"已落盘 {path}（{width}×{height}，{len(data)} 字节，{mime}）")

        results.append(ImageResult(path=path, width=width, height=height,
                                   size_bytes=len(data),
                                   asset_pointer=asset.asset_pointer,
                                   mime_type=mime))

    return GenerationResult(conversation_id=cid or "", title=title,
                            images=results, notes=notes)
