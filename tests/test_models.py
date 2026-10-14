"""领域模型 —— 尤其是 ImageAsset.from_part 这个"从服务端结构里认图"的映射。

这个映射有两处消费者（SSE 流解析、会话详情兜底），错一处就会漏图，
所以边界情况在这里钉死。
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from cgpt.models import (
    BEARER_TTL_SECONDS,
    SENTINEL_TTL_SECONDS,
    Credentials,
    GenerationResult,
    ImageAsset,
    ImageResult,
    SentinelTokens,
)

REAL_POINTER = "sediment://file_000000009d9881fd99df55e87397a00d"


def test_cookie_header_joins_with_semicolon_space() -> None:
    creds = Credentials(cookies={"a": "1", "b": "2"})
    assert creds.cookie_header() == "a=1; b=2"


def test_has_session_cookie_accepts_sharded_nextauth_cookies() -> None:
    creds = Credentials(cookies={"__Secure-next-auth.session-token.0": "x",
                                 "__Secure-next-auth.session-token.1": "y"})
    assert creds.has_session_cookie() is True


def test_has_session_cookie_rejects_unrelated_cookies() -> None:
    assert Credentials(cookies={"oai-did": "x"}).has_session_cookie() is False


def test_bearer_considered_expired_when_missing() -> None:
    assert Credentials(cookies={}, bearer=None).is_bearer_expired() is True


def test_bearer_expiry_boundary() -> None:
    now = time.time()
    fresh = Credentials(bearer="t", captured_at=now - 60)
    stale = Credentials(bearer="t", captured_at=now - BEARER_TTL_SECONDS - 1)
    assert fresh.is_bearer_expired(now) is False
    assert stale.is_bearer_expired(now) is True


def test_sentinel_freshness_uses_480s_not_540s_margin() -> None:
    now = time.time()
    assert SENTINEL_TTL_SECONDS == 480.0
    fresh = SentinelTokens(chat_requirements="a", proof="b", turnstile="c",
                           issued_at=now - 479)
    early = SentinelTokens(chat_requirements="a", proof="b", turnstile="c",
                           issued_at=now - 481)
    assert fresh.is_fresh(now) is True
    assert early.is_fresh(now) is False


def test_image_asset_from_real_capture_shape() -> None:
    """取自 docs/03 §4.7 的真实 image_asset_pointer 结构。"""
    part = {
        "content_type": "image_asset_pointer",
        "asset_pointer": REAL_POINTER,
        "mime_type": "image/png",
        "size_bytes": 2897667,
        "width": 1254,
        "height": 1254,
        "fovea": None,
        "metadata": {
            "dalle": {"gen_id": "c35e18d6-e6f0-4215-8523-69bc34a9b741",
                      "prompt": "", "seed": None, "parent_gen_id": None,
                      "edit_op": None,
                      "serialization_title": "DALL-E generation metadata"},
            "gizmo": None,
            "generation": {"gen_id": "c35e18d6-e6f0-4215-8523-69bc34a9b741",
                           "gen_size": "smimage", "gen_size_v2": "16",
                           "seed": None, "parent_gen_id": None,
                           "height": 1254, "width": 1254,
                           "transparent_background": False,
                           "is_sticker": False, "is_purchasable": None},
        },
    }
    asset = ImageAsset.from_part(part)
    assert asset is not None
    assert asset.asset_pointer == REAL_POINTER
    assert asset.file_id == "file_000000009d9881fd99df55e87397a00d"
    assert (asset.width, asset.height) == (1254, 1254)
    assert asset.size_bytes == 2897667
    assert asset.mime_type == "image/png"
    assert asset.gen_id == "c35e18d6-e6f0-4215-8523-69bc34a9b741"


@pytest.mark.parametrize("part", [
    None,                                  # parts 里可能出现 null
    "a string",                            # 类型不对
    {},                                    # 空对象
    {"content_type": "text"},              # 普通文本
    {"content_type": "image_asset_pointer"},                 # 缺 asset_pointer
    {"content_type": "image_asset_pointer", "asset_pointer": ""},   # 空指针
])
def test_image_asset_from_part_returns_none_for_non_assets(part: object) -> None:
    assert ImageAsset.from_part(part) is None


def test_image_asset_tolerates_missing_metadata() -> None:
    """dalle 元数据缺失时不能崩 —— 图还是好图。"""
    asset = ImageAsset.from_part({"content_type": "image_asset_pointer",
                                  "asset_pointer": REAL_POINTER})
    assert asset is not None
    assert asset.gen_id is None
    assert asset.width is None


def test_generation_result_primary_raises_when_no_images() -> None:
    result = GenerationResult(conversation_id="c1", title=None, images=[])
    with pytest.raises(IndexError):
        _ = result.primary


def test_generation_result_primary_is_first_image() -> None:
    first = ImageResult(path=Path("a.png"), width=1, height=1, size_bytes=1,
                        asset_pointer=REAL_POINTER, mime_type="image/png")
    second = first.model_copy(update={"path": Path("b.png")})
    result = GenerationResult(conversation_id="c1", images=[first, second])
    assert result.primary.path == Path("a.png")
