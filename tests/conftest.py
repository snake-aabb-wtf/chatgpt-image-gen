"""跨测试文件共用的 fixture。"""

from __future__ import annotations

import pytest


@pytest.fixture
def logs() -> list[str]:
    """收集 ``Client`` 打出的日志，供断言"有没有把话说清楚"。"""
    return []
