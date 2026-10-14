"""跨测试文件共用的 fixture。"""

from __future__ import annotations

from typing import Any, Callable

import pytest


@pytest.fixture
def logs() -> list[str]:
    """收集 ``Client`` 打出的日志，供断言"有没有把话说清楚"。"""
    return []


@pytest.fixture
def patch_browser_session(monkeypatch) -> Callable[[type], list[Any]]:
    """把 ``Client.ensure_browser`` 里 new 的 BrowserSession 换成假件。

    为什么必须这么做：``Client`` 是直接实例化 ``BrowserSession`` 的，没有注入点；
    而 ``_release_browser()`` 会把 ``_browser`` 置 None，所以**第二次**刷新时
    ``ensure_browser()`` 会新建一个 —— 如果没替换掉这个模块级符号，测试就会
    去开一个真浏览器（表现为 ``LoginBlockedError: 没有有效的登录 Cookie``，
    或者干脆弹出窗口）。

    用法::

        created = patch_browser_session(FakeBrowser)
        ...
        assert created[0].refresh_count == 1
    """

    def install(fake_class: type) -> list[Any]:
        created: list[Any] = []

        def factory(*_args: Any, **_kwargs: Any) -> Any:
            fake = fake_class()
            created.append(fake)
            return fake

        monkeypatch.setattr("cgpt.client.BrowserSession", factory)
        return created

    return install
