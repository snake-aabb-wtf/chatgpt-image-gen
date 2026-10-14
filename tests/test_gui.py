"""GUI 的冒烟测试。

只测**不需要人看**的部分：控件构建、账号自动填充、日志、忙碌态、缩略图。
真实登录/生图不在这里跑（会开浏览器、耗额度），留给人工验收。

没有可用显示环境时整体跳过 —— 这样在 CI 或纯 SSH 下不会假失败。
"""

from __future__ import annotations

import tkinter as tk
from pathlib import Path

import pytest

from cgpt.account import AccountSecret, save_account
from cgpt.config import Settings

gui = pytest.importorskip("cgpt.gui")


def _tk_available() -> bool:
    try:
        root = tk.Tk()
        root.destroy()
        return True
    except Exception:  # noqa: BLE001
        return False


def _module_root():
    """在**模块导入时**建好唯一的根窗口。

    这不是随手写的：本环境下 Tk 建根**只在导入期稳定**。实测同一段代码
    ``tk.Tk()``，在模块导入时 100% 成功，而在 fixture / 测试函数里执行会
    间歇性失败（``Can't find a usable init.tcl`` / ``couldn't read file …
    No error``），且与 pytest 的输出捕获、CWD、配置文件、环境变量都无稳定
    关联（逐一试过）。既然导入期可靠，就把根窗口放在导入期建。

    真实运行 ``python -m cgpt gui`` 不受影响 —— 它一个进程只建一个根，
    已用 ``tools/gui_smoke.py`` 单独验证过窗口能正常渲染。
    """
    try:
        root = tk.Tk()
        root.withdraw()
        return root
    except Exception:  # noqa: BLE001
        return None


_SHARED_ROOT = _module_root()

pytestmark = pytest.mark.skipif(_SHARED_ROOT is None,
                                reason="本环境无法创建 Tk 根窗口，跳过 GUI 测试"
                                       "（改用 python tools/gui_smoke.py 验证）")

EMAIL = "user@example.com"
PASSWORD = "Example-Passw0rd!"
TOTP = "JBSWY3DPEHPK3PXP"
LINE = f"{EMAIL}----{PASSWORD}----{TOTP}"


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        credentials_path=tmp_path / "credentials.json",
        profile_dir=tmp_path / "profile",
        debug_dir=tmp_path / "debug",
    )


@pytest.fixture
def app(tmp_path: Path):
    """构造 GUI 实例，复用导入期建好的根窗口。"""
    instance = gui.GuiApp(settings=_settings(tmp_path),
                          account_path=tmp_path / "account.txt",
                          root=_SHARED_ROOT)
    yield instance
    instance.destroy()


def drain(app) -> None:
    """把工作线程投递的事件取出来喂给处理器。

    ``_log`` 是投递到队列的（这是线程安全的做法），主线程要经过事件泵才会
    写进控件 —— 测试里必须显式排空，否则断言看到的是旧内容。
    """
    while not app._events.empty():
        app._handle_event(*app._events.get_nowait())


# --- 纯逻辑（不需要 Tk） --------------------------------------------------


def test_session_info_render_when_valid() -> None:
    text = gui.SessionInfo(ok=True, email=EMAIL, plan="free",
                           image_gen_enabled=True, remaining=22).render()
    assert "凭据有效" in text
    assert EMAIL in text and "free" in text and "22" in text


def test_session_info_render_when_invalid_uses_first_line_only() -> None:
    info = gui.SessionInfo(ok=False, detail="会话失效了\n第二行不该出现")
    text = info.render()
    assert "未登录" in text or "会话失效" in text
    assert "第二行" not in text


def test_session_info_render_without_quota() -> None:
    text = gui.SessionInfo(ok=True, email=EMAIL, image_gen_enabled=False).render()
    assert "生图不可用" in text
    assert "剩余额度" not in text


# --- 需要 Tk 的部分 -------------------------------------------------------


def test_autofills_saved_account(tmp_path: Path) -> None:
    save_account(AccountSecret(EMAIL, PASSWORD, TOTP),
                 tmp_path / "account.txt")
    fresh = gui.GuiApp(settings=_settings(tmp_path),
                       account_path=tmp_path / "account.txt",
                       root=_SHARED_ROOT)
    try:
        assert fresh.account_var.get() == LINE
    finally:
        fresh.destroy()


def test_starts_without_saved_account(app) -> None:
    assert app.account_var.get() == ""
    assert "未登录" in app.session_var.get()


def test_account_field_is_masked_by_default(app) -> None:
    assert app.account_entry.cget("show") == "•"


def test_toggle_mask_reveals_and_hides(app) -> None:
    app.show_var.set(True)
    app._toggle_mask()
    assert app.account_entry.cget("show") == ""
    app.show_var.set(False)
    app._toggle_mask()
    assert app.account_entry.cget("show") == "•"


def test_log_append_and_trim(app) -> None:
    for index in range(gui.MAX_LOG_LINES + 50):
        app._append_log(f"第 {index} 行")
    content = app.log_text.get("1.0", "end")
    assert "第 0 行" not in content              # 最旧的被裁掉
    assert f"第 {gui.MAX_LOG_LINES + 49} 行" in content
    lines = int(app.log_text.index("end-1c").split(".")[0])
    assert lines <= gui.MAX_LOG_LINES + 1


def test_log_is_readonly_to_user(app) -> None:
    assert app.log_text.cget("state") == "disabled"


def test_busy_disables_action_buttons(app) -> None:
    app._set_busy(True, "登录")
    for button in (app.login_button, app.relogin_button, app.check_button,
                   app.generate_button):
        assert str(button.cget("state")) == "disabled"
    assert "登录" in app.status_var.get()

    app._set_busy(False)
    for button in (app.login_button, app.relogin_button, app.check_button,
                   app.generate_button):
        assert str(button.cget("state")) == "normal"
    assert app.status_var.get() == "就绪"


def test_second_task_is_refused_while_busy(app) -> None:
    app._set_busy(True, "登录")
    app._submit("生成图片", lambda _ctx: None)
    assert app._busy is True
    drain(app)
    assert "已有任务在执行" in app.log_text.get("1.0", "end")


def test_bad_account_format_is_rejected_without_submitting(app, monkeypatch) -> None:
    shown: list[str] = []
    monkeypatch.setattr(gui.messagebox, "showerror",
                        lambda title, message, **kw: shown.append(message))
    app.account_var.set("这不是账号串")
    app.on_login()
    assert shown and "分隔符" in shown[0]
    assert app._busy is False                    # 没有派发任务


def test_missing_totp_is_rejected(app, monkeypatch) -> None:
    shown: list[str] = []
    monkeypatch.setattr(gui.messagebox, "showerror",
                        lambda title, message, **kw: shown.append(message))
    app.account_var.set(f"{EMAIL}----{PASSWORD}----")
    app.on_login()
    assert shown and "2FA" in shown[0]


def test_blank_prompt_is_rejected(app, monkeypatch) -> None:
    warned: list[str] = []
    monkeypatch.setattr(gui.messagebox, "showwarning",
                        lambda title, message, **kw: warned.append(message))
    app.prompt_text.delete("1.0", "end")
    app.on_generate()
    assert warned
    assert app._busy is False


def test_forget_removes_saved_account(app, tmp_path: Path) -> None:
    path = save_account(AccountSecret(EMAIL, PASSWORD, TOTP),
                        tmp_path / "account.txt")
    app.account_var.set(LINE)
    app.on_forget()
    assert not path.exists()
    assert app.account_var.get() == ""


def test_event_pump_delivers_log_and_session(app) -> None:
    app._emit("log", "来自工作线程的消息")
    app._emit("session", gui.SessionInfo(ok=True, email=EMAIL, plan="free",
                                         image_gen_enabled=True, remaining=7))
    drain(app)
    assert "来自工作线程的消息" in app.log_text.get("1.0", "end")
    assert "凭据有效" in app.session_var.get()


def test_done_event_clears_busy(app) -> None:
    app._set_busy(True, "生成图片")
    app._handle_event("done", "生成图片")
    assert app._busy is False
    assert "结束" in app.log_text.get("1.0", "end")


def test_thumbnail_of_real_png(app, tmp_path: Path) -> None:
    """1×1 PNG 能出缩略图（Pillow 或 Tk 两条路径都该成功）。"""
    png = tmp_path / "tiny.png"
    png.write_bytes(bytes.fromhex(
        "89504e470d0a1a0a0000000d494844520000000100000001080200000090"
        "7753de0000000c4944415408d763f8cfc000000301010018dd8db0000000"
        "0049454e44ae426082"))
    photo = app._load_thumbnail(png)
    assert photo is not None


def test_thumbnail_of_garbage_returns_none(app, tmp_path: Path) -> None:
    bad = tmp_path / "bad.png"
    bad.write_bytes(b"not an image")
    assert app._load_thumbnail(bad) is None


def test_show_result_updates_preview_and_log(app, tmp_path: Path) -> None:
    from cgpt.models import GenerationResult, ImageResult

    png = tmp_path / "img.png"
    png.write_bytes(bytes.fromhex(
        "89504e470d0a1a0a0000000d494844520000000100000001080200000090"
        "7753de0000000c4944415408d763f8cfc000000301010018dd8db0000000"
        "0049454e44ae426082"))
    result = GenerationResult(
        conversation_id="cid-1", title="t",
        images=[ImageResult(path=png, width=1, height=1, size_bytes=png.stat().st_size,
                            asset_pointer="sediment://file_x", mime_type="image/png")],
        notes=["字节数与元数据不一致"])
    app._show_result(result)
    log = app.log_text.get("1.0", "end")
    assert "img.png" in log
    assert "字节数与元数据不一致" in log
    assert app._photo is not None


def test_show_result_with_no_images_does_not_crash(app) -> None:
    from cgpt.models import GenerationResult

    app._show_result(GenerationResult(conversation_id="cid", images=[]))
    assert "没有产出图片" in app.log_text.get("1.0", "end")


# --- 人机验证的跨线程握手 -------------------------------------------------


def _pump_until(app, worker, timeout: float = 5.0) -> None:
    """主线程这边跑事件泵，直到工作线程结束。

    真实场景就是这样：Playwright 在工作线程里，弹框必须在主线程，
    两边靠 queue 传一个布尔值。
    """
    import queue as _queue
    import time as _time

    deadline = _time.monotonic() + timeout
    while worker.is_alive() and _time.monotonic() < deadline:
        try:
            kind, payload = app._events.get(timeout=0.1)
        except _queue.Empty:
            continue
        app._handle_event(kind, payload)
    worker.join(timeout=timeout)


@pytest.mark.parametrize("answer", [True, False])
def test_challenge_prompt_round_trip(app, monkeypatch, answer: bool) -> None:
    import threading

    monkeypatch.setattr(gui.messagebox, "askokcancel", lambda *a, **kw: answer)
    result: list[bool] = []
    worker = threading.Thread(target=lambda: result.append(
        app._challenge_prompt("https://chatgpt.com/backend-api/me")))
    worker.start()
    _pump_until(app, worker)

    assert result == [answer], "答复必须回到工作线程"


def test_challenge_prompt_event_carries_a_reply_queue(app) -> None:
    """事件里必须带一个可写回的队列，否则工作线程会一直等。"""
    import threading

    seen: list[tuple] = []

    def fake_ask(url, answer_queue):
        seen.append((url, answer_queue))
        answer_queue.put(True)

    original = app._ask_challenge
    app._ask_challenge = fake_ask
    try:
        worker = threading.Thread(target=lambda: app._challenge_prompt("https://x"))
        worker.start()
        _pump_until(app, worker)
    finally:
        app._ask_challenge = original

    assert seen and seen[0][0] == "https://x"
