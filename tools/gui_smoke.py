"""GUI 冒烟检查 —— 不依赖 pytest，直接跑就能确认界面能用。

为什么单独做一个：本环境下 Tk 在 pytest 里建根窗口不稳定（详见
``tests/test_gui.py`` 里的说明），所以除了 pytest 测试之外，再提供一个
"离开 pytest 也能验证界面"的入口。

用法::

    python tools/gui_smoke.py            # 建窗口、渲染一次、逐项检查、关闭
    python tools/gui_smoke.py --show     # 建完窗口停 5 秒（能亲眼看到界面）

退出码 0 = 全部通过，1 = 有检查项失败。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cgpt.account import AccountSecret, save_account  # noqa: E402
from cgpt.config import Settings  # noqa: E402

EMAIL = "user@example.com"
PASSWORD = "Example-Passw0rd!"
TOTP = "JBSWY3DPEHPK3PXP"
LINE = f"{EMAIL}----{PASSWORD}----{TOTP}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--show", action="store_true",
                        help="渲染后停 5 秒，便于肉眼确认")
    args = parser.parse_args()

    try:
        from cgpt import gui
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] 无法导入 GUI 模块：{exc!r}")
        return 1

    import tempfile

    tmp = Path(tempfile.mkdtemp(prefix="cgpt-gui-smoke-"))
    settings = Settings(
        credentials_path=tmp / "credentials.json",
        profile_dir=tmp / "profile",
        debug_dir=tmp / "debug",
    )
    account_path = tmp / "account.txt"
    save_account(AccountSecret(EMAIL, PASSWORD, TOTP), account_path)

    checks: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append((name, bool(ok), detail))

    def empty_prompt_is_blocked() -> bool:
        """空提示词必须被拦下，且**不能真的提交任务**（否则白花一次额度）。

        把弹框与提交都换成记录器 —— 否则这里会弹出模态窗口把冒烟测试挂住。
        """
        warned: list[str] = []
        submitted: list[str] = []

        original_warning = gui.messagebox.showwarning
        original_submit = app._submit
        gui.messagebox.showwarning = lambda title, *a, **kw: warned.append(title)
        app._submit = lambda name, func: submitted.append(name)
        try:
            app.prompt_text.delete("1.0", "end")
            app.on_generate()
        finally:
            gui.messagebox.showwarning = original_warning
            app._submit = original_submit
        return bool(warned) and not submitted

    def menu_labels(menu) -> list[str]:
        """菜单里的命令项标签（跳过分隔线）。"""
        end = menu.index("end")
        if end is None:
            return []
        return [menu.entrycget(i, "label") for i in range(end + 1)
                if menu.type(i) == "command"]

    def invoke(menu, label: str) -> bool:
        end = menu.index("end")
        for i in range(end + 1 if end is not None else 0):
            if menu.type(i) == "command" and menu.entrycget(i, "label") == label:
                menu.invoke(i)
                return True
        return False

    def set_clipboard(text: str) -> None:
        app.root.clipboard_clear()
        app.root.clipboard_append(text)
        app.root.update()

    def paste_via_menu(entry, menu) -> str:
        """走一遍"右键 → 粘贴"，返回控件里实际得到的内容。"""
        set_clipboard(LINE)
        entry.delete(0, "end")
        app.root.update()
        invoke(menu, "粘贴")
        app.root.update()
        return entry.get()

    def select_all_works(entry) -> bool:
        entry.delete(0, "end")
        entry.insert(0, LINE)
        # 必须先给焦点：Tk 的 event_generate 对**未聚焦**控件不会触发键盘绑定
        # （真实使用里用户会先点进输入框，所以这不影响功能）
        entry.focus_force()
        app.root.update()
        entry.event_generate("<Control-a>")
        app.root.update()
        return bool(entry.selection_present())

    def masked_copy_is_safe() -> bool:
        """掩码状态下复制，剪贴板拿到的应当是圆点而不是明文。"""
        entry = app.account_entry
        entry.configure(show="•")
        entry.delete(0, "end")
        entry.insert(0, LINE)
        app.root.update()
        set_clipboard("")
        entry.event_generate("<<SelectAll>>")
        app.root.update()
        invoke(app.account_menu, "复制")
        app.root.update()
        try:
            copied = app.root.clipboard_get()
        except Exception:  # noqa: BLE001 - 剪贴板空
            return False
        return bool(copied) and copied != LINE and set(copied) <= {"•"}

    try:
        app = gui.GuiApp(settings=settings, account_path=account_path)
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] 无法创建窗口：{exc!r}")
        print("       若是无桌面环境（纯 SSH / 容器），请改用命令行：")
        print('         python -m cgpt login')
        print('         python -m cgpt generate "生成一张地球图片"')
        return 1

    try:
        app.root.update()                      # 真正渲染一次

        check("窗口已创建", app.root.winfo_exists() == 1)
        check("窗口标题", app.root.title() == gui.WINDOW_TITLE,
              app.root.title())
        check("窗口尺寸已生效",
              app.root.winfo_width() > 1 and app.root.winfo_height() > 1,
              f"{app.root.winfo_width()}x{app.root.winfo_height()}")
        check("账号自动填充", app.account_var.get() == LINE)
        check("账号默认掩码", app.account_entry.cget("show") == "•")
        check("提示词留空（不预填示例）",
              app.prompt_text.get("1.0", "end").strip() == "",
              repr(app.prompt_text.get("1.0", "end")))
        check("空提示词会被拦下（不白花额度）",
              empty_prompt_is_blocked())
        check("输出目录提示可见",
              "output" in str(app.generate_button.master.winfo_children()[0].cget("text")),
              str(app.generate_button.master.winfo_children()[0].cget("text")))
        check("有「打开输出目录」按钮", app.open_dir_button.winfo_exists() == 1)
        check("会话状态可见", bool(app.session_var.get()),
              app.session_var.get())
        check("四个操作按钮就位",
              all(w.winfo_exists() for w in (app.login_button,
                                             app.relogin_button,
                                             app.check_button,
                                             app.generate_button)))
        check("日志区只读", app.log_text.cget("state") == "disabled")

        # --- 右键菜单（Tk 默认没有，必须自己挂）-------------------------
        # 不满足于"菜单对象存在"：真的走一遍菜单项，看控件里有没有东西。
        check("账号框有右键菜单",
              "粘贴" in menu_labels(app.account_menu),
              str(menu_labels(app.account_menu)))
        check("右键粘贴真的能用", paste_via_menu(app.account_entry,
                                                app.account_menu) == LINE,
              repr(app.account_var.get())[:40])
        check("Ctrl+A 全选能用", select_all_works(app.account_entry))
        # 只读区不该出现"按了没反应"的项
        log_labels = menu_labels(app.log_menu)
        check("只读日志菜单只有复制/全选",
              "复制" in log_labels and "粘贴" not in log_labels
              and "剪切" not in log_labels,
              str(log_labels))
        # 掩码状态下复制不能把明文放进剪贴板
        check("掩码框复制不泄漏明文", masked_copy_is_safe())

        # 忙碌态应禁用按钮（防止重复登录触发风控 / 重复生图白耗额度）
        app._set_busy(True, "登录")
        check("忙碌时禁用按钮",
              all(str(w.cget("state")) == "disabled"
                  for w in (app.login_button, app.generate_button)))
        app._set_busy(False)
        check("空闲时恢复按钮",
              all(str(w.cget("state")) == "normal"
                  for w in (app.login_button, app.generate_button)))

        # 事件泵：工作线程 → 主线程
        app._emit("log", "冒烟检查消息")
        app._emit("session", gui.SessionInfo(ok=True, email=EMAIL, plan="free",
                                             image_gen_enabled=True,
                                             remaining=22))
        while not app._events.empty():
            app._handle_event(*app._events.get_nowait())
        check("日志投递生效", "冒烟检查消息" in app.log_text.get("1.0", "end"))
        check("会话状态刷新", "凭据有效" in app.session_var.get(),
              app.session_var.get())

        if args.show:
            print("窗口已显示，5 秒后自动关闭…")
            app.root.deiconify()
            app.root.after(5000, app.root.quit)
            app.root.mainloop()
    finally:
        app.destroy()

    print(f"\nGUI 冒烟检查（{len(checks)} 项）")
    failed = 0
    for name, ok, detail in checks:
        mark = "PASS" if ok else "FAIL"
        if not ok:
            failed += 1
        line = f"  [{mark}] {name}"
        if detail:
            line += f"  —— {detail}"
        print(line)
    print(f"\n通过 {len(checks) - failed} / {len(checks)}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
