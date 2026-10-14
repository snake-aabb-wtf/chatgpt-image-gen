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

    try:
        app = gui.GuiApp(settings=settings, account_path=account_path)
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] 无法创建窗口：{exc!r}")
        print("       若是无桌面环境（纯 SSH / 容器），请改用命令行：")
        print('         python -m cgpt login')
        print('         python -m cgpt generate "生成一张地球图片" --out output/earth.png')
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
        check("提示词已预填", bool(app.prompt_text.get("1.0", "end").strip()),
              app.prompt_text.get("1.0", "end").strip())
        check("输出路径已预填", bool(app.output_var.get()),
              app.output_var.get())
        check("会话状态可见", bool(app.session_var.get()),
              app.session_var.get())
        check("四个操作按钮就位",
              all(w.winfo_exists() for w in (app.login_button,
                                             app.relogin_button,
                                             app.check_button,
                                             app.generate_button)))
        check("日志区只读", app.log_text.cget("state") == "disabled")

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
