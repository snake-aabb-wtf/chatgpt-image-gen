"""Tkinter 图形界面。

线程模型（这是本模块唯一需要小心的部分）：

* **主线程只碰 Tk**。Tkinter 不是线程安全的，任何控件操作都必须在主线程做。
* **工作线程独占 ``Client`` 与浏览器**。Playwright 的同步 API 必须在创建它的
  线程里使用，所以登录/生图全部丢给一个常驻工作线程，由它持有 Client。
* 两者通过两个 ``queue.Queue`` 通信：主线程把任务放进 ``_tasks``，
  工作线程把日志/结果放进 ``_events``，主线程用 ``after(100ms)`` 轮询取出。

这样界面全程不卡，也不会出现"跨线程用 Playwright"的隐患。
"""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Any, Callable


def _find_tcl_dir(base: Path, prefix: str) -> Path | None:
    if not base.is_dir():
        return None
    candidates = sorted(p for p in base.iterdir()
                        if p.is_dir() and p.name.startswith(prefix))
    return candidates[-1] if candidates else None


def _ensure_tcl_library() -> None:
    """在创建 Tk 之前显式钉住 Tcl/Tk 的库目录。

    为什么需要：Tcl 靠"解释器程序名"推断自己的库路径。当 Python 以
    ``python -m 包名`` 方式启动时，程序名是 ``包名/__main__.py`` 而不是
    ``python.exe``，Tcl 就可能推断到错误目录，报
    ``Can't find a usable init.tcl in the following directories``。

    这个问题**实测存在**：本项目的 GUI 测试在 pytest 里必失败，而同样代码
    直接跑却正常 —— 两者都命中"程序名不是 python.exe"这一类情形。
    ``python -m cgpt gui`` 正是这种启动方式，所以这一步不是可选的。

    显式设置 ``TCL_LIBRARY`` / ``TK_LIBRARY`` 是标准解法；且只在本机确实存在
    对应目录时才设置，不影响系统自带 Tcl 的其它平台。
    """
    base = Path(sys.base_prefix) / "tcl"
    for env_name, prefix in (("TCL_LIBRARY", "tcl8"), ("TK_LIBRARY", "tk8")):
        if os.environ.get(env_name):
            continue
        found = _find_tcl_dir(base, prefix)
        if found is not None:
            os.environ[env_name] = str(found)


_ensure_tcl_library()

import tkinter as tk  # noqa: E402  必须在 _ensure_tcl_library() 之后导入

from cgpt.account import (  # noqa: E402
    DEFAULT_ACCOUNT_PATH,
    AccountSecret,
    forget_account,
    load_account,
    parse_account_line,
    save_account,
)
from cgpt.config import Settings  # noqa: E402
from cgpt.errors import CgptError  # noqa: E402
from cgpt.models import GenerationResult  # noqa: E402

WINDOW_TITLE = "ChatGPT 生图工具"
PREVIEW_BOX = (430, 430)
MAX_LOG_LINES = 2000

#: 右键菜单项：``(标签, Tk 虚拟事件, 是否只在可编辑时出现)``。
#: 这些虚拟事件在 ttk.Entry 与 tk.Text 上都实测可用（见 tools/gui_smoke.py）。
_EDIT_MENU_ITEMS: tuple[tuple[str, str, bool], ...] = (
    ("剪切", "<<Cut>>", True),
    ("复制", "<<Copy>>", False),
    ("粘贴", "<<Paste>>", True),
    ("删除", "<<Clear>>", True),
    ("-", "", False),
    ("全选", "<<SelectAll>>", False),
)

#: 右键在不同平台上是不同的事件
_RIGHT_CLICK_SEQUENCES = ("<Button-3>", "<Button-2>", "<Control-Button-1>")


def attach_edit_menu(widget: tk.Misc, *, editable: bool = True) -> tk.Menu:
    """给 Entry / Text 挂上右键菜单。

    **Tk 默认不提供右键菜单** —— 这是 Tk 的缺口，不是哪里配错了。而本工具最
    核心的动作就是"把一整行账密粘进来"，没有右键粘贴很难用。

    ``editable=False``（日志区那种只读控件）只保留复制/全选，不会给出粘贴这种
    按了没反应的项。

    顺带绑上 ``Ctrl+A``：Tk 在 Windows 上**不**默认提供它，而"全选后粘贴覆盖"
    恰恰是换账号时最常见的动作。
    """
    menu = tk.Menu(widget, tearoff=False)
    for label, virtual_event, needs_editable in _EDIT_MENU_ITEMS:
        if label == "-":
            menu.add_separator()
            continue
        if needs_editable and not editable:
            continue
        menu.add_command(
            label=label,
            command=lambda event=virtual_event: widget.event_generate(event))

    def popup(event: tk.Event) -> str:
        try:
            widget.focus_set()
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            # 不 release 的话菜单会一直抓着鼠标，点别处没反应
            menu.grab_release()
        return "break"          # 别再往上传，免得触发别的默认行为

    for sequence in _RIGHT_CLICK_SEQUENCES:
        widget.bind(sequence, popup, add="+")

    if editable:
        for sequence in ("<Control-a>", "<Control-A>"):
            widget.bind(sequence,
                        lambda _e: (widget.event_generate("<<SelectAll>>"),
                                    "break")[1],
                        add="+")
    return menu


@dataclass
class SessionInfo:
    """一次会话探测的结果，用于界面上的状态条。"""

    ok: bool
    email: str | None = None
    plan: str | None = None
    account_id: str | None = None
    image_gen_enabled: bool = False
    remaining: int | None = None
    detail: str = ""

    def render(self) -> str:
        if not self.ok:
            return f"● 未登录 / 会话失效 —— {self.detail.splitlines()[0] if self.detail else ''}"
        parts = [f"● 凭据有效 · {self.email or '?'}"]
        if self.plan:
            parts.append(f"计划 {self.plan}")
        parts.append("生图可用" if self.image_gen_enabled else "生图不可用")
        if self.remaining is not None:
            parts.append(f"剩余额度 {self.remaining}")
        return " · ".join(parts)


class _Context:
    """工作线程私有的状态；Client 由它持有，绝不外泄到主线程。"""

    client: Any = None


class GuiApp:
    """GUI 主对象。只应在主线程实例化与调用 ``run()``。"""

    POLL_MS = 100

    def __init__(self, settings: Settings | None = None,
                 account_path: Path | str | None = None, *,
                 root: tk.Misc | None = None) -> None:
        """``root`` 省略时自己建一个 Tk 根窗口；传入时复用它（测试用）。

        复用根窗口是有意为之：同一进程里反复创建/销毁 Tk 根会让后续建根
        偶发 ``TclError``，所以测试全程只建一个根，各实例只挂/摘自己的容器。
        """
        self.settings = settings or Settings()
        self.account_path = Path(account_path) if account_path else DEFAULT_ACCOUNT_PATH

        self._tasks: queue.Queue = queue.Queue()
        self._events: queue.Queue = queue.Queue()
        self._worker: threading.Thread | None = None
        self._busy = False
        self._busy_task = ""
        self._photo: Any = None          # 必须持引用，否则图片会被回收
        self._last_result: GenerationResult | None = None

        self._owns_root = root is None
        self.root = tk.Tk() if root is None else root
        self.container = ttk.Frame(self.root, padding=10)
        self._build_ui()
        self._start_worker()
        self._bootstrap()

    # ------------------------------------------------------------------
    # 界面构建
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        if self._owns_root:
            self.root.title(WINDOW_TITLE)
            self.root.geometry("1020x800")
            self.root.minsize(860, 660)
        self._apply_fonts()

        main = self.container
        main.grid(row=0, column=0, sticky="nsew")
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)
        main.columnconfigure(0, weight=1)
        main.rowconfigure(3, weight=1)          # 结果区吃掉多余空间

        self._build_account_section(main, row=0)
        self._build_session_section(main, row=1)
        self._build_prompt_section(main, row=2)
        self._build_result_section(main, row=3)
        self._build_status_bar(main, row=4)

    def _apply_fonts(self) -> None:
        """Windows 上给中文选一个像样的默认字体；失败就沿用系统默认。"""
        try:
            style = ttk.Style()
            for name in ("TLabel", "TButton", "TEntry", "TCheckbutton",
                         "TLabelframe.Label", "TNotebook.Tab"):
                style.configure(name, font=("Microsoft YaHei UI", 9))
        except Exception:  # noqa: BLE001
            pass

    def _build_account_section(self, parent: ttk.Frame, *, row: int) -> None:
        frame = ttk.LabelFrame(parent, text="账号（格式：邮箱----密码----2FA密钥）",
                               padding=8)
        frame.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        frame.columnconfigure(0, weight=1)

        self.account_var = tk.StringVar()
        self.account_entry = ttk.Entry(frame, textvariable=self.account_var,
                                       show="•")
        self.account_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.account_entry.bind("<Return>", lambda _e: self.on_login())
        # 这里最需要右键粘贴：整行账密是粘进来的，不是敲进来的
        self.account_menu = attach_edit_menu(self.account_entry)

        self.login_button = ttk.Button(frame, text="登  录", width=10,
                                       command=self.on_login)
        self.login_button.grid(row=0, column=1)

        options = ttk.Frame(frame)
        options.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        options.columnconfigure(3, weight=1)

        # 用户明确选择了"直接记住"：默认勾选，自动填充
        self.remember_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options, text="记住账号", variable=self.remember_var,
                        command=self._on_remember_toggled).grid(row=0, column=0)

        self.show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options, text="显示明文", variable=self.show_var,
                        command=self._toggle_mask).grid(row=0, column=1, padx=(12, 0))

        ttk.Button(options, text="清除已保存", width=11,
                   command=self.on_forget).grid(row=0, column=2, padx=(12, 0))

        ttk.Label(options, foreground="#a15c00",
                  text=f"⚠ 勾选后密码与 2FA 密钥会明文保存在 {self.account_path}（仅本机）"
                  ).grid(row=0, column=3, sticky="w", padx=(12, 0))

    def _build_session_section(self, parent: ttk.Frame, *, row: int) -> None:
        frame = ttk.LabelFrame(parent, text="会话", padding=8)
        frame.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        frame.columnconfigure(0, weight=1)

        self.session_var = tk.StringVar(value="● 正在检查会话…")
        ttk.Label(frame, textvariable=self.session_var).grid(row=0, column=0,
                                                             sticky="w")
        self.check_button = ttk.Button(frame, text="校验会话", width=10,
                                       command=self.on_check_session)
        self.check_button.grid(row=0, column=1, padx=(8, 0))
        self.relogin_button = ttk.Button(frame, text="重新登录", width=10,
                                         command=self.on_login)
        self.relogin_button.grid(row=0, column=2, padx=(6, 0))

    def _build_prompt_section(self, parent: ttk.Frame, *, row: int) -> None:
        frame = ttk.LabelFrame(parent, text="提示词", padding=8)
        frame.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        frame.columnconfigure(0, weight=1)

        self.prompt_text = tk.Text(frame, height=3, wrap="word", undo=True)
        self.prompt_text.grid(row=0, column=0, columnspan=2, sticky="ew")
        # 刻意**不预填**任何提示词：预填的示例很容易被当成"就这么用"，
        # 用户一进来点「生成图片」就白花一次额度。留空 + on_generate 的空值
        # 校验，比给个看起来能直接用的默认值更诚实。
        # Ctrl+Enter 发送（单独 Enter 留给换行）
        self.prompt_text.bind("<Control-Return>",
                              lambda _e: (self.on_generate(), "break")[1])
        self.prompt_menu = attach_edit_menu(self.prompt_text)

        row_frame = ttk.Frame(frame)
        row_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        row_frame.columnconfigure(0, weight=1)

        # 不再让用户指定路径：一律落到 output/ 下、文件名随机。
        # 文件名随机之后不好找文件，所以配一个"打开输出目录"。
        ttk.Label(row_frame,
                  text=f"输出：{self.settings.output_dir}\\（文件名随机）"
                  ).grid(row=0, column=0, sticky="w")
        self.open_dir_button = ttk.Button(row_frame, text="打开输出目录", width=13,
                                          command=self.on_open_output_dir)
        self.open_dir_button.grid(row=0, column=1, padx=(6, 0))
        self.generate_button = ttk.Button(row_frame, text="生成图片", width=12,
                                          command=self.on_generate)
        self.generate_button.grid(row=0, column=2, padx=(6, 0))

    def _build_result_section(self, parent: ttk.Frame, *, row: int) -> None:
        frame = ttk.LabelFrame(parent, text="结果", padding=8)
        frame.grid(row=row, column=0, sticky="nsew")
        frame.columnconfigure(0, weight=0)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(0, weight=1)

        preview_frame = ttk.Frame(frame, relief="solid", borderwidth=1)
        preview_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        preview_frame.rowconfigure(0, weight=1)
        preview_frame.columnconfigure(0, weight=1)

        self.preview_label = ttk.Label(preview_frame, text="（尚无图片）",
                                       anchor="center", justify="center")
        self.preview_label.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)

        log_frame = ttk.Frame(frame)
        log_frame.grid(row=0, column=1, sticky="nsew")
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)

        self.log_text = tk.Text(log_frame, wrap="word", state="disabled",
                                height=12)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        # 只读：只给复制/全选，不出粘贴这种按了没反应的项
        self.log_menu = attach_edit_menu(self.log_text, editable=False)
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical",
                                  command=self.log_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=scrollbar.set)

    def _build_status_bar(self, parent: ttk.Frame, *, row: int) -> None:
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(parent, textvariable=self.status_var,
                  relief="sunken", anchor="w", padding=(6, 3)
                  ).grid(row=row, column=0, sticky="ew", pady=(8, 0))

    # ------------------------------------------------------------------
    # 人机验证：工作线程发起，主线程弹框
    # ------------------------------------------------------------------

    #: 等工作线程那边拿到答复的上限；超过就当作放弃，避免永久卡住
    CHALLENGE_WAIT_SECONDS = 600.0

    def _challenge_prompt(self, url: str) -> bool:
        """在工作线程里被调用：把"问用户"转交给主线程，然后阻塞等答复。

        为什么不能直接弹框：Tkinter 不是线程安全的，工作线程碰控件会出问题；
        而 Playwright 又必须留在工作线程。所以走 ``_emit`` + ``queue`` 这一趟。
        """
        answer: queue.Queue = queue.Queue(maxsize=1)
        self._emit("challenge", (url, answer))
        try:
            return bool(answer.get(timeout=self.CHALLENGE_WAIT_SECONDS))
        except queue.Empty:
            self._emit("log", "等待人工验证超时，已放弃")
            return False

    def _ask_challenge(self, url: str, answer: queue.Queue) -> None:
        """在主线程里弹框询问（由事件泵调用）。"""
        ok = messagebox.askokcancel(
            "需要完成人机验证",
            "被 Cloudflare 人机验证拦住 —— 这个验证**需要人点一下**，"
            "不会自己过去。\n\n"
            f"浏览器窗口已打开在：\n{url}\n\n"
            "请在那个窗口里完成验证（一般点一下复选框就行），\n"
            "完成后点「确定」继续。\n\n"
            "点「取消」则放弃本次操作。",
            parent=self.root)
        answer.put(ok)

    # ------------------------------------------------------------------
    # 工作线程
    # ------------------------------------------------------------------

    def _start_worker(self) -> None:
        self._worker = threading.Thread(target=self._worker_loop, daemon=True,
                                        name="cgpt-worker")
        self._worker.start()

    def _worker_loop(self) -> None:
        """常驻工作线程：独占 Client，顺序执行任务。"""
        ctx = _Context()
        while True:
            item = self._tasks.get()
            if item is None:
                break
            name, func = item
            try:
                func(ctx)
            except CgptError as exc:
                self._emit("error", str(exc))
            except Exception as exc:  # noqa: BLE001 - 界面不能因为异常而卡死
                self._emit("error", f"未预期的错误：{exc!r}")
            finally:
                self._emit("done", name)
        if ctx.client is not None:
            try:
                ctx.client.close()
            except Exception:  # noqa: BLE001
                pass

    def _emit(self, kind: str, payload: Any = None) -> None:
        """工作线程 → 主线程（线程安全）。"""
        self._events.put((kind, payload))

    def _log(self, message: str) -> None:
        self._emit("log", message)

    def _submit(self, name: str, func: Callable[[_Context], None]) -> None:
        if self._busy:
            self._log(f"已有任务在执行（{self._busy_task}），请稍候")
            return
        self._set_busy(True, name)
        self._tasks.put((name, func))

    def _set_busy(self, busy: bool, name: str = "") -> None:
        self._busy = busy
        self._busy_task = name if busy else ""
        state = "disabled" if busy else "normal"
        for button in (self.login_button, self.relogin_button,
                       self.check_button, self.generate_button):
            button.configure(state=state)
        if busy:
            self.status_var.set(f"正在执行：{name} …")
        else:
            self.status_var.set("就绪")

    # ------------------------------------------------------------------
    # 主线程事件泵
    # ------------------------------------------------------------------

    def _pump(self) -> None:
        try:
            while True:
                kind, payload = self._events.get_nowait()
                self._handle_event(kind, payload)
        except queue.Empty:
            pass
        self.root.after(self.POLL_MS, self._pump)

    def _handle_event(self, kind: str, payload: Any) -> None:
        if kind == "log":
            self._append_log(str(payload))
        elif kind == "error":
            self._append_log(f"✗ {payload}")
            messagebox.showerror("出错了", str(payload), parent=self.root)
        elif kind == "session":
            self.session_var.set(payload.render())
        elif kind == "result":
            self._show_result(payload)
        elif kind == "challenge":
            url, answer = payload
            self._ask_challenge(url, answer)
        elif kind == "done":
            self._set_busy(False)
            self._append_log(f"—— {payload} 结束 ——")

    def _append_log(self, message: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", message.rstrip() + "\n")
        # 日志无限增长会拖慢界面，超过上限就裁掉最旧的
        line_count = int(self.log_text.index("end-1c").split(".")[0])
        if line_count > MAX_LOG_LINES:
            self.log_text.delete("1.0", f"{line_count - MAX_LOG_LINES}.0")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _show_result(self, result: GenerationResult) -> None:
        self._last_result = result
        if not result.images:
            self._append_log("本次没有产出图片")
            return
        image = result.primary
        self._append_log(f"图片：{image.path}（{image.width}×{image.height}，"
                         f"{image.size_bytes} 字节）")
        for note in result.notes:
            self._append_log(f"注意：{note}")
        self._show_preview(Path(image.path))

    def _show_preview(self, path: Path) -> None:
        photo = self._load_thumbnail(path)
        if photo is None:
            self.preview_label.configure(image="", text=f"无法预览\n{path.name}")
            self._photo = None
            return
        self._photo = photo
        self.preview_label.configure(image=photo, text="")

    def _load_thumbnail(self, path: Path, box: tuple[int, int] = PREVIEW_BOX):
        """优先用 Pillow 缩放；没装则退回 Tk 自带的整数倍缩略。"""
        try:
            from PIL import Image, ImageTk

            with Image.open(path) as image:
                image.thumbnail(box)
                return ImageTk.PhotoImage(image)
        except Exception:  # noqa: BLE001 - 退回标准库路径
            pass
        try:
            photo = tk.PhotoImage(file=str(path))
            factor = max(1, -(-photo.width() // box[0]), -(-photo.height() // box[1]))
            if factor > 1:
                photo = photo.subsample(factor, factor)
            return photo
        except Exception:  # noqa: BLE001
            return None

    # ------------------------------------------------------------------
    # 交互
    # ------------------------------------------------------------------

    def _bootstrap(self) -> None:
        secret = load_account(self.account_path)
        if secret is not None:
            self.account_var.set(secret.to_line())
            self._append_log(f"已从 {self.account_path} 自动填入账号"
                             f"（{secret.masked()}）")
        else:
            self._append_log(f"未找到 {self.account_path}，请粘贴账号后点「登录」")

        if self.settings.credentials_path.exists():
            self._append_log(f"发现已有凭据 {self.settings.credentials_path}，"
                             f"正在校验会话…")
            self._submit("校验会话", self._task_check_session)
        else:
            self.session_var.set("● 未登录 —— 请粘贴账号并点「登录」")

    def _toggle_mask(self) -> None:
        self.account_entry.configure(show="" if self.show_var.get() else "•")

    def _on_remember_toggled(self) -> None:
        if not self.remember_var.get():
            self._append_log("已取消「记住账号」—— 下次登录时会清除本地保存的账号")

    def on_forget(self) -> None:
        if forget_account(self.account_path):
            self.account_var.set("")
            self._append_log(f"已删除 {self.account_path}")
        else:
            self._append_log("本地没有保存过账号")

    def on_open_output_dir(self) -> None:
        """打开输出目录。

        文件名随机之后，光看日志里的路径不够方便 —— 这个按钮是那次改动的配套。
        """
        target = Path(self.settings.output_dir)
        try:
            target.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self._append_log(f"创建输出目录失败：{exc}")
            return
        try:
            if sys.platform.startswith("win"):
                os.startfile(str(target))          # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(target)])
            else:
                subprocess.Popen(["xdg-open", str(target)])
            self._append_log(f"已打开输出目录：{target.resolve()}")
        except Exception as exc:  # noqa: BLE001 - 打不开不该影响别的功能
            self._append_log(f"打不开输出目录（{exc!r}），路径是：{target.resolve()}")

    def on_login(self) -> None:
        raw = self.account_var.get()
        try:
            secret = parse_account_line(raw)
        except ValueError as exc:
            messagebox.showerror("账号格式不对", str(exc), parent=self.root)
            self._append_log(f"✗ {exc}")
            return

        if self.remember_var.get():
            path = save_account(secret, self.account_path)
            self._append_log(f"账号已保存到 {path}（明文，仅本机）")
        else:
            forget_account(self.account_path)

        self._submit("登录", lambda ctx: self._task_login(ctx, secret))

    def on_check_session(self) -> None:
        self._submit("校验会话", self._task_check_session)

    def on_generate(self) -> None:
        prompt = self.prompt_text.get("1.0", "end").strip()
        if not prompt:
            messagebox.showwarning("提示词为空", "请先输入提示词。",
                                   parent=self.root)
            return
        self._submit("生成图片", lambda ctx: self._task_generate(ctx, prompt))

    # ------------------------------------------------------------------
    # 任务实现（在工作线程里执行）
    # ------------------------------------------------------------------

    def _task_login(self, ctx: _Context, secret: AccountSecret) -> None:
        from cgpt.client import Client

        self._log(f"登录 {secret.masked()} …")
        if ctx.client is not None:
            ctx.client.close()
            ctx.client = None

        client = Client.login(email=secret.email, password=secret.password,
                              totp_secret=secret.totp_secret,
                              settings=self.settings,
                              challenge_prompt=self._challenge_prompt,
                              log=self._log)
        ctx.client = client
        self._log(f"凭据已保存到 {client.save()}")
        # 浏览器窗口由 Client 在登录完成后自行关闭（见 Client._release_browser），
        # 这里不再重复关一次，免得日志里出现两遍"已关闭浏览器窗口"。
        self._emit("session", self._probe_session(ctx.client))

    def _task_check_session(self, ctx: _Context) -> None:
        from cgpt.client import Client

        if ctx.client is None:
            ctx.client = Client.from_credentials(
                settings=self.settings, challenge_prompt=self._challenge_prompt,
                log=self._log)
        self._emit("session", self._probe_session(ctx.client))

    def _task_generate(self, ctx: _Context, prompt: str) -> None:
        from cgpt.client import Client

        if ctx.client is None:
            ctx.client = Client.from_credentials(
                settings=self.settings, challenge_prompt=self._challenge_prompt,
                log=self._log)
        result = ctx.client.generate_image(prompt)
        ctx.client.save()        # 把刷新后的哨兵令牌一并存下
        self._emit("result", result)
        self._emit("session", self._probe_session(ctx.client))

    def _probe_session(self, client: Any) -> SessionInfo:
        """探测会话状态；任何失败都转成"不可用"而不是抛给界面。"""
        try:
            info = client.web.accounts_check()
            me = client.whoami()
        except CgptError as exc:
            return SessionInfo(ok=False, detail=str(exc))
        except Exception as exc:  # noqa: BLE001
            return SessionInfo(ok=False, detail=f"{exc!r}")

        remaining: int | None = None
        try:
            remaining = client.web.image_gen_remaining()
        except Exception:  # noqa: BLE001 - 额度查不到不影响会话判定
            pass
        return SessionInfo(ok=True, email=me.get("email"), plan=info.plan,
                           account_id=info.account_id,
                           image_gen_enabled=info.can_generate_images,
                           remaining=remaining)

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------

    def _on_close(self) -> None:
        if self._busy and not messagebox.askokcancel(
                "确认退出",
                f"「{self._busy_task}」正在执行，现在退出会中断它。\n确定退出吗？",
                parent=self.root):
            return
        self.destroy()

    def destroy(self) -> None:
        """收尾：停工作线程（它会关掉浏览器）、摘掉自己的控件。"""
        self._shutdown()
        try:
            self.container.destroy()
        except tk.TclError:
            pass
        if self._owns_root:
            try:
                self.root.destroy()
            except tk.TclError:
                pass

    def _shutdown(self) -> None:
        """让工作线程收尾（它会在退出前关掉浏览器）。"""
        self._tasks.put(None)
        if self._worker is not None and self._worker.is_alive():
            self._worker.join(timeout=15)

    def run(self) -> None:
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(self.POLL_MS, self._pump)
        self.root.mainloop()


def launch(settings: Settings | None = None) -> None:
    """入口：``python -m cgpt gui``。"""
    try:
        GuiApp(settings).run()
    except tk.TclError as exc:
        raise CgptError(
            f"无法启动图形界面（{exc}）。\n"
            "如果这是无桌面环境（例如纯 SSH / 容器），请改用命令行：\n"
            "  python -m cgpt login\n"
            "  python -m cgpt generate \"生成一张地球图片\""
        ) from exc
