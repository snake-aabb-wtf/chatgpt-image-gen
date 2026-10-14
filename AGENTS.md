# AGENTS.md

给在本仓库工作的**编码 agent**。人类入门看 [`README.md`](README.md)，协议细节看 `docs/`。

---

## 0. 一句话

用 ChatGPT 账密 + TOTP 登录 `chatgpt.com` 并请求生图。**两阶段架构是被逼出来的，不是设计偏好**：
Playwright 只负责过 Cloudflare + 登录 + 取令牌，业务请求走 curl_cffi 纯 HTTP。

---

## 1. 命令（已验证，可直接抄）

```bash
# 测试（194 个用例；pytest 会自己定位 rootdir，任意目录可跑）
python -m pytest tests/ -q
python -m pytest tests/test_api.py -q            # 单文件
python -m pytest tests/test_api.py -k sse -q     # 单主题

# 静态检查
python -m ruff check cgpt tests tools

# 离线自证（38 项，不联网、不需要账号）
python -m cgpt selftest

# 从抓包重建真值（约 2 秒；结果必须可复现）
python tools/build_har_vectors.py

# GUI 自检（14 项，不依赖 pytest）
python tools/gui_smoke.py

# 离线取证（不需要网络）
python -m cgpt sentinel decode "<gAAAAA… 令牌>"
python -m cgpt sentinel crack  "<t 或 turnstile blob>"
```

**⚠ 联网命令会花钱、会触发风控，未经明确要求不要跑：**

```bash
python -m cgpt login      # 真实登录：会走 CF + TOTP，反复跑会触发风控
python -m cgpt generate   # 真实生图：消耗账号 1 次 image_gen 额度
python -m cgpt gui        # 会弹窗，需要人工交互
```

判断 pytest 是否通过**看退出码**，不要解析输出：

```bash
python -m pytest tests/ -q > /dev/null 2>&1; echo $?   # 0 = 通过
```

> 本环境下 pytest 的摘要行（`194 passed in …`）有时不会到达调用方的管道，
> 只看输出会误判成失败。**退出码是唯一可靠信号。**

---

## 2. 不可违背的约束

这几条一旦破坏，会**静默地**让分析结论失效（测试可能还是绿的）。

| # | 约束 | 破坏后的症状 |
|---|------|-------------|
| 1 | `.gitattributes` 里 `*.har binary` **不能删** | 本机 `core.autocrlf=true`，git 会把 216 MB 的 HAR 当文本转换行尾，改变字节。而 `docs/01` §4.5、`docs/02` §4.5 的结论建立在**逐字节相等**上 |
| 2 | 源码/文档里**不得出现真实凭据**，用占位值 | 2FA 种子不在抓包里，一旦写进源码就永久泄漏（不会过期） |
| 3 | `.cgpt/` 是**活跃会话**，必须保持被忽略 | 提交上去等于交出当前账号 |
| 4 | 下载 URL 必须过 `assert_safe_download_url` | 把会话 Cookie 发给第三方域 = 凭据泄漏（含 SSRF 目标） |
| 5 | 生成物**不得带时间戳** | `cgpt/data/har_vectors.json` 每次重建都产生无意义 diff，掩盖真实变化 |
| 6 | 不要"简化"成纯 HTTP 登录 | 见 §3.1 —— 协议层就被堵死，改不出来 |
| 7 | 流已开始产出后**不得重发** | 重复发送消息 = 重复消耗生图额度 |

---

## 3. 这个仓库的坑（都踩过，别再踩）

### 3.1 为什么必须有浏览器（别试图去掉）

两条硬约束，`docs/01` 有完整证据：

* `cf_clearance` 带 `Partitioned`（CHIPS），按顶层站点分区绑定，且 Cloudflare 同时校验 TLS/JA3 与 HTTP/2 指纹；
* `t` / `turnstile` 的 XOR 密钥随**未解开的** `dx`（20~24 KB）下发 —— 能解密不等于能伪造，服务端认的是它自己那把密钥。

实测分层行为（`docs/验证报告` §3.3）：

```
https://chatgpt.com/api/auth/csrf        -> 200   ← 带 cf_clearance 时可纯 HTTP
https://auth.openai.com/log-in/password  -> 403 cf-mitigated: challenge
```

### 3.2 Tk 根窗口必须在**模块导入期**创建

`tests/test_gui.py` 顶部在 import 时建唯一根窗口并复用。这不是风格问题：

* 在 fixture / 测试函数里建根，本环境下**间歇失败**（`Can't find a usable init.tcl`、`couldn't read file … No error`）；
* 同样代码在导入期创建则 100% 成功。

已排除的因素：输出捕获（`-s` / `--capture=no` / `-p no:capture`）、CWD、pytest 配置、环境变量、文件读取本身（3000 次读 `init.tcl` 零失败）。
**注意：一个进程里连建 10 个根窗口是成功的** —— "多根窗口导致失败"这个假设已被证伪，别再照着它改。

`cgpt/gui.py::_ensure_tcl_library()` 显式钉住 `TCL_LIBRARY`/`TK_LIBRARY`，用于
`python -m 包名` 这类"程序名不是 python.exe"的启动方式。**必须在 `import tkinter` 之前调用。**

### 3.3 `decode_payload` 的判别顺序不能反

两种 `gAAAAA…` 形态**整串 base64 解码后都是 `0x80` 开头**，所以"首字节 0x80"不是判别条件。
真正的判据是**去掉 7 字符后能否解出 UTF-8 JSON**：载荷可以，Fernet 不行。
顺序必须是「先 JSON 形态，后 Fernet 形态」。

### 3.4 三个"看起来对但没用"的写法

| 写法 | 问题 |
|------|------|
| `base64.b64decode(x)` 默认 `validate=False` | 静默丢弃非法字符，垃圾也能"解"出东西。本项目一律 `validate=True`，与 JS `atob` 语义对齐 |
| 拿 `codec_roundtrip_matches()` 当密钥正确性的证据 | **XOR 是对合运算**，`encode(decode(x,k),k)==x` 对**任意** k 都成立。密钥正确性靠「明文能 JSON 解析」+「键符合 `探针号.答案号` 形状」 |
| `normalize_secret()` 做 base32 校验 | 它只做大小写/补齐，**对非法字符不报错**。要校验必须用 `decode_secret()` |

### 3.5 Playwright 线程亲和 + 不伪造成功

* Playwright 同步 API **必须在创建它的线程里使用**。GUI 因此让工作线程独占 `Client`，主线程只碰 Tk，两者用 `queue` + `after(100ms)` 通信。
* 生图**没有独立接口**，是否出图由服务端依据 `image_gen_tool_enabled` + 意图决定。
  **没出图是合法分支**，抛 `NoImageProducedError`，不要伪造成功、不要改成"返回占位图"。

### 3.6 浏览器：按需开、用完关，且回退必须惰性取数

`Client` 里有一条容易在"优化"时被破坏的不变量：

```
ensure_browser()   按需启动（start() 幂等，无条件调用）
_release_browser() 用完就关，幂等；login / refresh_sentinel 都在 finally 里调
_browser_fetch()   给 Cloudflare 回退用的**惰性**取数函数
```

* `_build_transport()` **必须始终挂上 `FallbackTransport`**，且回退走 `_browser_fetch`
  而不是直接绑 `self._browser.fetch_in_context`。
  曾经的写法是「浏览器为 None 就直接 return primary」——那样一旦"用完就关"，
  **回退会永久消失且不报任何错**，直到真被 Cloudflare 拦住才发现。
  回归测试见 `tests/test_client_lifecycle.py`。
* 反过来也不要"顺手"去掉 `_release_browser`：用户会看到刷新完令牌后浏览器窗口一直挂着。
* 例外：如果某次请求**真的**被 CF 拦过，浏览器会保持打开（回退刚用过它，随后续请求大概率还要用）。
  它会在下一轮刷新或 `Client.close()` 时关闭。

### 3.7 两条路都被拦 = 人工验证，必须交给用户

`FallbackTransport` 的契约（`tests/test_challenge.py` 钉住）：

```
primary 被拦 → fallback 重发 → 还被拦
    → challenge_solver(url)          交给用户去浏览器里过验证
        返回 True  → 重试一次
        返回 False → 抛 CloudflareChallengeError（说人话的那种）
```

三条不能破的规矩：

1. **回退之后必须再检查一次**。曾经的写法是回退完直接 `return response`，
   于是 403 漏到业务层，业务层去 `json()` 解析挑战页 HTML，报出
   "返回的不是 JSON（403）"—— 用户完全看不出该干什么。旧测试还把这个行为
   当成正确契约钉着（`test_fallback_transport_switches_when_browser_returns_challenge`），
   已改名为 `..._raises_when_browser_context_also_blocked`。
2. **让验证真正渲染出来只能靠导航**，不能在页面里 `fetch` —— 后者拿回的是挑战的
   响应体，页面上不会出现可点的 Turnstile 控件。见 `BrowserSession.open_for_challenge`。
3. **用户过完必须重读 Cookie**（`Client._reload_cookies_from_browser`）：
   `cf_clearance` 是在浏览器里刷新的，不重读就是拿旧 Cookie 再撞一次。

另外两条边界：

* **流已产出数据就绝不重发**（内层 `_stream_once` 与外层 `stream_lines` 各有一道
  闸）。宁可失败也不能重复发消息、重复消耗一次生图额度。
* 库的默认行为是 `challenge_prompt=None` → **不等待、直接抛错**。只有 CLI 与 GUI
  传入了交互实现。GUI 那边走 `_emit("challenge", (url, queue))` + 主线程弹框，
  因为 Tk 不是线程安全的而 Playwright 必须留在工作线程。

---

## 4. 架构地图（按任务找文件）

| 要做的事 | 看这里 |
|---------|--------|
| 登录流程 / 页面选择器 / CF 回退 | `cgpt/auth/browser.py`（627 行，最复杂的文件）|
| TOTP | `cgpt/auth/totp.py`（仅标准库，无 pyotp）|
| 凭据持久化 | `cgpt/auth/store.py` |
| 指纹载荷编解码 | `cgpt/sentinel/payload.py` |
| 工作量证明 | `cgpt/sentinel/pow.py` |
| XOR 混淆 | `cgpt/sentinel/xor.py` |
| Fernet 头解析 | `cgpt/sentinel/fernet.py` |
| 传输层（curl_cffi + 浏览器回退）| `cgpt/api/transport.py` |
| SSE / JSON-Patch 解析 | `cgpt/api/sse.py` |
| 端点封装 | `cgpt/api/client.py` |
| 生图编排 + 产物自证 | `cgpt/api/image.py` |
| 库入口 / 令牌刷新策略 | `cgpt/client.py` |
| GUI | `cgpt/gui.py` |
| 账号串解析 | `cgpt/account.py` |
| 离线自证 | `cgpt/selftest.py` + `cgpt/data/har_vectors.json` |
| 流式读 HAR（117 MB 不全量载入）| `cgpt/har.py` |

**分层规矩**：`sentinel/*` 是纯函数、无 IO、无网络依赖 —— 因此能被离线自证。
不要往里面加网络调用或文件读写。

---

## 5. 改代码时的规矩

* **测试用真值，不用抄来的数字**。真值由 `tools/build_har_vectors.py` 从 `legacy/har/` 现场提取；写死文档里的数字等于只验证抄写。
* **加测试要能失败**。空 fixture、缺样本必须让自证**失败**而不是"零项全过"（见 `MIN_SAMPLES` 与 `tests/test_selftest.py`）。
* **错误消息要可操作**：说清"发生了什么 + 下一步敲什么命令"，不要裸抛 `KeyError`。
* **日志到 stderr，数据到 stdout**。CLI 靠这个支持管道。
* 依赖克制：TOTP 用标准库；图片头解析用标准库（`probe_image`）；只有 Pillow 在 GUI 缩略图里是**可选**的，且有 `PhotoImage.subsample` 兜底。
* 改 `cgpt/api/*` 后跑 `tests/test_api.py`；改 `sentinel/*` 后**必须**跑 `python -m cgpt selftest`。

---

## 6. 验证纪律

先离线，后联网。理由：联网失败时很难区分"协议实现错了"还是"环境被拦了"。

```
1. python -m ruff check cgpt tests tools
2. python -m pytest tests/ -q          # 看退出码
3. python -m cgpt selftest             # 38/38
4. python tools/gui_smoke.py           # 14/14（改了 GUI 才需要）
5. 联网验证 —— 仅在明确要求时
```

**声称"完成"前必须有命令输出支撑。** 不要凭"代码看起来对"就下结论。

---

## 7. 文档与证据的关系

```
legacy/har/          7 份真实抓包（216 MB）—— 一切结论的证据基础
legacy/tools/        既有的浏览器取证脚本 sentinel-hook.js
docs/01~04/          逆向分析报告（预存），大量引用 har/xxx.har
docs/验证报告-*.md    本工具的实测验证记录
docs/superpowers/    设计文档
```

**`docs/01`~`04` 里的 `har/xxx.har` 路径是故意保持失效的**，别去"修"它们 ——
那是历史分析记录，改成跟随现状会让它失去"当时看到的就是这个"的意义。
对应关系：`har/X.har` → `legacy/har/X.har`（`legacy/README.md` 有说明）。

**改协议实现前先读对应文档章节**，里面标了哪些是**已验证**、哪些是**推断**：

| 主题 | 文档 |
|------|------|
| 登录链路、指纹/PoW、MFA、Cookie 生命周期 | `docs/01` |
| 对话链路、三条哨兵头、540 秒令牌复用 | `docs/02` |
| 生图链路、SSE 12 事件、签名 URL 取图 | `docs/03` |
| 接口清单（方法/参数/请求体/响应体）| `docs/04` |

---

## 8. 快速自检清单

动手前问自己：

- [ ] 我要改的东西在 §4 的哪一行？读那个文件了吗？
- [ ] 会不会碰到 §2 的任何一条约束？
- [ ] 改完跑 §6 的哪几步？联网验证真的必要吗（要花额度/触发风控）？
- [ ] 我加的东西**能失败**吗？还是只是"看起来在测"？
- [ ] 有没有把真实凭据写进代码或文档？
