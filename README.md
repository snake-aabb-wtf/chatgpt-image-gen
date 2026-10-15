# cgpt-imagen

用 **ChatGPT 账号密码 + 2FA（TOTP）** 登录 `chatgpt.com`，然后**程序化请求生成图片**并落盘的 Python 工具。

交付形态：**图形界面 + CLI + 可导入的 Python 库**。

```bash
python -m cgpt gui                                      # 图形界面（推荐）
```

GUI 里粘贴一行 `邮箱----密码----2FA密钥` 即可登录，再填提示词点「生成图片」。

```bash
python -m cgpt login    --email you@example.com        # 或者走命令行
python -m cgpt whoami                                   # 校验会话 / 看账号能力
python -m cgpt generate "生成一张地球图片"                # 生图 → output/<随机名>.png
python -m cgpt selftest                                 # 离线自证（不联网）
```

实测产物：1254×1254 PNG，2,711,942 字节，内嵌 C2PA 来源凭证。

---

## 1. 它为什么长这样

`docs/` 里的 4 份逆向分析报告给出了三条硬约束，直接决定了架构：

| 约束 | 结论 | 后果 |
|------|------|------|
| Cloudflare 网关层 | `cf_clearance` 带 `Partitioned`（CHIPS），且校验 TLS/HTTP2 指纹 | **登录必须用真实浏览器** |
| Sentinel 探针答案表 `t` | 密钥随**未解开的** `dx` 下发，无法自行伪造 | **对话准入令牌只能由真实页面的 SDK 产出** |
| Sentinel 指纹与 PoW | 算法已完全还原，可纯 Python 复现 | 这部分**用 Python 实现并离线自证** |
| 生图 | 没有独立接口，复用 `f/conversation`，是否出图由服务端 feature + 意图决定 | 请求体不写任何生图字段；出图与否要能**如实报告** |

于是分成两个阶段：

```
┌─ 阶段 A：真实浏览器（Playwright + Chromium）─────────────────────────┐
│  唯一目的：拿凭据。不承担业务请求。                                   │
│  ① 过 Cloudflare（真浏览器天然通过）                                 │
│  ② 邮箱 → 密码 → TOTP 六位码                                        │
│  ③ 从应用自己的网络流量里"捡"凭据（不猜、不逆向）：                    │
│       Cookie              ← context.cookies()                       │
│       Authorization       ← 任一条 /backend-api/* 请求头              │
│       chatgpt-account-id  ← 同上                                     │
│       三条哨兵令牌        ← 应用自己发的 chat-requirements/finalize   │
│  ④ 落盘 .cgpt/credentials.json（0600）                               │
└──────────────────────────────────────────────────────────────────────┘
                              ↓
┌─ 阶段 B：纯 HTTP（curl_cffi，impersonate=chrome）────────────────────┐
│  ① GET  /backend-api/accounts/check      → 校验会话 + 读生图开关      │
│  ② POST /backend-api/f/conversation/prepare → conduit_token（可选）  │
│  ③ POST /backend-api/f/conversation (SSE)   → sediment://file_<id>  │
│  ④ GET  /backend-api/files/download/file_<id> → 服务端签名的 URL     │
│  ⑤ GET  <download_url>                      → PNG 字节落盘 + 自证    │
│                                                                      │
│  兜底：403 + cf-mitigated: challenge → 改用页面上下文 fetch 重发      │
└──────────────────────────────────────────────────────────────────────┘
```

**为什么凭据是"捡"而不是"造"**：`Authorization` 与 `chatgpt-account-id` 的确切取值由前端决定，监听应用自身请求即可拿到**服务端实际接受的那一份**，比猜端点可靠。

---

## 2. 安装

需要 Python ≥ 3.12。

```bash
pip install -r requirements.txt
python -m playwright install chromium      # 首次需要下载浏览器
```

依赖：`playwright`、`curl_cffi`、`pydantic`、`click`。TOTP 用标准库实现，**不需要 pyotp**。

---

## 3. 使用

### 3.0 图形界面（推荐）

```bash
python -m cgpt gui
```

```
┌─ 账号（格式：邮箱----密码----2FA密钥）─────────────────────────┐
│ [••••••••••••••••••••••••••••••••••••]           [登  录]   │
│ ☑ 记住账号   ☐ 显示明文   [清除已保存]                        │
│ ⚠ 勾选后密码与 2FA 密钥会明文保存在 .cgpt/account.txt（仅本机）│
├─ 会话 ──────────────────────────────────────────────────────┤
│ ● 凭据有效 · user@example.com · 计划 free · 剩余额度 22  │
│                                    [校验会话] [重新登录]      │
├─ 提示词 ────────────────────────────────────────────────────┤
│ [（留空，自己填）                                  ]          │
│ 输出：output\（文件名随机）  [打开输出目录]   [生成图片]     │
├─ 结果 ──────────────────────────────────────────────────────┤
│ ┌──────────────┐  ┌──────────────────────────────────────┐  │
│ │   图片预览    │  │ 日志（实时滚动）                      │  │
│ └──────────────┘  └──────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

要点：

* **账号串就是一行**：`邮箱----密码----2FA密钥`，直接粘贴。分隔符、大小写、
  空格、换行都做了容错；密码里含 `----` 也能正确解析。
* **勾选「记住账号」后会自动填充**，下次打开直接点「生成图片」即可。取消勾选
  会在下次登录时清除本地保存的账号；也可以随时点「清除已保存」。
* **默认掩码显示**，需要核对时勾「显示明文」。
* **提示词框刻意留空**，不给示例 —— 预填的示例很容易被当成"就这么用"，
  一进来点「生成图片」就白花一次额度。空着点生成只会弹个提示，不会发请求。
* **会话有 90 天寿命**：登录一次后，平时直接输入提示词生图，不需要重新登录。
* **按钮在执行期间会禁用** —— 重复点登录会触发风控，重复点生成会白耗额度。
* 出图后自动在左侧显示预览（优先用 Pillow 缩放，没装则用 Tk 自带缩略）。
* `Ctrl+Enter` 在提示词框里直接发送；账号框里按 `Enter` 直接登录。
* **右键菜单**：账号框、提示词框、日志区都支持右键（剪切/复制/粘贴/删除/全选），
  账号框和提示词框还支持 `Ctrl+A` 全选 —— 整行账密是粘进来的，这两个不能少。
  日志区是只读的，所以它的菜单里不会出现粘贴这类按了没反应的项。
* 登录时会弹出一个浏览器窗口过 Cloudflare，登录完成后自动关闭（令牌过期时
  需要时会自动重开）。

**⚠ 关于「记住账号」**：这会把密码与 2FA 密钥以**明文**写入
`.cgpt/account.txt`。这是你选择的便利性取舍 —— 文件尽力设为 0600 且
`.cgpt/` 已在 `.gitignore` 里，但同机器上的其它进程仍可读。不想留就把勾去掉。

无桌面环境（纯 SSH / 容器）下启动 GUI 会给出明确提示并引导改用命令行。

界面自检：

```bash
python tools/gui_smoke.py          # 14 项检查，不依赖 pytest
python tools/gui_smoke.py --show   # 显示窗口 5 秒，肉眼确认
```

### 3.1 登录（命令行）

```bash
# 推荐：用环境变量传敏感值，避免进 shell 历史
export CGPT_EMAIL='you@example.com'
export CGPT_PASSWORD='...'
export CGPT_TOTP_SECRET='...'          # 2FA 设置页给出的 base32 密钥
python -m cgpt login
```

Windows PowerShell：

```powershell
$env:CGPT_EMAIL='you@example.com'; $env:CGPT_PASSWORD='...'; $env:CGPT_TOTP_SECRET='...'
python -m cgpt login
```

登录成功会输出 Cookie 数量、Bearer 长度、`account_id`、`oai-did` 与哨兵令牌状态。

**关于 2FA 密钥**：是设置 2FA 时给出的 base32 字符串（例如 `JBSWY3DPEHPK3PXP`），**不是**恢复码。大小写、空格、连字符都会被自动容错。

### 3.2 生图

```bash
python -m cgpt generate "生成一张地球图片"
```

**输出不需要你操心**：一律落到 `output/` 目录，文件名随机（16 位十六进制），
后缀跟图片实际格式走（PNG → `.png`）。实际路径在下面的 JSON 里。
GUI 里对应一个「打开输出目录」按钮，省得你去翻随机文件名。

输出 JSON（`stdout`；日志走 `stderr`，方便管道）：

```json
{
  "conversation_id": "6acf78a3-...",
  "title": "生成地球图片",
  "images": [{
    "path": "output\\3f2a9c1b4d5e4f6a.png",
    "width": 1254, "height": 1254, "size_bytes": 2711942,
    "mime_type": "image/png",
    "asset_pointer": "sediment://file_0000000092a482088cc65529e4b4cd58"
  }],
  "notes": []
}
```

`notes` 记录"下到了图但元数据对不上"这类非致命差异；为空表示字节数与宽高全部与 `image_asset_pointer` 元数据一致。

> 想换目录就改 `Settings.output_dir`（默认 `output/`）。
> 需要指定**文件名**时，库调用可以传 `out=`，但 CLI 与 GUI 都不暴露它 ——
> 日常使用不该被这个问题打断。

### 3.3 作为库

```python
from cgpt import Client

# 复用已登录的凭据
client = Client.from_credentials(".cgpt/credentials.json")
result = client.generate_image("生成一张地球图片")
print(result.primary.path, result.primary.width, result.primary.height)

# 或者先登录一次
client = Client.login(email="...", password="...", totp_secret="...")
client.save()
```

### 3.4 离线取证

哨兵材料可以离线解码，不需要网络：

```bash
python -m cgpt sentinel decode "gAAAAAB..."   # 识别形态并解出 25 字段指纹
python -m cgpt sentinel crack  "<t 或 turnstile>"   # 还原 XOR 答案表
```

```python
from cgpt.sentinel import decode_payload, crack, parse_fernet, solve

info = decode_payload(token)      # → PayloadInfo(kind, prefix, solved, fields…)
result = crack(blob)              # → CrackResult(key, source, plaintext…)
```

---

## 4. 离线自证

这是本项目最值得说的一部分：**仓库里就有 6 份真实抓包**，可以拿真值离线证伪自己。

```bash
python -m cgpt selftest
```

真值由 `tools/build_har_vectors.py` 从 `legacy/har/` **现场提取**（不是抄文档里的数字），产出 `cgpt/data/har_vectors.json`：

```bash
python tools/build_har_vectors.py
```

自证覆盖 38 项：

| 类别 | 样本 | 判据 |
|------|:----:|------|
| TOTP | 18 组 | RFC 6238 附录 B 官方向量 |
| PoW | 5 | `H(seed+b64)[:6] <= difficulty` **且计数器与抓包一致** |
| 指纹载荷 | 7 | 解码→重编码**逐字节相同**（验证 `ensure_ascii=False` 等编码细节）|
| XOR | 10 | 还原密钥 = `17.41`/`46.46`/`70.41`/`27.27`/`90.31`/`64.8`/`97.63`/`31.99`/`3.74`/`4.07`，且明文符合「探针号.答案号」结构 |
| Fernet | 4 | 头布局 + 内嵌时间戳合理 |
| 跨抓包复用 | 9 | 复核文档的"逐字节复用"结论，**含一条反例** |

自证**不会假通过**：样本数量有下限校验，空 fixture / 截断 fixture 一律判失败。

---

## 5. 实测结果

用本项目提供的账号跑通，且与 `docs/` 的记录互相印证：

| 项 | 实测 | docs 记录 |
|----|------|-----------|
| `account_id` | `edebbcbb-3f1d-4963-8ec1-54810e3f2c44` | 一致 |
| `user_id` | `user-LkCB8RihStg7myaLj2HRube6` | 一致 |
| `amr` | `["pwd","urn:openai:amr:password","otp","mfa","urn:openai:amr:otp_totp"]` | 一致 |
| MFA factor id | `6ac5c502fea8819191edc40e2f016413` | 一致 |
| Bearer 长度 | 2069 | 2076 |
| SSE 事件数 | 12 | 12 |
| PNG | 1254×1254，2,711,942 B | 1254×1254，2,897,667 B |
| C2PA | `jumb` ×14、`c2pa` ×28 | 一致 |

---

## 6. 已知限制

* **必须有真实浏览器**：`cf_clearance` 是 `Partitioned` 的，`t`/`turnstile` 的密钥随未解开的 `dx` 下发。纯 HTTP 登录这条路在协议层就被堵死，本工具不假装能绕。
* **生图由服务端决定**：请求体里没有 `image_gen`/`tools` 字段，是否出图取决于服务端 feature 开关 + 模型对意图的判断。没出图时抛 `NoImageProducedError`（被驳回时抛 `PromptRejectedError`），**不会伪造成功**。
* **会消耗账号额度**：每跑一次 `generate` 就是一次真实生图（实测剩余额度 24 → 22）。
* **登录页改版会失败**：失败时会把截图 + HTML + 可见文本存到 `.cgpt/debug/`，据此可快速修选择器。建议加 `--headed` 人工观察。
* **未做**：本地 HTTP 服务 / OpenAI 兼容反代、多账号池、文件上传、SSE 文本流式展示、令牌后台续期守护。
* **每次生图都会开一下浏览器（约 8 秒）**：三条 `openai-sentinel-*` 令牌是**一次性**的，
  同一批只能用一次（实测：全新令牌首次使用成功，同一批 47 秒后再用必 403，而只换令牌就又能成功
  —— 已排除频率限制）。所以每次生图前都要回浏览器重取一批，这一步省不掉。
* **后台开的浏览器窗口会自动最小化，不抢焦点**（Windows）。实测只占用约 0.8 秒就
  把焦点还给你，而它跑完令牌抓取会自己关掉。需要你亲自处理的场合（登录、人机验证）
  仍然正常弹出窗口。想关掉这个行为：`Settings.minimize_browser = False`。

### 排错

| 现象 | 处理 |
|------|------|
| 卡在邮箱步骤 | 多为页面未完成 hydration；工具会自动回退重试 3 次 |
| `ERR_CONNECTION_TIMED_OUT` | 网络抖动；导航已内置退避重试 |
| 找不到验证码输入框 | 密码通过后 `auth.openai.com` 还要过一次 Cloudflare，可能需要几十秒；工具会等 90 秒 |
| 弹出「需要完成人机验证」 | 见下方专节 —— 去浏览器窗口点一下，然后点确定即可 |
| 浏览器里出现「请稍候…」 | 这是 Cloudflare 验证，**需要你点一下，它不会自己过去**。工具会把窗口提到前台并弹框提示 |
| 换账号登录后还是旧账号 | 已修：登录前会先确认当前会话属于谁，不是这个账号就先登出再走完整流程 |
| 生图报 403（空响应体） | 哨兵令牌被复用/消耗了。新版会在每次生图前自动重取；若仍出现，说明令牌在别处被用掉了（比如另一个进程用了同一份凭据），工具会自动重取一次再试 |
| 「助手只回了一段文字，没有调用生图工具」 | 这一轮没画图。多半是提示词被内容策略拦下，或者提示词本身没要求生成图片。**不消耗额度**，也不用等 —— 工具会立刻退出并把模型的原话打出来 |
| `SessionExpiredError` | 重跑 `python -m cgpt login` |

### 被人机验证拦住时怎么办

Cloudflare 有时会要求**人工**过验证（不是 TLS 指纹问题，伪装也过不去）。工具会自动处理，不需要你重跑：

1. 先照常走 HTTP；被拦 → 自动改用浏览器上下文重发；
2. **两条路都被拦** → 把浏览器窗口**导航**到被拦的地址，让 Cloudflare 的验证页真正渲染出来
   （在页面里 `fetch` 只会拿回挑战的 HTML 响应体，页面上不会出现可点的控件）；
3. 弹框 / 命令行提示你：**去那个窗口里完成验证**（一般点一下复选框就行）；
4. 你说完成后 → **重读浏览器里的 Cookie**（`cf_clearance` 是在浏览器里刷新的，
   不重读就是拿旧 Cookie 再撞一次）→ **自动重试**刚才那个请求。

命令行版本长这样：

```
⚠ 被 Cloudflare 人机验证拦住，自动用浏览器重发也没过去。
  浏览器窗口已打开在：https://chatgpt.com/backend-api/me
  请在浏览器里完成验证（一般点一下复选框就行），
  然后回到这里按回车 —— 我会重读 Cookie 并自动重试。
  完成了吗（回车=是，输入 n=放弃）:
```

**两条安全边界**：

* 流式请求（`f/conversation`）**一旦开始产出数据就绝不重发** —— 那会重复发送消息、
  重复消耗一次生图额度。这种情况直接报错，不会偷偷多花你一次。
* 作为库使用时默认**不等待**（`challenge_prompt=None`），直接抛 `CloudflareChallengeError`，
  不会让调用方莫名阻塞。CLI 与 GUI 各自传入了自己的交互实现。

---

## 7. 安全说明

* **下载 URL 主机名白名单**：`files/download` 返回的 `download_url` 在发请求**之前**校验主机名，非 `chatgpt.com` 直接抛 `UnsafeDownloadURLError` —— 绝不把会话 Cookie 带到第三方域（含云元数据地址等 SSRF 目标）。
* **凭据文件 0600**：`.cgpt/` 已列入 `.gitignore`。请勿提交或外传（含 90 天会话 Cookie 与 10 天 Bearer）。
* **敏感值不进日志**：只打印长度与存在性，不打印内容。
* **`dx` / `collector_dx` 未解开**：本工具不尝试绕过它，只从其宿主 SDK 取结果。

---

## 8. 项目结构

```
cgpt/
  client.py            库入口：Client（登录 / 生图 / 惰性刷新令牌）
  gui.py               Tkinter 图形界面（工作线程独占 Client，界面不卡）
  account.py           账号串解析与本地记忆
  cli.py               click 命令组
  config.py            Settings（客户端标识头、超时、时区）
  models.py            Credentials / SentinelTokens / ImageResult / GenerationResult
  errors.py            异常层次（每种可行动的失败一个类型）
  har.py               流式 HAR 读取（117 MB 抓包不全量载入）
  selftest.py          离线自证
  data/har_vectors.json  从抓包提取的真值
  auth/
    totp.py            RFC 6238（标准库）
    store.py           凭据持久化
    browser.py         Playwright 登录 + 凭据抓取 + Cloudflare 回退
  sentinel/
    payload.py         25 字段指纹编解码（两种 gAAAAA 形态的判别）
    pow.py             FNV-1a + murmur 混合、解题
    xor.py             t / turnstile 的 XOR 还原
    fernet.py          Fernet 头解析
  api/
    transport.py       curl_cffi + 浏览器回退
    sse.py             SSE / JSON-Patch delta 解析
    client.py          端点封装
    image.py           生图编排 + 取图 + 产物自证
tests/                 182 项测试（含真值回归、GUI 冒烟、安全约束）
tools/
  build_har_vectors.py 从 legacy/har/ 提取真值
  gui_smoke.py         图形界面自检（不依赖 pytest）
legacy/                本项目之前就存在的素材（6 份抓包 + 既有取证脚本）
docs/                  逆向分析报告 + 设计文档 + 验证报告
```

---

## 9. 协议依据

| 主题 | 文档 |
|------|------|
| 登录链路、Sentinel 指纹/PoW、MFA、Cookie 全生命周期 | `docs/01-chatgpt-login-鉴权与校验分析.md` |
| 对话链路、三条哨兵头、540 秒令牌复用 | `docs/02-chatgpt-chat-鉴权与校验分析.md` |
| 生图链路、SSE 12 事件、签名 URL 取图 | `docs/03-chatgpt-generate-image-鉴权与校验分析.md` |
| 接口清单（可照抄的调用参考） | `docs/04-ChatGPT-Web-接口清单.md` |
| 本工具的设计文档 | `docs/superpowers/specs/2026-10-14-chatgpt-image-gen-tool-design.md` |
| 实测验证报告 | `docs/验证报告-2026-10-14.md` |
