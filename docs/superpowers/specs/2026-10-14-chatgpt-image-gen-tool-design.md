# ChatGPT 账密 + 2FA 登录并请求生图工具 —— 设计文档

> 日期：2026-10-14 · 状态：已批准（对话中）· 目标读者：实现者与验收者
> 依据文档：`docs/01`（登录链路）、`docs/02`（对话链路）、`docs/03`（生图链路）、`docs/04`（接口清单）
> 依据代码：`tools/sentinel-hook.js`（Sentinel 解码/XOR 还原的 JS 参考实现）
> 依据数据：`har/` 下 6 份真实抓包（离线验证的真值来源）

---

## 1. 目标与非目标

### 1.1 目标

用给定账号（邮箱 + 密码 + TOTP 密钥）程序化地：

1. 完成 `chatgpt.com` 的登录，取得可用的会话凭据；
2. 发起一次生图请求，拿到生成的图片；
3. 把图片字节落盘，并返回结构化结果（路径、尺寸、字节数、会话 id、资产指针）。

交付形态：**CLI + 可导入的 Python 库**。

### 1.2 成功判据（验收标准）

| # | 判据 | 验证方式 |
|---|------|---------|
| A | 离线自证全绿：PoW / 指纹载荷 / XOR / Fernet 四类实现与 `har/` 真值一致 | `python -m cgpt selftest`，逐项打印证据 |
| B | 真机登录成功，落盘凭据含 session cookie、`cf_clearance`、`Authorization`、`chatgpt-account-id`、三条哨兵令牌 | `python -m cgpt login` 输出 + 凭据文件 |
| C | 真机生图成功，PNG 落盘 | `python -m cgpt generate "..."` |
| D | 产物自证：PNG 魔数 `89 50 4E 47`、宽高与 `image_asset_pointer` 元数据一致、字节数与 `file_size_bytes` 一致 | 由 `generate` 内置校验并打印 |

A 是 B/C 的前提：先证明协议实现正确，再谈联网。

### 1.3 非目标（YAGNI）

明确不做：本地 HTTP 服务 / OpenAI 兼容反代、多账号池与轮换、会话管理（重命名/删除/分享/归档）、文件上传、SSE 文本流式展示、令牌后台续期守护进程、并发请求调度。

---

## 2. 协议依据（本设计的硬约束）

以下四点直接决定架构，全部有 `docs/` 证据锚点：

| # | 结论 | 证据 | 对本设计的约束 |
|---|------|------|--------------|
| 1 | 客户端 Sentinel 的**指纹载荷与 PoW 算法已完全还原**，可用 Python 复现 | `01` §4.5–§4.7（5/5 逐字节回验通过） | 这部分**纯 Python 实现**，并且能离线自证 |
| 2 | `t` / `turnstile` 是环境探针答案表，`base64(XOR(JSON, 密钥))`，**密钥随未解开的 `dx` 下发** | `01` §4.8.1、§7 第 2 条 | **无法自行伪造** → 必须从真实浏览器 SDK 取令牌 |
| 3 | `cf_clearance` 带 `Partitioned`（CHIPS），按顶层站点分区绑定；`password/verify` 会被 CF 直接 403 挑战 | `01` §4.3、§4.13.3 | **登录必须走真实浏览器** |
| 4 | 生图无独立接口，复用 `POST /backend-api/f/conversation`；是否出图由服务端 feature 开关 + 意图决定 | `03` §4.3、`04` §0 | 请求体**不写**任何 image_gen 字段；出图与否要能如实报告 |

补充约束：

- 三条 `openai-sentinel-*` 头是**同一套**（同一次 `finalize` 产出），必须在一次请求里成套使用（`02` §4.4 的坑）。
- 令牌 TTL = **540 秒**，是"人级"凭证，跨页面复用（`02` §4.5）。本工具把 540 秒作为凭据有效期上限。
- `Authorization: Bearer <OIDC RS256 JWT>` 有效期 10 天（`01` §4.12.1）。
- 图片资产指针形如 `sediment://file_<id>`，出现在 SSE 的 `delta` 事件（`o:"add"` 追加 `tool` 消息）中（`03` §4.7.1 事件 7）。
- 取图两步：`files/download/file_<id>` 换服务端签名的 `download_url` → `GET` 该 URL 取字节（`03` §4.9）。

---

## 3. 架构：两阶段混合

```
┌─ 阶段 A：真实浏览器（Playwright + Chromium）────────────────────────────┐
│  目的唯一：拿凭据。不承担业务请求。                                      │
│                                                                        │
│  ① goto chatgpt.com/auth/login   ← 真浏览器天然通过 Cloudflare 挑战       │
│  ② 填邮箱 → 填密码 → TOTP 6 位码 → 提交                                  │
│  ③ 落地 chatgpt.com 后，从应用自己的网络流量里读凭据（不猜、不逆向）：     │
│       Cookie              ← context.cookies()                          │
│       Authorization       ← 任一条 /backend-api/* 请求头                 │
│       chatgpt-account-id  ← 同上                                        │
│       三条哨兵令牌        ← 应用自己发的 chat-requirements/finalize       │
│                              request.proofofwork → proof-token          │
│                              request.turnstile   → turnstile-token      │
│                              response.token      → chat-requirements-token│
│  ④ 凭据落盘 .cgpt/credentials.json（0600）                              │
└────────────────────────────────────────────────────────────────────────┘
                                  ↓
┌─ 阶段 B：纯 HTTP（curl_cffi，impersonate=chrome）───────────────────────┐
│  ① POST /backend-api/f/conversation/prepare      → conduit_token（可选） │
│  ② POST /backend-api/f/conversation   (SSE)      → 找 sediment://file_<id>│
│  ③ GET  /backend-api/files/download/file_<id>    → download_url         │
│  ④ GET  <download_url>                           → PNG 字节            │
│                                                                        │
│  兜底：任一请求返回 403 + cf-mitigated: challenge                        │
│        → 改用 page.evaluate(fetch) 在浏览器上下文重发同一请求             │
└────────────────────────────────────────────────────────────────────────┘
```

**阶段划分的理由**：约束 2、3 决定了浏览器不可省略；约束 1 决定了 Sentinel 的客户端部分值得用 Python 实现（可离线自证、可用于解码取证）；而业务请求走 HTTP 才能提供"接口"式的调用体验与更快的迭代速度。

**为什么凭据用"捡"而不是"造"**：`Authorization` 与 `chatgpt-account-id` 的确切取值由前端决定（本例前端是 Codex 内嵌浏览器，走 `getBrowserChatGptAuthSnapshot()?.accessToken` 这类注入 API，见 `chatgpt_login_包含敏感数据.har` 内联 JS）。监听应用自身请求即可拿到**服务端实际接受的那一份**，比猜测端点更可靠。

---

## 4. 组件设计

### 4.1 目录结构

```
cgpt/
  __init__.py            导出 Client / ImageResult / __version__
  __main__.py            python -m cgpt 入口
  cli.py                 click 命令组
  config.py              Settings（pydantic-settings + 可选 YAML）
  errors.py              异常层次
  models.py              Credentials / SentinelTokens / ImageResult（pydantic）
  auth/
    totp.py              RFC 6238（仅 stdlib hmac/hashlib/base64/struct）
    store.py             凭据持久化、0600、过期判断
    browser.py           Playwright 会话：登录状态机 + 凭据抓取
  sentinel/
    payload.py           25 字段指纹编解码（gAAAAAB/C 前缀 + ~S）
    pow.py               fnv1a_mix + 解题循环
    xor.py               t/turnstile 的解封与密钥还原
    fernet.py            Fernet 头解析
  api/
    transport.py         curl_cffi 传输层 + 浏览器回退
    sse.py               SSE / JSON-Patch delta 解析
    client.py            ChatGptWebClient（各端点薄封装）
    image.py             generate_image() 编排
tests/
  fixtures/har_vectors.json   从 har/ 提取的真值（由脚本生成）
  test_totp.py / test_pow.py / test_payload.py / test_xor.py / test_fernet.py
  test_sse.py / test_image_extract.py
```

每个模块单一职责：`sentinel/*` 是纯函数、无 IO、可独立测试；`api/*` 只依赖 `models` 与 `errors`；`auth/browser.py` 是唯一接触 Playwright 的模块。

### 4.2 关键接口

```python
# 库入口
from cgpt import Client

client = Client.from_credentials(".cgpt/credentials.json")
result = client.generate_image("生成一张地球图片", out="earth.png")
# GenerationResult(conversation_id, title, images: list[ImageResult])
#   images[0] 是主图；一并返回全部资产指针的下载结果（一轮可能产出多张）
# ImageResult(path, width, height, size_bytes, asset_pointer, mime_type)

# 登录（一次性，落盘凭据）
client = Client.login(email=..., password=..., totp_secret=..., profile_dir=".cgpt/profile")
client.save(".cgpt/credentials.json")

# 离线取证（不需要网络）
from cgpt.sentinel import decode_payload, crack_xor, parse_fernet, solve_pow
```

### 4.3 凭据模型

```python
class SentinelTokens(BaseModel):
    chat_requirements: str   # → openai-sentinel-chat-requirements-token
    proof: str               # → openai-sentinel-proof-token
    turnstile: str           # → openai-sentinel-turnstile-token
    issued_at: float         # 用于 540s TTL 判断

class Credentials(BaseModel):
    cookies: dict[str, str]
    bearer: str | None
    account_id: str | None
    device_id: str | None          # oai-did
    sentinel: SentinelTokens | None
    captured_at: float
    user_agent: str
    originator: str                # 默认 "chatgpt.com"
```

过期策略：`sentinel` 超过 480 秒（留 60 秒余量）即视为失效 → 自动回浏览器重取；`bearer` 超过 9 天视为失效 → 要求重新登录。

结果模型：

```python
class ImageAsset(BaseModel):
    file_id: str              # file_<id>（asset_pointer 去掉 sediment://）
    asset_pointer: str        # sediment://file_<id>
    width: int | None
    height: int | None
    size_bytes: int | None
    mime_type: str | None

class ImageResult(BaseModel):
    path: Path
    width: int
    height: int
    size_bytes: int
    asset_pointer: str
    mime_type: str

class GenerationResult(BaseModel):
    conversation_id: str
    title: str | None
    images: list[ImageResult]  # images[0] 为主图；一轮可能产出多张，全部下载
```

---

## 5. 数据流（一次生图）

```
generate_image(prompt, out)
  ├─ 载入凭据；哨兵令牌过期？ → 复用浏览器 profile 静默回访 chatgpt.com 重取
  ├─ GET  /backend-api/accounts/check/v4-2023-04-27
  │      → 校验会话有效、取 account_id、读 image_gen_tool_enabled
  │        （开关为假 → 立即报错，不浪费一次生图额度）
  ├─ POST /backend-api/f/conversation/prepare       → conduit_token
  ├─ POST /backend-api/f/conversation               → SSE
  │      headers: authorization / chatgpt-account-id / oai-did / oai-language
  │               / originator / 三条 openai-sentinel-* / x-conduit-token
  │      body:    messages=[{content:{content_type:"text", parts:[prompt]}}]
  │               model:"auto", parent_message_id:"client-created-root",
  │               action:"next", timezone, client_prepare_state:"success", ...
  │      流中解析：conversation_id ← delta.v.conversation_id
  │                asset_pointer  ← delta.v.message.content.parts[0].asset_pointer
  ├─ 若流中未出现资产指针（SSE 正文可能缺失，见 03 §0 边界 2）
  │      → 退化为 GET /backend-api/conversations/<id>?num_turns=10，在消息树里找
  ├─ GET  /backend-api/files/download/file_<id>?conversation_id=<id>&download_intent=false&inline=true
  │      → download_url
  ├─ GET  download_url                              → PNG 字节
  └─ 落盘 + 校验（魔数/IHDR 宽高/字节数）→ ImageResult
```

## 6. 错误处理

| 情况 | 行为 |
|------|------|
| CF 挑战（403 + `cf-mitigated: challenge`） | 阶段 B 自动回退浏览器上下文重发；回退也失败则抛 `CloudflareChallengeError`，提示用 `--headed` 观察 |
| 会话失效（401 / `me` 失败） | 抛 `SessionExpiredError`，提示重跑 `login` |
| 登录要求改密 / 额外验证 / CAPTCHA | 登录状态机识别页面特征，**截图存 `--debug-dir`**，抛 `LoginBlockedError` 并说明卡在哪一步 |
| TOTP 被拒 | 允许重试一次（处理时钟偏移 ±30s 窗口），仍失败则抛 `TotpRejectedError` |
| 账号无生图能力（`image_gen_tool_enabled` 缺失） | 抛 `ImageGenUnavailableError`，附 feature 名 |
| 模型未调用图像工具（正常返回文本） | 轮询会话详情至超时（默认 12 分钟）；超时抛 `NoImageProducedError`，**如实报告未出图**，绝不伪造成功 |
| 额度耗尽 | `conversation/init` 的 `limits_progress` 里 `image_gen.remaining == 0` → 提前报错 |
| **`download_url` 指向非 `chatgpt.com` 域** | **发请求前**抛 `UnsafeDownloadURLError` —— 绝不把会话 Cookie 带到第三方域（凭据泄漏防护） |
| 提示词为空或纯空白 | 本地抛 `InvalidPromptError`，**不发起任何网络请求**（避免白白消耗一次生图额度） |
| `credentials.json` 不存在 / 损坏 / 缺字段 | 抛 `CredentialsNotFoundError`，消息里给出应执行的命令，而不是 `KeyError` |

## 7. 验证策略

**原则：先用真值证伪自己，再联网。**

### 7.1 离线自证（`python -m cgpt selftest`）

真值**从 `har/` 现场提取**，不写死文档里的数字（避免抄答案式的假通过）：

| 测试 | 真值来源 | 判据 |
|------|---------|------|
| TOTP | RFC 6238 附录 B | 8/8 相符 |
| PoW | 各 HAR 的 `seed`/`difficulty` + 实提交答案 | `H(seed+b64)[:6] <= difficulty` **且解码出的计数器与抓包一致** |
| 指纹载荷 | `p` / `proofofwork` / `turnstile` 原文 | 解码→重编码**逐字节相同** |
| XOR | 文档列出的 10 个 blob | 还原密钥 ∈ {`17.41`,`46.46`,`70.41`,`27.27`,`90.31`,`64.8`,`97.63`,`31.99`,`3.74`,`4.07`} 且明文可 `json.loads` |
| Fernet | `c` 与 `/sentinel/req` 响应 `token` | 两者逐字节相同；内嵌时间戳与 HTTP `date` 差 < 5 秒 |

### 7.2 真机端到端

严格按 §1.2 的 B / C / D 三条判据执行，并把每步证据（状态码、令牌长度、Fernet 时间戳、PNG 头 8 字节、IHDR 宽高）打印出来。

## 8. 风险与缓解

| 风险 | 缓解 |
|------|------|
| curl_cffi 的 TLS 指纹与 Playwright Chromium 版本不匹配 → CF 403 | UA 与 impersonate 版本对齐；自动浏览器回退 |
| 新设备/新 IP 触发额外验证 | 使用持久化 profile 复用设备指纹；一次登录后长期复用凭据，不反复登录 |
| 生图由服务端意图决定，可能不出图 | §6 的 `NoImageProducedError` 路径；如实报告 |
| 抓包中的 `originator: Codex Browser` 是 Codex 环境特有值 | 默认改为网页端取值，且做成可配置；真机若 403 则回退到抓包观测值 |
| 540 秒 TTL 导致长流程中途失效 | 令牌在发请求前才取；`prepare` 与 `conversation` 之间不做耗时操作 |

## 9. 交付物

1. `cgpt/` Python 包（上述结构）
2. `tests/` 离线测试 + `tests/fixtures/` 真值提取脚本
3. `README.md`：安装、CLI 用法、库用法、设计说明、已知限制
4. `requirements.txt`
5. 验证报告：离线自证输出 + 真机端到端证据

## 10. 变更记录

| 日期 | 变更 |
|------|------|
| 2026-10-14 | 初稿，基于 4 份分析文档 + 6 份 HAR 定稿 |
