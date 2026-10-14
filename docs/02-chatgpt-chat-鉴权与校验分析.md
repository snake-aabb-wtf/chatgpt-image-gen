# chatgpt_chat.har —— ChatGPT 对话链路鉴权与校验逻辑分析

> 分析对象：`chatgpt_chat.har`（3.86 MB，43 条请求，时间跨度 `2026-10-14T09:43:35.199Z` ~ `09:44:07.727Z`，约 32 秒）
> **补充抓包**：`chatgpt_chat_包含敏感数据.har`（CS，20 条，10:44Z）、`chatgpt_image_包含敏感数据.har`（IS，19 条，11:00Z）、`chatgpt_多轮对话_包含敏感数据.har`（MT，19 条，11:05Z，**两轮对话 / 两轮 Sentinel**）—— 补齐了被脱敏掉的 Cookie 与 Bearer、SSE 事件结构、以及"跨轮/跨抓包令牌复用"的直接证据；文中凡引用它们都标注文件缩写。
> 场景：登录完成后，在 ChatGPT Web 发送一条消息「你好」并收到回答
> 账号：`logo-pie2i@icloud.com` / `user-LkCB8RihStg7myaLj2HRube6` / 计划 `free` / 工作区 `edebbcbb-3f1d-4963-8ec1-54810e3f2c44`
> 前置阅读：`01-chatgpt-login-鉴权与校验分析.md`（Sentinel 指纹载荷与 PoW 算法在同一文档中完整推导，本文直接引用其结论）
> 接口速查：**`04-ChatGPT-Web-接口清单.md` §2** —— 对话链路每个接口的方法/参数/请求体/SSE 事件结构。

---

## 0. 阅读前必读：本 HAR 的能力边界

**三个重要缺口**，直接影响可下结论的范围：

1. **无 Cookie、无 `Authorization`**（**仅本脱敏版如此**）：导出工具把凭据头全部裁剪（43 条中 `request.cookies[]` 非空 = 0，`Cookie`/`Authorization` 头 = 0）。会话凭据客观存在（`/backend-api/me` 返回了完整用户信息），但**其载体在本文件不可见**。⚠️ 已由补充抓包 `chatgpt_chat_包含敏感数据.har` 补全：真实流量**同时携带 22 个 Cookie 与 `Authorization: Bearer`**（详见 `01` §4.12），不要把本文件的"没有"当成"客户端没发"。
2. **SSE 响应体未落盘**：核心请求 `[4] /backend-api/f/conversation` 的响应声明 `size=10587` 字节、`content-type: text/event-stream`，但 `content.text` 为空字符串（`stored=0`）。因此**助手回复的事件流内容（文本、消息 id、工具调用）无法从本文件取证**；唯一残留的是 HAR 私有字段 `_eventSourceMessages`（23 条**无载荷**的事件时间戳，见 §4.1）。
   → **补充抓包已补齐事件流结构**：`chatgpt_image_包含敏感数据.har [1]` 的 SSE 正文完整落盘（12 个事件、含 `delta`/`resume_conversation_token`/`title_generation` 等），结构见 `03` 文档 **§4.7.1**。
3. **本轮对话的会话详情不可查**：该 HAR 里没有 `/backend-api/conversations/<id>` 的详情请求；要观察消息级结构需借助图片 HAR（见 `03` 文档 §4.7）。
4. **一个已被后续交叉比对填平的缺口**：`[4]` 实际使用的三条 Sentinel 令牌来自"上一轮"（约 09:42:04）。该轮**并不在**本文件里，但它是 **`chatgpt_login.har` 的 `[674]→[712]`**（登录流程末尾那次 `chat-requirements`）—— 三条值**逐字节相同**，缺口已闭合（见 §4.5）。

> 因此本文聚焦**可完整取证的部分**：三条 Sentinel 准入头、`conduit_token`、会话标识头矩阵、请求体字段的来源与语义、以及 `prepare → conversation` 两段式协议。

### 噪声说明

43 条里 27 条是静态资源（`chatgpt.com/cdn/assets/*.js` 前端分块 **25** 条 + 2 个 favicon），3 条 Statsig/Datadog 遥测（`/ces/v1/rgstr`、`/ces/v1/telemetry/intake`），与鉴权无关。真正承载鉴权/校验的是 **13 条** `/backend-api/*` 请求。

---

## 1. 结论速览（TL;DR）

对话链路的准入 = **一次两段式 "chat-requirements" 校验 + 三条 Sentinel 请求头 + 一个可选的 conduit 票据**：

```
[准备阶段]  POST /backend-api/f/conversation/prepare     ← 输入草稿/上下文变化时"预发送"
            body: {client_prepare_state:"sent", partial_query:{...}, client_prepare_dispatch:"debounced", ...}
            resp: {status:"ok", conduit_token:<ES256 JWT, 60s>}

[准入校验]  POST /backend-api/sentinel/chat-requirements/prepare   （无请求体，仅 {"p": 指纹}）
            resp: {persona, prepare_token(Fernet), turnstile:{required,dx}, proofofwork:{required,seed,difficulty}, so:{required,collector_dx}}
[本地解题]  H(seed + base64(指纹载荷)) 前 6 位十六进制 ≤ difficulty     → proofofwork
[准入换取]  POST /backend-api/sentinel/chat-requirements/finalize
            body: {prepare_token, proofofwork, turnstile}
            resp: {persona:"chatgpt-freeaccount", token:<Fernet>, expire_after:540, expire_at}

[正式发送]  POST /backend-api/f/conversation     (SSE)
            headers:
              openai-sentinel-chat-requirements-token: <finalize 返回的 token>
              openai-sentinel-proof-token:            "gAAAAAB" + b64(指纹载荷) + "~S"
              openai-sentinel-turnstile-token:        <XOR 保护的探针答案表（非 CF 令牌）>
            body: {action:"next", model:"auto", messages:[...], client_prepare_state:"sent", ...}
```

> ⚠️ **上图是"机制"层面的典型顺序，本 HAR 的实际时序与它不同**：`[4]`（"你好"这条消息）携带的三条头是**约 90 秒前（09:42:04）签发的旧令牌**；而图中 `[27]→[31]` 这一轮新令牌是在 `[4]` 发出**之后**才生成的，本 HAR 里没被用到（后被图片会话复用）。原因就是 540 秒 TTL 缓存 —— 详见 §4.5。

**关键结论（均有直接证据，见 §4）**

| # | 结论 | 证据 |
|---|------|------|
| 1 | 对话准入凭证放在**请求头**里，且是**三条** `openai-sentinel-*` 头 | `[4]` 请求头 |
| 2 | 头里的三条 `openai-sentinel-*` 令牌**不是**本轮 `[27]→[31]` 新签发的那一套，而是**上一轮签发、仍在 540 秒 TTL 内的缓存值**；那一轮就是 `chatgpt_login.har [674]→[712]`，**三值逐字节相同** | `[4]` 头（3084/673/1740）vs `[31]`（3064/725/1828）不等；vs `login[712]` **全等** |
| 2b | 本轮 `[31]` 新签发的那一套，随后被**图片会话**（`chatgpt_generate_image.har [8]`）**逐字节复用** | 跨 HAR 比对（§4.5）|
| 3 | `chat-requirements/prepare` 的 `p` 与对话无关地复用登录侧同一套**指纹载荷格式**（`gAAAAAC`+b64） | `[27]` 请求体 |
| 4 | PoW 算法与登录链路完全相同（同一 `sentinel sdk.js`）| `[27]/[31]` 实测命中 |
| 5 | `conduit_token` 是 ES256 签名 JWT，**60 秒有效**，含后端实例内网地址；**不是**必需凭证（本 HAR 中 `[4]` 未携带仍成功） | `[1]` 响应 + `[4]` 无该头 |
| 6 | 助手回复的 SSE 正文未落盘 → 消息级结构无法从本 HAR 取证 | `[4]` `stored=0` |
| 7 | 传输层为 **Cookie + `Authorization: Bearer`（OIDC RS256 访问令牌）双凭据**；本文件因脱敏看不到，补充抓包已证实 | `01` §4.12 / 补充抓包 |
| 8 | `/backend-api/me` 的 `amr` 字段明确回显了登录方式：password + TOTP | `[25]` 响应 |

---

## 2. 抓包概览

* **主机**：`chatgpt.com` 43/43（无第三方，除 CDN 分块）
* **方法**：GET 34 / POST 9
* **状态**：200 ×40，202 ×3（遥测）
* **时间线关键节点**：
  * `09:43:35.199` `[0] system_hints`（页面初始化，拉取可用工具/系统提示清单）
  * `09:43:35.223` `[1] f/conversation/prepare`（草稿预发送，`partial_query.parts=["你"]`）
  * `09:43:35.648` `[4] f/conversation`（正式发送，`messages[0].parts=["你好"]`，耗时 13.6 s）
  * `09:43:40.920` `[29] conversation/init`（会话初始化/额度查询）
  * `09:43:48.946` `[34] f/conversation/prepare`（**第二轮** prepare，已带 `conversation_id` 与上一轮 `parent_message_id`）
  * `09:44:06` `[41] wham/usage`、`09:44:07` `[42] wham/tasks/list`

> 注意 `[1]` 与 `[4]` 相隔仅 425 ms：**prepare 是"边输入边预发送"的防抖机制**（`client_prepare_dispatch:"debounced"`），而不是必经的握手步骤。`partial_query.parts=["你"]` vs `messages[0].parts=["你好"]` 正好证明这一点 —— 用户在 prepare 之后又补了一个字。

---

## 3. 会话与标识头矩阵（`/backend-api/*` 全量统计）

除 `[38]`~`[40]`（遥测）外，**每一条** `/backend-api/*` 请求都带下列头：

| 头 | 值 | 说明 | 出现次数（entry）|
|----|----|------|------|
| `chatgpt-account-id` | `edebbcbb-3f1d-4963-8ec1-54810e3f2c44` | **账号/工作区 ID**，业务 API 的租户隔离键 | **15**：`[0][1][4][25][26][27][29][31][34][36][37][38][40][41][42]` |
| `oai-did` | `57cab66a-0ad5-42c6-8d2d-2f2e9b2a8d28` | 设备 ID（与登录链路同一 UUID）| **11**：`[0][1][4][25][26][27][29][31][34][36][37]`（`[38][40][41][42]` **没有**）|
| `oai-language` | `zh-CN` | 界面语言 | **13**（`[38][40]` 无）|
| `originator` | `Codex Browser` | 客户端来源标识（本次抓包来自 Codex 内嵌浏览器）| **15**（与 account-id 同集合）|
| `x-openai-web-frontend` | `codex_webview` | 前端形态 | **11** |
| `x-openai-codex-window-type` | `browser` | 宿主窗口类型 | **11** |
| `x-oai-mcp-form-version` | `2` | MCP 表单协议版本 | **11** |
| `referer` | `https://chatgpt.com/` | 同源校验 | **42**（除 `[39]`）|
| `oai-app-brand` | `chatgpt` | 产品标识 | **1**（仅 `[41]`）|

> **补充抓包的动态 Cookie**：`_uasid` / `_umsid`（各 ~478/334 字符，HttpOnly、30 分钟）**每次发送都在 `f/conversation` 的响应里重新签发**——补充抓包 `[1]`（turn 1，11:05:30）与 `[10]`（turn 2，11:05:48）各下发一对。它们与 `oai-sc`（每轮 sentinel 调用重发）一起构成"按轮轮换"的 Cookie 集合。

> 注意分布差异：`[41]/[42]`（`wham/*` 用量类接口）**不带** `oai-did`；`[38]/[40]`（Statsig 遥测）**既不带** `oai-did` **也不带** `oai-language`（只带 `chatgpt-account-id` + `originator` + `statsig-*`）。即"设备维度"头并非全局强制，而是按端点族裁剪。

**仅在对话发送时出现**的头：

| 头 | `[4]` 实际值（截断）| 说明 |
|----|-----------|------|
| `openai-sentinel-chat-requirements-token` | `gAAAAABqz05uLNAzyZjGd0…`（**3084** 字符）| **对话准入令牌**。⚠️ 注意：它**不是**本轮 `[31]` finalize 返回的那个（那个是 `gAAAAABqz07O…`，3064 字符），而是**上一轮（约 09:42:06）签发、仍在 540 秒 TTL 内的缓存值** —— 详见 §4.5 |
| `openai-sentinel-proof-token` | `gAAAAABWzMwMDAsIldlZCBPY3QgMTQgMjAyNiAxNzo0MjowNCBHTVQr…wwLDBd~S`（**673** 字符）| **PoW 答案**（指纹载荷 + `~S`）；内嵌时间戳 `17:42:04`、计数器 `[3]=11` → **上一轮**的解答 |
| `openai-sentinel-turnstile-token` | `TBIYAx8CBQwOE3VIGm5zdnVmdXMDdW9lUnZ4…`（**1740** 字符）| **环境探针答案表**（`base64(XOR(JSON,"70.41"))`，24 项；**不是** Cloudflare Turnstile 令牌，见 §4.4 与 `01` §4.8.1），同样是上一轮的值 |
| `x-oai-turn-trace-id` | `3a1794e8-2838-4094-8808-1b6a2d0e5942` | **本轮 turn 的追踪 ID**（客户端生成）。出现 **3 次**：`[1]`（本轮 prepare）与 `[4]`（本轮发送）**同值**，而 `[34]`（下一轮 prepare）是**另一个值** `49bc21e2-d9fc-4357-a309-789739fc7f5d` → 它把"一次 prepare + 一次发送"绑定成一轮。该值还被回显进 `[39]` 的 Datadog 遥测体（`"turn_trace_id":"3a1794e8-…"`，同处还有 `turn_session_id`/`turn_exchange_id` 与**等于 `[4]` 响应头 `x-oai-request-id` 的 `server_request_id`**）→ 客户端视角与服务端视角在此对齐 |
| `x-openai-web-sse-compression` | `gzip` | SSE 压缩协商 |
| `oai-echo-logs` | `1,18901,0,48501,1,48521,0,97631` | **日志回显采样指令**（成对 `开关,点位`，服务端据此决定回传哪些诊断日志）|
| `content-type` | `application/json` | — |

> `oai-echo-logs` 是很有意思的反滥用/诊断机制：客户端主动声明"我对这些日志点位感兴趣"，服务端可选择回显；值形如 `<0|1>,<点位号>,...`，本次开放了 18901/48501/48521/97631 四个点位。

---

## 4. 机制详解

### 4.1 两段式对话协议：`f/conversation/prepare` → `f/conversation`

#### `[1] prepare`（草稿/上下文变化的"预发送"）

```json
{
  "action": "next",
  "is_do_not_remember": false,
  "model": "auto",
  "parent_message_id": "client-created-root",
  "timezone": "Asia/Shanghai",
  "timezone_offset_min": -480,
  "client_contextual_info": {
    "app_name": "chatgpt.com", "app_surface": "codex_browser",
    "has_web_push_capabilities": true, "web_push_notification_permission": "default"
  },
  "local_function_names": ["local.continue_in_work"],
  "supported_encodings": ["v1"],
  "client_prepare_state": "sent",
  "partial_query": {
    "id": "2574b1a4-52c8-40cf-b5fb-2aeb22e99f63",
    "author": { "role": "user" },
    "content": { "content_type": "text", "parts": ["你"] }
  },
  "client_prepare_dispatch": "debounced",
  "client_prepare_source": "context_change"
}
```

响应（385 字节）：

```json
{ "status": "ok",
  "conduit_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJjb25kdWl0X3V1aWQiOiI1ZmU4NWUwZGM5ODg0NTQwYjVmOWM3MTg3ZTdiMDY2MCIsImNvbmR1aXRfbG9jYXRpb24iOiIxMC4xMjguMjguMjU0OjgzMDciLCJjbHVzdGVyIjoidW5pZmllZC0xMjUiLCJpYXQiOjE3OTE5NzEwMTYsImV4cCI6MTc5MTk3MTA3NiwidHVybl90b3BpY19pZCI6bnVsbH0.N0gcjEPSsrjzxETeZNoHYhoEuUJYZ7ZsxFEniX0MWGlaGOVlE8nIxZG-dtw-jJroxDS6szZ4-QDFOAeZ5pKxGg" }
```

**`client_prepare_*` 三兄弟的语义**（本次抓包两个样本可对比）：

| 字段 | `[1]`（首轮）| `[34]`（次轮）| 含义 |
|------|-------------|--------------|------|
| `client_prepare_state` | `sent` | `sent` | prepare 所处的客户端状态机状态 |
| `client_prepare_dispatch` | `debounced` | `debounced` | 由**防抖**触发（非用户按回车）|
| `client_prepare_source` | `context_change` | `context_change` | 触发源：上下文变化 |
| `partial_query` | 有（`"你"`）| **无** | 仅在有草稿文本时携带 |
| `conversation_id` | 无 | `6acf4ecb-037c-83e8-b125-11a2df60724c` | 会话已建立后才带 |
| `parent_message_id` | `client-created-root` | `ff9aeb90-1ba8-4b81-8623-c6292fd592ec` | 首轮为客户端根节点，次轮为服务端消息 id |

> **设计意图（推断）**：`prepare` 让服务端在用户真正发送前完成"路由预热/模型选择/配额预检"，并顺便下发 `conduit_token` 指向具体后端实例，从而缩短正式发送的首字节时间。响应头 `s-cf-origin-ttfb-msec: 7603` 与 `s-sa-server-ttfb-msec: 7028.879`（见 `[4]`）说明真正的生成发生在服务端，耗时数秒。

#### `[4] f/conversation`（正式发送，SSE 流式）

请求体（816 字节）：

```json
{
  "turn_attribution": { "turn_trigger": "composer" },
  "action": "next",
  "is_do_not_remember": false,
  "model": "auto",
  "parent_message_id": "client-created-root",
  "timezone": "Asia/Shanghai",
  "timezone_offset_min": -480,
  "client_contextual_info": { "...": "同 prepare" },
  "local_function_names": ["local.continue_in_work"],
  "messages": [{
    "id": "0d439a4a-d5ac-4b43-9884-ee60236aa33b",      // 客户端生成的消息 id
    "author": { "role": "user", "name": null, "metadata": {} },
    "content": { "content_type": "text", "parts": ["你好"] },
    "create_time": 1791971015.622,                      // 客户端时间戳
    "recipient": "all",
    "status": "finished_successfully",
    "end_turn": null, "weight": 1, "channel": null, "metadata": {}
  }],
  "supported_encodings": ["v1"],
  "genui_state_snapshots": [],
  "client_prepare_state": "sent"
}
```

**哪些字段是"服务端回显/客户端生成"**：

| 字段 | 来源 | 证据 |
|------|------|------|
| `parent_message_id: "client-created-root"` | 客户端占位符 | 首轮对话无服务端父节点；次轮变为服务端 id |
| `messages[].id` | **客户端**生成的 UUID | 与 `partial_query.id`（`2574b1a4-…`）不同，且 `[34]` 的 `parent_message_id` 是服务端后续分配的 `ff9aeb90-…` |
| `client_prepare_state: "sent"` | 客户端状态机 | 与 prepare 阶段同名同值，属于**回显自身状态**而非服务端票据 |
| `turn_attribution.turn_trigger: "composer"` | 客户端 | 标识本轮由输入框触发 |
| `*_token` / `*_proof` / checksum | **无** | 请求体中**不存在**任何 Sentinel 相关字段（全部在请求头），也不存在 `conversation_mode`、`tools`、`author`（图片 HAR 亦同，见 `03` §4.6）|

#### 多轮对话的 id 链（补充抓包实测，3 轮）

`chatgpt_多轮对话_包含敏感数据.har` 把"首轮之后 id 从哪来"这条链完整跑了一遍（该抓包 `[1]`/`[10]` 是两次发送）：

| 轮次 | 发送 entry | `conversation_id` | `parent_message_id` | 用户消息 id（客户端生成）|
|------|-----------|------------------|--------------------|----------------------|
| 第 1 轮 | `[1]`（11:05:27）| `null` | **`client-created-root`** | `eafc6ddf-b75a-403d-9994-a0d8726aab76`（`"你好"`）|
| 第 2 轮 | `[10]`（11:05:45）| **`6acf61f9-1a10-83e8-ab8b-d322445bc4af`** | **`8d6dea6b-62dd-4834-9d8b-2935230fe455`** | `4672606d-b452-4622-8618-9066ef36e63f`（`"你是谁"`）|
| （第 3 轮准备）| `[13]` | `6acf61f9-…` | **`7eed8666-21a6-4606-a7ee-6bde2bf970b4`** | — |

**结论**：`conversation_id` 与"上一轮助手消息的 id"都是**服务端在首轮 SSE 里下发的**——尽管本抓包的 SSE 正文同样未落盘（`[1]`/`[10]` 均 `stored=0`），但它们在**紧接着的 `[6]` prepare 请求体里出现了**，足以证明客户端是从首轮流里拿到的；`[13]` 又带上了第 2 轮的助手 id，说明这条链**每轮递进**。这与 `03` §4.7.1 记录的 SSE 事件 2（`p:"" o:"add"` 的 `v.conversation_id`）与事件 7（追加助手消息）完全对应。

响应：

| 项 | 值 |
|----|----|
| 状态 | `200`，`content-type: text/event-stream; charset=utf-8` |
| 响应头 `x-conduit-token` | **新的** ES256 JWT（`conduit_uuid=6f754817e9ec48eb8ab553d27bac2ad8`，`conduit_location=10.128.246.219:8303`）→ **服务端在响应里滚动续期** |
| 响应头 `x-build` | `56870b24a797-convo`（后端构建号，可用于版本指纹识别）|
| 响应头 `x-oai-request-id` | `531a8656-08f1-49de-a483-3e1b7da45704`（服务端请求 id，用于追查）|
| 响应头 `s-cf-origin-ttfb-msec` / `s-sa-server-ttfb-msec` | `7603` / `7028.879`（各段时延回执）|
| 响应体 | **未落盘（`stored=0`）**，但见下方"事件级时间戳" |

**SSE 事件级时间戳（部分补偿）**：`[4]` 条目内保留了 HAR 的私有字段 `_eventSourceMessages`，含 **23 条**事件记录（`eventName`：`delta` ×15、`message` ×8，`eventId` 为空串），时间范围 `1791971023.92` ~ `1791971029.18`（=`09:43:43.9Z` ~ `09:43:49.2Z`），与 `[4]` 的总耗时（13.578 s，`09:43:35.65` 起）尾部吻合。

> 这提供了**事件粒度的时间线**（可用于判断首 token 延迟、流式节奏），但**不含事件载荷**（`data:` 内容），因此助手回复的文本、消息 id、工具调用等仍无法取证。这一点比"完全没有 SSE 信息"要好，但远不足以还原消息内容。

**关于 `oai-echo-logs`**：`[4]` 的值是 `1,18901,0,48501,1,48521,0,97631`（4 组点位），而图片 HAR `[8]` 的同类头有 **9 组**点位（多出 `106650/106973`、`116512/138268`、`144027/144406`）→ **生图链路的日志回显范围更大**。

### 4.2 `conduit_token`：60 秒有效的后端粘滞票据

三个样本的 JWT 载荷（`alg: ES256`，三段 36/227/86 字符）：

| 来源 | `conduit_uuid` | `conduit_location` | `cluster` | `iat` | `exp` | 有效期 |
|------|---------------|-------------------|-----------|-------|-------|--------|
| `[1]` prepare 响应 | `5fe85e0dc9884540b5f9c7187e7b0660` | `10.128.28.254:8307` | `unified-125` | 1791971016 | 1791971076 | **60 s** |
| `[34]` prepare 响应 | `06551cd088cd4b2ab497f17ec13ac16b` | `10.131.124.65:8302` | `unified-125` | 1791971030 | 1791971090 | 60 s |
| `[4]` 响应头 | `6f754817e9ec48eb8ab553d27bac2ad8` | `10.128.246.219:8303` | `unified-125` | — | — | 60 s |

**可观察事实**：

1. `conduit_token` 由 `prepare` 响应**签发**，`f/conversation` 响应头**续期**；
2. 载荷暴露了后端实例的**内网 IP:port** 与集群名（`unified-125`）—— 这是分析其部署拓扑的副产品；
3. **它不是必需凭证**：本 HAR 的 `[4]` 请求**没有**携带 `x-conduit-token`（`[1]` 的 prepare 响应在 `09:43:36` 才返回，而 `[4]` 在 `09:43:35.648` 就已发出 —— 令牌尚未到手），请求仍返回 200。对照图片 HAR 的 `[8]`（prepare 完成后才发送）**确实携带**了该头 → **推断**它是"能带就带"的路由优化，缺失时服务端自行路由。

### 4.3 Sentinel chat-requirements：对话侧准入校验

#### `[27] POST /backend-api/sentinel/chat-requirements/prepare`

请求体只有**一个字段**（699 字节）：

```json
{"p":"gAAAAACWzMwMDAsIldlZCBPY3QgMTQgMjAyNiAxNzo0MzozNSBHTVQrMDgwMCAo5Lit5Zu95qCH5YeG5pe26Ze0KSIs…LDAsMF0="}
```

* 格式与登录侧**完全一致**：`"gAAAAAC"` + base64(25 元素指纹数组)，此处**未带 `~S`**（尚未解题）；
* 与登录侧唯一差别：**没有 `id` / `flow` 字段**（设备 id 由 `oai-did` 请求头承担，端点本身不需要 flow 参数）。

响应（88486 字节，比登录侧大得多）：

```json
{
  "persona": "chatgpt-freeaccount",                    // 登录后身份画像
  "prepare_token": "gAAAAABqz07J1NPXDQz9Lon5zdeUeyzwITisJMYOmb5SazA7…",   // 3512 字符 Fernet
  "turnstile": { "required": true, "dx": "PBp5bWF1enlKeFttfBxfaTdQVXRzd3x5…" },
  "proofofwork": { "required": true, "seed": "0.2250343410955007", "difficulty": "06b983" },
  "so": { "required": true, "collector_dx": "PBp5bWFxbWJDYVd1GW1TElxKWWNvYmRu…" }
}
```

| 字段 | 说明 |
|------|------|
| `persona` | `chatgpt-freeaccount`（登录侧未登录时为 `chatgpt-noauth`）——**服务端按账号等级下发不同强度的挑战**的抓手 |
| `prepare_token` | 3512 字符 Fernet，**本次校验的会话票据**，finalize 时必须原样回传 |
| `turnstile.dx` | **探针问卷指令**（约 20~24 KB 混淆密文；字段名沿用了 "turnstile" 但内容是 OpenAI 自己的采集通道，与网关层 Cloudflare 无关）|
| `proofofwork` | PoW 参数（`seed` + 6 位十六进制 `difficulty`）|
| `so` | **Session Observer**：额外的行为采集要求。本文件为 `collector_dx`（约 32 KB 混淆密文）；**补充抓包中该对象多出 `snapshot_dx`（26244 字符）**，即采集项随版本/轮次扩展 |

> `so` 是登录侧 `sentinel/req` **没有**的字段 —— 对话侧的采集要求更强。但 finalize 请求体只提交了三项（见下），`so` 的消费路径在本次抓包中未闭合（**待验证**）。

#### `[31] POST /backend-api/sentinel/chat-requirements/finalize`

请求体（三项，共 ~5.9 KB）：

```json
{
  "prepare_token": "gAAAAABqz07J1NPXDQz9Lon5zdeUeyzwITisJMYOmb5SazA7…",   // 原样回传 (3512)
  "proofofwork": "gAAAAABWzMwMDAsIldlZCBPY3QgMTQgMjAyNiAxNzo0Mzo0MSBHTVQrMDgwMCAo…c5MTk3MDkxMzk4Ny4yLDAsMCwwLDAsMCwwLDBd~S",  // 725
  "turnstile": "SRUZABkGAQwIFXNAEw8VHhUWAhkGDwwIBgIAHQUACgEWCgceFR8HGQMVFAEBCgEaAhsQBBocBwQVFBB0…"   // 1828
}
```

响应（3150 字节）：

```json
{ "persona": "chatgpt-freeaccount",
  "token": "gAAAAABqz07O3vK_IPNlTkVCKiXd7QWyAc2cGinFJDZ1nWeJL8SwtyTFfHOp4ijmEaHYep7F6I9AwK9q…",  // 3064
  "expire_after": 540, "expire_at": 1791971562 }
```

**这个 `token` 是"第 2 代"准入令牌** —— 它会被放进**下一条**对话请求的 `openai-sentinel-chat-requirements-token` 头里。注意在本 HAR 中它**没有被任何请求使用**：`[4]`（"你好"）用的是更早的第 1 代（`gAAAAABqz05u…`，3084 字符，09:42:06 签发），而 `[27]→[31]` 这一轮是在 `[4]` 已经发出之后才发起的（详见 §4.5）。真正用上它的是**图片 HAR 的 `[8]`**（逐字节相同）。

#### PoW 与指纹载荷：与登录链路同源

* `proofofwork` = `"gAAAAAB"` + base64(指纹数组, 其中 `[3]` = 命中的循环计数器) + `"~S"`；
* 算法：`H = FNV-1a32 + murmur 雪崩混合 → 8 位十六进制`；判定 `H(seed + base64载荷).substring(0, len(difficulty)) <= difficulty`；
* 本 HAR 实测（已复算通过）：

| 项 | 值 |
|----|----|
| `seed` | `0.2250343410955007` |
| `difficulty` | `06b983`（= 440707，比较空间 2²⁴ = 16777216 → 单次通过率 2.63%，期望 ~38 次）|
| 提交答案中的计数器 `[3]` | `40` |
| `H(seed + 载荷)` | `009b70bc` → 前 6 位 `009b70` ≤ `06b983` ✅ |
| 指纹数组其他字段 | `[1]` 时间字符串、`[4]` UA、`[6]` 常量 `132f33eb…`、`[14]` 随机 UUID、`[9]`=4（耗时 ms）|

> 完整推导（含 SDK 源码还原、逐字节回验）见 `01` 文档 §4.5–§4.7。

### 4.4 三条 `openai-sentinel-*` 头的角色分工

下表左列是**本 HAR `[4]` 实际携带的**（即上一轮缓存值）：

| 头 | `[4]` 实际值形态 | `[31]` 本轮新值（供对照）| 来源 | 服务端校验什么（推断）|
|----|----------------|----------------------|------|---------------------|
| `openai-sentinel-chat-requirements-token` | `gAAAAABqz05u…` Fernet（**3084**）| `gAAAAABqz07O…`（3064）| `finalize` 响应的 `token` | 解密后取出 persona/配额/挑战通过标记；**540 秒内有效** |
| `openai-sentinel-proof-token` | `gAAAAAB`+b64(指纹)+`~S`（**673**，`[3]`=11，指纹时间 `17:42:04`）| 同结构（725，`[3]`=40，`17:43:41`）| 客户端本地 PoW 计算 | 用 `seed` 重算哈希，验证前缀 ≤ `difficulty`，同时核对指纹真实性 |
| `openai-sentinel-turnstile-token` | base64(XOR(json))（**1740**）| 同结构（1828）| **客户端采集并加密的探针答案表**（键=`探针号.答案号`）| 解密后核对各项环境/行为采集值（见 `01` §4.8.1）|

**三者缺一不可**（推断）：requirements-token 证明"通过过挑战"，proof-token 证明"算了 PoW 且指纹可信"，turnstile-token 证明"是人"。

> ⚠️ **一个容易踩的坑**：三条头里的值彼此**成套**（同一次 finalize 产生的），但与本 HAR 里可见的 `[27]/[31]` **不是同一套**。核对时必须做逐字节比较，不能只看前缀 `gAAAAAB` 就下结论 —— 本文件在初稿中正是因此写错过一次，后经逐字节比对纠正（见 §4.5）。

### 4.5 令牌 TTL 与跨会话复用（重要发现）

`finalize` 返回 `expire_after: 540`（540 秒 = 9 分钟）；SDK 源码中对应常量：

```js
const se = 5e3, ue = 54e4, …        // ue = 540000 ms = 540 s
// requirementsToken() 的缓存判定：Date.now() - e.lastFetchTime < ue
```

#### 4.5.1 本 HAR 内可见的三代令牌

| 代次 | 生成时刻 | chat-requirements token | proof-token | turnstile | 被谁使用 |
|------|---------|------------------------|-------------|-----------|---------|
| 第 1 代（**来自登录 HAR**：`login[674]→[712]`，09:42:03~09:42:06）| 3084 字符，`…qz05u…`，Fernet ts `1791970926` | 673 字符，`[3]`=11，指纹时间 `17:42:04` | 1740 字符（key `70.41`，24 项探针）| **`[4]`（"你好"这条消息）**，三值**逐字节相同** |
| 第 2 代（本 HAR 可见）| 09:43:35（prepare `[27]`）~ 09:43:41（finalize `[31]`）| 3064 字符，`…qz07O…`，ts `1791971022` | 725 字符，`[3]`=40，时间 `17:43:41` | 1828 字符 | **图片会话 `[8]`**（另一个 HAR）|
| 第 3 代 | 09:44:39 ~ 09:44:41（图片 HAR `[12]/[14]`）| 3084 字符，ts `1791971081` | 681 字符，`[3]`=13，时间 `17:44:39` | 1756 字符（key `90.31`，22 项）| 未被使用（后台预刷新）|
| 第 4 代 | 10:44:13（**补充抓包** `[10]/[11]`）| 3172 字符，ts `1791974573` | 709 字符，`[3]`=16，时间 `18:44:13` | 1796 字符（key `64.8`，23 项）| 该抓包的 `[6]` 对话请求 |
| 第 5 代 | 11:00:22 ~ 11:00:23（**图片敏感抓包** `[3]/[4]`）| 3084 字符，ts `1791975623` | 645 字符 | 1772 字符（key `97.63`，21 项）| **被多轮抓包的 turn 1 复用**（11:05:27，距签发 5 分 4 秒）|
| 第 6 代 | 11:05:26 ~ 11:05:27（**多轮抓包** `[3]/[4]`）| 3172 字符 | 669 字符（`[3]`=30，diff `069c35`）| 1824 字符（key `31.99`，23 项）| **该抓包 turn 2**（`[10]`）|
| 第 7 代 | 11:05:45 ~ 11:05:47（**多轮抓包** `[11]/[12]`）| 3128 字符 | 701 字符（`[3]`=0，diff `0640d7`）| 1744 字符（key `3.74`，22 项）| **无人使用**（第 3 轮未在抓包内发送）|

**"跨抓包复用"实测汇总**（三代都做了逐字节比对）：

```
图片敏感[4].token  == 多轮[1].chat-req-token      ? True   (3084, 相距 5 分 4 秒)
图片敏感[4].proof  == 多轮[1].proof-token         ? True   (645)
图片敏感[4].turnst  == 多轮[1].turnstile-token     ? True   (1772)
多轮[4].token      == 多轮[10].chat-req-token     ? True   (3172, 同抓包内相邻两轮)
多轮[12].token     == 任何发送请求                 ? 未被使用 (3128)
```

**三代令牌的逐字节比对（已实测）**：

```
[4].chat-req  == [31].resp.token       ? False      (3084 vs 3064, ts 09:42:06 vs 09:43:42)
[4].proof     == [31].req.proofofwork  ? False      (673 vs 725, 17:42:04 vs 17:43:41)
[4].turnstile == [31].req.turnstile    ? False      (1740 vs 1828)
[8].chat-req  == [31].resp.token       ? True       ✅
[8].proof     == [31].req.proofofwork  ? True       ✅
[8].turnstile == [31].req.turnstile    ? True       ✅
```

#### 4.5.2 结论

1. **`[4]` 用的是约 90 秒前（09:42:04）缓存下来的旧令牌** —— 那一轮发生在本 HAR 开始录制之前，但**已被 `chatgpt_login.har` 完整记录**（`[674]` 挑战 → `[712]` finalize，三值逐字节相同），因此挑战参数与 PoW 都可在登录文档中复算。
2. **`[27]→[31]` 这一轮是为"下一条消息"提前刷新的**：它在 `[4]` 发出之后 0.6 秒才发起（`[4]` 09:43:35.648 发出，`[27]` 09:43:35.9 才响应、`[31]` 09:43:41 完成），因此 `[4]` 不可能用上它。该轮会话在这里**没有发送第二条消息**，所以第 2 代令牌在本 HAR 中"看似没用上"。
3. 但**图片 HAR 的 `[8]` 恰好逐字节复用了第 2 代令牌**（09:44:36 发出，距签发 55 秒，仍在 540 秒 TTL 内）—— 说明令牌缓存是**浏览器配置级（跨页面/跨会话）共享**的，而不仅是当前页面的局部状态。

> 这三点共同验证了 SDK 源码里的缓存模型（`ue = 540000 ms`）：**Sentinel 令牌是"人/会话级"凭证**，540 秒内跨页面、跨对话复用；页面会顺手做后台预刷新，但不保证用得上。

#### 4.5.3 跨 HAR 复用明细（第 2 代令牌 → 图片会话）

| 令牌 | 本 HAR 第 2 代（`[31]`）| 图片 HAR `[8]` 实际使用 | 图片 HAR 自己刷新的第 3 代（`[14]`）| 是否复用 |
|------|--------------|----------------------|--------------------------|---------|
| chat-requirements token | `gAAAAABqz07O3vK_IPNlTkVC…`（3064）| **完全相同**（3064）| `gAAAAABqz08JPujoUD_EG_h1…`（3084）| ✅ 复用 |
| proof-token | `…MCwwLDBd~S`（725）| **完全相同**（725）| `…LDAsMF0=~S`（681）| ✅ 复用 |
| turnstile-token | `SRUZABkGAQw…`（1828）| **完全相同**（1828）| `QhIcBB8IBQwJE3piGmtwTnVk…`（1756）| ✅ 复用 |

即：**同一浏览器配置内，chat-requirements 令牌在 540 秒内被跨页面复用**（图片会话 09:44:36 发出的请求，复用了 09:43:42 签发的令牌），客户端同时**并行发起**了自己的 `prepare/finalize` 刷新（图片 HAR `[12]/[14]`，09:44:39~41，但它当晚于 `[8]` 0.6 秒才开始）。这解释了真实用户连续操作时 Sentinel 请求并不频繁的现象，也说明**该令牌是"人"级凭证而非"请求"级凭证**。

### 4.6 传输层鉴权：Cookie + Bearer 双凭据

> **重要更正**：本文早期版本依据本文件（脱敏版 HAR）得出"`Authorization` = 0 → Web 端不使用 Bearer Token"。补充抓包 **`chatgpt_chat_包含敏感数据.har`**（20 条，含敏感数据）证明这是**导出工具脱敏造成的误判**：该抓包里 **14/14 条 `/backend-api/*` 请求同时携带 Cookie 与 `Authorization: Bearer <RS256 OIDC 访问令牌>`**（2076 字符，`iss=https://auth.openai.com`，`scp` 与登录时申请的 scope 一致，`exp` 10 天）。

* 本文件（脱敏版）中 `Authorization`、`Cookie` 均被裁掉 → **不能**用"头不存在"推断"客户端没发"；
* 补充抓包中另可见 **22 个 Cookie**（含分片的 `__Secure-next-auth.session-token.0/.1`、`cf_clearance`、Sentinel 自己下发的 `oai-sc`）与 `Set-Cookie` 动态；
* 完整的 JWT claims 拆解、Cookie 清单与属性、`oai-sc` 说明见 `01` 文档 **§4.12**（已按补充抓包重写）。

**仍然成立的部分**：`/backend-api/me`（`[25]`）返回的 `amr` 字段把登录方式写在了响应里，可与 `01` 的登录流程互相印证：
* `[25]` 的 `amr` 字段直接把登录方式写在了响应里，可与 `01` 文档的登录流程互相印证：

```json
{ "object": "user", "id": "user-LkCB8RihStg7myaLj2HRube6",
  "email": "logo-pie2i@icloud.com", "name": "William Smith",
  "created": 1791345899, "mfa_flag_enabled": true,
  "amr": ["pwd", "urn:openai:amr:password", "otp", "mfa", "urn:openai:amr:otp_totp"],
  "email_domain_type": "social", "ads_segment_id": 8682,
  "orgs": { "data": [ { "id": "org-E6aE4dHgK96ZTkDnmLiKkcQz", "title": "Personal", "personal": true, "is_default": true, "role": "owner" } ] } }
```

> `amr` 里的 `otp` / `urn:openai:amr:otp_totp` 与登录 HAR `entry 627` 的 `mfa/verify`（`type: totp`）**完全对应** —— 这是"登录流程"与"业务会话"之间最强的闭环证据。

### 4.7 配额与风控可见面

| 端点 | 证据 | 内容 |
|------|------|------|
| `[29] conversation/init` | 响应 729 字节 | `limits_progress`：`deep_research` 余 5、`file_upload` 余 15、`paste_text_to_file` 余 3、**`image_gen` 余 24**、`reason` 余 44（各自带 `reset_after`）；`default_model_slug: auto`；`file_attachment_limits.max_size_mb: 512` |
| `[41] wham/usage` | 响应 939 字节 | `plan_type: "free"`、`rate_limit.allowed: true`、主窗口 2592000 秒（30 天）、`credits.has_credits: false` |
| `[42] wham/tasks/list` | 响应 35 字节 | 空任务列表 |
| `[0] system_hints` | 响应 3250 字节 | 可用工具清单（如 `plugin:connector_openai_deep_research`，含 `required_features`/`required_models`/`required_conversation_modes`）→ **工具是否可用由服务端下发的清单决定，不在请求体里声明** |

> `[0]` 与图片 HAR 的 `[10]` 是同源机制：**客户端不提交"我要用哪个工具"，而是服务端根据 feature 开关自主决定**。这解释了为何生图请求体里看不到任何 image_gen 字段（见 `03` §4.6）。

### 4.8 反滥用与遥测（简要）

* **Cloudflare**：所有响应带 `cf-ray: *-LHR`、`cf-cache-status: DYNAMIC`、`nel`/`report-to`；SSE 响应额外带 `s-cf-origin-ttfb-msec`/`s-cf-quic-rtt-msec`/`s-cf-tcp-rtt-msec`/`s-sa-server-ttfb-msec` 时延回执。
* **`oai-echo-logs`**：日志采样点位协商（见 §3 表）。
* **Statsig**（`[40]` 等）：`/ces/v1/rgstr?k=client-sYWqzCYMRkUg4DqqiZcR5DGTNl2iD7zNJY0HoeDLzxR&st=javascript-client-react&sv=3.34.0&t=…&sid=…`（性能/特性遥测）。
* **Datadog**（`[39]`）：`/ces/v1/telemetry/intake?ddforward=…dd-api-key=pub1f79f8ac903a5872ae5f53026d20a77c…`。
* 上述遥测**不参与鉴权**，但其请求同样携带 `chatgpt-account-id`（可用于关联审计）。

---

## 5. 字段速查表

| 字段/头 | 出现位置 | 来源 | 作用 | 可伪造 |
|---------|---------|------|------|--------|
| `chatgpt-account-id` | 所有业务请求头 | 服务端（`[670] accounts/check` 一类接口下发）| 租户隔离 | 需与会话匹配 |
| `oai-did` | 所有业务请求头 | 客户端 cookie | 设备识别 | ✅ |
| `x-oai-turn-trace-id` | prepare + conversation | 客户端生成 | 串联一轮 turn | ✅ |
| `openai-sentinel-chat-requirements-token` | conversation 头 | `finalize` 响应 | **准入凭证**（540 s）| ❌ Fernet |
| `openai-sentinel-proof-token` | conversation 头 | 客户端 PoW | 工作量证明 + 指纹 | ✅ 算法已还原 |
| `openai-sentinel-turnstile-token` | conversation 头 | 客户端 XOR | **环境探针答案表**（键=`探针号.答案号`），非 CF 令牌 | ✅ 密钥可由已知明文推导 |
| `x-conduit-token` | prepare 响应 / conversation 请求+响应 | 服务端签名 JWT | 后端实例粘滞（60 s）| ❌ ES256 |
| `p` | prepare 请求体 | 客户端 | 指纹（`gAAAAAC`+b64）| ✅ |
| `prepare_token` | prepare 响应 → finalize 请求 | 服务端 Fernet | 挑战会话票据 | ❌ |
| `proofofwork` | finalize 请求 | 客户端 | PoW 答案 | ✅ |
| `turnstile` | finalize 请求 | 客户端 XOR | **环境探针答案表**（键=`探针号.答案号`），非 CF 令牌 | ✅ 密钥可由已知明文推导 |
| `so.collector_dx` | prepare 响应 | 服务端 | 行为采集要求 | — |
| `conduit_token` | prepare 响应体 / conversation 响应头 | 服务端 | 见上 | ❌ |
| `client_prepare_*` | prepare 请求体 | 客户端状态机 | 触发方式声明 | ✅ |
| `partial_query` / `messages` | prepare / conversation | 客户端 | 草稿 / 正式消息 | ✅ |
| `oai-echo-logs` | conversation 头 | 客户端 | 日志回显协商 | ✅ |

---

## 6. 可复现性评估

| 环节 | 能否纯脚本复现 | 说明 |
|------|--------------|------|
| 三条 Sentinel 头的**前两条** | ✅ | 指纹构造 + PoW 算法完全还原；`chat-requirements-token` 需先成功调用 `finalize` |
| `prepare` 取挑战 | ✅ | 只需 `{"p": ...}` |
| `finalize` 换取 token | ⚠️ | 需要**有效的探针答案表**（`turnstile` 字段，格式与密钥推导已还原，见 `01` §4.8.1）+ 服务端 `prepare_token`；脚本环境可构造但需保证采集值自洽 |
| `conduit_token` | ❌ | ES256 服务端签名 |
| 会话 Cookie | ❌ | 需真实登录（登录链路含 Cloudflare + MFA，见 `01`）|
| **整体**：模拟一次对话 | ❌ | 卡在 Turnstile 与会话 Cookie |

**结论**：对话链路的客户端可复现部分（指纹 + PoW）已被完整还原；真正的门槛是 **Turnstile 令牌**（必须在真实浏览器里取得）与**会话 Cookie**。这也是"用脚本直接调 `/backend-api/f/conversation`"必须借助真实浏览器上下文的原因。

---

## 7. 不确定与待验证

1. **SSE 正文未落盘** → 本文件无法取证助手回复的文本、`conversation_id` 的下发时机、工具调用；只有 23 条无载荷事件的**时间戳**可用（§4.1）。**事件级结构已由补充抓包补齐**（`03` §4.7.1：12 个事件、JSON-Patch 式 `delta`、`resume_conversation_token`、图片指针在 `delta` 事件中下发）。
2. **会话 Cookie 名称与属性不可见**：无法确认是否为 `__Secure-next-auth.session-token`（该字符串在三个 HAR 原始文本中均 0 次出现）；`[38]/[40]` 的遥测体内虽证明了 `DeviceId = stableID = WebAnonymousCookieID = 57cab66a-…`（即 `oai-did`）与 `account_id = workspace_id = edebbcbb-…`（即 `chatgpt-account-id`）的对应关系，但**这两个标识的 cookie 名仍未出现**。
3. **`so`（Session Observer）的消费路径未闭合**：`prepare` 要求 `so.required=true` 并下发 `collector_dx`，但 `finalize` 只提交三项；推测存在独立的旁路上报（可能走 `sessionObserverToken()` 或在后续请求的 `x-*` 头中），**未验证**。
4. **`conduit_token` 是否在某些风控档位下变为强制**：本 HAR 证明"不带也能成功"，但无法排除高风控账号下的强制要求。
5. **三条 Sentinel 头是否都强制**：本次全部携带；缺少任一条时的服务端行为未观测到（无法主动构造反例）。
6. **`x-oai-turn-trace-id` 与 `oai-echo-logs` 点位的语义**属推断（前者确为 turn 级关联 id —— 同值出现在 `[1]/[4]/[34]` 并被回显进 `[39]` 的 Datadog 请求体作为 `turn_trace_id`；后者为采样指令）。
7. **`persona` 等级与挑战强度的映射**：本账号为 `free`，`persona=chatgpt-freeaccount`。**补充证据（10 个样本）**：跨 6 份抓包的 `difficulty` 全部落在 **2.38% ~ 2.98%**（均值 2.75%，取值集合 {`061a80`,`069c35`,`069cee`,`06b983`,`0640d7`,`07a120`×5}）→ **没有观察到按账号/按轮次自适应的迹象**，更像"固定带宽内随机"。付费账号是否更高仍未验证。
8. **第 1 代令牌的来源已确认**（`chatgpt_login.har [674]/[712]`，三值逐字节相同），但其**XOR 密钥的生成规则**未确认（密钥 `70.41` 在 HAR 原文中检索不到，见 `01` §4.8.1 与 §7）。
9. **`_eventSourceMessages` 中 `eventId` 全部为空串**，因此无法把事件与消息 id 关联。
10. **本 HAR 存储的前端 JS 里搜不到 Sentinel 相关字符串**（`openai-sentinel-*`、`chat-requirements`、`fnv`、`murmur` 等 0 命中），发起 `[4]` 的 `399565.e8fa4b686e.js` 等 18 个 bundle **未被采集** → **本文件无法自证** SDK 源码结论，那些结论依赖登录 HAR 中抓到的 `sentinel sdk.js`（见 `01` §4.7）。

---

## 8. 附录：关键证据索引

| entry | 方法 | 状态 | URL | 价值 |
|-------|------|------|-----|------|
| 0 | GET | 200 | `/backend-api/system_hints?exclude_logo=true&mode=plugins` | 服务端下发的工具清单 |
| **1** | POST | 200 | `/backend-api/f/conversation/prepare` | 草稿预发送 + **conduit_token 签发** |
| **4** | POST | 200 | `/backend-api/f/conversation` | **三条 Sentinel 头 + turn-trace + echo-logs + 请求体；SSE 未落盘** |
| 25 | GET | 200 | `/backend-api/me` | **会话有效的直接证据 + `amr` 回显登录方式** |
| 26 | GET | 200 | `/backend-api/settings/is_adult` | 账号设置 |
| **27** | POST | 200 | `/backend-api/sentinel/chat-requirements/prepare` | **对话侧挑战（含 `so`）** |
| 29 | POST | 200 | `/backend-api/conversation/init` | 配额/限制清单 |
| **31** | POST | 200 | `/backend-api/sentinel/chat-requirements/finalize` | **准入 token 换取** |
| 34 | POST | 200 | `/backend-api/f/conversation/prepare` | 次轮 prepare（带 conversation_id）|
| 36/37 | GET | 200 | `/backend-api/conversations?...` | 会话列表（含 `conversation_id`）|
| 41/42 | GET | 200 | `/backend-api/wham/usage`、`/wham/tasks/list` | 计划与用量 |
| 38~40 | POST | 202 | `/ces/v1/*` | 遥测（噪声）|

### 复现本文结论所用的方法（可审计）

1. 全量扫描 43 条请求的头部集合，统计 `chatgpt-account-id`/`oai-did`/`openai-sentinel-*` 等的出现次数与取值；
2. 对 `[1]/[4]/[27]/[31]` 逐条 dump 完整请求体与响应体；
3. 解析 `[1]` 的 `conduit_token`（JWT 三段 base64url 解码）取出 `conduit_uuid`/`conduit_location`/`cluster`/`iat`/`exp`；
4. 复算 `[27]→[31]` 的 PoW：`H(seed + 载荷)` 前缀比对（命中）；
5. **逐字节比对矩阵**（本节结论的关键步骤）：
   * `[4]` 的三条头 vs `[31]` 的请求体/响应体 → **全部不等**（长度 3084/673/1740 vs 3064/725/1828，Fernet 内嵌时间戳 09:42:06 vs 09:43:42）→ 得出"`[4]` 用的是上一轮缓存令牌"；
   * `chatgpt_generate_image.har [8]` 的三条头 vs 本 HAR `[31]` 的请求体/响应体 → **全部逐字节相同** → 得出"第 2 代令牌被图片会话复用"；
   * 解码每条 proof-token 的载荷，读取其 `[1]` 时间字符串与 `[3]` 计数器，用于给每代令牌定位时间（`17:42:04`/`17:43:41`/`17:44:39`）；
   * 解析每条要求令牌的 Fernet 头（版本 `0x80` + 4 字节 0 + 4 字节大端时间戳），用于核对签发时刻。
6. `Authorization`/`Cookie` 在本文件（脱敏版）的出现次数统计（各 0 次）—— **该步骤只能证明"本文件没记录"，不能证明"客户端没发送"**；后续依据补充抓包 `chatgpt_chat_包含敏感数据.har` 做了更正（§4.6）；
7. 提取 `[4]._eventSourceMessages` 统计 SSE 事件名与时间范围（23 条、`delta`×15/`message`×8）。

> 本文所有数值与 Base64/JSON 片段均直接取自 HAR 原文；标注「推断」「待验证」的条目为逻辑推理，未获直接证据。
>
> **勘误记录**：本文初稿曾把 `[4]` 携带的三条 Sentinel 头误认为与 `[31]` 新签发的那一套相同（仅凭 `gAAAAAB` 前缀与"值看起来很长"就下了结论）。经逐字节比对后已全部纠正 —— 这也说明此类分析中**前缀相同不代表值相同**，必须做完整比较。
