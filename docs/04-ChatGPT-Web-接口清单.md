# ChatGPT Web 端接口清单（对话 / 生图 全链路 API 参考）

> 本文是 `01`~`03` 三份 HAR 分析文档的**索引化补充**：把散落在各文档"逐请求 dump"里的接口，整理成一张可直接照着调用的清单。
> 覆盖对象：`chatgpt.com` 的 **Web 前端接口**（不含 Platform API `api.openai.com`）。
> 证据来源：4 份抓包 —— `chatgpt_login.har`（L）、`chatgpt_chat.har`（C）、`chatgpt_generate_image.har`（I）、以及两份含敏感数据的补充抓包 `chatgpt_chat_包含敏感数据.har`（CS）、`chatgpt_image_包含敏感数据.har`（IS）。
> 所有"证据"列都写成 `文件[entry]` 形式，可回原文件核对。

---

## 0. 先看这张图：一次"发送消息"到底经过哪些接口

```
                    ┌─────────────── 认证层（每个 /backend-api/* 请求都要）───────────────┐
                    │ ① Cloudflare：cf_clearance / __cf_bm（边缘层，人机校验通过后才有）  │
                    │ ② 会话层：Cookie(__Secure-next-auth.session-token.0/.1)             │
                    │         + Authorization: Bearer <OIDC RS256 JWT>                    │
                    │ ③ 准入层：openai-sentinel-chat-requirements-token                   │
                    │         + openai-sentinel-proof-token + openai-sentinel-turnstile-token │
                    └─────────────────────────────────────────────────────────────────────┘

 ① GET  /backend-api/accounts/check/v4-2023-04-27      ← 账号/能力开关（image_gen_tool_enabled 等）
 ② POST /backend-api/f/conversation/prepare            ← 草稿预发送，拿 conduit_token（可选）
 ③ POST /backend-api/f/conversation                    ← ★ 真正发送（SSE 流式返回）
 ④ POST /backend-api/sentinel/chat-requirements/prepare  ← 准入挑战（通常与 ③ 并行/之后）
 ⑤ POST /backend-api/sentinel/chat-requirements/finalize ← 换取准入令牌（540 秒有效）
 ⑥ POST /backend-api/conversation/init                 ← 会话初始化 / 配额
 ⑦ GET  /backend-api/conversations/<id>                ← 取回消息树（生图时在这里发现资产指针）

 —— 生图特有（拿到 sediment:// 指针之后）——
 ⑧ GET  /backend-api/files/download/file_<id>?conversation_id=...   ← 换签名 URL
 ⑨ GET  /backend-api/estuary/content?id=...&sig=...                 ← 下载图片字节
```

**一句话结论：生图没有独立接口。** 它复用 ③ `POST /backend-api/f/conversation`，用户在 `messages[].content.parts` 里只发文本；是否调用图像工具由**服务端**依据 `image_gen_tool_enabled` 开关 + 意图决定（证据：`IS[1]` 请求体无任何 `tools`/`image_gen`/`dalle` 字段，但 SSE 事件 7 返回了图片资产指针）。生图"特有"的只有 ⑧⑨ 两个**取图**接口。

---

## 1. 认证层：每个接口需要哪一层？

| 接口族 | CF 边缘 | Cookie+Bearer | Sentinel 三件套 |
|--------|:------:|:-------------:|:---------------:|
| `f/conversation`（发消息，含生图） | ✅ | ✅ | **✅ 必需** |
| `f/conversation/prepare` | ✅ | ✅ | ❌ |
| `sentinel/chat-requirements/{prepare,finalize}` | ✅ | ✅ | ❌（它自己就是发令牌的）|
| `conversation/init`、`conversations*`、`me`、`accounts/check`、`system_hints`、`wham/*` | ✅ | ✅ | ❌ |
| `files/download/file_<id>` | ✅ | ✅ | ❌ |
| `estuary/content` | ✅ | ✅（仅 `chatgpt-account-id` + `originator`，**不带 `oai-did`**）| ❌（授权靠 URL 里的 `sig`）|

* 证据：`CS` 全量 14 条 `/backend-api/*` 均带 `authorization: Bearer …`（2076 字符 RS256 JWT）+ 23 个 Cookie；`I[24]/[27]` 的 estuary 请求头集合明显更窄。
* 三层的关系见 `01` 文档 §4.3（Cloudflare）、§4.12（Cookie+Bearer）、§4.13（Cookie 全生命周期）、§4.6~4.8（Sentinel）。

**三个域、三套互不相通的 Cookie 罐**（`01` §4.13.1，依据 LS 抓包实测）：

| 域 | Cookie 数 | 代表 | 备注 |
|----|:--------:|------|------|
| `chatgpt.com` | 22~25 | `__Secure-next-auth.session-token.0/.1`、`cf_clearance`(.chatgpt.com)、`oai-sc`(.chatgpt.com)、`oai-client-session-epoch` | 业务接口的会话凭据在这里 |
| `auth.openai.com` | 15 | `auth-session-minimized`、`__Host-usc_*`、`oai-login-csrf_dev_*`、`cf_clearance`(.auth.openai.com)、`oai-sc`(.openai.com) | **只在登录过程中存在**，MFA 成功后部分被清空 |
| `sentinel.openai.com` | 5 | `oai-did`、`oaicom-stable-id`、`oai-sc`、`__cflb`、`__cf_bm` | 挑战 iframe 自己的罐 |

⚠️ **两张 `cf_clearance` 不可互换**：属性含 `Partitioned`（CHIPS），按顶层站点分区绑定。

---

## 2. 对话链路接口

### 2.1 `POST /backend-api/f/conversation/prepare` —— 草稿预发送

| 项 | 内容 |
|----|------|
| 作用 | 输入过程中/上下文变化时"预热"，返回后端实例票据 `conduit_token`（60 秒）|
| 认证 | Cookie + Bearer（**不需要** Sentinel 三件套）|
| 证据 | `C[1]`、`C[34]`、`I[7]`、`I[20]`、`IS[0]`、`IS[12]` |

**请求体字段**（`C[1]` 实测 640 字节）：

| 字段 | 类型 | 来源 | 说明 |
|------|------|------|------|
| `action` | `"next"` | 客户端固定 | 动作类型 |
| `is_do_not_remember` | bool | 客户端 | 是否不记忆 |
| `model` | `"auto"` | 客户端 | 模型 slug，实测恒为 `auto` |
| `parent_message_id` | string | 客户端 | 首轮 `"client-created-root"`；次轮为服务端消息 id |
| `timezone` / `timezone_offset_min` | `"Asia/Shanghai"` / `-480` | 客户端 | 时区 |
| `client_contextual_info` | object | 客户端 | `{app_name, app_surface, has_web_push_capabilities, web_push_notification_permission}` |
| `local_function_names` | string[] | 客户端 | 实测 `["local.continue_in_work"]` |
| `supported_encodings` | string[] | 客户端 | `["v1"]` |
| `client_prepare_state` | `"sent"` | 客户端状态机 | prepare 阶段的状态 |
| `partial_query` | object | 客户端 | 草稿：`{id, author:{role}, content:{content_type:"text", parts:["你"]}}`；无草稿时省略（`C[34]`）|
| `client_prepare_dispatch` | `"debounced"` | 客户端 | 触发方式（防抖）|
| `client_prepare_source` | `"context_change"` | 客户端 | 触发源 |
| `conversation_id` | string | 服务端 | 仅次轮出现（`C[34]`）|

**响应**（385 字节）：`{"status":"ok","conduit_token":"<ES256 JWT, 60s>"}`

### 2.2 `POST /backend-api/f/conversation` —— 发送消息（SSE）★核心

| 项 | 内容 |
|----|------|
| 作用 | 发送一轮消息，流式返回结果；**生图也走这里** |
| 认证 | Cookie + Bearer + **三条 `openai-sentinel-*` 头（必需）** |
| 证据 | `C[4]`、`I[8]`、`IS[1]`、`IS[6]` |

**请求头**（完整必需集）：

| 头 | 必需 | 值来源 |
|----|:----:|--------|
| `authorization` | ✅ | `Bearer <OIDC 访问令牌>`（登录时获取，10 天有效）|
| `chatgpt-account-id` | ✅ | 账号 ID（`accounts/check` 下发）|
| `oai-did` | ✅ | `oai-did` cookie |
| `oai-language` | ✅ | `zh-CN` |
| `originator` | ✅ | `Codex Browser`（官方网页端另有取值）|
| `x-openai-web-frontend` / `x-openai-codex-window-type` | ✅ | `codex_webview` / `browser` |
| `x-oai-mcp-form-version` | ✅ | `2` |
| **`openai-sentinel-chat-requirements-token`** | **✅** | `chat-requirements/finalize` 返回的 `token`（Fernet，540 s）|
| **`openai-sentinel-proof-token`** | **✅** | 客户端 PoW：`"gAAAAAB" + b64(25 字段指纹) + "~S"` |
| **`openai-sentinel-turnstile-token`** | **✅** | 客户端采集答案表：`base64(XOR(JSON, 密钥))` |
| `x-conduit-token` | ❌ 可选 | `prepare` 响应（60 s）；实测"有则带"（`I[8]` 带、`C[4]` 未带）|
| `x-oai-turn-trace-id` | ⭕ | 客户端生成，串联本轮 prepare/send |
| `oai-echo-logs` | ⭕ | 日志回显点位协商 |
| `content-type` | ✅ | `application/json` |

**请求体字段**（`C[4]` 816 字节 / `IS[1]` 837 字节）：

| 字段 | 说明 |
|------|------|
| `turn_attribution` | `{"turn_trigger":"composer"}` |
| `action` / `is_do_not_remember` / `model` / `parent_message_id` / `timezone` / `timezone_offset_min` | 同 §2.1 |
| `client_contextual_info` / `local_function_names` / `supported_encodings` | 同 §2.1 |
| `messages` | **消息数组**（见下）|
| `genui_state_snapshots` | `[]` |
| `client_prepare_state` | `"sent"`（prepare 未回）或 `"success"`（prepare 已完成）|
| `conversation_mode` / `tools` / `*_token` / checksum | **不存在** —— 生图也无需声明 |

`messages[]` 元素（客户端构造）：

```json
{ "id": "<客户端生成的 UUID>",
  "author": { "role": "user", "name": null, "metadata": {} },
  "content": { "content_type": "text", "parts": ["生成一张有关于地球的图片"] },
  "create_time": 1791971075.997,
  "recipient": "all", "status": "finished_successfully",
  "end_turn": null, "weight": 1, "channel": null, "metadata": {} }
```

**多轮对话的 id 链**（`chatgpt_多轮对话_包含敏感数据.har` 三轮实测）：

| 轮次 | `conversation_id` | `parent_message_id` |
|------|------------------|--------------------|
| 第 1 轮 | `null` | `"client-created-root"`（客户端占位符）|
| 第 2 轮 | `6acf61f9-1a10-83e8-ab8b-d322445bc4af`（服务端在首轮 SSE 里下发）| `8d6dea6b-…`（**首轮助手消息 id**，同由服务端下发）|
| 第 3 轮准备 | 同上 | `7eed8666-…`（**第 2 轮助手消息 id**）|

即：客户端只负责生成**用户消息的 id**；`conversation_id` 与后续 `parent_message_id` 都从 SSE 流里取（对应 `03` §4.7.1 的事件 2 与事件 7）。

**响应**：`200` + `text/event-stream`，**12 个事件**（结构详见 `03` §4.7.1）：

| # | event | 载荷 |
|---|-------|------|
| 0 | `delta_encoding` | `"v1"` |
| 1 | — | `resume_conversation_token`（ES256 JWT，4 小时续传票据，含 `turn_topic_id`）|
| 2 | `delta` | `p:"" o:"add"` 追加 `model_editable_context` 消息 + `conversation_id` |
| 3 | — | `message_marker` |
| 4 | `delta` | `o:"add"` 追加助手 `code` 消息（`{"skipped_mainline":true}`，工具信封）|
| 5 | `delta` | `p:"/message/status" o:"replace" v:"finished_successfully"` |
| 6 / 8 | — | `title_generation`（自动标题）|
| **7** | **`delta`** | **`o:"add"` 追加 `tool` 消息 → `content_type:"multimodal_text"` → `image_asset_pointer` + `sediment://file_<id>`** ← 生图产物在此下发 |
| 9 | — | `server_ste_metadata` |
| 10 | — | `message_stream_complete` |
| 11 | — | `[DONE]` |

> 事件语义是 **JSON-Patch 风格**：`p`=目标路径（空=追加到消息数组）、`o`=操作（`add`/`replace`）、`v`=值、`c`=序号。

### 2.3 `POST /backend-api/conversation/init` —— 会话初始化 / 配额

**请求**（`C[29]`，172 字节）：`{"conversation_id":null,"conversation_origin":null,"gizmo_id":null,"requested_default_model":null,"system_hints":null,"timezone":"Asia/Shanghai","timezone_offset_min":-480}`

**响应**（729 字节）：`{"type":"conversation_detail_metadata","banner_info":null,"blocked_features":[],"model_limits":[],"limits_progress":[{"feature_name":"image_gen","remaining":24,"reset_after":"…"},…],"default_model_slug":"auto","file_attachment_limits":{"max_size_mb":512}}`

### 2.4 `GET /backend-api/conversations` —— 会话列表

```
GET /backend-api/conversations?exclude_conversation_origin=tpp&expand=false&hide_snorlax=false
    &is_archived=false&is_starred=false&limit=20&order=updated&offset=0
GET /backend-api/conversations?conversation_origin=tpp&expand=false&hide_snorlax=false   ← TPP 另一类会话
```
证据：`C[36]/[37]`、`I[21]/[22]`、`IS[10]/[11]`。注意 `conversation_origin=tpp` 与 `exclude_conversation_origin=tpp` 是**两次不同查询**。

### 2.5 `GET /backend-api/conversations/<conversation_id>` —— 会话详情（消息树）

```
GET /backend-api/conversations/6acf60c6-6674-83e8-9c87-0473a4687643?num_turns=10&include_has_versions=true
```
证据：`I[23]`、`IS[6]/[9]`。返回顶层 34 个字段（`title`/`create_time`/`default_model_slug`/`conversation_origin`/`is_temporary_chat`/`memory_scope`/`disabled_tool_ids`/`messages[]`/`current_node`/…），其中 `messages[]` 角色依次为 `user` → `assistant(model_editable_context)` → `assistant(code, recipient=工具内部名)` → `tool(multimodal_text)`。

---

## 3. 生图链路接口（取图专用）

### 3.1 `GET /backend-api/files/download/file_<file_id>` —— 换取签名下载 URL

```
GET /backend-api/files/download/file_000000003218824383bf262ec925b22e
    ?conversation_id=6acf60c6-6674-83e8-9c87-0473a4687643
    &download_intent=false&inline=true[&include_library_file_state=true]
```

**响应**（414 字节）：

```json
{ "status": "success",
  "download_url": "https://chatgpt.com/backend-api/estuary/content?id=file_000000003218824383bf262ec925b22e&ts=497771&p=fsns&cid=1&sig=69d9f1e1ba3b4eed153dbe6da8ffd7ef3414ad767b7474305121d140298d9b22&v=0",
  "file_name": "user-<user>/3ad7ad8b-89a3-4e12-ac8b-9c9edfdbcce2.png",
  "file_size_bytes": 2854094 }
```

* `include_library_file_state=true/false` 两版响应**完全相同**（`I[19]` vs `I[26]`）→ 该参数不影响签名。
* 证据：`I[19]/[26]`、`IS[7]/[13]`。

### 3.2 `GET /backend-api/estuary/content` —— 用签名 URL 下载字节

```
GET /backend-api/estuary/content?id=<file_id>&ts=<n>&p=fsns&cid=1&sig=<64位hex>&v=0
```

| 参数 | 含义 | 备注 |
|------|------|------|
| `id` | 文件 ID | = `sediment://` 指针去掉 scheme |
| `ts` | **非时间戳** | `497769` → 17 分钟后 `497771`（+2）→ 更像全局单调计数（推断）|
| `p` | `fsns` | 存储命名空间标记（推断）|
| `cid` | `1` | 容器/集群序号（推断）|
| `sig` | 64 位十六进制 = 32 字节 | **服务端签发的 HMAC**；同参数下**确定性**（`I[19]`/`I[26]` 两次签发完全相同），客户端零计算 |
| `v` | `0` | 签名版本 |

**响应**：`200 image/png`（实测 2,897,667 / 2,854,094 字节，1254×1254，含 C2PA `jumb` box）；带 `etag`，复取可 `304`。
**请求头特殊**：只带 `chatgpt-account-id` + `originator`（**不带** `oai-did`/`oai-language`/`x-openai-web-frontend`）→ 授权模型是"签名 URL"而非会话头。
证据：`I[24]/[27]`、`IS[8]/[14]`。

### 3.3 `/backend-api/estuary/*` 其它动作（**本次未抓到**）

上传/写库等接口在 4 份抓包里都没出现（只抓到 `content` 下载）——若需要，得抓一次**文件上传**流程。

---

## 4. Sentinel 准入接口（两条链路）

### 4.1 对话链路（chatgpt.com）

```
POST /backend-api/sentinel/chat-requirements/prepare
     body: {"p":"gAAAAAC"+base64(25字段指纹数组)}          ← 无 id/flow 字段
     resp: {persona, prepare_token(Fernet), turnstile:{required,dx}, proofofwork:{required,seed,difficulty},
            so:{required, collector_dx[, snapshot_dx]}}

POST /backend-api/sentinel/chat-requirements/finalize
     body: {prepare_token, proofofwork:"gAAAAAB"+b64(指纹,[3]=计数器)+"~S", turnstile:"base64(XOR(答案JSON,密钥))"}
     resp: {persona, token(Fernet, 540 s), expire_after:540, expire_at}
     → 该 token 即请求头 openai-sentinel-chat-requirements-token
```
证据：`C[27]/[31]`、`I[12]/[14]`、`L[674]/[712]`、`CS[10]/[11]`、`IS[3]/[4]`。
算法（PoW / 指纹 / 答案表）见 `01` §4.5~§4.7 与 §4.8.1。

### 4.2 登录链路（auth.openai.com + sentinel.openai.com）

```
POST https://sentinel.openai.com/backend-api/sentinel/req
     body: {"p":"gAAAAAC"+b64(指纹), "id":"<oai-did cookie>", "flow":"password_verify"}
     resp: {persona:"chatgpt-noauth", token(Fernet), expire_after:540, turnstile:{required,dx},
            proofofwork:{required,seed,difficulty}}
     → 组装请求头 openai-sentinel-token: {"p":答案,"t":答案表,"c":resp.token,"id":…,"flow":…}
       用在 POST https://auth.openai.com/api/accounts/password/verify
```
证据：`L[275]/[285]`、`L[440]/[449]`、`L[497]`。

---

## 5. 只读 / 辅助接口

| 接口 | 作用 | 关键响应字段 | 证据 |
|------|------|-------------|------|
| `GET /backend-api/accounts/check/v4-2023-04-27` | 账号 + **能力开关** | `account_id`、`plan_display_name`、features 含 **`image_gen_tool_enabled`** | `I[1]`、`L[670]/[796]/[817]` |
| `GET /backend-api/me` | 用户信息 | `id`、`email`、`amr`（登录方式）、`orgs` | `C[25]` |
| `GET /backend-api/settings/is_adult` | 成年标记 | — | `C[26]`、`CS[7]` |
| `GET /backend-api/models` | 可用模型清单 | — | `L[672]` |
| `GET /backend-api/system_hints?exclude_logo=true&mode=plugins` | **服务端下发的工具/提示清单** | `system_hints[]`（含 `required_features`/`required_models`）| `C[0]`、`I[10]`、`CS[0]` |
| `GET /backend-api/wham/usage` | 计划与额度 | `plan_type`、`rate_limit.*`、`credits.*` | `C[41]`、`I[30]`、`CS[19]`、`IS[18]` |
| `GET /backend-api/wham/accounts/check` | 账号状态 | — | `L[669]` |
| `GET /backend-api/wham/tasks/list?limit=20&task_filter=current` | 任务列表 | `{items:[],cursor:null}` | `C[42]`、`CS[18]` |
| `GET /backend-api/conversations/…`（见 §2.5）| — | — | — |
| `GET /backend-api/pins?item_type=conversation` | 置顶会话 | — | `L[823]` |
| `GET /backend-api/pageConfigs/billing` | 计费页配置 | — | `L[794]` |
| `GET /backend-api/beacons/home?product=chatgpt&selected_model_slug=auto&…` | 首页埋点 | — | `I[5]/[6]` |
| `GET /backend-api/celsius/ws/user` | WS 通道发现 | — | `L[725]` |
| `wss://ws.chatgpt.com/p6/ws/user/<user_id>?verify=<ts>-<sig>` | 长连接（带签名准入）| — | `L[792]` |
| `POST /backend-api/files/…`（上传）| **未抓到** | — | — |

---

## 6. 登录相关接口（`01` 文档的接口化摘要）

| 接口 | 作用 | 关键参数 | 证据 |
|------|------|---------|------|
| `GET /api/auth/providers` | NextAuth provider 列表 | — | `L[10]` |
| `GET /api/auth/csrf` | 取 CSRF | `csrfToken` | `L[11]` |
| `POST /api/auth/signin/openai?prompt=login&screen_hint=…&login_hint=…&auth_session_logging_id=…&ext-oai-did=…` | 发起 OAuth | body: `callbackUrl` + `csrfToken` + `json=true` | `L[12]` |
| `GET https://auth.openai.com/api/accounts/authorize?client_id=app_X8zY6vW2pQ9tR3dE7nK1jL5gH&scope=…&state=…&device_id=…&ccaps=…` | 授权端点（302）| `state` 服务端生成、无 PKCE | `L[13]` |
| `POST https://auth.openai.com/api/accounts/password/verify` | 校验密码 | body `{password}` + 头 `openai-sentinel-token` | `L[285]`(403 CF) / `L[449]`(200) |
| `POST https://auth.openai.com/api/accounts/mfa/issue_challenge` | 下发 MFA 挑战 | `{id,type:"totp",force_fresh_challenge}` | `L[489]` |
| `POST https://auth.openai.com/api/accounts/mfa/verify` | 校验 TOTP | `{id,type:"totp",code:"678799"}` | `L[627]` |
| `GET /api/auth/callback/openai?code=ac_…&state=…` | 回调换会话（302）| `code` 一次性 | `L[631]` |

---

## 7. 一次"生图"的完整调用示例（按真实抓包顺序，标注可伪造性）

```http
# ① 账号能力（决定能不能生图）
GET /backend-api/accounts/check/v4-2023-04-27
Cookie: …; Authorization: Bearer <OIDC JWT>          # ❌ 不可伪造（10 天有效）
→ features 含 "image_gen_tool_enabled"

# ② 会话预热（可选）
POST /backend-api/f/conversation/prepare
{"action":"next","model":"auto","parent_message_id":"client-created-root",
 "timezone":"Asia/Shanghai","timezone_offset_min":-480,"client_prepare_state":"sent",
 "partial_query":{"id":"<uuid>","author":{"role":"user"},"content":{"content_type":"text","parts":["生成一张地球图片"]}}}
→ {"status":"ok","conduit_token":"<ES256 JWT, 60s>"}   # ❌ 服务端签名

# ③ 发送（生图就走这里）
POST /backend-api/f/conversation
authorization: Bearer <OIDC JWT>                        # ❌
chatgpt-account-id: <account_id>                        # 需与会话匹配
oai-did: <device_id>                                    # ✅ 客户端可控
openai-sentinel-chat-requirements-token: gAAAAAB…        # ❌ 服务端 Fernet（540 s）
openai-sentinel-proof-token: gAAAAAB<b64(指纹,[3]=n)>~S  # ✅ 算法已还原，可本地生成
openai-sentinel-turnstile-token: <base64(XOR(答案,密钥))>  # ✅ 密钥可从密文推导，可本地生成
x-conduit-token: <60s JWT>                              # ❌（可选）
{"turn_attribution":{"turn_trigger":"composer"},"action":"next","model":"auto",
 "parent_message_id":"client-created-root","messages":[{…"parts":["生成一张地球图片"]…}],
 "client_prepare_state":"success", …}
→ 200 text/event-stream … 事件 7 里给出 sediment://file_<id>

# ④ 取图（两步）
GET /backend-api/files/download/file_<id>?conversation_id=<cid>&download_intent=false&inline=true
→ {"download_url":"https://chatgpt.com/backend-api/estuary/content?id=…&ts=…&p=fsns&cid=1&sig=…&v=0"}
GET  <上一步的 download_url>                              # ❌ sig 服务端签发，客户端算不出
→ 200 image/png (1254×1254, 含 C2PA)
```

**纯脚本可行性小结**：Sentinel 的**客户端部分**（指纹 + PoW + 答案表）已完全可复现（`tools/sentinel-hook.js`）；卡点在 ① Cookie/Bearer（需真实登录）、② `cf_clearance`（Cloudflare 边缘层）、③ 服务端 Fernet 与 `sig`（不可伪造）。详见 `01` §6 与 `03` §6。

---

## 8. 覆盖度与缺口

**已覆盖**（有实测请求/响应）：上表全部 ⩽ 20 个接口，含对话、生图取图、Sentinel 双链路、登录认证。

**未覆盖 / 需再抓**：

| 缺口 | 说明 |
|------|------|
| 文件**上传**接口 | 4 份抓包只有下载（`estuary/content`），未见上传侧 URL 与签名方式 |
| 语音 / 实时（`celsius`、`wss`） | 只见发现请求与 WS 握手，未见消息协议 |
| 会话重命名 / 删除 / 分享 / 归档 | 未触发 |
| `conversation_mode`（如画布、深度研究） | 只在 `system_hints` 里看到能力清单，未见对应请求 |
| TPP 类会话（`conversation_origin=tpp`）| 只在列表查询里出现过，未见其详情接口 |
| `dx` / `collector_dx` / `snapshot_dx` 的**内容** | 密文未解开（已排除短周期 XOR）|

---

## 9. 与其它文档的对应关系

| 本文段落 | 对应详细分析 |
|---------|-------------|
| §1 认证层 | `01` §4.3（Cloudflare）、§4.12（Cookie+Bearer 逐 claim 拆解）、§4.6~§4.8（Sentinel）|
| §2.2 SSE 结构 | `03` §4.7.1（12 事件逐个说明）|
| §3 取图链路 | `03` §4.9（签名 URL 三重证据）|
| §2.1/§2.2 请求体字段来源 | `02` §4.1（哪些是客户端生成 / 服务端回显）|
| §4 Sentinel | `01` §4.5（指纹 25 字段）、§4.7（PoW 算法与实测）、§4.8.1（答案表解密，7 个密钥样本）|
| §6 登录接口 | `01` §3 全链路时序、§4.1~§4.4、§4.10（MFA）、§4.11（回调）|
