# chatgpt_generate_image.har —— ChatGPT 生成图片链路鉴权与校验逻辑分析

> 分析对象：`chatgpt_generate_image.har`（9.51 MB，31 条请求，时间跨度 `2026-10-14T09:44:19.354Z` ~ `09:45:06.824Z`，约 47 秒）
> **补充抓包**：`chatgpt_image_包含敏感数据.har`（8.65 MB，19 条，`11:00:12Z` ~ `11:00:53Z`，同一账号新一轮生图）—— 补齐了本文被脱敏掉的 **Cookie / `Authorization: Bearer`**、**SSE 事件流正文**（§4.7.1）、以及 **`oai-sc` 轮换**等证据；文中凡引用它都明确标注。
> 场景：已登录状态下，在 ChatGPT Web 输入「生成一张地球图片」→ 模型调用图像生成工具出图 → 前端下载该 PNG
> 账号：`logo-pie2i@icloud.com` / `user-LkCB8RihStg7myaLj2HRube6` / 计划 `free` / 工作区 `edebbcbb-3f1d-4963-8ec1-54810e3f2c44`
> 会话 ID：`6acf4f06-9ab0-83e8-916b-f85af7805dc9`（标题「生成地球图片」）
> 前置阅读：`01-chatgpt-login-鉴权与校验分析.md`（Sentinel 指纹与 PoW 算法完整推导）、`02-chatgpt-chat-鉴权与校验分析.md`（对话链路准入机制）
> 接口速查：**`04-ChatGPT-Web-接口清单.md` §3** —— 生图取图三步（`conversations/<id>` 找指针 → `files/download` 换签名 URL → `estuary/content` 下载）。

---

## 0. 阅读前必读：本 HAR 的能力边界与看点

**边界**：

1. **无 Cookie、无 `Authorization`**（**仅本脱敏版如此**）：31 条中 `request.cookies[]` 非空 = 0；`Cookie`/`Authorization` 头 = 0。⚠️ 这是导出工具脱敏的结果，**不代表客户端没发** —— 补充抓包 `chatgpt_chat_包含敏感数据.har` 证明真实流量同时携带 22 个 Cookie（含 `cf_clearance`、分片的 `__Secure-next-auth.session-token.0/.1`、Sentinel 自建的 `oai-sc`）与 `Authorization: Bearer <OIDC RS256 JWT>`，详见 `01` 文档 §4.12。
2. **出图那一轮的 SSE 正文未落盘**：`[8] /backend-api/f/conversation` 声明 `size=5783`、`content-type: text/event-stream`，但 `content.text` 为空。因此**图片是在第几个事件里下发的、事件流结构如何，无法直接取证**。
   → **补充抓包已补齐**：`chatgpt_image_包含敏感数据.har [1]` 的 SSE 正文完整落盘（5830 字节、12 个事件），结构见 **§4.7.1**。
3. **补救**：本 HAR 的 `[23] GET /backend-api/conversations/<id>` 返回了完整会话详情，**把出图那一轮的消息级结构补全了**（§4.7）——这是三个 HAR 中唯一能观察到 `image_asset_pointer` 的地方。

**本 HAR 的独特看点**（另外两个 HAR 没有的）：

* **令牌跨会话复用**的硬证据（§4.4）：图片会话发的三条 Sentinel 令牌是**上一个 chat 会话签发的**，其自己发起的 `prepare/finalize` 反而没被使用；
* **`x-conduit-token` 真实被使用**的一次（§4.5），且与 `client_prepare_state` 的关系可解释 chat HAR 里"没带"的原因；
* **服务端签名的文件下载 URL 链路**（§4.9）：`files/download` → `estuary/content?...&sig=...` → PNG 字节，`sig` 完全由服务端签发。

---

## 1. 结论速览（TL;DR）

生图链路的**鉴权与普通对话完全一致**（同一套 `chat-requirements` + 三条 Sentinel 头 + 可选 conduit 票据）；**"生图"本身不是鉴权层的能力，而是服务端根据 feature 开关自主选择工具的结果**——请求体里没有任何 image_gen/dalle/tools 字段。

```
[准入复用]  [12] prepare  →  [14] finalize   （并行刷新，但见 §4.4：这一轮的结果其实没被用上）
            [8] 实际携带的凭证 = 上一个 chat 会话在 540s 内签发的三条令牌（逐字节相同）

[发起请求]  [7] f/conversation/prepare  →  取到 conduit_token
            [8] f/conversation (SSE)
                headers: 3× openai-sentinel-*, x-conduit-token(来自[7]), x-oai-turn-trace-id
                body:    messages[0].content.parts=["生成一张地球图片"], model:"auto"
                         （无 tools / 无 image_gen / 无 dalle / 无 checksum 字段）

[服务端出图] 模型自主调用图像工具 → 产出 file_000000009d9881fd99df55e87397a00d
            （会话详情 [23] 可见：tool 消息 parts[0].content_type="image_asset_pointer"
              asset_pointer="sediment://file_000000009d9881fd99df55e87397a00d"，1254×1254 PNG）

[取图链路]  [19]/[26] GET /backend-api/files/download/file_...?conversation_id=...&inline=true
                → 响应 {"status":"success","download_url":"https://chatgpt.com/backend-api/estuary/content
                        ?id=file_...&ts=497769&p=fsns&cid=1&sig=<64位十六进制>&v=0", ...}
            [24] GET 上述 download_url  → 200，2,897,667 字节 PNG
            [27] 带 if-none-match / if-modified-since 再取 → 304（ETag 命中，不重传）
```

**关键结论**（全部有直接证据）

| # | 结论 | 证据 |
|---|------|------|
| 1 | 生图请求的鉴权 = 与对话链路**完全相同**的三条 Sentinel 头 | `[8]` 请求头 |
| 2 | 三条令牌是**上一个会话（chat HAR）签发**的，且**逐字节相同**；本会话自己的 `[14]` 刷新结果未被使用 | 跨 HAR 比对（§4.4）|
| 3 | 令牌 TTL = **540 秒**，SDK 常量 `ue=54e4`（ms）与之吻合 | `[12]/[14]` 响应 + SDK 源码 |
| 4 | `x-conduit-token` 在**本 HAR 被真实使用**，来源是 `[7]` prepare 的响应 | `[8]` 头 == `[7]` 响应（逐字节相同）|
| 5 | **请求体里没有** `tools`/`image_gen`/`dalle`/`conversation_mode`/任何 `*_token` → 生图由服务端决定 | `[8]` 请求体全文 |
| 6 | 图片以 `sediment://` 资产指针下发，带 `dalle.gen_id` 与尺寸元数据 | `[23]` 会话详情 |
| 7 | 图片下载 URL 的 `sig`（64 位十六进制）**由服务端签发**，客户端零计算 | `[19]/[26]` 响应 vs `[24]/[27]` 请求（逐字符相同）|
| 8 | `estuary/content` 的请求头**不带 `oai-did`/`oai-language`/`x-openai-web-frontend`**，只带 `chatgpt-account-id` + `originator` | `[24]/[27]` 头集合 |
| 9 | 生成的 PNG 内嵌 **C2PA 来源凭证**（14 个 `jumb` box / 28 处 `c2pa` 标记）| `[24]` 响应体解码 |
| 10 | 配额由服务端记账：`image_gen` 剩余额度在 `conversation/init` 中下发（本账号余 24 次）| `chatgpt_chat.har [29]`（跨文件引用）|

---

## 2. 抓包概览

| 主机 | 请求数 | 说明 |
|------|--------|------|
| `chatgpt.com` | 28 | 业务 API + CDN 资源 |
| `persistent.oaistatic.com` | 3 | 首页图标（`image-square@3x.png` 等，与鉴权无关）|

* **方法**：GET 23 / POST 8
* **状态**：200 ×28、202 ×2（遥测）、304 ×1（图片缓存复验）
* **时间线**：

| 时刻（UTC）| entry | 耗时 | 事件 |
|------|-------|------|------|
| 09:44:19.354 | `[0]` | 21 ms | favicon（页面已在）|
| 09:44:19.581 | `[1]` | 1222 ms | `accounts/check` → **`chatgpt-account-id` 与 feature 开关来源** |
| 09:44:19.686 | `[2][3][4]` | 2~6 ms | 首页用例图标 `image-square` / `pencil` / `globe`（暗示用户从"图片"用例入口进入）|
| 09:44:20.8 / 22.5 | `[5][6]` | 1871 / 3395 ms | `beacons/home` 埋点 |
| 09:44:28.718 | `[7]` | 1481 ms | `f/conversation/prepare` → 签发 `conduit_token`（`iat=1791971070`）|
| **09:44:36.007** | **`[8]`** | **18293 ms** | **`f/conversation`（出图那一轮，SSE，实际耗时 18.3 秒）** |
| 09:44:36.449 | `[10]` | 2049 ms | `system_hints` 工具清单 |
| 09:44:36.606 | `[12]` | 2583 ms | `sentinel/chat-requirements/prepare`（**在 `[8]` 已经发出之后 0.6 秒才发起**）|
| 09:44:39.707 | `[14]` | 1448 ms | `sentinel/chat-requirements/finalize`（响应 `09:44:41`，其令牌未被 `[8]` 使用）|
| 09:44:54.167 | `[19]` | 1273 ms | `files/download` → 拿到签名下载 URL |
| 09:44:54.195 | `[20]` | 1794 ms | 第二次 `f/conversation/prepare`（新一轮输入框预热）|
| 09:44:54.42x | `[21][22]` | ~1.8~2.1 s | 会话列表刷新 |
| 09:44:54.431 | `[23]` | 2385 ms | **会话详情 → 图片资产指针**（`create_time=09:44:53.9`）|
| 09:44:55.445 | `[24]` | 6301 ms | `estuary/content` → **200 PNG（2.9 MB）** |
| 09:45:01.833 | `[26]` | 917 ms | 再次 `files/download`（参数少一个 `include_library_file_state`）|
| 09:45:02.755 | `[27]` | 869 ms | 同一签名 URL 复取 → **304** |
| 09:45:06.824 | `[30]` | 970 ms | `wham/usage` |

> **时序上的两个要点**：
> ① `[12]`（Sentinel 刷新）比 `[8]`（对话请求）晚 0.6 秒才开始 —— 这从时间维度**坐实**了 `[8]` 只能用 540 秒内缓存的旧令牌（§4.4）；
> ② `[19]`（取图）在 `[8]` 结束（`09:44:54.30`）前 0.13 秒就发出 —— 说明**携带图片资产指针的 SSE 事件在流关闭之前就已到达**（推断）。

---

## 3. 传输层鉴权：与对话链路同构

`[1] accounts/check/v4-2023-04-27`（9311 字节）是本次抓包中**账号身份与能力开关的唯一来源**：

```json
{ "account_id": "edebbcbb-3f1d-4963-8ec1-54810e3f2c44",
  "created_time": "2026-10-07T04:05:02.225354Z",
  "plan_display_name": "Free",
  "is_deactivated": false,
  "can_access_with_session": true,
  "pthdnu": "9a077e77608a3aa6c8769b5279a6fbf84441946232772b2485075f5b72bcb97f",
  "eligible_for_reactivation": true, ... }
```

以及一份 **feature 开关清单**，其中包含本次生图能力的关键项：

```
["gizmo_canvas_toggle","gizmo_reviews","gpt5","gpt5_mini","image_gen_tool_enabled",
 "library_shared_content_available","mfa","model_ab_use_v2","moonshine", ...]
```

> **`image_gen_tool_enabled`** 就是"这个账号能不能用图像生成工具"的开关 —— 它在 **`accounts/check` 的响应里**，而不是在生图请求里。这是"能力由服务端授予"的直接证据。

随后所有 `/backend-api/*` 请求都带同一组标识头（与 `02` 文档完全一致）：

| 头 | 值 | 出现次数 |
|----|----|---------|
| `chatgpt-account-id` | `edebbcbb-3f1d-4963-8ec1-54810e3f2c44` | 18（`[1][5][6][7][8][10][12][14][19][20][21][22][23][24][26][27][28][30]`）|
| `oai-did` | `57cab66a-0ad5-42c6-8d2d-2f2e9b2a8d28` | 14（缺 `[24][27][28][30]` —— **`estuary/content` 不带设备头**，见 §4.9）|
| `oai-language` | `zh-CN` | 15 |
| `originator` | `Codex Browser` | 18 |
| `x-openai-web-frontend` | `codex_webview` | 14 |
| `x-openai-codex-window-type` | `browser` | 14 |
| `x-oai-mcp-form-version` | `2` | 14 |
| `x-oai-turn-trace-id` | `665c4fe6-dd37-4ddb-a961-9c612f6c4490` | **3 次**：`[7]`+`[8]`（本轮 prepare 与发送，**同值**）、`[20]`（下一轮 prepare，值不同：`f0178f47-cbcb-4770-99ea-f83173793c6d`）|
| `x-conduit-token` | `eyJhbGciOiJFUzI1NiIs…`（352）| **1 次**（仅 `[8]`，来源为 `[7]` 的响应 —— 见 §4.5）|

**注意 `estuary/content` 是例外**：`[24]/[27]` **只带** `chatgpt-account-id` + `originator`（+ 缓存复验头），**不带** `oai-did`/`oai-language`/`x-openai-web-frontend`/`x-oai-mcp-form-version`。这说明该端点的授权模型是 **"签名 URL"**（见 §4.9），而非会话头。

---

## 4. 机制详解

### 4.1 生图会话的 Sentinel 凭证链

| entry | 请求 | 关键内容 |
|-------|------|---------|
| `[12]` | `POST /backend-api/sentinel/chat-requirements/prepare` | 请求体 `{"p":"gAAAAAC…"}`（739 字符，指纹载荷，未带 `~S`）|
| `[14]` | `POST /backend-api/sentinel/chat-requirements/finalize` | `{prepare_token(2713+), proofofwork, turnstile}` → 响应 `token`（3084 字符 Fernet）|

`[12]` 响应中的挑战参数（本次）：

```json
{ "persona": "chatgpt-freeaccount",
  "prepare_token": "gAAAAABqz08G…",
  "turnstile": { "required": true, "dx": "PBp5bWF2dHlCfFttfBxfaTdTW3R7c3x5…" },
  "proofofwork": { "required": true, "seed": "0.8625556315869432", "difficulty": "07a120" },
  "so": { "required": true, "collector_dx": "PBp5bWFyc3lNeFttfBxfaTdXXHR0d3x5…" } }
```

**PoW 复算（已通过）**：

| 项 | 值 |
|----|----|
| `seed` | `0.8625556315869432` |
| `difficulty` | `07a120` = 500000；比较空间 2²⁴ = 16777216 → 单次通过率 2.98%，期望 ≈ 33.6 次 |
| 提交答案的计数器 `[3]` | `13` |
| `H(seed + 载荷)` | `025bd1d6` → 前 6 位 `025bd1` ≤ `07a120` ✅ |
| `[14]` 请求 `proofofwork` | `"gAAAAAB" + b64(25 字段指纹数组) + "~S"`（681 字符）|

> 算法细节与逐字节回验方法见 `01` 文档 §4.5–§4.7。

### 4.2 三条 `openai-sentinel-*` 头（`[8]` 真实值）

| 头 | 长度 | 值（截断）| 来源 |
|----|------|-----------|------|
| `openai-sentinel-chat-requirements-token` | 3064 | `gAAAAABqz07O3vK_IPNlTkVCKiXd7QWyAc2cGinFJDZ1nWeJL8SwtyTFfHOp4ijmEaHYep7F6I9AwK9q…` | **不是本会话 `[14]` 的结果**，见 §4.4 |
| `openai-sentinel-proof-token` | 725 | `gAAAAABWzMwMDAsIldlZCBPY3QgMTQgMjAyNiAxNzo0Mzo0MSBHTVQrMDgwMCAo…MCwwLDBd~S` | 同上（`[9]`=4 ms、`[3]`=40 的那份）|
| `openai-sentinel-turnstile-token` | 1828 | `SRUZABkGAQwIFXNAEw8VHhUWAhkGDwwIBgIAHQUACgEWCgceFR8HGQMVFAEBCgEaAhsQBBocBwQVFBB0…` | 同上（**环境探针答案表**，见 §4.4）|

### 4.3 请求体：**没有任何生图专用字段**

`[8]` 请求体全文（节选关键部分）：

```json
{
  "turn_attribution": { "turn_trigger": "composer" },
  "action": "next",
  "is_do_not_remember": false,
  "model": "auto",
  "parent_message_id": "client-created-root",
  "timezone": "Asia/Shanghai", "timezone_offset_min": -480,
  "client_contextual_info": { "app_name": "chatgpt.com", "app_surface": "codex_browser", ... },
  "local_function_names": ["local.continue_in_work"],
  "messages": [{
    "id": "c4471620-f9f3-4dfa-ba7a-e5a360972381",
    "author": { "role": "user", "name": null, "metadata": {} },
    "content": { "content_type": "text", "parts": ["生成一张地球图片"] },
    "create_time": 1791971075.997,
    "recipient": "all", "status": "finished_successfully", "weight": 1
  }],
  "supported_encodings": ["v1"],
  "genui_state_snapshots": [],
  "client_prepare_state": "success"
}
```

**逐项排查结论**：请求体中**不存在** `tools` / `tool_ids` / `image_gen` / `image_generation` / `dalle` / `conversation_mode` / `author` / `checksum` / `*_token` / `*_proof` 等字段。用户消息就是一条普通文本消息（`content_type: "text"`）。

> 因此"生图"这一能力是**服务端**根据 `image_gen_tool_enabled`（§3）+ `system_hints` 工具清单（`[10]`，本次列出 `plugin:connector_openai_deep_research` 等 3 项）+ 用户意图**自主决定**调用哪个工具，客户端既不声明也不指定。

### 4.4 令牌跨会话复用（本 HAR 最有价值的发现）

`[8]` 用的三条令牌与 **`chatgpt_chat.har`**（另一个抓包文件、另一个会话、更早 60 余秒）的令牌**逐字节完全相同**：

| 令牌 | `[8]` 实际使用 | `chatgpt_chat.har [31]` | 本 HAR `[14]` 自己刷新的 | 复用？ |
|------|---------------|------------------------|------------------------|--------|
| chat-requirements token | `gAAAAABqz07O3vK_IPNlTkVC…`（3064）| **完全相同** | `gAAAAABqz08JPujoUD_EG_h1…`（3084）| ✅ |
| proof-token | `…MCwwLDBd~S`（725）| **完全相同** | `…LDAsMF0=~S`（681）| ✅ |
| turnstile-token | `SRUZABkGAQwIFXNAEw8VHhUW…`（1828，key `27.27`，24 项探针）| **完全相同** | `QhIcBB8IBQwJE3piGmtwTnVk…`（1756，key `90.31`，22 项）| ✅ |

> 这三条令牌**都已解密**（详见 `01` 文档 §4.8.1）：`chat-requirements-token` 是服务端 Fernet（不可解析），而 `proof-token` 是 25 字段指纹载荷、`turnstile-token` 是"探针号.答案号 → 采集值"的答案表 —— 后两者都是**客户端可自行生成**的，并非 Cloudflare 令牌。

解读（含 Fernet 时间戳佐证）：

* `[8]` 使用的 chat-requirements token 内嵌时间戳 = `1791971022`（`09:43:42Z`，即 chat 会话 `[31]` finalize 的响应时刻）；
* 图片会话在 `09:44:39` 自己完成了一次 `prepare/finalize`（`[12]/[14]`，令牌内嵌时间戳 `1791971081`），但**发起请求时用的仍是旧令牌** —— 因为旧令牌在 540 秒 TTL 内仍然有效，前端缓存直接命中；
* SDK 源码中的对应常量与判定逻辑：

```js
const se = 5e3, ue = 54e4, …;                    // ue = 540000 ms = 540 s
// requirementsToken(): Date.now() - e.lastFetchTime < ue ? 用缓存 : 重新取
```

**含义**：Sentinel 令牌是 **"人/会话级"凭证**（540 秒内跨页面、跨对话复用），而不是"请求级"一次性凭证。这对反滥用体系很重要：既避免每轮对话都重做一次 PoW + 探针采集，又保证凭证短时有效。并行发生的 `[12]/[14]` 属于**后台预刷新**（提前续期），本次没有赶上 `[8]` 的发送时刻。

> 三代令牌的完整链路（三份 HAR 串起来）：**登录流程** `login[674]→[712]`（09:42:03~06）→ 被 **chat 会话** `[4]` 使用（09:43:35）→ **chat 会话** `[27]→[31]` 刷新（09:43:35~41）→ 被 **图片会话** `[8]` 复用（09:44:36）→ **图片会话** `[12]/[14]` 再刷新（09:44:39~41，未被使用）。每一代的三个值都已在对应 HAR 中逐字节核对。

### 4.5 `conduit_token`：本次被真实使用

`[7] prepare` 响应：

```json
{ "status": "ok",
  "conduit_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.…" }
```

JWT 载荷（ES256）：

```json
{ "conduit_uuid": "86e88d124c8e45bc8df64f7b9bd986db",
  "conduit_location": "10.129.130.133:8305",
  "cluster": "unified-125",
  "iat": 1791971070, "exp": 1791971130,        // 60 秒有效
  "turn_topic_id": null }
```

| 对比项 | 本 HAR（image） | `chatgpt_chat.har`（chat） |
|--------|----------------|---------------------------|
| `[8]/[4]` 是否携带 `x-conduit-token` | **携带**，且与 `[7]` 响应的值逐字节相同 | **未携带** |
| `client_prepare_state` | `"success"`（prepare 已完成）| `"sent"`（prepare 尚未返回）|
| 时间关系 | `[7]` 09:44:3x 完成 → `[8]` 随后发出 | `[1]` prepare 与 `[4]` 发送相隔 425 ms，响应晚于发送 |

> **结论**：`conduit_token` 是"**能带就带**"的后端实例粘滞票据（60 秒），不是必需凭证 —— chat 会话没带也成功了；本 HAR 因为 prepare 先返回，所以带上了。`client_prepare_state` 的 `sent → success` 正好记录了客户端状态机的推进。

**补充抓包新增证据 —— 两种同源票据**：

| 票据 | 位置 | 载荷 | 有效期 |
|------|------|------|--------|
| `x-conduit-token` | prepare 响应 → `f/conversation` 请求头 | `{conduit_uuid, conduit_location, cluster:"unified-125"/"unified-186", iat, exp, turn_topic_id:null}` | **60 秒** |
| `resume_conversation_token` | **SSE 事件 1**（响应体内，见 §4.7.1）| `{conduit_uuid:"f5b9ded0…", conduit_location:"10.128.147.19:8305", cluster:"unified-186", iat, exp, turn_topic_id:"conversation-turn-1194ecb1-…"}` | **4 小时** |

两者同源（同为 ES256、同样的 claims 结构、同样暴露后端实例），差别在于：请求票据的 `turn_topic_id` 是 `null`，而流内票据被填成 `conversation-turn-<uuid>` —— 它是这一轮真正建立后才生成的**断线续传凭证**（可用于重连接着读流）。

### 4.6 第二次 prepare 与后续列表刷新

| entry | 内容 |
|-------|------|
| `[20]` | `f/conversation/prepare`，签发**新的** conduit token（`conduit_uuid=73e9a5c0221a4540b7bc2d474ccb4b43`，实例 `10.129.226.63:8302`，`iat=1791971096`）→ 说明每次 prepare 都可能路由到不同后端实例 |
| `[21]/[22]` | 会话列表 `exclude_conversation_origin=tpp` 与 `conversation_origin=tpp` 两次查询（后者返回 `{"items":[],"total":0}`）|
| `[23]` | 会话详情（见 §4.7）|

### 4.7 出图那一轮的消息结构（来自 `[23]` 会话详情）

`[23] GET /backend-api/conversations/6acf4f06-9ab0-83e8-916b-f85af7805dc9?num_turns=10&include_has_versions=true`

会话元数据：`title="生成地球图片"`、`create_time=1791971079.161463`、`default_model_slug="auto"`、`is_temporary_chat=false`、`memory_scope="global_enabled"`。

消息序列（同一 `turn_exchange_id = e9f298f1-62f7-4a89-b638-25030185b035`）：

| # | 角色 | `content_type` | 要点 |
|---|------|---------------|------|
| 0 | `user` | `text` | `parts=["生成一张地球图片"]`，`id=c4471620-…`（**与 `[8]` 请求体里的消息 id 相同**），`metadata.request_id="9a5be288-…"`，`can_save=false` |
| 1 | `assistant` | `model_editable_context` | 模型可编辑上下文占位（`model_set_context=""`、`structured_context=null`）|
| 2 | `assistant` | `code` | **工具调用信封**：`recipient = "t2uay3k.sj1i4kz"`（服务端下发的**工具内部名**），`text = "{\"skipped_mainline\":true}"`（跳过主线，直接交给工具），`end_turn=false`、`weight=1.0` |
| 3 | **`tool`** | `multimodal_text` | `author.name = "t2uay3k.sj1i4kz"`，`recipient="all"`，`parts[0]` 即生成结果；`create_time=1791971093.915`（距用户消息 **17.9 秒**，与 `[8]` 的 18.3 秒 SSE 时长吻合）|

四条消息共享同一个 `turn_exchange_id = e9f298f1-62f7-4a89-b638-25030185b035`（轮次关联键）。

`messages[3].content.parts[0]` 的完整结构（**图片资产指针**）：

```json
{ "content_type": "image_asset_pointer",
  "asset_pointer": "sediment://file_000000009d9881fd99df55e87397a00d",
  "mime_type": "image/png",
  "size_bytes": 2897667,
  "width": 1254, "height": 1254,
  "fovea": null,
  "metadata": {
    "dalle": { "gen_id": "c35e18d6-e6f0-4215-8523-69bc34a9b741",
               "prompt": "", "seed": null, "parent_gen_id": null, "edit_op": null,
               "serialization_title": "DALL-E generation metadata" },
    "gizmo": null,
    "generation": { "gen_id": "c35e18d6-e6f0-4215-8523-69bc34a9b741",
                    "gen_size": "smimage", "gen_size_v2": "16", "seed": null,
                    "parent_gen_id": null, "height": 1254, "width": 1254,
                    "transparent_background": false, "is_sticker": false, "is_purchasable": null }
  } }
```

该消息的元数据另外带有：

```json
"metadata": { "image_gen_title": "...",
              "permissions": [ { "type": "notification", "status": "requested",
                                 "notification_channel_id": "image_gen",
                                 "notification_channel_name": "ImageGen",
                                 "notification_priority": 4 } ],
              "turn_exchange_id": "e9f298f1-…", "can_save": false }
```

> 注意 `permissions` 的类型是 **`notification`**（出图完成后的通知通道 `image_gen`，优先级 4），**不是**安全/授权许可 —— 不要误读为"工具申请权限"。另外 `metadata.dalle.serialization_title` 直接写明 `"DALL-E generation metadata"`，`gen_size: "smimage"` 与 `gen_size_v2: "16"` 是产物规格标记。

> **`sediment://` 是 ChatGPT 内部资产 URI 方案**：前端拿到该指针后，必须走 `files/download` 换取带签名的 HTTP URL（§4.9）才能取到字节。本 HAR 中 `sediment://` 出现 1 次、`file-service://` 0 次。

### 4.7.1 SSE 事件流完整结构（补充抓包首次落盘）

原始三份 HAR 的 `f/conversation` 正文都没落盘；补充抓包 **`chatgpt_image_包含敏感数据.har` 的 `[1]`** 把它完整存了下来（`size=5830 / stored=5830`）。这一轮的出图过程共 **12 个事件**：

| # | SSE `event` | 载荷要点 |
|---|-------------|---------|
| 0 | `delta_encoding` | `data: "v1"` —— 声明后续 delta 的编码版本 |
| 1 | *(无 event 名)* | `{"type":"resume_conversation_token","kind":"topic","token":"<ES256 JWT>","conversation_id":"6acf60c6-…"}` —— **断线续传票据**，JWT 载荷含 `conduit_uuid`/`conduit_location:"10.128.147.19:8305"`/`cluster:"unified-186"`/`iat`/`exp`（**有效期 4 小时**）/`turn_topic_id:"conversation-turn-1194ecb1-…"` |
| 2 | `delta` | `{"p":"","o":"add","v":{"message":{…"content_type":"model_editable_context"…},"conversation_id":"6acf60c6-…","error":null,"error_code":null}}` |
| 3 | *(无)* | `{"type":"message_marker","message_id":…,"marker":…}` |
| 4 | `delta` | `o:"add"` 追加助手消息：`content_type:"code"`、`text:"{\"skipped_mainline\":true}"`、`status:"in_progress"`（**工具调用信封**，与 `[23]` 会话详情里的 `messages[2]` 对应）|
| 5 | `delta` | `{"p":"/message/status","o":"replace","v":"finished_successfully"}` —— **JSON-Patch 语义**（`p`=路径、`o`=操作、`v`=值）|
| 6 | *(无)* | `{"type":"title_generation","title":"…"}` —— 自动生成会话标题 |
| 7 | **`delta`** | `o:"add"` 追加**工具消息**：`author.role:"tool"`、`author.name:"t2uay3k.sj1i4kz"`、`content_type:"multimodal_text"`、`parts[0].content_type:"image_asset_pointer"`、**`asset_pointer:"sediment://file_000000003218824383bf262ec925b22e"`**、`size_bytes:2854094`、`1254×1254`、`dalle.gen_id` |
| 8 | *(无)* | `title_generation`（第二次）|
| 9 | *(无)* | `{"type":"server_ste_metadata", …}` —— 服务端元数据 |
| 10 | *(无)* | `{"type":"message_stream_complete","conversation_id":…}` |
| 11 | *(无)* | `[DONE]` |

**要点**：

1. **图片资产指针确实是在 SSE 里下发的**（事件 7）—— 这证实了本文早期版本中"携带图片资产指针的事件在流关闭前到达"的**推断**（原依据：`[19] files/download` 比 `f/conversation` 结束早 0.13 s 发出）。
2. 事件流是 **JSON-Patch（RFC 6902 风格）的增量协议**：`p` 为空表示"向消息数组追加一条消息"，`p:"/message/status"` 表示"就地把某字段改成新值"。
3. 除消息外还夹带三类控制事件：`resume_conversation_token`（续传票据）、`title_generation`（标题生成）、`server_ste_metadata` / `message_stream_complete`（收尾）。
4. 事件里**不含**任何校验/鉴权凭据 —— 准入校验全部发生在请求头（§4.2），流内只有业务数据与续传票据。

### 4.8 日志回显点位：`oai-echo-logs`（生图链路范围更大）

`[8]` 的 `oai-echo-logs` 比 chat 会话更长：

```
1,18901,0,48501,1,48521,0,97631,1,106650,0,106973,1,116512,0,138268,1,144027,0,144406
```

即在 chat 会话的 4 个点位基础上又追加了 5 组（`106650/106973`、`116512/138268`、`144027/144406`）—— **生图链路的日志回显范围比普通对话更大**（与图片生成的诊断需求相符）。格式为成对的 `开关,点位号`，客户端声明采样意愿，服务端决定是否回显。

### 4.9 文件下载链路与"签名 URL"（server-issued signature）

#### 第 1 步：`files/download` 换取签名 URL

`[19]`（带 `include_library_file_state=true`）与 `[26]`（不带该参数）请求同一个文件：

```
GET /backend-api/files/download/file_000000009d9881fd99df55e87397a00d
    ?conversation_id=6acf4f06-9ab0-83e8-916b-f85af7805dc9
    &download_intent=false&inline=true[&include_library_file_state=true]
```

两次响应体**完全相同**（414 字节）：

```json
{ "status": "success",
  "download_url": "https://chatgpt.com/backend-api/estuary/content?id=file_000000009d9881fd99df55e87397a00d&ts=497769&p=fsns&cid=1&sig=7dec3eb0cdbdc71b17a83e56b26fe0f0326a61c2803d63717d7299b01593d5df&v=0",
  "metadata": null,
  "file_name": "user-LkCB8RihStg7myaLj2HRube6/ce59a281-19d7-4cdf-86fb-d4b7a483c220.png",
  "creation_time": null, "no_auth_user_upload": null, "mime_type": null,
  "file_size_bytes": 2897667 }
```

| 查询参数 | 值 | 说明 |
|----------|-----|------|
| `id` | `file_000000009d9881fd99df55e87397a00d` | 文件 ID（= `sediment://` 指针去掉 scheme）|
| `ts` | `497769` | 时间戳类参数（语义未确认，见 §7）；**补充抓包给出新证据**：另一个文件在 17 分钟后取值为 `497771`（仅 +2）→ 更像**全局单调计数/版本号**，而非 Unix 时间戳 |
| `p` | `fsns` | 分区/存储命名空间标记（推断）|
| `cid` | `1` | 容器/集群序号（推断）|
| `sig` | `7dec3eb0…3d5df`（64 位十六进制 = 32 字节）| **HMAC 签名**（服务端签发）|
| `v` | `0` | 签名版本号 |

#### 第 2 步：用签名 URL 取字节

`[24]` 请求的 URL 与上面 `download_url` **逐字符相同**，返回：

| 项 | 值 |
|----|----|
| 状态 | `200` |
| `content-type` | `image/png` |
| `content-disposition` | `attachment; filename="ce59a281-19d7-4cdf-86fb-d4b7a483c220.png"` |
| 字节数 | **2,897,667**（与 `file_size_bytes` 完全一致）|
| PNG 头 | `89 50 4E 47 0D 0A 1A 0A` |
| IHDR | **1254 × 1254**，bitDepth 8，colorType 2（truecolor）|
| C2PA | 含 `jumb` box ×14、`c2pa` 标记 ×28 → **内嵌内容来源凭证**（AI 生成水印/溯源）|
| `etag` | `"0x8DF29D7CB3AC49B"` |

`[27]` 带 `if-none-match: "0x8DF29D7CB3AC49B"` 与 `if-modified-since` 复取 → **304**（不重传 2.9 MB）。

#### 第 3 步：`sig` 的定性 —— **服务端签发，客户端零计算**

三重证据：

1. **逐字符相同**：`[24]/[27]` 的请求 URL 与 `[19]/[26]` 响应中的 `download_url` 完全一致（无任何客户端改写）；
2. **确定性**：`[19]` 与 `[26]` 两次签发相隔数秒、查询参数不同（前者多 `include_library_file_state=true`），但 `sig`/`ts`/`p`/`cid`/`v` **完全相同** → 是对 `(id, ts, p, cid, v, …)` 的确定性 HMAC，而非随机 nonce；
3. **无密钥痕迹**：全 HAR 中不存在任何签名密钥、也不存在 `Authorization` 头；`[24]/[27]` 只带了 `chatgpt-account-id` 与 `originator`。

> 因此攻击面在于"能否拿到 `files/download` 的签名 URL"（需要有效会话），而不是"能否自己算出 `sig`"。`sig` 的具体 HMAC 输入串与密钥不可知（**待验证**）。

---

## 5. 字段速查表

| 字段/头 | 出现位置 | 来源 | 作用 | 可伪造 |
|---------|---------|------|------|--------|
| `chatgpt-account-id` | 所有业务请求头 | `[1] accounts/check` 下发 | 租户隔离 | 需与会话匹配 |
| `oai-did` | 多数业务请求头 | 客户端 cookie | 设备识别 | ✅ |
| `x-oai-turn-trace-id` | `[7]` + `[8]` | 客户端 | 绑定一轮 turn | ✅ |
| `openai-sentinel-chat-requirements-token` | `[8]` 头 | 服务端 Fernet（**复用了 chat 会话的**）| 对话准入 | ❌ |
| `openai-sentinel-proof-token` | `[8]` 头 | 客户端 PoW | 工作量证明 + 指纹 | ✅ 算法已还原 |
| `openai-sentinel-turnstile-token` | `[8]` 头 | 客户端 XOR | **环境探针答案表**（键=`探针号.答案号`），不是 CF 令牌 | ✅ 密钥可由已知明文推导（`01` §4.8.1）|
| `x-conduit-token` | `[7]` 响应 → `[8]` 请求头 | 服务端 ES256 JWT | 后端实例粘滞（60 s）| ❌ |
| `p` / `proofofwork` / `prepare_token` / `turnstile` | `[12]/[14]` | 见 `01` §4 | Sentinel 三步 | 混合 |
| `client_prepare_state` | `[8]` 体 | 客户端状态机 | `sent` / `success` | ✅ |
| `image_gen_tool_enabled` | `[1]` 响应 | **服务端 feature 开关** | 决定能否生图 | ❌ |
| `sediment://file_...` | `[23]` 会话详情 | 服务端 | 图片资产指针 | ❌（服务端产物）|
| `dalle.gen_id` / `generation.gen_size` | `[23]` | 服务端 | 生成溯源元数据 | ❌ |
| `download_url` / `sig` / `ts` / `p` / `cid` / `v` | `[19]/[26]` 响应 | **服务端签发** | 授权取图（HMAC 签名 URL）| ❌ |
| `etag` / `if-none-match` | `[24]` 响应 / `[27]` 请求 | 服务端 | 缓存复验（304）| — |
| `oai-echo-logs` | `[8]` 头 | 客户端 | 日志回显点位（9 组）| ✅ |

---

## 6. 可复现性评估

| 环节 | 能否纯脚本复现 | 说明 |
|------|--------------|------|
| Sentinel 挑战 + PoW 计算 | ✅ | 算法完全还原，`[12]/[14]` 已复算通过 |
| 三条 Sentinel 头组装 | ✅/⚠️ | `proof-token`（25 字段载荷）与 `turnstile-token`（探针答案表）**均可自行构造**；`chat-requirements-token` 需 `finalize` 成功（依赖服务端 `prepare_token`）|
| `conduit_token` | ❌ | 服务端 ES256 签名 |
| **让模型生图** | ❌ | 请求体无任何生图参数，完全由服务端 feature + 意图决定；没有可用会话就无法触发 |
| `sediment://` → `download_url` | ❌ | 需会话 + 服务端签发 |
| `estuary/content` 取图 | ❌ | 依赖上一步的 `sig`（虽有会话头，但 `sig` 才是关键）|
| PNG 解析 / C2PA 提取 | ✅ | 纯本地（字节已在 HAR 中）|

**结论**：生图链路的**准入校验**与普通对话共用同一套机制（客户端部分可复现）；但**生图行为本身**与**产物获取**都强依赖服务端授权（feature 开关 + 服务端签发的签名 URL），纯脚本无法绕过。

---

## 7. 不确定与待验证

1. ~~**`[8]` 的 SSE 正文未落盘** → 无法确认图片是在哪个事件中下发~~ **已解决**：补充抓包 `chatgpt_image_包含敏感数据.har [1]` 的 SSE 完整落盘，图片资产指针出现在**第 7 个事件的 `delta` 操作**里（`o:"add"` 追加 `tool` 消息），见 **§4.7.1**。同一结构下，本 HAR 的 `[8]` 应当也是"事件 2 给 `conversation_id` → … → 某事件给 `image_asset_pointer`"，但本文件的具体事件序号**仍无法回填**（正文缺失）。
2. **`sig` 的 HMAC 输入串与算法**未知：已知 `sig = HMAC(?, ?)` 的 32 字节输出，`ts/p/cid/v` 极可能是签名输入的一部分，但无法验证。
3. **`ts=497769` 的语义**未确认：不像 Unix 秒（太小）、不像毫秒（太小），可能是相对计数或存储分片序号。**补充抓包的新证据**：另一个文件在约 17 分钟后取值为 `497771`（仅 +2）→ 更支持"**全局单调计数/版本号**"而非时间戳（仍属推断）。
4. **`p=fsns` / `cid=1` / `v=0`** 的取值含义属**推断**（存储命名空间 / 容器 / 签名版本）。
5. **工具内部名 `t2uay3k.sj1i4kz`** 与产品功能（图像生成）的映射关系未知；它出现在 `recipient` 与 `author.name`，是纯服务端字符串。
6. **`so`（Session Observer）**：`[12]` 要求 `so.required=true` 并下发 `collector_dx`，但 `[14]` 未提交相关字段；其消费路径未闭合（与 `02` §7 同一问题）。
7. **`dx` / `collector_dx` 的加密方案**：`[12]` 的 `turnstile.dx`（约 20 KB）与 `so.collector_dx`（约 24 KB）**仍未解开** —— 已排除"短周期密钥 XOR"（对 2~160 的所有密钥长度施加严格 ASCII 列约束均无解），推测为更长随机密钥或流密码。对照之下，**`turnstile`（答案表）已经解开**：`base64(XOR(ASCII JSON, 5 字符数字密钥))`，本 HAR 的密钥为 `27.27`（`[8]` 复用）与 `90.31`（`[14]` 新签发），见 `01` §4.8.1。
8. **`permissions` 记录的下游行为**：已确认它是**通知权限**（`type:"notification"`、`notification_channel_id:"image_gen"`、优先级 4），但"服务端为何把它写进消息元数据"（是否为前端触发浏览器通知的条件）未验证。
9. **`gen_size_v2:"16"` 与 `fovea` 字段**的语义未确认（前者推断为规格版本号，后者恒为 `null`，可能是图像金字塔/缩略图指针占位）。
10. **`instant`/`thinking` 等模型档位是否影响生图准入**未在本次抓包体现（`model` 恒为 `auto`）。

---

## 8. 附录：关键证据索引

| entry | 方法 | 状态 | URL | 价值 |
|-------|------|------|-----|------|
| **1** | GET | 200 | `/backend-api/accounts/check/v4-2023-04-27` | **`chatgpt-account-id` 来源 + `image_gen_tool_enabled` 开关** |
| **7** | POST | 200 | `/backend-api/f/conversation/prepare` | **签发 `conduit_token`（本轮实际使用的那一个）** |
| **8** | POST | 200 | `/backend-api/f/conversation` | **三条 Sentinel 头 + conduit + turn-trace + 请求体（SSE 未落盘）** |
| 10 | GET | 200 | `/backend-api/system_hints?exclude_logo=true&mode=plugins` | 服务端工具清单 |
| **12** | POST | 200 | `/backend-api/sentinel/chat-requirements/prepare` | **挑战（seed/difficulty/so）** |
| **14** | POST | 200 | `/backend-api/sentinel/chat-requirements/finalize` | **本会话刷新出的新令牌（未被 `[8]` 使用）** |
| **19** | GET | 200 | `/backend-api/files/download/file_...?…&include_library_file_state=true` | **服务端签发 `download_url` + `sig`** |
| **20** | POST | 200 | `/backend-api/f/conversation/prepare` | 第二次 prepare（另一后端实例）|
| 21/22 | GET | 200 | `/backend-api/conversations?...` | 会话列表 |
| **23** | GET | 200 | `/backend-api/conversations/6acf4f06-…?num_turns=10&include_has_versions=true` | **`sediment://` 资产指针 + `dalle.gen_id` + 工具消息结构** |
| **24** | GET | 200 | `/backend-api/estuary/content?…&sig=…` | **签名 URL 取图（2,897,667 B PNG，1254×1254，含 C2PA）** |
| **26** | GET | 200 | `/backend-api/files/download/file_...`（少一个参数）| 与 `[19]` 对比证明 `sig` 确定性 |
| **27** | GET | 304 | `/backend-api/estuary/content?…&sig=…` | **ETag 缓存复验** |
| 30 | GET | 200 | `/backend-api/wham/usage` | 会话有效反证（email/plan/user_id）|
| 25/28/29 | POST | 202/200 | `/ces/v1/telemetry/intake`、`/ces/v1/rgstr`、`/ces/statsc/flush` | 遥测（噪声，其中 `[25]` 体内含 `"turn_use_case":"image gen"`）|
| 0/2/3/4/5/6/9/11/13/15/16/17/18 | GET | 200/304 | `cdn/assets/*`、`persistent.oaistatic.com/*`、`beacons/home` | 前端资源（噪声）|

### 复现本文结论所用的方法（可审计）

1. 全量 dump 31 条的请求/响应头与体，按"是否携带鉴权材料"筛选；
2. 解析 `[7]/[8]` 的 `x-conduit-token`（base64url 解 JWT 载荷）并做**逐字节比对**确定其来源；
3. 对 `[12]/[14]` 复算 PoW（`H(seed+载荷)` 前缀比对，命中 `025bd1 ≤ 07a120`）；
4. **跨 HAR 逐字节比对** `[8]` 的三条 Sentinel 头 与 `chatgpt_chat.har [31]` 的提交/响应值 → 得出 540 秒跨会话复用结论；
5. 解析 Fernet 令牌头部（版本 `0x80` + 4 字节 0 + 4 字节大端时间戳 + 16 字节 IV + 密文 + 32 字节 HMAC），用内嵌时间戳核对 HTTP `date`；
6. 把 `[24]` 的 base64 响应体解码为字节，校验 PNG 魔数、解析 IHDR 取宽高与色深、统计 `jumb`/`c2pa` 标记；
7. 比对 `[19]/[26]` 响应中的 `download_url` 与 `[24]/[27]` 的请求 URL（逐字符相同）→ 定性 `sig` 为服务端签发。

> 本文所有数值、Base64/JSON 片段、字节数均直接取自 HAR 原文并已复算；标注「推断」「未确认」的条目为逻辑推理，未获直接证据。
