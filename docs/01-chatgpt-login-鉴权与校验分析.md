# chatgpt_login.har —— ChatGPT 登录流程鉴权与校验逻辑分析

> 分析对象：`chatgpt_login.har`（111.65 MB，826 条请求，时间跨度 `2026-10-14T09:37:44Z` ~ `09:42:17Z`，约 4 分 33 秒）
> HAR 生成工具：`WebInspector/537.36`（Chromium 内核浏览器导出） · 客户端 UA：`Chrome/154.0.8037.59` / Windows x64 / `zh-CN`
> 账号：`logo-pie2i@icloud.com`（本地时区 Asia/Shanghai，出口 IP 归属地被服务端判定为 GB）
> 文档定位：逆向分析报告，所有结论均标注证据来源（HAR entry 序号）与置信度。
> 配套阅读：**`04-ChatGPT-Web-接口清单.md`** —— 把本文与 `02`/`03` 涉及的所有接口整理成可照抄的 API 参考（方法/路径/参数/请求体/响应体/必需性/证据）。

---

## 0. 阅读前必读：证据来源与能力边界

**本文的证据来源（4 份抓包）**

| # | 文件 | 用途 |
|---|------|------|
| 1 | `chatgpt_login.har` | 主对象：完整登录链路（826 条）|
| 2 | `chatgpt_chat.har` / `chatgpt_generate_image.har` | 交叉验证 Sentinel 令牌的三代流转（对话 / 生图）|
| 3 | **`chatgpt_login_包含敏感数据.har`**（**LS**，79 MB / 552 条）| **登录流程的未脱敏抓包**：325 条 Set-Cookie、三域 Cookie 全量、auth 侧 sentinel 材料 —— §4.13 与 §4.12 的依据 |
| 4 | `chatgpt_chat_包含敏感数据.har`（CS）/ `chatgpt_image_包含敏感数据.har`（IS）/ `chatgpt_多轮对话_包含敏感数据.har`（MT）| 登录后的业务链路：Cookie+Bearer 双凭据、SSE 结构、跨轮/跨抓包令牌复用 |

**边界**：本 HAR（`chatgpt_login.har`）**没有记录任何 Cookie，也没有记录任何 `Authorization` 头**（全量扫描：`request.cookies[]` 非空条目 = 0/826；`Cookie` 头 = 0；`Set-Cookie` 响应头 = 0）。这是导出工具（WebInspector）的**脱敏**行为 —— 注意这不代表"服务端没下发"或"客户端没发送"，补充抓包已证明两者都存在。

由此产生两条硬约束：

1. **会话凭据本身在本 HAR 中不可观察**，只能通过"哪些请求成功返回了需要登录的数据"来反推它已经生效；其真实形态见 §4.12（依据补充抓包）。
2. 判定"某请求是否已登录"，靠的是**可观察的旁证**：`chatgpt-account-id`、`oai-did`、`/backend-api/me` 返回 200、登录后 `302 → https://chatgpt.com/` 等。

因此本文重点分析的是**在 HAR 中可完整还原的部分**：CSRF 令牌、OAuth 授权参数、设备指纹（Sentinel `p`）、服务端挑战与工作量证明（PoW）、`openai-sentinel-token` 头的组装、Fernet 令牌、MFA、探针答案表解密，以及登录后的完整鉴权契约。凡是推断，均在文中标注「**推断**」。

### 噪声说明

826 条里约 415 条是遥测：`auth.openai.com/awe/api/v2/rum`（Datadog RUM，**377** 次，其中 **179** 次 403 —— 被广告拦截插件拦掉，与鉴权无关）、`chatgpt.com/ces/v1/*`（Statsig，28 次）、`/unauth-mweb/events/*`（8 次）、`ab.chatgpt.com`（2 次）。**本文所有结论都不依赖这些请求。** 静态资源另有 135 条（`auth-cdn.oaistatic.com` 的 175 个请求中含 111 个 `.js` 与 20 个 `.css`，其余为字体/图片），亦已排除。真正的业务 API（`/backend-api/*`）只有 **47** 条。

---

## 1. 结论速览（TL;DR）

这次登录**不是**"账号密码 → 拿 token"的单跳模型，而是四层校验叠加：

| # | 校验层 | 载体 | 谁校验 | 关键证据 |
|---|--------|------|--------|----------|
| 1 | **CSRF 令牌** | `csrfToken`（NextAuth）| chatgpt.com | entry 11 响应 / entry 12 请求体 |
| 2 | **OAuth 授权码 + state** | `state`、`code=ac_...` | auth.openai.com + chatgpt.com 回调 | entry 12/13/627/631 |
| 3 | **Cloudflare 人机校验** | `cf-mitigated: challenge` + Turnstile | Cloudflare 边缘节点 | entry 285(403) → 296~309(解题) → 449(200) |
| 4 | **OpenAI Sentinel：设备指纹 + 工作量证明** | `openai-sentinel-token` 头（`{p,t,c,id,flow}`）| auth.openai.com | entry 275/440/497/285/449 |

其中第 4 层是整条链路的技术核心，也是本文篇幅最大的部分。核心机制：

```
浏览器指纹(25 字段数组) --base64--> p 载荷
    ↓
POST sentinel.openai.com/backend-api/sentinel/req
    {p:"gAAAAAC"+b64(指纹), id:<oai-did cookie>, flow:"password_verify"}
    ↓ 服务端返回
    {persona, token:<Fernet>, expire_after:540, turnstile:{required,dx}, proofofwork:{required,seed,difficulty}}
    ↓ 客户端解题（工作量证明，见 §4.7）
    answer = "gAAAAAB" + b64(指纹数组[其中 [3]=成功计数器]) + "~S"
    ↓ 组装请求头（见 §4.8）
POST auth.openai.com/api/accounts/password/verify
    openai-sentinel-token: {"p":<answer>, "t":<XOR保护的探针答案表>, "c":<服务端token原样回传>, "id":<设备ID>, "flow":"password_verify"}
    body: {"password":"..."}
```

**已在本次分析中被完全验证的结论**（可复现，见 §4.6/§4.7/§4.8.1）：

- 指纹载荷与解题答案的**编解码格式被逐字节还原**：对 HAR 中 5 处真实提交值做"重新编码 → 与抓包原文逐字节比对"，**5/5 完全一致**。
- 工作量证明算法被完整还原并用真实数据**验算通过 5/5**：`H(seed + base64载荷)` 的十六进制前缀 ≤ `difficulty`。
- `openai-sentinel-token.c` **就是** `/sentinel/req` 响应里的 `token` 字段，逐字节相同（2/2 验证）。
- **`t` 字段被离线解密**（密钥分别为 `17.41` / `46.46`，由已知明文推导独立还原），明文是"探针编号.答案编号 → 采集值"的 JSON 表，含屏幕几何、`["Google Inc.","Win32",8,10]`、DOM rect、二进制样本等 —— **它不是 Cloudflare Turnstile 令牌**（见 §4.8.1）。
- **登录后是"Cookie + Bearer"双凭据模型**：`Authorization: Bearer <RS256 OIDC 访问令牌>`（`iss=https://auth.openai.com`，`exp` 10 天，claims 里带着 `authsess_*` 与 `chatgpt_account_id`）叠加 NextAuth 会话 Cookie（分片 JWE）与 `cf_clearance`（见 §4.12，依据补充抓包）。

---

## 2. 抓包概览

### 2.1 主机分布

| 主机 | 请求数 | 角色 |
|------|--------|------|
| `auth.openai.com` | 394 | 登录页与账号 API（authorize / password / mfa）|
| `chatgpt.com` | 223 | NextAuth 接入层 + 登录后业务 API |
| `auth-cdn.oaistatic.com` | 175 | 登录页静态资源 |
| `sentinel.openai.com` | 11 | **Sentinel 指纹与挑战服务** |
| `challenges.cloudflare.com` / `brunhild.challenges.cloudflare.com` | 8 | **Cloudflare Turnstile 人机校验** |
| `cdn.openai.com` / `persistent.oaistatic.com` / `cdn.auth0.com` | 7 | 其它静态资源 |
| `wss://ws.chatgpt.com/...` | 3 | 登录后的 WebSocket 长连接 |
| `ab.chatgpt.com` | 2 | 遥测 |

### 2.2 状态码分布（含噪声）

`200 ×411`、`202 ×211`（遥测 202 Accepted）、`403 ×181`（其中 179 条为 Datadog RUM 被拦截；**剩下 2 条是真正有价值的**：entry 285 的 `cf-mitigated: challenge` 与 entry 295 的登录页 403）、`204/304/302/101/0/401` 少量。

> ⚠️ 403 绝大多数是广告拦截插件拦 Datadog 造成的噪声，**不要**把 403 一律解读为"鉴权失败"。

### 2.3 页面（HAR `pages`）揭示的用户操作序列

| page | 标题（截断）| 含义 |
|------|------|------|
| page_1 | `chatgpt.com/auth/login_with?...&login_hint=logo-pie2i@icloud.com...` | 用户带邮箱预填进入登录页 |
| page_2 | `auth.openai.com/api/accounts/authorize?...&state=iJUv3oNoqN2q-...` | 跳到 OAuth 授权端点 |
| page_3/page_4 | `auth.openai.com/log-in/password` | 输密码（page_4 是 CF 拦截后重新加载）|
| page_5 | `chatgpt.com/api/auth/callback/openai?code=ac_4QUJ...&state=iJUv3oNoqN2q-...` | 授权码回调，**登录完成** |

---

## 3. 全链路时序（按真实发生顺序，非 entry 序号顺序）

```
[阶段 0] 未登录态
  chatgpt.com/auth/login_with?callback_path=%2F&screen_hint=login_or_signup
      &login_hint=logo-pie2i@icloud.com
      &auth_session_logging_id=2d5501de-1771-47ef-9ebb-be4eba2f4e86   ← 全链路贯穿的会话日志 ID
      &ext-oai-did=57cab66a-0ad5-42c6-8d2d-2f2e9b2a8d28              ← 设备 ID，来自 oai-did cookie
      (entry 9, 200)

[阶段 1] NextAuth 发起登录（chatgpt.com 侧）
  GET  /api/auth/providers            (entry 10) → 列出 openai / openai-dev / openai-sidetron(-dev) 4 个 provider
  GET  /api/auth/csrf                 (entry 11) → {"csrfToken":"e24c435d...c1f8"}
  POST /api/auth/signin/openai?prompt=login&screen_hint=login_or_signup
       &auth_session_logging_id=...&ext-oai-did=...&login_hint=...
       body: callbackUrl=https%3A%2F%2Fchatgpt.com%2F & csrfToken=<上一步> & json=true    (entry 12, 200)
       → 响应返回下一步 URL（OAuth authorize 全参数）

[阶段 2] OAuth 授权（auth.openai.com 侧）
  GET /api/accounts/authorize?client_id=app_X8zY6vW2pQ9tR3dE7nK1jL5gH
      &scope=openid email profile offline_access model.request model.read organization.read organization.write
      &response_type=code&redirect_uri=https://chatgpt.com/api/auth/callback/openai
      &audience=https://api.openai.com/v1
      &device_id=57cab66a-...&prompt=login&screen_hint=login_or_signup
      &auth_session_logging_id=...&ext-oai-did=...&login_hint=...
      &ccaps=login_methods%20chatgpt_login_finalizer_v1
      &auth_return_target_category=chatgpt_home
      &state=iJUv3oNoqN2q-gxChWbMJJj3xKZ_Vj1iVEvr0HEfa68    ← CSRF/防重放 state（服务端生成）
      (entry 13, 302 → Location: https://auth.openai.com/log-in/password)

[阶段 3] 登录页加载 + 反机器人初始化
  GET /log-in/password                                    (entry 14, 200, 77KB HTML)
  Cloudflare JSD 脚本下发 + oneshot 上报                  (entry 96/97/102)
  sentinel frame.html + sdk.js 加载                       (entry 103/126/248)

[阶段 4] 第一次提交密码 —— 被 Cloudflare 拦下
  POST sentinel.openai.com/backend-api/sentinel/req       (entry 275) → 拿到挑战
  POST /api/accounts/password/verify                      (entry 285)
       openai-sentinel-token: {"p":"gAAAAAB...~S","t":"<1452字符>","c":"gAAAAAB...","id":"57cab66a-...","flow":"password_verify"}
       → 403 + `cf-mitigated: challenge` + "Just a moment..." HTML   ← 被 CF 挑战拦截，非密码错误！

[阶段 5] 用户完成 Cloudflare Turnstile 人机校验
  orchestrate/chl_page/v1                             (entry 296)
  turnstile/v0/g/<sitekey>/api.js?render=explicit      (entry 297)
  turnstile iframe + /fo/ 挑战提交 + /ci/ 校验         (entry 299/300/302/305/306/307/308)
  POST /log-in/password                                (entry 309, 200)  ← 校验通过，回到登录表单

[阶段 6] 重新取挑战 → 第二次提交密码 —— 成功
  POST sentinel/req                                    (entry 440) → 新挑战
  POST /api/accounts/password/verify                   (entry 449, 200)
       body: {"password":"Tiv$fra5HNVnh*W0"}
       → 响应返回 continue_url=/mfa-challenge/... 与 oai-client-auth-session 对象

[阶段 7] MFA（TOTP 二次验证）
  POST /api/accounts/mfa/issue_challenge               (entry 489)
       {"id":"6ac5c502fea8819191edc40e2f016413","type":"totp","force_fresh_challenge":false}
  POST sentinel/req                                    (entry 497)
  POST /api/accounts/mfa/verify                        (entry 627, 200)
       {"id":"6ac5c502...","type":"totp","code":"678799"}
       → 响应给出 continue_url = chatgpt.com/api/auth/callback/openai?code=ac_4QUJ...&state=iJUv3oNoqN2q-...

[阶段 8] 授权码回调 —— 换会话
  GET /api/auth/callback/openai?code=ac_4QUJ2aT0EbZjC6DrDte2QYwYlGsDMTh90-K5MHcAXvQ.IsoIDmusR6ksuUyPI8_QPteD7QSjpA-gqry6eg7LX3w&scope=...&state=iJUv3oNoqN2q-...
       (entry 631) → 302 Location: https://chatgpt.com/       ← 此处下发会话 Cookie（本 HAR 未记录）
  GET https://chatgpt.com/                              (entry 633, 200, 632KB HTML)

[阶段 9] 登录后初始化（全部带 chatgpt-account-id / oai-did）
  GET  /backend-api/wham/accounts/check                (entry 669)
  GET  /backend-api/accounts/check/v4-2023-04-27       (entry 670)
  GET  /backend-api/models                             (entry 672)
  POST /backend-api/sentinel/chat-requirements/prepare (entry 674)  ← 第二套 sentinel 流程（对话用）
  GET  /backend-api/me                                 (entry 683)
  POST /backend-api/conversation/init                  (entry 691)
  POST /backend-api/sentinel/chat-requirements/finalize(entry 712)  ← 拿到对话准入 token
  GET  wss://ws.chatgpt.com/p6/ws/user/user-LkCB8Rih...?verify=1791970926-3y8iGP... (entry 792, 101)
```

> **两次 sentinel 流程的区分**：阶段 4/6/7 面向 `auth.openai.com`，用 `sentinel.openai.com/backend-api/sentinel/req` + 请求头 `openai-sentinel-token`，`flow` 取值 `password_verify`（MFA 阶段复用同一 SDK 实例与缓存）。阶段 9 面向 `chatgpt.com`，改用 `chatgpt.com/backend-api/sentinel/chat-requirements/{prepare,finalize}`，结果放在请求体里。两套共用同一份指纹载荷格式。

---

## 4. 逐项机制详解

### 4.1 CSRF 令牌（NextAuth）

| 项 | 值 |
|----|----|
| 获取 | `GET /api/auth/csrf`（entry 11）|
| 响应 | `{"csrfToken":"e24c435d4f1ddfe14d04a4132fe6ee63bd7fb868d4392cbf625e417c4cfac1f8"}` |
| 提交 | `POST /api/auth/signin/openai`（entry 12）请求体 `application/x-www-form-urlencoded`：`callbackUrl=...&csrfToken=<同值>&json=true` |
| 校验 | 服务端比对；`json=true` 使响应为 JSON（`{"url":"..."}`）而非 302，便于前端跳转 |

**观察**：`csrfToken` 是 64 位十六进制（32 字节随机数），与登录会话绑定；它保护的是 chatgpt.com 自己的 `signin` 端点，与后续 OpenAI 账号体系的 `state` 是两套独立机制。

### 4.2 OAuth 授权请求（关键参数逐个说明）

来自 entry 12 的响应体（服务端下发的完整 URL）与 entry 13 的实际跳转：

| 参数 | 值 | 作用 |
|------|-----|------|
| `client_id` | `app_X8zY6vW2pQ9tR3dE7nK1jL5gH` | ChatGPT Web 的 OAuth 客户端 ID |
| `response_type` | `code` | 授权码模式 |
| `redirect_uri` | `https://chatgpt.com/api/auth/callback/openai` | 回调地址（必须与注册值一致，否则拒绝）|
| `scope` | `openid email profile offline_access model.request model.read organization.read organization.write` | `offline_access`=要 refresh token；`model.*`/`organization.*` 是 ChatGPT 业务权限 |
| `audience` | `https://api.openai.com/v1` | 目标资源服务器 |
| `state` | `iJUv3oNoqN2q-gxChWbMJJj3xKZ_Vj1iVEvr0HEfa68` | **服务端生成的防 CSRF/防重放随机串**，回调时原样带回比对 |
| `device_id` / `ext-oai-did` | `57cab66a-0ad5-42c6-8d2d-2f2e9b2a8d28` | 设备标识，两处同值 |
| `prompt` / `screen_hint` | `login` / `login_or_signup` | 强制走登录页 |
| `login_hint` | `logo-pie2i@icloud.com` | 预填邮箱 |
| `auth_session_logging_id` | `2d5501de-1771-47ef-9ebb-be4eba2f4e86` | 贯穿 login_with → authorize → password/verify → mfa 的**会话日志与关联 ID**（服务端在 `oai-client-auth-session` 中回显）|
| `ccaps` | `login_methods chatgpt_login_finalizer_v1` | 客户端能力声明（capabilities），告知服务端前端支持哪些新流程 |
| `auth_return_target_category` | `chatgpt_home` | 登录后回跳目标分类 |

**观察**：请求中**没有 PKCE（`code_challenge`/`code_verifier`）**。安全边界依赖 `state` + 授权码一次性 + `redirect_uri` 白名单。

**设备 ID 的一致性链路**（同一 UUID 出现在 5 处，可 cross-check）：
`login_with?ext-oai-did=` → `signin/openai?ext-oai-did=` → `authorize?...&device_id=&ext-oai-did=` → `sentinel/req` 请求体 `id` → Sentinel 头 `id`。而 `sentinel/req` 里的 `id` 直接取自 **`oai-did` cookie**（SDK 源码：`t.id = En.getCookies()["oai-did"]`）。

### 4.3 Cloudflare 人机校验（本 HAR 里最容易被误读的一环）

**entry 285 是关键证据**：第一次 `password/verify` 返回 **403**，响应头包含

```
cf-mitigated: challenge
content-type: text/html; charset=UTF-8
content-security-policy: default-src 'none'; script-src 'nonce-...' 'unsafe-eval' https://challenges.cloudflare.com; ...
server: cloudflare
```

响应体是 Cloudflare 的 `Just a moment...` 挑战页。**随后**才发生：

| entry | 请求 | 说明 |
|-------|------|------|
| 296 | `GET /cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1?ray=...` | CF 挑战编排 |
| 297 | `GET challenges.cloudflare.com/turnstile/v0/g/4df4a60fa397/api.js?onload=...&render=explicit` | **Turnstile 组件**（sitekey `0x4AAAAAAADnPIDROrmt1Wwj` 见 entry 300）|
| 299/308 | `POST auth.openai.com/cdn-cgi/challenge-platform/h/g/fo/883959597:1791969322:...` | 挑战答案上报（含时间戳与签名路径）|
| 300 | `GET .../turnstile/f/av0/rch/ch8jc/0x4AAAAAAADnPIDROrmt1Wwj/light/fbE/new/normal` | Turnstile 渲染 |
| 302/306/307 | `POST challenges.cloudflare.com/cdn-cgi/challenge-platform/h/g/fo/2579014096:1791969325:...` | 指纹/行为上报 |
| 304 | `GET .../pat/...` → **401** | 中间态失败（CF 内部），随后重试 |
| 305 | `GET .../ci/...` → 200 | 校验完成 |
| 309 | `POST /log-in/password` → 200 | 校验通过，重新加载登录页 |

**结论**：`password/verify` 的 403 **不是密码错误**，而是 Cloudflare 在边缘拦截并要求人机校验。这与 Sentinel 的 PoW 是**两套并存**的机制：CF 在网关层，Sentinel 在应用层。

### 4.4 Sentinel SDK 的加载与运行位置

| entry | 资源 | 说明 |
|-------|------|------|
| 103 / 396 | `sentinel.openai.com/backend-api/sentinel/sdk.js`（1482 B）| **引导脚本**：定义 `window.__sentinel_token_pending` / `__sentinel_init_pending` / `window.SentinelSDK` 占位对象，把业务方的调用排队 |
| 248 / 430 | `sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260810913b`（121 B）| **iframe 壳**：`<script src='https://sentinel.openai.com/sentinel/20260810913b/sdk.js'>` |
| 126 / 270 / 417 / 435 | `sentinel.openai.com/sentinel/20260810913b/sdk.js`（33820 B）| **真正干活的 SDK**（字符串数组混淆，版本号 `20260810913b` 硬编码在路径里）|

SDK 公开 API（从其尾部导出对象读出）：

```js
window.SentinelSDK = {
  init,                  // 初始化
  requirementsToken,     // 取缓存的 "requirements token"（未解出时返回 null）
  sessionObserverToken,  // 取 session observer token（本 HAR 中 auth 侧未启用）
  timing,                // 暴露耗时数据
  token,                 // 主入口：异步取得完整 token（本 HAR 的调用路径）
}
```

对 iframe 的判断逻辑（源码还原）：

```js
const isInIframe = (() => {
  if (window.frameElement === window) return false;
  try { const u = new URL(window.location.href); return KNOB.origin === u.origin; } catch { return false; }
})();
// requirementsToken() 在 iframe 内调用会抛错： "...should not be called from within an iframe."
```

即：**PoW 计算发生在 sentinel.openai.com 的 iframe 内**（同源隔离，业务页面拿不到计算细节），结果通过 `postMessage` 回传。这也解释了为什么 HAR 里所有 `/sentinel/req` 请求的 `Origin/Referer` 都是 `https://sentinel.openai.com/...`（entry 275/440/497 的请求头可验证）。

### 4.5 指纹载荷 `p` —— 结构被逐字节还原

#### 4.5.1 外观

```json
{"p":"gAAAAACWzMwMDAsIldlZCBPY3QgMTQgMjAyNiAxNzozOTo0MSBHTVQrMDgwMCAo5Lit5Zu95qCH5YeG5pe26Ze0KSIs...wwXQ==~S",
 "id":"57cab66a-0ad5-42c6-8d2d-2f2e9b2a8d28",
 "flow":"password_verify"}
```

#### 4.5.2 解码规则（已对 5 个真实样本逐字节验证）

```
p = <7 字符前缀> + <标准 base64> [+ "~S"]
                  └─ base64(UTF-8(JSON.stringify(25 元素数组)))
```

* 前缀两种取值，来自 SDK 里硬编码的字符串常量：
  * `"gAAAAAB"` —— **本次新解出的答案**（用在 `finalize.proofofwork` 与 `openai-sentinel-token.p`）—— 对应 `getRequirementsTokenBlocking()`；求解函数返回 `"gAAAAAB" + answer`，而 `answer = base64(载荷) + "~S"`，故该前缀**必然伴随 ~S**。
  * `"gAAAAAC"` —— **缓存读取的 requirements token**（用在 `chat-requirements/prepare` 的 `p`）—— 对应 `getRequirementsToken()`：`"gAAAAAC" + store.get("requirementsSeed")`。是否带 `~S` **取决于缓存内容的来历**：首次生成（从未参与解题）时不带（本 HAR 三次 `chat-requirements/prepare` 的 `p` 均如此，字段 `[3]=1`）；而 `auth.openai.com` 侧 `/sentinel/req` 请求体里的 `p` **带 `~S`**（entry 275/440/497），因为那是上一轮已解出、仍在 540 秒 TTL 内的缓存值。
  * 两者 base64 解码后前 5 字节都是 `80 00 00 00 00`，是 **Fernet 风格版本头**（`0x80` + 类型判别位）；第 7 个字符即判别位的 base64 表现（`gAAAAAB` 补位解码后第 6 字节为 `0x40`，`gAAAAAC` 为 `0x80`）。
* 前缀**不是 base64 流的一部分**：SDK 源码是用字符串拼接把 7 字符常量**前置**到一份独立编码的 base64 之上（`"gAAAAAC" + b64(json)`），而不是"二进制头 + JSON 一起编码"。因此解析时必须**先去掉 7 个字符**，余下部分长度恰为 4 的倍数，按标准 base64 解码即得 JSON。
* `~S` 是**"已解出（solved）"后缀标记**，只有经过 PoW 求解的载荷才带。
* 由于前缀恰好是 7 字符（非 4 的倍数），**整个字符串单独做 base64 解码会失败**（`number of data characters (601) cannot be 1 more than a multiple of 4`）—— 这是一个可用于识别该格式的特征。正确做法是**去掉前 7 字符**再解码。

#### 4.5.3 载荷 25 个字段的含义（取自真实样本，`entry 674` 请求体）

| idx | 样本值 | 含义（含推断）|
|-----|--------|------|
| 0 | `3000` | 格式版本号 |
| 1 | `"Wed Oct 14 2026 17:42:03 GMT+0800 (中国标准时间)"` | `new Date().toString()`，本地时区字符串 |
| 2 | `4377018368` | 屏幕相关常量（样本中恒定）|
| 3 | `1` / `11` / `21` / `40` / `42` | **PoW 计数器**（见 §4.7，已验证）|
| 4 | `"Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/154.0.0.0 Safari/537.36"` | `navigator.userAgent` |
| 5 | `null` 或 `"https://chatgpt.com/cdn-cgi/challenge-platform/scripts/jsd/api.js?onload=jsdOnload"` | 当前脚本/CF JSD 探针地址 |
| 6 | `"132f33eb272ff65e6bd412b5f3578ab9b3f322cb"` | 常量指纹串（样本中恒定，疑为构建/版本标识）|
| 7 | `"zh-CN"` | `navigator.language` |
| 8 | `"zh-CN,zh"` | `navigator.languages.join(",")` |
| 9 | 浮点或整数（`2.200000047683716` / `4` / `6`）| **计时/噪声字段**：解出时被写入 `Math.round(performance.now()-t0)`（毫秒），未解出时是原始浮点 |
| 10 | `"login−[object NavigatorLogin]"` 等 | **随机抽取的"环境属性"样本**：每次调用随机挑一个 navigator/window 属性名并拼接其值 |
| 11 | `"__reactContainer$3qng6006zy4"` / `"_reactListeningipu1ujrcui9"` | 随机抽取的 DOM 内部属性名（React 运行时痕迹）|
| 12 | `"length"` / `"onslotchange"` / `"customElements"` | 随机抽取的事件/属性名 |
| 13 | `9237.100000023842` / `107030.5` | 随机时间量（疑似 `performance` 某指标）|
| 14 | `"a4b93372-589a-4feb-8dfc-ccb2c254c645"` | 每次调用新生成的 UUID（随机性来源）|
| 15 | `""` | 空串占位 |
| 16 | `8` | `navigator.hardwareConcurrency`（本机 8 核）|
| 17 | `1791970913987.2` | 页面 `timeOrigin` 类时间戳 |
| 18–24 | `0,0,0,0,0,0,0` | 保留位（本次抓包全程为 0）|

> **设计意图（推断）**：字段 10~14 每次调用都从大池子里随机挑选 —— 这是**刻意的反指纹稳定性设计**：真实浏览器的这些属性组合本就随机，脚本化重放很难复现同一分布；服务端可据此评估"像不像真人浏览器"。

#### 4.5.4 编码函数（SDK 源码还原）

```js
function b64_of_json(t) {                       // SDK 内部函数 _()
  t = JSON.stringify(t);
  return window.TextEncoder
    ? btoa(String.fromCharCode(...new TextEncoder().encode(t)))   // 先 UTF-8 再 btoa
    : btoa(unescape(encodeURIComponent(t)));
}
```

> 注意 `String.fromCharCode(...bytes)` 的展开写法：载荷较大时理论上存在栈溢出风险，实测 700 字符左右无碍。

### 4.6 服务端挑战：`/sentinel/req` 的请求与响应

**请求**（entry 275，`Content-Type: text/plain;charset=UTF-8`，`Origin/Referer` 均为 `https://sentinel.openai.com/...`）：

```json
{"p":"gAAAAACWzMwMDAs...wwXQ==~S","id":"57cab66a-0ad5-42c6-8d2d-2f2e9b2a8d28","flow":"password_verify"}
```

**响应**（200，`application/json`，27 KB）：

```json
{
  "persona": "chatgpt-noauth",
  "token": "gAAAAABqz03pMARmsYF_N7_rQj5oOW3haIrY_vOJRcFWWaK_...oeVqgdZwDEEDKPyfUfHF",
  "expire_after": 540,
  "expire_at": 1791971333,
  "turnstile":  { "required": true, "dx": "PBp5bWFwcXlDf1ttfBxfaTdVXnR6cHx5BX9ffnhxVng3..." },
  "proofofwork":{ "required": true, "seed": "0.4087385554133105", "difficulty": "069cee" }
}
```

| 字段 | 作用 |
|------|------|
| `persona` | 当前身份画像：未登录 = `chatgpt-noauth`；登录后 = `chatgpt-freeaccount` |
| `token` | **服务端签发的 Fernet 令牌**（见 §4.9），客户端必须原样回传（在头的 `c` 字段）|
| `expire_after` / `expire_at` | 有效期 540 秒（9 分钟）与绝对到期时间戳 |
| `turnstile.required` + `dx` | **要求提交一轮环境探针采集**；`dx` 是本轮"要采集哪些项"的指令载荷（20~24 KB 混淆密文，未能解开）。⚠️ 字段名沿用了 "turnstile"，但内容是 OpenAI 自己的采集通道，**与网关层的 Cloudflare Turnstile 是两回事**（后者见 §4.3）|
| `proofofwork.required/seed/difficulty` | 要求完成工作量证明；`seed` 是随机浮点串，`difficulty` 是 **6 位十六进制阈值** |

本 HAR 三次挑战的实测参数：

| 挑战来源 | seed | difficulty | 阈值十进制 | 单次尝试通过率 |
|----------|------|-----------|-----------|---------------|
| entry 275 | `0.4087385554133105` | `069cee` | 433390 | 2.583% |
| entry 440 | `0.4968081291607215` | `061a80` | 400000 | 2.384% |
| entry 497 | `0.15530849575293793` | `07a120` | 500000 | 2.980% |

> 通过率 = `0x0NNNNN / 0x1000000`，即期望尝试次数 ≈ 34~42 次。这是"**轻量 PoW**"：足以劝退无脑脚本重放，但正常浏览器 <10 ms 即可完成。

### 4.7 工作量证明 PoW —— 算法完整还原并实测通过

#### 4.7.1 SDK 源码（从混淆代码中还原，变量名已语义化）

```js
class AnswerGenerator {
  answers   = new Map();
  maxAttempts = 5e5;                         // 上限 50 万次

  // 单次尝试：t0=起始时间, seed, difficulty, payload=指纹数组, counter
  attempt = (t0, seed, difficulty, payload, counter) => {
    payload[3] = counter;                                          // ← 计数器写入字段 3
    payload[9] = Math.round(performance.now() - t0);                // ← 已耗时(ms)写入字段 9
    const b64 = b64_of_json(payload);                               // 载荷 base64
    const h   = fnv1aMix(seed + b64);                               // ← 哈希输入 = seed 字符串 + base64 载荷
    return h.substring(0, difficulty.length) <= difficulty          // ← 字典序比较，等价于十六进制数值比较
      ? b64 + "~S"                                                  // 命中：返回 base64 + "~S"
      : null;
  };

  _generateAnswerSync(seed, difficulty) {
    const t0 = performance.now();
    const payload = this.buildFingerprint();                        // 25 字段指纹数组
    for (let c = 0; c < this.maxAttempts; c++) {
      const ans = this.attempt(t0, seed, difficulty, payload, c);   // 从 c=0 开始递增
      if (ans) return ans;
    }
    return this.errorToken(...);                                    // 失败时返回 wQ8Lk5... + b64(错误信息)
  }
}

// 哈希：FNV-1a 32 位 + murmur 风格雪崩混合，输出 8 位小写十六进制
function fnv1aMix(str) {
  let e = 2166136261;
  for (let i = 0; i < str.length; i++) {
    e ^= str.charCodeAt(i);
    e = Math.imul(e, 16777619) >>> 0;
  }
  e ^= e >>> 16;
  e = Math.imul(e, 2246822507) >>> 0;
  e ^= e >>> 13;
  e = Math.imul(e, 3266489909) >>> 0;
  e ^= e >>> 16;
  return (e >>> 0).toString(16).padStart(8, "0");
}
```

外层包装：

```js
solve(challenge, forceSync) {
  const { seed, difficulty } = challenge.proofofwork;
  // …缓存命中则直接返回
  const answer = this._generateAnswerSync(seed, difficulty);
  return "gAAAAAB" + answer;        // ← 前缀在此外加
}
```

#### 4.7.2 用真实抓包数据验算（5/5 通过）

把 HAR 中**实际提交的答案**取出，按上述公式重算：

| 来源 | seed | difficulty | 载荷字段[3] | `H(seed + b64)` 前 6 位 | 判定 |
|------|------|-----------|------------|------------------------|------|
| chat HAR entry 31 | `0.2250343410955007` | `06b983` | 40 | `009b70` | `009b70 ≤ 06b983` ✅ |
| image HAR entry 14 | `0.8625556315869432` | `07a120` | 13 | `025bd1` | `025bd1 ≤ 07a120` ✅ |
| login HAR entry 712 | `0.9208149957912333` | `07a120` | 11 | `001e37` | `001e37 ≤ 07a120` ✅ |
| login HAR header[285] | `0.4087385554133105` | `069cee` | 21 | `057ce0` | `057ce0 ≤ 069cee` ✅ |
| login HAR header[449] | `0.4968081291607215` | `061a80` | 42 | `03dad0` | `03dad0 ≤ 061a80` ✅ |

另外还验证了两件事：

1. **载荷格式无误**：将抓包中的载荷 JSON 反序列化后按上述规则**重新编码**，与抓包原文 base64 **逐字节相同（5/5）**。
2. **计数器语义**：字段 `[3]` 命中值分别为 11/13/21/40/42，与 2.4%~3.0% 的单次通过率相符（期望 ~34 次）。注意由于字段 `[9]`（已耗时 ms）也参与哈希，**每毫秒载荷都在变**，所以"最小通过计数器"不能脱离时间戳复现 —— 这正是该实现的一个巧妙之处。

#### 4.7.3 为什么这样设计（推断）

* 哈希输入包含**整份指纹**（base64 后 ~500-700 字符），意味着解题过程必须持有真实指纹，无法用短随机数代替；
* 阈值只有 6 位十六进制（约 1/34 的中签率）→ 客户端开销可忽略，但配合 `expire_after=540` 与 `dx` 采集指令，服务端获得了**每次请求一次的行为采样点**；
* 真正的门槛在 Turnstile 与指纹真实性，PoW 只是"低成本的诚意证明"。

### 4.8 `openai-sentinel-token` 头的组装（auth.openai.com 专用）

真实值（entry 449，已截断长字段）：

```json
{
  "p":    "gAAAAABWzMwMDAsIldlZCBPY3QgMTQgMjAyNiAxNzo0MTowOCBHTVQrMDgwMCAo...wwXQ==~S",
  "t":    "TxQZGgYGFBQWdHZRdhYaFgcfGgAGFBQWeXBVW3lMUwsMGBQAAAAEDhYMDHV3dXdvdXd1...CwkUUw==",
  "c":    "gAAAAABqz041byY4R_2p-Lp0Sz_62sDTjjXxduF1_Sz2Hz5dR3cpyZNUbPmEhtZyfuxwEP...RCHm2w==",
  "id":   "57cab66a-0ad5-42c6-8d2d-2f2e9b2a8d28",
  "flow": "password_verify"
}
```

| 字段 | 内容 | 证据/置信度 |
|------|------|------------|
| `p` | **PoW 答案**：`"gAAAAAB" + b64(指纹数组, [3]=计数器) + "~S"` | **已验证**（§4.7.2）|
| `c` | **服务端签发的挑战令牌**：与 `/sentinel/req` 响应的 `token` **逐字节相同**（entry 275→285、440→449 两组均验证 `identical bytes? True`）| **已验证** |
| `t` | **`base64( XOR( JSON 答案集, 密钥 ) )` —— 环境探针采集的答案表**（不是 Cloudflare Turnstile 令牌）| **已解密**（§4.8.1）|
| `id` | = `oai-did` cookie 的值（SDK 源码：`t.id = En.getCookies()["oai-did"]`）| **已验证** |
| `flow` | 调用方传入的流程名，本 HAR 均为 `password_verify` | 已验证 |

`t` 的编码方式（SDK 源码还原）：

```js
function xorString(str, key) {          // SDK 内部函数 Pn/_t
  let out = "";
  for (let i = 0; i < str.length; i++)
    out += String.fromCharCode(str.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  return out;
}
// 读取（SDK 内部）：
JSON.parse(xorString(atob(value), String(cookieStore.get(KEY_NAME))));
```

即 `value = base64( XOR( JSON字符串, 密钥 ) )`，密钥按字节循环使用。它不是 Fernet（不含 `0x80` 头）。

> **LS 补充实测（§4.13.6）**：该头**只出现在 `POST /api/accounts/password/verify` 一处**（`LS[288]`，4260 字符；MFA 的两步都不带）；而 `/sentinel/req` 的 POST 用的是 `Content-Type: text/plain;charset=UTF-8`（不是 JSON），body 为 `{"p": "gAAAAAC…"}`。LS 该轮 `t` 的 XOR 密钥为 **`4.07`**（15 项探针），已排除来自 Cookie / `oai-sc` / 指纹载荷 —— 见 §7 第 2 条。

### 4.8.1 `t` / `turnstile` 已被解密（本轮分析的重大突破）

**解密方法**（不依赖任何密钥字典）：明文是 JSON，因此首字节必为 `{` 或 `[`；又因为明文是纯 ASCII，可对每个"密钥列"施加"异或结果必须落在 `0x20~0x7e`"的约束。据此枚举密钥长度 L，逐列求交集，再用 `JSON.parse` 验证即可唯一还原密钥与明文。

**已解出的全部 5 个 blob**（三份 HAR 覆盖）：

| blob | 长度 | **XOR 密钥** | 解密后条目数 |
|------|------|-------------|-------------|
| `login[285]` 头 `t` | 1088 B | **`17.41`** | 16 |
| `login[449]` 头 `t` | 1063 B | **`46.46`** | 15 |
| `login[712]` finalize `turnstile` | 1304 B | **`70.41`** | 24 |
| `chat[4]` 头 `turnstile-token`（与上一行**逐字节相同**）| 1304 B | `70.41` | 24 |
| `chat[31]` finalize `turnstile` | 1370 B | **`27.27`** | 24 |
| `image[8]` 头 `turnstile-token`（与上一行**逐字节相同**）| 1370 B | `27.27` | 24 |
| `image[14]` finalize `turnstile` | 1315 B | **`90.31`** | 22 |
| 补充抓包 `[6]` 头 `turnstile-token` | 1720 B | **`64.8`** | 23 |
| 图片补充抓包 `[4]` finalize `turnstile` | 1728 B | **`97.63`** | 21 |
| 多轮补充抓包 `[4]` finalize `turnstile` | 1824 B | **`31.99`** | 23 |
| 多轮补充抓包 `[12]` finalize `turnstile` | 1744 B | **`3.74`** | 22 |

> 密钥形如 `NN.NN`（或 `NN.N`）的短十进制数，**每一轮都不同**（`17.41` / `46.46` / `70.41` / `27.27` / `90.31` / `64.8` / `97.63` / `31.99` / `3.74`）。**来源仍未确定**，已排除的假设：① 五份 HAR 原文里都不存在这些字面串；② 补充抓包中 23 个 cookie 的值都不等于也不包含密钥；③ prepare/finalize 响应的明文字段里没有（已用正则穷举 `\d{1,3}\.\d{1,2}`，0 命中）；④ 不是 `dx`/`collector_dx`/`prepare_token`/`token` 经 FNV 混合派生的常见格式；⑤ 不是 `oai-sc` 内嵌时间戳的简单函数（已试 `ts%100`、`(ts//10)%100.ts%100`、`ts%1000/10` 等公式，均不命中）。**当前最合理的解释（推断）**：客户端能用 SDK 内嵌密钥解出 `dx`，而 `dx` 里除问卷外还带着本轮的答案密钥；服务端自己生成 `dx`，因此双方共享该密钥。

**明文结构**（`login[285]` 为例，键为 `"探针号.答案号"`）：

```
'41.05'  = {"availWidth":1920,"availHeight":1032,"availLeft":0,"availTop":0,
            "colorDepth":24,"height":1080,"width":1920,"pixelDepth":24}     ← 屏幕几何
'98.82'  = ["Google Inc.","Win32",8,10]                                      ← vendor/platform/核数/内存
'21.33'  = {"x":0,"y":525.75,"width":33.25,"height":22,"top":525.75,
            "right":33.25,"bottom":547.75,"left":0}                          ← DOM 元素 getBoundingClientRect
'35.51'  = 0.9265087602572634                                                ← 浮点测量值
'90.9'   = "AAAAAA=="          '12.79' = <19 字节全 0>                       ← 占位/空样本
'23.47'  = <187 字节二进制>     '92.07' = <121 字节二进制>                    ← 疑似哈希类样本
'22.84' / '28.25' = ""                                                       ← 空字符串
```

`login[712]`/`chat[4]` 那一份（24 项）另含 `'22.71' = 10737786880`（≈10 GiB，与 `performance.memory.jsHeapSizeLimit` 量级一致）、`'39.18' = 368640`、`'79.82'/'96.17' = true`、以及 12/18/20/82/178 字节的二进制样本。

**结论修正**：`t` / `turnstile` **不是** Cloudflare Turnstile 的响应令牌，而是**服务端下发的一组环境/行为探针的答案表**（键为"探针编号.答案编号"）。不同轮次的探针编号集合基本不同（如 login[285] 的 16 项与 chat[31] 的 24 项交集很小），这与挑战里 `turnstile.dx`（约 20~24 KB 的指令密文）"本轮要采集哪些项"的定位吻合：`dx` 下发问卷 → 客户端作答 → 答案 XOR 加密后回传。这也解释了为什么 `estuary`/`turnstile` 这类字段名容易误导：**OpenAI 复用了 "turnstile" 这个名字来指代自己的采集通道**。

**仍未解开的部分**：`dx` 与 `so.collector_dx`（20~24 KB）**解不开**——已排除"短周期密钥 XOR"（对 2~160 的所有密钥长度施加严格 ASCII 列约束均无解），说明它用了更强的方案（更长的随机密钥或流密码）。可观察到它们的前 5 字节在全部 6 个样本中恒定（`3c 1a 79 6d 61`），提示明文有恒定的 JSON 前缀。

> 配套工具：`tools/sentinel-hook.js`（浏览器 Console 脚本）可直接在真实会话里抓取并自动解密 `t`/`turnstile`，也能解出 `p`/`proofofwork` 的 25 字段载荷并识别 Fernet 令牌。全部逻辑已用本 HAR 的真实样本自测 **16/16 通过**。

### 4.9 Fernet 令牌（`token` / `c`）的结构

对 entry 275 的 `token` 做 base64 解码，得到 1689 字节：

```
version  = 0x80                     (Fernet v0x80 版本标记)
timestamp= 1791970793               (8 字节大端 Unix 时间戳；与抓包时刻吻合)
iv       = 300466b1817f37bf...      (16 字节 AES-CBC IV)
body     = 1632 字节密文
hmac     = d817ab8239825d5f542824be... (末 32 字节 HMAC-SHA256 校验)
```

entry 440 的 `token` 同理：`version=0x80`, `timestamp=1791970869`, 1609 字节。

**要点**：这是**服务端密钥加密的不透明令牌**，客户端只能缓存与回传，无法解析或伪造。它与 PoW 答案 `p`、探针答案表 `t` 三者绑定成一次"准入凭证"，一起送给 `password/verify`。

### 4.10 MFA（TOTP）

| 步骤 | entry | 请求 | 响应关键字段 |
|------|-------|------|-------------|
| 下发挑战 | 489 | `POST /api/accounts/mfa/issue_challenge`<br>`{"id":"6ac5c502fea8819191edc40e2f016413","type":"totp","force_fresh_challenge":false}` | `oai-client-auth-session.mfa_challenge_factors[0] = {"factor_type":"totp","id":"6ac5c502...","is_recovery":false}`，并记录 `metadata.challenge_issue_count:1` |
| 取新挑战 | 497 | `POST sentinel/req`（`flow: password_verify`）| 同一套 sentinel 流程复用 |
| 校验 | 627 | `POST /api/accounts/mfa/verify`<br>`{"id":"6ac5c502...","type":"totp","code":"678799"}` | **200**，返回 `continue_url = https://chatgpt.com/api/auth/callback/openai?code=ac_4QUJ...&state=...` |

**观察**：
* MFA 的 `factor_id` 由服务端下发（不是客户端生成），`type: totp` 表示 6 位动态口令；
* `force_fresh_challenge:false` 允许复用已有挑战（避免频繁下发）；
* MFA 提交**没有再带** `openai-sentinel-token` 头（对比 entry 449 有、entry 627 无），说明 Sentinel 头只在"密码校验"这一步被强制要求；
* `code` 是明文 6 位数字 —— 该端点依赖已建立的 `authsess_*` 会话（见下）而非额外签名。

**贯穿会话的 `oai-client-auth-session` 对象**（首次出现在 entry 449 响应，之后 489/627 持续回显）：

```json
{
  "app_name_enum": "chat",
  "auth_session_logging_id": "2d5501de-1771-47ef-9ebb-be4eba2f4e86",
  "country_code_hint": "GB",
  "destination_app_name": "ChatGPT Web",
  "openai_client_id": "app_X8zY6vW2pQ9tR3dE7nK1jL5gH",
  "original_screen_hint": "login_or_signup",
  "passwordless_disabled": true,
  "requested_oauth_scopes": ["email","model.read","model.request","offline_access","openid","organization.read","organization.write","profile"],
  "session_id": "authsess_BICQKpxVaIzNjfoZVJsXDMoI",
  "username": {"kind":"email","value":"logo-pie2i@icloud.com"},
  "mfa_factors": [{"id":"6ac5c502...","factor_type":"totp","is_recovery":false}]
}
```

`session_id = authsess_...` 是**服务端会话标识**，绑定整条登录会话（cookie 未记录，但其存在可由该对象回显推断）。

### 4.11 授权码与 state 的回调校验

```
entry 627 → continue_url:
  https://chatgpt.com/api/auth/callback/openai
    ?code=ac_4QUJ2aT0EbZjC6DrDte2QYwYlGsDMTh90-K5MHcAXvQ.IsoIDmusR6ksuUyPI8_QPteD7QSjpA-gqry6eg7LX3w
    &scope=openid+email+profile+offline_access+model.request+model.read+organization.read+organization.write
    &state=iJUv3oNoqN2q-gxChWbMJJj3xKZ_Vj1iVEvr0HEfa68

entry 631 → GET 上述 URL → 302  Location: https://chatgpt.com/
```

* `code` 形如 `ac_<base64url>.<base64url>`（两段结构，第二段 43 字符 ≈ 32 字节，疑似绑定/证明段）；
* `state` 与 entry 13 授权请求中的 `state` **完全一致** → 服务端据此完成 CSRF 校验；
* 登录成功后回跳 `https://chatgpt.com/`，**会话 Cookie 在此响应下发**（本 HAR 未记录，但 entry 633 之后所有 `/backend-api/*` 均成功即为证据）。

### 4.12 登录后请求的鉴权契约

> **重要更正（依据补充抓包 `chatgpt_chat_包含敏感数据.har`）**：本文早期版本根据原始三份 HAR 得出"Web 端不使用 Bearer Token、纯 Cookie 会话"的结论 —— **这是错的**。那三份 HAR 是导出工具**脱敏版**（`Cookie` 与 `Authorization` 头都被裁掉），并非客户端没发。补充抓包（含敏感数据）显示：**每个 `/backend-api/*` 请求同时携带 Cookie 与 `Authorization: Bearer <OIDC 访问令牌>`**。以下为更正后的完整契约。

#### 4.12.1 `Authorization: Bearer` —— OIDC 访问令牌（RS256 JWT）

补充抓包中 14 条请求全部携带，且**全程同一个 token**（2076 字符，三段 106/1619/342）：

```
header : {"alg":"RS256","kid":"qAgbfguRn1QO32qNOWHKNrFKMOwSew1TamFZPCI78HQ","typ":"JWT"}
签名   : 256 字节（RSA-2048）
payload（节选，敏感值已在本文中脱敏）:
  iss = "https://auth.openai.com"
  aud = ["https://api.openai.com/v1"]
  client_id = "app_X8zY6vW2pQ9tR3dE7nK1jL5gH"        ← 与 §4.2 授权请求同一 client_id
  sub = "auth0|<账号主体>"                             ← Auth0 体系的用户主体
  scp = ["openid","email","profile","offline_access",
         "model.request","model.read","organization.read","organization.write"]
                                                      ← 与 §4.2 请求的 scope 完全一致
  "https://api.openai.com/auth" = {
      "amr": ["pwd","urn:openai:amr:password","otp","mfa","urn:openai:amr:otp_totp"],
      "chatgpt_login_finalizer_auth_session_id": "authsess_BICQKpxVaIzNjfoZVJsXDMoI",
      "chatgpt_account_id": "edebbcbb-3f1d-4963-8ec1-54810e3f2c44",
      "chatgpt_account_user_id": "<user_id>__<account_id>",
      "chatgpt_plan_type": "free", "chatgpt_data_residency": "no_constraint", ... }
  "https://api.openai.com/mfa" = {"required": "yes"}
  "https://api.openai.com/profile" = {"email":"logo-pie2i@icloud.com","email_verified":true,...}
  pwd_auth_time = 1791970911733   (2026-10-14T09:41:51Z，即 MFA 通过时刻)
  iat/nbf = 1791970917 (09:41:57Z)   exp = 1792834916 (10 天后)
  jti = "051ce03793154b7899bdfaad6c331c5b"   session_id = "authsess_BICQKpxVaIzNjfoZVJsXDMoI"
```

**这条 JWT 把登录流程与业务会话完全焊死了**：
* `chatgpt_login_finalizer_auth_session_id` / `session_id` = `authsess_BICQKpxVaIzNjfoZVJsXDMoI` —— **正是登录 HAR 里 `oai-client-auth-session.session_id` 的值**（见 §4.10）；
* `scp` 与 §4.2 授权请求的 `scope` 一一对应；`amr` 与登录时的密码 + TOTP 一致；
* `pwd_auth_time` ≈ 登录 HAR `entry 627`（`mfa/verify` 200）的时刻；
* `chatgpt_account_id` = 业务请求头 `chatgpt-account-id` 的值；`chatgpt_plan_type` = `wham/usage` 里的 `free`。

**有效期 10 天**（`exp - iat ≈ 864000s`），与下一节的会话 Cookie 并存 —— 即 Web 客户端是**双凭据**模型：Cookie 承载 NextAuth 会话，Bearer 承载对 `api.openai.com` 域的 OAuth 授权。

#### 4.12.2 Cookie 清单（补充抓包，22 个，每个请求全量携带）

| Cookie | 长度 | 性质 | 说明 |
|--------|------|------|------|
| `__Secure-next-auth.session-token.0` / `.1` | 3933 / 416 | **会话凭据（核心）** | NextAuth v5 加密会话 Cookie，因超过 4 KB 被**分片**成两段；`.0` 是 JWE，头部 `{"alg":"dir","enc":"A256GCM"}`（4 段：39/0/16/3875 字符），密文 2906 字节 → **服务端密钥加密，客户端不可解析** |
| `cf_clearance` | 511 | Cloudflare 通行证 | 网关层人机校验通过后签发（对应 §4.3）；**这是纯脚本方案最难绕过的一环** |
| `__cf_bm` / `__cflb` / `_cfuvid` | 199 / 43 / 114 | Cloudflare 机器人管理 | 边缘层风控与会话粘滞 |
| `oai-sc` | 248 | **Sentinel 采集 Cookie** | 前缀 `0` + Fernet 令牌（`0x80` 版本 + 时间戳），由 `chat-requirements/{prepare,finalize}` **响应 Set-Cookie 下发**，`Domain=.chatgpt.com; Max-Age=31536000`（1 年）、**非 HttpOnly**（前端 JS 可读）。**每一轮 sentinel 调用都会重新签发**：补充抓包实测 `prepare` 与 `finalize` 各下发一次、相差 1 秒（10:44:13 / 10:44:14），请求携带的则是"上一次收到的那一份"（10:42:53 签发）→ 说明它是**按轮轮换的采集用材料**（与 §4.8.1 的每轮不同 XOR 密钥相呼应，但**未证明**二者是同一来源）|
| `oai-did` | 36 | 设备 ID | 与请求头 `oai-did`、指纹载荷 `id` 同值 |
| `__Host-next-auth.csrf-token` | 131 | CSRF | 与 `/api/auth/csrf` 返回值同源 |
| `__Secure-next-auth.callback-url` | 28 | 登录回跳 | NextAuth |
| `oai-client-session-epoch` | 36 | 会话纪元 UUID | 可用于识别"同一登录会话" |
| `__oailb` | 317 | **边缘路由票据** | ES256 JWT，`kid=oailb-v1`，载荷可见 `{"host":"chat.gateway.unified-186.api.openai.com", ...}` |
| `_account` / `_account_is_fedramp` | 8 / 5 | 账号切换 | `personal` / `false` |
| `g_state` | 140 | Google 登录状态 | 第三方 |
| `oai-hlib` / `oai_pl_permission_state` / `codex_sidebar_width` / `oai-mweb-route` / `oai-mweb-origin` | 4~5 | UI 状态 | 与鉴权无关 |
| `_dd_s_v2` | 127 | Datadog | 遥测采样 |
| `_uasid` / `_umsid` | 478 / 334 | **本会话新签发** | 由 `POST /backend-api/f/conversation` 的响应 Set-Cookie 下发：`HttpOnly; Path=/; SameSite=none; Secure; expires=+30min` |

**观察**：会话 Cookie 采用 NextAuth 的**分片方案**（`.0`/`.1`）而非单条大 Cookie —— 这解释了为什么抓包工具若不展开 `cookies[]` 数组、只看 `Cookie` 头会难以完整还原（单条 Cookie 上限约 4096 字节）。

#### 4.12.3 其余标识头

| 头 | 值 | 作用 |
|----|----|------|
| `chatgpt-account-id` | `edebbcbb-3f1d-4963-8ec1-54810e3f2c44` | **账号/工作区 ID**，业务 API 的租户隔离键（login HAR 中首次出现于 entry 669；与 JWT 的 `chatgpt_account_id` 一致）|
| `oai-did` | `57cab66a-0ad5-42c6-8d2d-2f2e9b2a8d28` | 设备 ID（与登录前一致）|
| `oai-language` | `en`（entry 669）→ `zh-CN`（entry 679 起）| 界面语言 |
| `originator` | `Codex Browser` | 客户端来源标识（这套抓包来自 Codex 内嵌浏览器）|
| `oai-app-brand` / `oai-product-sku` / `oai-ep-cache-bypass` | `chatgpt` / `PROMPT_TEXT_AREA` / `true` | 产品与缓存控制 |
| `OAI-Session-Id` | `a8840729-2f5f-4eba-8d96-32c8404c5bb3` | 会话级 UUID（出现在 entry 0，即登录前也有）|

> 关于 `access-control-allow-headers: "Content-Type, Authorization"`（login HAR 里 175 次响应头）：它说明服务端**允许**客户端发 `Authorization`；补充抓包证明客户端**确实在发** —— 之前的"允许但不使用"判断是脱敏造成的误读。

**WebSocket 准入**（login HAR entry 792）：`wss://ws.chatgpt.com/p6/ws/user/user-LkCB8RihStg7myaLj2HRube6?verify=1791970926-3y8iGP%252F0sgTm52SM7t2Y%252Bqj1yMqY%252BOrflsuF2ZQUc7U%253D`
—— `user-<随机ID>` 路径段 + **带过期时间戳的 `verify` 签名**（`1791970926` 为 Unix 秒），即 WebSocket 也有独立的、短时效的准入签名。

### 4.13 会话建立与 Cookie 全生命周期（依据登录敏感抓包）

**证据**：`chatgpt_login_包含敏感数据.har`（552 条，`2026-10-14T11:25:11Z` ~ `11:26:38Z`，本文简称 **LS**）。该抓包把此前所有"凭据不可见"的空白一次补齐：**325 条 Set-Cookie**、Cookie 全量、auth 域上的完整认证链。

#### 4.13.1 三个域 = 三套互不相通的 Cookie 罐

实测：每个请求携带的 Cookie **严格按域匹配**（`cookies[]` 数组与原始 `Cookie` 头逐条一致，不存在跨域投递）：

| 域 | Cookie 数 | 内容 |
|----|:--------:|------|
| `chatgpt.com`（含 `.chatgpt.com`）| 22~25 | 会话凭据 + UI 状态 + CF + `oai-sc`(.chatgpt.com) |
| `auth.openai.com`（含 `.openai.com`）| 15 | **认证过程凭据** + CF + `oai-sc`(.openai.com) |
| `sentinel.openai.com` | 5 | 仅 `oai-did`、`oaicom-stable-id`、**`oai-sc`**、`__cflb`、`__cf_bm` |

**关键推论**：`auth.openai.com` 的认证过程凭据（`auth-session-minimized`、`__Host-usc_*`、`oai-login-csrf_*`…）**不会**发往 `chatgpt.com`；两个域之间唯一的桥是 `GET /api/auth/callback/openai?code=ac_…&state=…` 这一步的 **OAuth 授权码**。

#### 4.13.2 会话 Cookie 的确切规格与轮换

```
[355] GET /api/auth/callback/openai?code=ac_GlIry8A9…&state=qNOe0c5shLwnxZvFV1Er3zk37kxqREyn-9m3yzQrDNo  → 302 Location: https://chatgpt.com/
      Set-Cookie: __Secure-next-auth.session-token.0=<3933 字符>   ✓ 
      Set-Cookie: __Secure-next-auth.session-token.1=<416 字符, tKavUTT4…>
      属性: Max-Age=7776000（90 天）; Domain=.chatgpt.com; Path=/; HttpOnly; Secure; SameSite=Lax

[357] GET https://chatgpt.com/  → 200
      Set-Cookie: __Secure-next-auth.session-token.0=<3933>          ← 同一 JWE 前缀
      Set-Cookie: __Secure-next-auth.session-token.1=<416, X5vyNDUZ…> ← ★ 分片值已轮换
```

* OAuth `state` 在 `[8] authorize` 与 `[355] callback` **完全一致**（`qNOe0c5shLwnxZvFV1Er3zk37kxqREyn-9m3yzQrDNo`）；
* `__Secure-next-auth.state`（JWE，260 字符，Max-Age=900）在回调时被 **`Max-Age=0` 清除**（一次性）；
* 会话 Cookie 在回调处签发后，**首次页面加载 `[357]` 会再签发一次**（`.1` 分片变化）—— 即"登录完成 → 打开首页"这个动作会刷新会话分片。

#### 4.13.3 `cf_clearance`：两张独立的通行证，且带 `Partitioned`

| 签发点 | 域 | 长度 | 属性 |
|--------|----|------|------|
| `[186] GET auth.openai.com/cdn-cgi/challenge-platform/h/g/jsd/oneshot` | `auth.openai.com` | 533 | `HttpOnly; SameSite=None; **Partitioned**; Secure; Path=/; Expires=+1 年` |
| `[504] GET chatgpt.com/cdn-cgi/challenge-platform/h/g/jsd/oneshot/4df…` | `chatgpt.com` | 511 | 同上（域不同）|

**要点**：`Partitioned`（CHIPS）意味着该通行证被绑定到**顶层站点分区**，因此两个域的 `cf_clearance` 不能互换、也无法靠拷贝 cookie 复用 —— 这从机制上解释了为什么"纯脚本登录 ChatGPT 很难"：必须先各自过一遍 Cloudflare 的 JS 挑战（`jsd/oneshot`）。

#### 4.13.4 `oai-sc`：sentinel 专用 Cookie，每次调用都重发

| 签发点 | 域 | 值长度 | 属性 |
|--------|----|:------:|------|
| `[274] POST sentinel.openai.com/backend-api/sentinel/req` | `.openai.com` | 269 | `Max-Age=31536000; SameSite=none; Secure`（非 HttpOnly）|
| `[343]` 同上（第二次 /sentinel/req）| `.openai.com` | 269 | 同上 |
| `[398] POST chatgpt.com/…/chat-requirements/prepare` | `.chatgpt.com` | 248 | 同上 |
| `[437] POST chatgpt.com/…/chat-requirements/finalize` | `.chatgpt.com` | 248 | 同上 |

**结论**：`oai-sc` 是 sentinel 体系的**逐轮材料**（auth 侧与 chat 侧各一份），1 年有效却每次挑战都重发。**但它与 `t`/`turnstile` 的 XOR 密钥无关**：LS 的密钥为 `4.07`，而该轮 `oai-sc`（ts=1791977146）的各种派生式（`ts%100`、`ts%1000/10`、`(ts//10)%100.ts%100`、IV 字节等）全部不命中，密钥也不出现在其值或解码字节中。

#### 4.13.5 认证过程的凭据链（每步都在轮换，MFA 后即销毁）

| Cookie | 长度 | 属性 | 生命周期 |
|--------|:----:|------|---------|
| `oai-mweb-auth-pending` | 82 | `Max-Age=900; Domain=.chatgpt.com; HttpOnly` | `[1]` 交接时签发（`<auth_session_logging_id>.l.<random>`）|
| `oai-login-csrf_dev_3772291445` | 224 | `Max-Age=3600; HttpOnly` | `[8]` authorize 签发；内容 = `base64("<unix秒>|<随机串>")` |
| `rg_context` / `iss_context` | 4 / 7 | `Max-Age=2700` | `prim` / `default` |
| `oai-client-auth-info` | 291→383 | `Max-Age=2592000`（30 天）| `base64(JSON)`：`{last_login_identifier:{type:email,value:…}, last_login_strategy:"auth0", last_login_method_by_user_id:{<user_id>:"password"}}` |
| **`auth-session-minimized`** | 602 | `Max-Age=2700; Domain=auth.openai.com; HttpOnly` | **ES256 JWS**：`{session_id:"authsess_tRVIYAAak6riIE0ZpqtvczEQ", auth_session_logging_id, source_surface_stable_id:<oai-did>, openai_client_id, app_name_enum:"chat", auth_session_affinity:"<b64>"}`；在 `[8]/[288]/[314]` **每步重新签发**，`[351]` MFA 成功后 **被清空**（`Max-Age=0`）|
| **`auth-session-minimized-client-checksum`** | 91 | `Max-Age=2700` | `{"affinity":"<与上一条 JWS 内同值的 b64>"}` —— **客户端侧的镜像校验值**（服务器在 JWS 里签一份、客户端另存一份，不一致即会话失效）|
| **`__Host-unified_session_manifest`** | 183→304→394 | `Max-Age=34560000`（400 天）| ES256 JWS：`{version:3, iat, sessions:[{cookie_id:"<__Host-usc_ 后缀>", unified_session_id:"us_4ndWtBw8ZgA1Qx5ZZ1i007sJ"}]}` |
| **`__Host-usc_<cookie_id>`** | 363 | `Max-Age=34560000; HttpOnly` | ES256 JWS：`{type:"us", protocol_version:"3", cookie_id, encrypted_authenticated_data:"us_…", **client_secret**:"QWNcpdf4gdHFhysbKtEIGX9l"}`；`[8]` 清除旧值 → `[351]` MFA 成功后签发**新的一份** |
| `oaicom-stable-id` | 36 | `Max-Age=31536000; Domain=openai.com` | `[9]` 签发的一次性稳定 ID（UUID），与 `oai-did` 平行 |
| `oai-asli` | 36 | `Domain=chatgpt.com` | 回到 chatgpt 域后保存 `auth_session_logging_id`（= `[1]` 的 pending 值）|
| `oai-client-session-epoch` | 36 | `Max-Age=7776000; Domain=.chatgpt.com` | `[355]` 签发（与会话 Cookie 同寿命）|

**`auth_session_affinity` 解码**（base64 → JSON）：`{"rc": 12, "cs": "65ce42b6ab", "ws": 0, "wt": 1791977123}` —— `rc` 疑为请求计数、`cs` 为校验串、`wt` 为时间窗，与 `*-client-checksum` 构成**双向绑定**。

#### 4.13.6 各认证步骤到底需要什么凭据（实测）

| 步骤 | entry | 携带的准入材料 | 是否需要 sentinel |
|------|-------|---------------|:----------------:|
| `POST /api/auth/signin/openai` | `[7]` | chatgpt 域 22 个 Cookie（含 `cf_clearance`）+ CSRF token（表单体）| ❌ |
| `GET /api/accounts/authorize` | `[8]` | `oai-did`、`__Secure-next-auth.state` 等 | ❌ |
| `POST sentinel.openai.com/…/sentinel/req` | `[274]`、`[343]` | 仅 5 个 Cookie（`oai-did`、`oaicom-stable-id`、`oai-sc`、`__cflb`、`__cf_bm`）；`Content-Type: **text/plain;charset=UTF-8**` | 它自己就是发令牌的 |
| **`POST /api/accounts/password/verify`** | `[288]` | 15 个 Cookie + **`openai-sentinel-token`（4260 字符）** + `x-access-flow-invocation-id` + `x-openai-document-navigation-id`；body `{"password":"…"}` | **✅ 唯一需要的一步** |
| `POST /api/accounts/mfa/issue_challenge` | `[314]` | 15 个 Cookie；body `{"id":"6ac5c502fea8819191edc40e2f016413","type":"totp","force_fresh_challenge":false}` | ❌ |
| `POST /api/accounts/mfa/verify` | `[351]` | 15 个 Cookie；body `{"id":"6ac5c502…","type":"totp","code":"165730"}` | ❌ |
| `GET /api/auth/callback/openai` | `[355]` | chatgpt 域 22 个 Cookie + `code` + `state` | ❌ |

**两个更正**：
1. **`openai-sentinel-token` 只出现在 `password/verify` 一处**（全 HAR 仅 1 条，`[288]`）—— 此前（脱敏版）只能确认"密码校验带 sentinel"，现在可确认 **MFA 两步都不带**；
2. MFA 的 `id` 是 **32 位十六进制挑战 ID**（`6ac5c502fea8819191edc40e2f016413`），而**不是** `authsess_*` 会话 ID；`[288]` 响应体 `page.payload.factor_id` 与 `factors[].id` 给出的就是这个值，`continue_url` 指向 `/mfa-challenge/<该 ID>`。

#### 4.13.7 认证主体的"交接"路径

```
[288] password/verify 200 → 响应体 page.type="mfa_challenge"（factor_id=6ac5c502…）
[314] mfa/issue_challenge 200 → 同一 factor id
[351] mfa/verify 200 → continue_url = "https://chatgpt.com/api/auth/callback/openai?code=ac_GlIry8A9…"（294 字符）
                     + __Host-usc_* 换新、auth-session-minimized 清空
[355] 浏览器跳转该 URL → chatgpt.com 域签发会话 Cookie（§4.13.2）→ 302 到 https://chatgpt.com/
[357] 首页加载 → 会话分片轮换
[393+] 之后所有 /backend-api/* 带上 Authorization: Bearer（§4.12.1）
```

**要点**：跳转目标（含授权码）是**由服务端在 `mfa/verify` 的响应体里给出的**（`continue_url` / `page.payload.url`），不是客户端自己拼的。

---

## 5. 字段速查表（校验/鉴权相关）

| 字段 | 出现位置 | 来源 | 用途 | 可伪造？ |
|------|---------|------|------|---------|
| `csrfToken` | `/api/auth/signin/openai` body | `GET /api/auth/csrf` | NextAuth CSRF 防护 | 需先取，可自动获取 |
| `state` | authorize / callback | auth.openai.com 生成 | OAuth 防 CSRF/重放 | ❌ 服务端比对 |
| `code` | callback | auth.openai.com 生成 | 换取会话 | ❌ 一次性 |
| `device_id` / `ext-oai-did` / `oai-did` | 全链路 | 客户端 cookie | 设备识别 | ✅ 客户端可控 |
| `auth_session_logging_id` | 全链路 | chatgpt.com 生成 | 会话日志关联 | ✅ 透传值 |
| `cf-mitigated` / Turnstile | entry 285~309 | Cloudflare | 网关层人机校验 | ❌ 需真实浏览器行为 |
| `p` | sentinel 请求体 / 头 | **客户端计算** | 指纹 + PoW 答案 | ✅ 算法已还原，可本地生成 |
| `t` | sentinel 头 | 客户端 XOR 混淆 | **环境探针答案表**（键=`探针号.答案号`）| ✅ 密钥可由已知明文推导（§4.8.1）|
| `c` | sentinel 头 | **服务端 Fernet 令牌** | 挑战凭证，原样回传 | ❌ 不可伪造 |
| `token`(响应) | `/sentinel/req` | 服务端 | 同上（`c` 的来源）| ❌ |
| `prepare_token` | `chat-requirements/*` | 服务端 Fernet | 对话准入凭证 | ❌ |
| `persona` | sentinel 响应 | 服务端 | 身份画像 | — |
| `expire_after/expire_at` | sentinel 响应 | 服务端 | 540 秒有效期 | — |
| `seed` / `difficulty` | sentinel 响应 | 服务端 | PoW 参数 | — |
| `proofofwork` | finalize body | 客户端计算 | PoW 答案 | ✅（同上）|
| `turnstile` | finalize body | 客户端 XOR 混淆 | 同 `t`：探针答案表 | ✅（同上）|
| `mfa code` | `/mfa/verify` | 用户 TOTP | 二次验证 | ❌ |
| `chatgpt-account-id` | 业务请求头 | 服务端下发/客户端记忆 | 租户隔离 | 需与会话匹配 |

---

## 6. 复现可行性评估

| 环节 | 能否纯脚本复现 | 说明 |
|------|--------------|------|
| CSRF + OAuth 授权跳转 | ✅ | 标准流程，注意 `state`/`code` 一次性 |
| Sentinel 指纹 + PoW 计算 | ✅ | 算法已完整还原（§4.5/§4.7），可直接实现 |
| `/sentinel/req` 取挑战 | ✅ | 只需 `p` + `id` + `flow` |
| **Cloudflare 挑战（网关层）** | ❌ | 需要真实浏览器执行环境；HAR 显示 `password/verify` 会因 CF 挑战直接 403 |
| **`t` 字段（探针答案集）** | ✅ | 格式与密钥推导均已还原（§4.8.1）：只要按同样的 25 项探针**如实作答**即可生成，无需真实浏览器上下文（但"如实"要求采集到的环境值自洽）|
| **`dx` 指令（探针问卷本身）** | ❌ | 20~24 KB，已排除短周期 XOR，无法解出内容 |
| `c` / `token` / `prepare_token` | ❌ | 服务端 Fernet，不可伪造 |
| MFA | ❌ | 需要 TOTP 种子 |

**结论**：Sentinel 这一层的**客户端部分**（指纹构造 + PoW + 探针答案编码）已经完全可复现；但登录链路的实际门槛在于 **Cloudflare 网关层挑战** 与服务端不透明令牌（Fernet、`dx` 指令），二者共同构成"必须真实浏览器 + 不可离线伪造"的防线。这也解释了为何纯 HTTP 脚本登录 ChatGPT 一直很困难，而社区方案普遍走 `undetected-chromedriver` / Playwright 路线。

---

## 7. 不确定与待验证

1. ~~**Cookie 与会话凭据**：本 HAR 完全未记录……~~ **已解决**（依据 LS 抓包，见 §4.12、§4.13）：会话凭据是 `__Secure-next-auth.session-token.0/.1`（分片 JWE，90 天，HttpOnly）+ `Authorization: Bearer`（RS256 OIDC 令牌）；认证过程的临时凭据链、`cf_clearance`（Partitioned）、`oai-sc` 的四个签发点均已实测。
2. **XOR 密钥的来源**：`t`/`turnstile` 的明文与密钥都已被还原（§4.8.1、§4.13.4），密钥是每轮不同的短十进制数（累计 10 个样本：`17.41`/`46.46`/`70.41`/`27.27`/`90.31`/`64.8`/`97.63`/`31.99`/`3.74`/`4.07`）。**来源仍未确认**，已排除 6 条假设：① 五份 HAR 原文中无字面串；② 不等于也不包含于任何 Cookie 值（含 auth 域）；③ 不在 prepare/finalize//sentinel/req 响应的明文字段中（正则穷举 `\d{1,3}\.\d{1,2}`，0 命中）；④ 不是 `dx`/`collector_dx`/`prepare_token`/`token` 的常见 FNV 派生；⑤ 不是 `oai-sc` 内嵌时间戳的函数；⑥ **不是指纹载荷 25 字段中任一字段的任何常见变换**（8 组「载荷 ↔ 密钥」配对、每组约 100 种公式，零命中）。SDK 里的 `errorPrefix = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"` 亦已排除。**剩余最合理解释（推断）**：密钥随 `dx` 一并下发（客户端用 SDK 内嵌密钥解出 `dx` 后取得，服务端自己生成 `dx` 故双方共享）。工具不需要知道来源 —— 可从密文直接还原。
3. **`difficulty` 是否随账号信誉/风控等级动态调整**：**10 个样本**（跨 6 份抓包，含 auth 侧与对话侧）全部落在 **2.38%~2.98%**，取值集合 {`061a80`,`069c35`,`069cee`,`06b983`,`0640d7`,`07a120`×5} → **未观察到自适应迹象**，更像固定带宽内随机。付费账号是否更高仍未验证。
4. **`persona` 的取值集合**：已观察到 `chatgpt-noauth`（登录前）、`chatgpt-freeaccount`（登录后）；其它画像（plus/pro/team）未验证。
5. **载荷字段语义**：`[17]` = `performance.timeOrigin`、`[13]` = `performance.now()` 已由 LS 精确验证（`1791977120894.7 + 27959.1 ms = 11:25:48.8`，与该轮 `[1]` 时间戳一致；其余 7 轮同页会话共享 `timeOrigin = 1791970913987.2`）。字段 2/6 恒定，判为常量指纹；16 判为 `hardwareConcurrency`（值 8）属**推断**。
6. **`so`（session observer）字段**：`so.required=true` + `collector_dx`（+ 10:44 之后新增的 `snapshot_dx`），但 `finalize` 请求体只提交 `prepare_token`/`proofofwork`/`turnstile` 三项 —— **`so` 的答案提交路径在 5 份抓包中都未出现**（推测走独立的 beacon/上报接口，本次未触发）。
7. **`/backend-api/conversation/init` 与 wss 的 `verify` 签名生成规则**未在本次范围内解析（属对话链路，见 `02` 文档）。
8. **`dx` / `collector_dx` / `snapshot_dx` 的内容**（20~32 KB 密文）未解开：已排除短周期 XOR（密钥长度 2~160 全部无解），8 个样本前 5 字节恒为 `3c 1a 79 6d 61`。

---

## 8. 附录：关键证据索引

| entry | 方法 | 状态 | URL（截断）| 价值 |
|-------|------|------|-----------|------|
| 9 | GET | 200 | `chatgpt.com/auth/login_with?...` | 登录入口参数 |
| 10 | GET | 200 | `/api/auth/providers` | OAuth provider 列表 |
| 11 | GET | 200 | `/api/auth/csrf` | CSRF 令牌 |
| 12 | POST | 200 | `/api/auth/signin/openai?...` | CSRF 提交 + OAuth URL 下发 |
| 13 | GET | 302 | `auth.openai.com/api/accounts/authorize?...` | 全部授权参数 |
| 14 | GET | 200 | `auth.openai.com/log-in/password` | 登录页 |
| 96/97/102 | GET/POST | 302/200 | `cdn-cgi/challenge-platform/...` | CF JSD 脚本与上报 |
| 103 | GET | 200 | `sentinel.../sdk.js` | 引导脚本 |
| 126/270 | GET | 200/304 | `sentinel.../20260810913b/sdk.js` | **PoW 算法来源** |
| 248/430 | GET | 200 | `sentinel.../frame.html?sv=20260810913b` | iframe 壳 |
| **275** | POST | 200 | `sentinel.../sentinel/req` | **挑战 1 + Fernet token** |
| **285** | POST | **403** | `/api/accounts/password/verify` | **CF 拦截证据 + 完整的 sentinel 头** |
| 296~309 | 多种 | 200 | `challenges.cloudflare.com/...` | Turnstile 全流程 |
| **440** | POST | 200 | `sentinel.../sentinel/req` | **挑战 2** |
| **449** | POST | 200 | `/api/accounts/password/verify` | **密码通过 + `oai-client-auth-session`** |
| 489 | POST | 200 | `/api/accounts/mfa/issue_challenge` | MFA 挑战下发 |
| 497 | POST | 200 | `sentinel.../sentinel/req` | 挑战 3 |
| 627 | POST | 200 | `/api/accounts/mfa/verify` | TOTP 通过 + 回调 URL |
| 631 | GET | 302 | `/api/auth/callback/openai?code=...` | **授权码回调（会话建立点）** |
| 669/670 | GET | 200 | `/backend-api/wham/accounts/check`、`/accounts/check/...` | `chatgpt-account-id` 首次出现 |
| 674 | POST | 200 | `/backend-api/sentinel/chat-requirements/prepare` | 对话侧 sentinel 挑战 |
| 683 | GET | 200 | `/backend-api/me` | 登录成功的直接证据 |
| 691 | POST | 200 | `/backend-api/conversation/init` | 会话初始化 |
| 712 | POST | 200 | `/backend-api/sentinel/chat-requirements/finalize` | **对话准入 token** |
| 792 | GET | 101 | `wss://ws.chatgpt.com/...&verify=...` | WebSocket 签名准入 |

### 附录 B：LS（`chatgpt_login_包含敏感数据.har`）关键 entry

| entry | 方法 | 状态 | URL（截断）| 价值 |
|-------|------|------|-----------|------|
| 1 | POST | 204 | `chatgpt.com/unauth-mweb/auth/handoff` | `oai-mweb-auth-pending`（认证会话 ID 的起点）|
| 7 | POST | 200 | `/api/auth/signin/openai?...` | `__Secure-next-auth.state`（JWE，900 s）|
| **8** | GET | 302 | `auth.openai.com/api/accounts/authorize?...` | **认证凭据一次性下发**：`oai-login-csrf_*`、`auth-session-minimized`、`__Host-unified_session_manifest`、`__Host-usc_*`、`oai-client-auth-info` |
| 9 | GET | 200 | `auth.openai.com/log-in/password` | `oaicom-stable-id`、`oai-did`（`.openai.com`）|
| 186 | GET | 200 | `auth.openai.com/cdn-cgi/challenge-platform/h/g/jsd/oneshot` | **`cf_clearance`（auth 域，Partitioned）** |
| **274** | POST | 200 | `sentinel.openai.com/backend-api/sentinel/req` | 挑战 1 + **`oai-sc`（.openai.com）签发** |
| **288** | POST | 200 | `/api/accounts/password/verify` | **全 HAR 唯一的 `openai-sentinel-token`（4260 字符）**；`t` 解密密钥 `4.07` |
| 314 | POST | 200 | `/api/accounts/mfa/issue_challenge` | `factor_id=6ac5c502fea8819191edc40e2f016413` |
| 343 | POST | 200 | `sentinel.openai.com/.../sentinel/req` | 挑战 2 + `oai-sc` 重发 |
| 351 | POST | 200 | `/api/accounts/mfa/verify` | TOTP 通过；**auth-session cookie 清空**、`__Host-usc_*` 换新、`continue_url` 指向回调 |
| **355** | GET | 302 | `/api/auth/callback/openai?code=ac_…&state=…` | **会话 Cookie 签发点**（`__Secure-next-auth.session-token.0/.1`）、`state` 校验、`_account` 写入 |
| 357 | GET | 200 | `https://chatgpt.com/` | **会话分片轮换**（`.1` 变化）|
| 398 / 437 | POST | 200 | `/backend-api/sentinel/chat-requirements/{prepare,finalize}` | 对话侧挑战 + `oai-sc`(.chatgpt.com) 签发 |
| 393+ | GET/POST | 200 | `/backend-api/*` | **`Authorization: Bearer`（OIDC，10 天）首次出现** |
| 504 | GET | 200 | `chatgpt.com/cdn-cgi/challenge-platform/h/g/jsd/oneshot/…` | **`cf_clearance`（chatgpt 域）** |

### 复现本文结论所用的方法（可审计）

1. `json.load` 解析 HAR → 按 host/URL 归组，剔除遥测与静态资源；
2. 对 sentinel 相关条目逐个 dump 完整请求/响应头与体；
3. 从 `sentinel/.../sdk.js`（33 KB，字符串数组混淆）中定位特征常量（`2166136261`、`"~S"`、`"gAAAAAB"`、`"proofofwork"`、`"difficulty"`）并还原算法；
4. 用 Python 复现 `fnv1aMix` 与载荷编解码，对 HAR 中 5 处真实提交值做**逐字节回验**（全部通过）；
5. 对 `c` 与响应 `token` 做二进制比对（全部相同）。

> 本文所有数值、Base64 片段与十六进制均直接取自 HAR 原文；标注「推断」的条目为逻辑推理，未获直接证据。
