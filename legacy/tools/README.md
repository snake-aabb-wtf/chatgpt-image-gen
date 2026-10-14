# tools —— Sentinel 校验材料提取 / 解密脚本

本目录放的是配合 `docs/` 三份分析文档使用的**取证工具**，不属于被分析的抓包文件。

## sentinel-hook.js 是什么

一个**自包含、无依赖**的浏览器 Console 脚本，用来在真实会话里把 ChatGPT 的 Sentinel 校验字段抓出来并解密：

| 能力 | 说明 |
|------|------|
| 抓取 | 钩住 `fetch` / `XHR`，捕获 `openai-sentinel-token`（登录链路）与 `openai-sentinel-*-token`（对话链路）三类头，以及 `chat-requirements/finalize` 请求体里的 `p` / `proofofwork` / `prepare_token` / `turnstile` |
| **解密 `t` / `turnstile`** | 这三类字段是 `base64(XOR(ASCII JSON, 密钥))`。脚本有三条还原路径：① 用 cookie/storage 里的值当候选密钥；② 单字节暴力；③ **已知明文推导**（明文是 JSON ⇒ 首字节 `{`；明文是纯 ASCII ⇒ 逐列施加 `0x20~0x7e` 约束，解出密钥长度与内容）。第 ③ 条不依赖任何字典 |
| 直接还原密钥 | 同时挂 `atob` 与 `String.fromCharCode`：SDK 的解密是 `JSON.parse(xor(atob(v), key))`，而 xor 逐字符调用 `String.fromCharCode(ct[i] ^ key[i % L])` ⇒ 配对后可直接算出 `key[i % L] = ct[i] ^ out[i]`，再取最小周期即得密钥
| 解码载荷 | `p` / `proofofwork`（`gAAAAAB/C` + 独立 base64）→ 解出 25 字段指纹数组，含 `[3]` PoW 计数器 |
| 识别 Fernet | `c` / `token` / `prepare_token` → 识别为 `0x80｜4B 0｜4B 大端时间戳｜16B IV｜密文｜32B HMAC`，并解出内嵌时间戳（可用来核对签发时刻与 540 秒 TTL）|

## 用法

```text
1) F12 → Console（若提示 allow pasting，先输入 allow pasting 回车）
2) 粘贴 sentinel-hook.js 全文，回车 —— 打印 [sentinel-hook] 已安装
3) 触发一次校验：
   · 对话链路：在输入框发一条消息（会先跑 chat-requirements prepare/finalize）
   · 登录链路：走一次登录
4) Console 会自动打印：抓到的字段 → 明文 → XOR 密钥
5) 汇总：copy(SentinelXOR.report())
```

**什么都没抓到**：

* 对话链路若把 SDK 跑在 iframe 内 → 在 Console 左上角的 context 下拉框切到 sentinel 相关 frame 再贴一次；
* 登录链路的 SDK 运行在 `sentinel.openai.com` 的 iframe 内 → 把执行上下文切到 `frame.html`（sentinel.openai.com）后再贴。

**离线 / 手动模式**（例如只有抓包文件）：

```js
SentinelXOR.crackToConsole('<t 或 turnstile 的值>')             // 用当前上下文的 cookie/storage 作候选
SentinelXOR.crackWithKeys('<blob>', { 'cookie:xxx': '值' })     // 手动指定候选密钥
SentinelXOR.decodePayload('<p 或 proof-of-token 的值>')          // 解出 25 字段指纹数组
```

> 安全：脚本只读取当前页面的 cookie / storage 作为**候选密钥**在本地试解，**不发起任何网络请求**；密钥与明文只打印在你自己的 Console。

## 自测状态（16/16 通过）

用例覆盖三条解密路径、载荷解码与 Fernet 识别，其中"真实样本"直接取自 `chatgpt_login.har`：

| 用例 | 结果 |
|------|------|
| A1~A5 配对还原密钥、非 XOR 数据不误报 | ✅ |
| B1~B2 候选密钥（cookie）命中 | ✅ |
| C1 单字节密钥暴力 | ✅ |
| D1 已知前缀推导还原短密钥 | ✅ |
| E1/E1b **真实 `t` 被独立解出**：key=`17.41`，16 项，内层含屏幕几何 / `Google Inc.` / DOM rect | ✅ |
| E2/E3 真实 `p` → 25 字段载荷、`[3]`=21、时间戳正确 | ✅ |
| E4/E5 真实 `c` 与 `prepare_token` → 识别为 Fernet，时间戳 1791970793 = `2026-10-14T09:39:53Z` | ✅ |
| E6 真实 `proofofwork` → 25 字段且 `solved=true` | ✅ |

## 本次用它（及其 Python 等价实现）解出的全部字段

| blob | 长度 | XOR 密钥 | 解密后条目 |
|------|------|---------|-----------|
| `chatgpt_login.har [285]` 头 `t` | 1088 B | `17.41` | 16 |
| `chatgpt_login.har [449]` 头 `t` | 1063 B | `46.46` | 15 |
| `chatgpt_login.har [712]` finalize `turnstile` = `chatgpt_chat.har [4]` 头 | 1304 B | `70.41` | 24 |
| `chatgpt_chat.har [31]` finalize `turnstile` = `chatgpt_generate_image.har [8]` 头 | 1370 B | `27.27` | 24 |
| `chatgpt_generate_image.har [14]` finalize `turnstile` | 1315 B | `90.31` | 22 |
| `chatgpt_chat_包含敏感数据.har [6]` 头 `turnstile-token` | 1720 B | `64.8` | 23 |
| `chatgpt_image_包含敏感数据.har [4]` finalize `turnstile` | 1728 B | `97.63` | 21 |
| `chatgpt_多轮对话_包含敏感数据.har [4]` finalize `turnstile` | 1824 B | `31.99` | 23 |
| `chatgpt_多轮对话_包含敏感数据.har [12]` finalize `turnstile` | 1744 B | `3.74` | 22 |
| `chatgpt_login_包含敏感数据.har [288]` 头 `t`（auth 侧）| 1520 B | `4.07` | 15 |

明文结构见 `docs/01-chatgpt-login-鉴权与校验分析.md` §4.8.1。

> 密钥形态是**短十进制数**（`17.41` / `46.46` / `70.41` / `27.27` / `90.31` / `64.8`），每轮不同。它**不在** cookie 值里、不在挑战响应的明文字段里、也不是 `dx` 的简单哈希派生 —— 来源仍是开放问题。好消息是：**工具不需要知道来源**，第 ③ 条路径直接从密文本身就能还原密钥。

## 仍未解决

`turnstile.dx` 与 `so.collector_dx`（20~24 KB）**解不开**：已排除短周期密钥 XOR（密钥长度 2~160 全部无法满足"严格 ASCII 列约束"），推测为更长随机密钥或流密码。可观察特征：全部 6 个样本的前 5 字节恒为 `3c 1a 79 6d 61`，说明明文有恒定前缀。
