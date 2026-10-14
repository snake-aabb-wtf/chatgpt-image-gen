# legacy —— cgpt 项目之前就存在的素材

这里存放**先于 cgpt 工具**存在于仓库里的文件。它们不是工具的一部分，而是工具的
**依据**：`docs/01`~`04` 那四份逆向分析报告就是基于这些抓包写出来的。

```
legacy/
  har/                    6 份真实抓包（共约 230 MB）
    chatgpt_login.har                     117 MB / 826 条
    chatgpt_login_包含敏感数据.har          83 MB / 552 条
    chatgpt_generate_image.har            9.5 MB / 31 条
    chatgpt_image_包含敏感数据.har          8.7 MB / 19 条
    chatgpt_chat.har                      3.9 MB / 43 条
    chatgpt_chat_包含敏感数据.har          1.4 MB / 20 条
    chatgpt_多轮对话_包含敏感数据.har       1.3 MB / 19 条
  tools/
    sentinel-hook.js      浏览器 Console 取证脚本（抓取并解密 Sentinel 字段）
    README.md             上面那个脚本的用法说明
```

## 谁还在用这些文件

只有一处代码依赖：`tools/build_har_vectors.py` 从这里提取离线自证用的真值
（产出 `cgpt/data/har_vectors.json`）。它已经指向 `legacy/har/`。

```bash
python tools/build_har_vectors.py     # 从 legacy/har/ 重新提取真值
```

自证本身（`python -m cgpt selftest`）读的是**提取好的** `cgpt/data/har_vectors.json`，
不碰这里的原始抓包 —— 所以日常使用与跑测试都不需要这 230 MB。

## 一个已知的失效引用

`docs/01`~`04` 里大量使用 `har/xxx.har` 这种写法（例如 `chatgpt_login.har[285]`），
那是**移动前**的路径。这些是历史分析记录，**故意保持原样**没有改写 ——
把证据文档改成"跟随现状"反而会让它失去"当时看到的就是这个"的意义。

阅读时对应关系很简单：

| 文档里写的 | 现在的位置 |
|-----------|-----------|
| `har/<文件名>.har` | `legacy/har/<文件名>.har` |
| `tools/sentinel-hook.js` | `legacy/tools/sentinel-hook.js` |

## 关于体积

这 216 MB 抓包**已经入库**（提交 `debf80b`）。它们是文本 JSON，git 压缩效果很好：
`.git/` 只有约 54 MB，而不是 216 MB。

两点相关的仓库设置：

* `.gitattributes` 把 `*.har` 标为 `binary`。这是**必须**的 —— 本机
  `core.autocrlf=true`，若不标记，git 会把这些 JSON 当文本并在签出时转换行尾，
  改变文件字节。而 `docs/01` §4.5 与 `docs/02` §4.5 的结论正是建立在
  **逐字节相等**之上的，字节一变那些结论就不可复现了。
* 提交后已校验：7 份抓包的文件大小与移动前完全一致，且用它们重新提取真值，
  `pow`/`xor`/`kinds`/`identical` 四类向量与提交内 `cgpt/data/har_vectors.json`
  逐字段相同 —— 说明内容一个字节都没被改动。

> 若以后要推到远端（GitHub 等）：这些抓包里含抓包**当时有效**的会话 Cookie 与
> `Authorization: Bearer`（`cf_clearance` 亦在其中）。它们会过期，但推送前值得
> 再确认一次这是你想要的。2FA 种子**不在**抓包里（服务端只收到 6 位验证码），
> 源码与文档中也已替换为占位值。
