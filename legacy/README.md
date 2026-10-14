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

这 230 MB 不适合进版本库。当前仓库还没有初始化 git；如果以后要 `git init`，
建议先把它们排除：

```gitignore
legacy/har/
```
