"""异常层次。

设计原则：每一种"用户能采取行动"的失败都有独立类型，且消息本身要可操作
（说清发生了什么 + 下一步该做什么），而不是把底层异常直接抛给用户。
"""

from __future__ import annotations


class CgptError(Exception):
    """本工具所有异常的基类。"""


# --- 凭据 / 会话 ---------------------------------------------------------


class CredentialsNotFoundError(CgptError):
    """凭据文件不存在、损坏或缺少必需字段。"""


class SessionExpiredError(CgptError):
    """会话已失效（Cookie / Bearer 不再被服务端接受）。"""


# --- 登录 ---------------------------------------------------------------


class LoginError(CgptError):
    """登录流程失败的基类。"""


class LoginBlockedError(LoginError):
    """登录被风控/额外验证阻断（改密、CAPTCHA、设备验证等）。

    截图路径会附在消息里，便于人工判断卡在哪一步。
    """


class TotpRejectedError(LoginError):
    """TOTP 验证码被服务端拒绝（含时钟偏移重试后仍失败）。"""


# --- 网关 / 传输 ---------------------------------------------------------


class CloudflareChallengeError(CgptError):
    """被 Cloudflare 边缘挑战拦截（403 + cf-mitigated: challenge）。"""


class TransportError(CgptError):
    """网络层失败（DNS、连接、超时、TLS 等），与业务状态码无关。

    ``status_code`` 让调用方能**按状态码**判断，而不是去匹配错误文本 ——
    字符串匹配太脆，改一个字就失效。
    """

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class SentinelRejectedError(CgptError):
    """服务端拒绝了这次对话发送（通常是 403）。

    实测确认的成因：**三条哨兵令牌是一次性的** —— 同一批 ``openai-sentinel-*``
    只能用于一次 ``f/conversation``。第二次复用必然 403
    （响应体为空、``content-type: application/json``，不是 Cloudflare 边缘挑战）。

    已验证不是频率限制：刚成功后 47 秒，只换令牌就能再次成功。
    """


class PromptRejectedError(CgptError):
    """助手只回了一段文字、没调用生图工具 —— 这一轮没有画图。

    两种成因，**从返回内容上分不开**，所以文案里两个都要说：

    * 提示词被内容策略拦下（违规驳回）；
    * 提示词本身就没要求生成图片（比如问了句"1+1 等于几"）。

    为什么单独一个类型：这**不是**故障，而是服务端明确地没打算画图。
    早先的实现只找图片资产，找不到就当"图还在生成"，于是轮询到超时 ——
    用户看到的就是"卡死"。现在立刻失败，并把模型的原话带出来。
    """


class UnsafeDownloadURLError(CgptError):
    """服务端下发的 download_url 指向非 chatgpt.com 域。

    这是一个**凭据泄漏防护**：带 Cookie 去请求第三方域等同于把会话凭据
    交给对方。此处必须在发请求之前失败。
    """


# --- 生图 ---------------------------------------------------------------


class InvalidPromptError(CgptError):
    """提示词为空或纯空白。本地拦截，不消耗生图额度。"""


class ImageGenUnavailableError(CgptError):
    """账号没有生图能力（accounts/check 的 features 缺少开关）。"""


class QuotaExhaustedError(CgptError):
    """生图额度耗尽。"""


class NoImageProducedError(CgptError):
    """请求成功，但模型没有调用图像工具（正常返回了文本）。

    如实报告"未出图"，绝不伪造成功。
    """
