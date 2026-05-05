"""
LM Studio 本地 AI 后端
======================
LM Studio 暴露 OpenAI 兼容 API，默认地址 http://localhost:1234/v1。
此后端继承 OpenAIBackend，仅做少许定制。
"""

from .openai_backend import OpenAIBackend


class LMStudioBackend(OpenAIBackend):
    """
    LM Studio 后端。
    与 OpenAIBackend 完全兼容，仅默认值不同。
    """

    def __init__(
        self,
        api_base: str = "http://localhost:1234/v1",
        api_key: str = "lm-studio",
        timeout: float = 120.0,      # 本地模型可能较慢
        max_retries: int = 2,
        default_model: str = "qwen2.5-7b-instruct",
    ):
        super().__init__(
            api_base=api_base,
            api_key=api_key,
            timeout=timeout,
            max_retries=max_retries,
            default_model=default_model,
        )


__all__ = ["LMStudioBackend"]
