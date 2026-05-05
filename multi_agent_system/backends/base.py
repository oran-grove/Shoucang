"""
LLM 后端抽象接口
================
定义所有后端的公共接口，支持同步/异步调用。
"""

from abc import ABC, abstractmethod
from typing import Optional


class BaseLLMBackend(ABC):
    """
    LLM 后端抽象基类。
    所有后端（OpenAI API / LM Studio / 其他）均需实现此接口。
    """

    @abstractmethod
    def chat_sync(
        self,
        system_prompt: str,
        user_prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ) -> str:
        """
        同步对话，返回 LLM 回复文本。
        """
        ...

    @abstractmethod
    async def chat(
        self,
        system_prompt: str,
        user_prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ) -> str:
        """
        异步对话，返回 LLM 回复文本。
        """
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """检查后端是否可用"""
        ...


__all__ = ["BaseLLMBackend"]
