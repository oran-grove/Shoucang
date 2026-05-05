"""
智能体基类
==========
封装 LLM 调用、消息收发、结果解析等通用能力。
"""

import json
import logging
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Optional

from .message import AgentMessage, MessageType, ThreatVerdict, TrafficVerdict, SeverityLevel

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """
    所有智能体的抽象基类。
    - 持有 LLM 后端引用
    - 提供 send_message / receive 的消息通信接口
    - 子类实现 process() 作为入口
    """

    def __init__(
        self,
        name: str,
        system_prompt: str = "",
        model_name: str = "gpt-4o-mini",
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ):
        self.name = name
        self.system_prompt = system_prompt
        self.model_name = model_name
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._llm_backend: Any = None       # 由编排器注入
        self._message_bus: Any = None       # 由编排器注入
        self._knowledge_base: Any = None    # 由编排器注入

    def set_backend(self, backend: Any) -> None:
        self._llm_backend = backend

    def set_message_bus(self, bus: Any) -> None:
        self._message_bus = bus

    def set_knowledge_base(self, kb: Any) -> None:
        self._knowledge_base = kb

    # ----- 消息通信辅助 -----
    def send_message(
        self,
        recipient: str,
        msg_type: MessageType,
        payload: Any,
        correlation_id: str = "",
    ) -> None:
        msg = AgentMessage(
            msg_type=msg_type,
            sender=self.name,
            recipient=recipient,
            payload=payload,
            correlation_id=correlation_id,
        )
        if self._message_bus:
            self._message_bus.publish(msg)
        else:
            logger.warning("[%s] 消息总线未注入，消息丢弃: %s", self.name, msg_type.value)

    def receive(self, msg: AgentMessage) -> Any:
        """
        接收消息并响应（可在子类覆写）。
        返回处理结果，None 表示不响应。
        """
        return None

    # ----- LLM 调用封装 -----
    async def call_llm(
        self,
        user_prompt: str,
        system_prompt_override: str = "",
    ) -> str:
        """
        异步调用 LLM 后端。
        """
        if not self._llm_backend:
            raise RuntimeError(f"智能体 [{self.name}] 未绑定 LLM 后端")
        sys_prompt = system_prompt_override or self.system_prompt
        return await self._llm_backend.chat(
            system_prompt=sys_prompt,
            user_prompt=user_prompt,
            model=self.model_name,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )

    def call_llm_sync(
        self,
        user_prompt: str,
        system_prompt_override: str = "",
    ) -> str:
        """
        同步调用 LLM 后端。
        """
        if not self._llm_backend:
            raise RuntimeError(f"智能体 [{self.name}] 未绑定 LLM 后端")
        sys_prompt = system_prompt_override or self.system_prompt
        return self._llm_backend.chat_sync(
            system_prompt=sys_prompt,
            user_prompt=user_prompt,
            model=self.model_name,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )

    @staticmethod
    def extract_json_from_response(text: str) -> dict[str, Any]:
        """
        从 LLM 回复中提取 JSON。
        支持 ```json ... ``` 包裹及裸 JSON。
        """
        # 尝试提取代码块
        code_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', text, re.DOTALL)
        if code_match:
            text = code_match.group(1)
        # 尝试匹配花括号
        brace_match = re.search(r'\{.*\}', text, re.DOTALL)
        if brace_match:
            try:
                return json.loads(brace_match.group(0))
            except json.JSONDecodeError:
                pass
        logger.warning("无法从 LLM 回复中提取 JSON: %s", text[:200])
        return {"error": "json_parse_failed", "raw": text}

    # ----- 子类接口 -----
    @abstractmethod
    async def process(self, *args: Any, **kwargs: Any) -> Any:
        """
        核心处理逻辑，子类必须实现。
        """
        ...

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}({self.name}, model={self.model_name})>"


__all__ = ["BaseAgent"]
