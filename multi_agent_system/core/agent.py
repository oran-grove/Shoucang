"""
智能体基类
==========
封装 LLM 调用和结果解析等通用能力。
"""

import json
import json5
import logging
import re
from abc import ABC, abstractmethod
from typing import Any, cast

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """
    所有智能体的抽象基类。
    - 持有 LLM 后端引用
    - 提供 call_llm / extract_json_from_response 通用能力
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

    def set_backend(self, backend: Any) -> None:
        self._llm_backend = backend

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
        使用 json5 处理 JS 风格输出（无引号键名、单引号等），
        失败时使用修复逻辑处理嵌套引号等边缘情况。
        """
        # 提取代码块
        code_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', text, re.DOTALL)
        if code_match:
            text = code_match.group(1)

        # 匹配花括号
        brace_match = re.search(r'\{.*\}', text, re.DOTALL)
        if not brace_match:
            logger.warning("无法从 LLM 回复中找到 JSON 对象: %s", text[:200])
            return {"error": "json_parse_failed", "raw": text}

        json_str = brace_match.group(0)

        # 1. 尝试标准 JSON
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            pass

        # 2. 尝试 json5（处理无引号键名、单引号正常值）
        try:
            return cast(dict[str, Any], json5.loads(json_str))
        except Exception:
            pass

        # 3. 修复单引号内嵌套单引号的畸变：将外层单引号替换为双引号
        repaired = BaseAgent._fix_nested_quotes(json_str)
        if repaired:
            try:
                return cast(dict[str, Any], json5.loads(repaired))
            except Exception:
                pass

        logger.warning("无法从 LLM 回复中提取 JSON，原始内容: %s", text[:200])
        return {"error": "json_parse_failed", "raw": text}

    @staticmethod
    def _fix_nested_quotes(js_str: str) -> str | None:
        """
        逐键值对扫描，将单引号值转为 json.dumps 处理后的双引号值。
        处理 reasoning: '...含'evil'...' 这类内部嵌套单引号的畸变。
        """
        result = []
        i = 0
        n = len(js_str)
        while i < n:
            # 匹配无引号键名后跟 :
            m = re.match(r'([a-zA-Z_]\w*)\s*:\s*', js_str[i:])
            if m:
                result.append(m.group())
                i += m.end()
                # 跳过空白
                while i < n and js_str[i] in ' \t':
                    result.append(js_str[i])
                    i += 1
                if i < n and js_str[i] == "'":
                    # 单引号值：找后跟 , 或 } 的最后一个单引号
                    i += 1
                    value_start = i
                    closing = -1
                    j = i
                    while j < n:
                        if js_str[j] == "'":
                            after = j + 1
                            while after < n and js_str[after] in ' \t':
                                after += 1
                            if after >= n or js_str[after] in ',}':
                                closing = j
                                break
                        j += 1
                    if closing >= 0:
                        inner = js_str[value_start:closing]
                        result.append(json.dumps(inner, ensure_ascii=False))
                        i = closing + 1
                    else:
                        # 未找到闭合引号，保留原样
                        result.append("'")
                else:
                    if i < n:
                        result.append(js_str[i])
                        i += 1
            else:
                result.append(js_str[i])
                i += 1
        repaired = ''.join(result)
        return repaired if repaired != js_str else None

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
