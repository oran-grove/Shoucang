"""
DeepSeek API 后端
================
基于 DeepSeek API 最新规范（V4）。

当前可用模型：
- deepseek-v4-flash — 快速响应模型
- deepseek-v4-pro — 旗舰推理模型

可选参数（通过 extra_body 传递）：
- thinking: {"thinking": {"type": "enabled"}} 或 {"thinking": {"type": "disabled"}}
- reasoning_effort: "high" 或 "max"

API 参考：https://api-docs.deepseek.com/
Base URL: https://api.deepseek.com
"""

import logging
import time
from typing import Any, Optional

import httpx

from .base import BaseLLMBackend, ModelInfo
from .openai_backend import OpenAIBackend

logger = logging.getLogger(__name__)

# ============================================================
# DeepSeekBackend
# ============================================================


class DeepSeekBackend(OpenAIBackend):
    """
    DeepSeek API 后端（V4）。

    基于 OpenAI 兼容协议，额外支持：
    - thinking — 思考模式开关 (enabled/disabled)
    - reasoning_effort — 推理强度 (high/max)
    - 自动提取 reasoning_content — 思考过程（可选拼接至回复）

    使用示例：

        backend = DeepSeekBackend(api_key="sk-xxx")
        reply = backend.chat_sync("system", "user prompt")
        reply = backend.chat_sync(
            "system", "complex problem",
            model="deepseek-v4-pro",
            thinking_enabled=True,
            reasoning_effort="max",
        )
    """

    # —— 内置模型元数据（供前端 / CLI 拉取列表） ——
    KNOWN_MODELS: dict[str, dict[str, Any]] = {
        "deepseek-v4-flash": {
            "display_name": "DeepSeek V4 Flash",
            "type": "llm",
            "description": "⚡ DeepSeek V4 快速响应模型，低延迟，适合常规任务",
            "supports_thinking": True,
            "supports_reasoning_effort": False,
            "max_context_length": 131072,
            "is_recommended": True,
        },
        "deepseek-v4-pro": {
            "display_name": "DeepSeek V4 Pro",
            "type": "llm",
            "description": "🧠 DeepSeek V4 旗舰推理模型，深度思考，擅长复杂逻辑、数学、代码推理",
            "supports_thinking": True,
            "supports_reasoning_effort": True,
            "max_context_length": 131072,
            "is_recommended": False,
        },
    }

    def __init__(
        self,
        api_key: str,
        api_base: str = "https://api.deepseek.com",
        timeout: float = 120.0,
        max_retries: int = 5,
        default_model: str = "deepseek-v4-flash",
        default_thinking_enabled: Optional[bool] = None,
        default_reasoning_effort: Optional[str] = None,
        include_reasoning: bool = False,
        **kwargs,
    ):
        """
        Args:
            api_key: DeepSeek API 密钥（sk- 开头）
            api_base: API 地址（默认 https://api.deepseek.com）
            timeout: 单次请求超时秒数（推理模型建议 >= 120s）
            max_retries: 最大重试次数
            default_model: 默认使用的模型名称
            default_thinking_enabled: 默认思考模式（None 表示不显式设置）
            default_reasoning_effort: 默认推理强度 ("high" | "max")，None 表示不启用
            include_reasoning: 是否在返回文本中包含 reasoning_content（思考过程）
            **kwargs: 透传至 OpenAIBackend（预留扩展）
        """
        super().__init__(
            api_base=api_base,
            api_key=api_key,
            timeout=timeout,
            max_retries=max_retries,
            default_model=default_model,
        )
        self._default_thinking_enabled = default_thinking_enabled
        self._default_reasoning_effort = default_reasoning_effort
        self._include_reasoning = include_reasoning

    # ============================================================
    # 模型列表
    # ============================================================

    def list_models(self) -> list[ModelInfo]:
        """
        列出 DeepSeek 可用模型。

        优先从 API GET /models 获取；若失败，回退到内置 KNOWN_MODELS。
        """
        models: list[ModelInfo] = []
        try:
            resp = self._get_client().get(f"{self.api_base}/models")
            if resp.status_code == 200:
                data = resp.json()
                raw_list = data.get("data", data) if isinstance(data, dict) else data
                if isinstance(raw_list, list):
                    for m in raw_list:
                        mid = m.get("id", "")
                        if not mid:
                            continue
                        meta = self.KNOWN_MODELS.get(mid, {})
                        models.append(ModelInfo(
                            model_id=mid,
                            type="llm",
                            status="available",
                            instance_id=mid,
                            context_length=m.get("context_length", meta.get("max_context_length", 131072)),
                        ))
        except Exception as e:
            logger.debug("从 DeepSeek API 获取模型列表失败: %s，使用内置列表", e)

        if not models:
            for model_id, meta in self.KNOWN_MODELS.items():
                models.append(ModelInfo(
                    model_id=model_id,
                    type=meta.get("type", "llm"),
                    status="available",
                    instance_id=model_id,
                    context_length=meta.get("max_context_length", 131072),
                ))

        return models

    def list_loaded_models(self) -> list[ModelInfo]:
        """云端 API 无"已加载"概念，返回所有已知模型"""
        return self.list_models()

    def is_model_loaded(self, model_id: str) -> bool:
        """云端 API 始终可用"""
        return True

    def ensure_model_loaded(self, model_name: str) -> bool:
        """云端 API 无需加载"""
        return True

    # ============================================================
    # Payload 构建 — 支持 thinking + reasoning_effort
    # ============================================================

    def _build_payload(
        self,
        system_prompt: str,
        user_prompt: str,
        model: Optional[str],
        temperature: float,
        max_tokens: int,
        thinking_enabled: Optional[bool] = None,
        reasoning_effort: Optional[str] = None,
    ) -> dict:
        """
        构建 DeepSeek chat 请求体。

        Args:
            system_prompt: 系统提示词
            user_prompt: 用户提示词
            model: 模型名称
            temperature: 温度
            max_tokens: 最大输出 token
            thinking_enabled: 思考模式开关 (True/False/None=使用默认)
            reasoning_effort: 推理强度 ("high" | "max")，None 表示不设置
        """
        effective_model = model or self.default_model
        payload = super()._build_payload(system_prompt, user_prompt, effective_model, temperature, max_tokens)

        # extra_body 参数
        extra: dict[str, Any] = {}

        # thinking 开关
        effective_thinking = thinking_enabled if thinking_enabled is not None else self._default_thinking_enabled
        if effective_thinking is not None:
            extra["thinking"] = {"type": "enabled" if effective_thinking else "disabled"}

        # reasoning_effort
        effective_effort = reasoning_effort or self._default_reasoning_effort
        if effective_effort:
            extra["reasoning_effort"] = effective_effort

        if extra:
            payload["extra_body"] = extra

        return payload

    def _extract_response_content(self, data: dict) -> str:
        """从 API 响应提取文本，可选拼接 reasoning_content"""
        choice = data["choices"][0]
        message = choice["message"]
        content = message.get("content", "") or ""

        if self._include_reasoning:
            reasoning = message.get("reasoning_content", "") or ""
            if reasoning:
                content = f"[思考过程]\n{reasoning}\n\n[回复]\n{content}"

        return content

    # ============================================================
    # 同步 / 异步 Chat
    # ============================================================

    def chat_sync(
        self,
        system_prompt: str,
        user_prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 2048,
        thinking_enabled: Optional[bool] = None,
        reasoning_effort: Optional[str] = None,
    ) -> str:
        """同步对话"""
        payload = self._build_payload(
            system_prompt, user_prompt, model,
            temperature, max_tokens,
            thinking_enabled, reasoning_effort,
        )

        logger.debug(
            "DeepSeek sync chat: model=%s thinking=%s reasoning_effort=%s",
            payload.get("model"),
            payload.get("extra_body", {}).get("thinking", {}).get("type", "N/A"),
            payload.get("extra_body", {}).get("reasoning_effort", "N/A"),
        )

        last_error = ""
        for attempt in range(self.max_retries):
            try:
                resp = self._get_client().post(
                    f"{self.api_base}/chat/completions",
                    json=payload,
                )
                resp.raise_for_status()
                return self._extract_response_content(resp.json())
            except httpx.HTTPStatusError as e:
                last_error = f"HTTP {e.response.status_code}: {e.response.text[:300]}"
                logger.warning("DeepSeek API 调用失败 (attempt %d/%d): %s", attempt + 1, self.max_retries, last_error)
                if e.response.status_code in (401, 403):
                    raise RuntimeError(f"DeepSeek API 认证失败: {last_error}") from e
                if e.response.status_code == 429:
                    wait = 3 * (2 ** attempt)
                    logger.warning("速率限制，等待 %ds 后重试", wait)
                    time.sleep(wait)
                    continue
            except httpx.RequestError as e:
                last_error = str(e)
                logger.warning("DeepSeek 网络错误 (attempt %d/%d): %s", attempt + 1, self.max_retries, last_error)
            if attempt < self.max_retries - 1:
                time.sleep(2 ** attempt)

        raise RuntimeError(f"DeepSeek API 调用失败，已重试 {self.max_retries} 次: {last_error}")

    async def chat(
        self,
        system_prompt: str,
        user_prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 2048,
        thinking_enabled: Optional[bool] = None,
        reasoning_effort: Optional[str] = None,
    ) -> str:
        """异步对话"""
        import asyncio

        payload = self._build_payload(
            system_prompt, user_prompt, model,
            temperature, max_tokens,
            thinking_enabled, reasoning_effort,
        )

        logger.debug(
            "DeepSeek async chat: model=%s thinking=%s reasoning_effort=%s",
            payload.get("model"),
            payload.get("extra_body", {}).get("thinking", {}).get("type", "N/A"),
            payload.get("extra_body", {}).get("reasoning_effort", "N/A"),
        )

        last_error = ""
        for attempt in range(self.max_retries):
            try:
                resp = await self._get_async_client().post(
                    f"{self.api_base}/chat/completions",
                    json=payload,
                )
                resp.raise_for_status()
                return self._extract_response_content(resp.json())
            except httpx.HTTPStatusError as e:
                last_error = f"HTTP {e.response.status_code}: {e.response.text[:300]}"
                logger.warning("DeepSeek API 异步调用失败 (attempt %d/%d): %s", attempt + 1, self.max_retries, last_error)
                if e.response.status_code in (401, 403):
                    raise RuntimeError(f"DeepSeek API 认证失败: {last_error}") from e
                if e.response.status_code == 429:
                    wait = 3 * (2 ** attempt)
                    logger.warning("速率限制，等待 %ds 后重试", wait)
                    await asyncio.sleep(wait)
                    continue
            except httpx.RequestError as e:
                last_error = str(e)
                logger.warning("DeepSeek 网络错误 (attempt %d/%d): %s", attempt + 1, self.max_retries, last_error)
            if attempt < self.max_retries - 1:
                await asyncio.sleep(2 ** attempt)

        raise RuntimeError(f"DeepSeek API 调用失败，已重试 {self.max_retries} 次: {last_error}")

    # ============================================================
    # 便捷方法
    # ============================================================

    def is_available(self) -> bool:
        """检查 DeepSeek API 连通性"""
        try:
            resp = self._get_client().get(f"{self.api_base}/models")
            return resp.status_code == 200
        except Exception:
            return False

    def get_model_metadata(self, model_id: Optional[str] = None) -> dict:
        """获取模型元数据（用于前端展示）"""
        if model_id:
            meta = self.KNOWN_MODELS.get(model_id, {})
            return {
                "model_id": model_id,
                "display_name": meta.get("display_name", model_id),
                "type": meta.get("type", "llm"),
                "description": meta.get("description", ""),
                "supports_thinking": meta.get("supports_thinking", False),
                "supports_reasoning_effort": meta.get("supports_reasoning_effort", False),
                "max_context_length": meta.get("max_context_length", 131072),
            }
        return {
            mid: {
                "model_id": mid,
                "display_name": meta.get("display_name", mid),
                "type": meta.get("type", "llm"),
                "description": meta.get("description", ""),
                "supports_thinking": meta.get("supports_thinking", False),
                "supports_reasoning_effort": meta.get("supports_reasoning_effort", False),
                "max_context_length": meta.get("max_context_length", 131072),
            }
            for mid, meta in self.KNOWN_MODELS.items()
        }

    def get_backend_info(self) -> dict:
        """获取后端运行信息（用于前端状态面板）"""
        return {
            "backend_type": "deepseek",
            "api_base": self.api_base,
            "default_model": self.default_model,
            "default_thinking_enabled": self._default_thinking_enabled,
            "default_reasoning_effort": self._default_reasoning_effort,
            "include_reasoning": self._include_reasoning,
            "is_available": self.is_available(),
            "known_models": self.get_model_metadata(),
            "api_models": [
                {"model_id": m.model_id, "context_length": m.context_length}
                for m in self.list_models()
            ],
        }


__all__ = [
    "DeepSeekBackend",
]