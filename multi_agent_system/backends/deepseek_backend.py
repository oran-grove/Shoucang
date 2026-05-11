"""
DeepSeek API 后端
================
支持 DeepSeek V2/V3/V4 系列模型及 DeepSeek-R1 推理模型。

DeepSeek API 完全兼容 OpenAI 接口格式，地址 https://api.deepseek.com/v1。

核心特性：
- 标准 chat 模型（deepseek-chat）— 支持 V2/V3/V4 系列
- 推理模型（deepseek-reasoner）— 支持思考深度控制 (reasoning_effort)
- 自动处理 reasoning_content 文本提取
- 内置模型名称常量和推荐配置

API 参考：
- 文档: https://api-docs.deepseek.com/
- Base URL: https://api.deepseek.com/v1
- 模型列表: GET /v1/models
- Chat: POST /v1/chat/completions

DeepSeek V4 / 思考深度说明：
- deepseek-chat（V4 系列）支持 reasoning_effort 参数，值可为 "low" | "medium" | "high"
- deepseek-reasoner（R1 系列）同样支持 reasoning_effort，且响应中附带 reasoning_content
- reasoning_content 会在 choices[0].message.reasoning_content 中返回（思考过程）
"""

import logging
from typing import Any, Optional

import httpx

from .base import BaseLLMBackend, ModelInfo
from .openai_backend import OpenAIBackend

logger = logging.getLogger(__name__)

# ============================================================
# DeepSeek 模型名称常量
# ============================================================


class DeepSeekModel:
    """DeepSeek 官方模型名称常量"""

    # --- 便捷别名（推荐使用） ---
    CHAT = "deepseek-chat"          # DeepSeek-V4 旗舰对话模型（默认）
    REASONER = "deepseek-reasoner"  # DeepSeek-R1-V4 推理模型

    # --- 当前最新（V4 系列，2026） ---
    CHAT_V4 = "deepseek-chat"        # DeepSeek-V4 旗舰对话模型（默认）
    REASONER_V4 = "deepseek-reasoner"  # DeepSeek-R1-V4 推理模型

    # --- V3 系列（兼容旧版） ---
    CHAT_V3 = "deepseek-chat"        # V3 同样映射到此名称
    REASONER_V1 = "deepseek-reasoner"

    # --- 历史模型（可能已下线） ---
    CHAT_V2 = "deepseek-chat"        # V2 同样映射

    # --- 推荐默认值 ---
    DEFAULT_CHAT = "deepseek-chat"
    DEFAULT_REASONER = "deepseek-reasoner"


# ============================================================
# DeepSeek 推理/思考强度枚举
# ============================================================

class ReasoningEffort:
    """DeepSeek reasoning_effort 参数取值"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# ============================================================
# DeepSeekBackend
# ============================================================


class DeepSeekBackend(OpenAIBackend):
    """
    DeepSeek API 后端。

    基于 OpenAI 兼容协议，额外支持：
    - reasoning_effort — 控制推理模型的思考深度（low/medium/high）
    - 自动提取 reasoning_content — 返回文本中附带思考过程（可选）
    - 内置模型名称列表 — 便于前端选择和自动切换

    使用示例：

        backend = DeepSeekBackend(api_key="sk-xxx")
        # 使用标准对话模型
        reply = backend.chat_sync("system", "user prompt")
        # 使用推理模型 + 高思考深度
        reply = backend.chat_sync(
            "system", "complex problem",
            model="deepseek-reasoner",
            reasoning_effort="high",
        )
    """

    # —— 内置模型元数据（供前端 / CLI 拉取列表） ——
    KNOWN_MODELS: dict[str, dict[str, Any]] = {
        "deepseek-chat": {
            "display_name": "DeepSeek-V4 Chat",
            "type": "llm",
            "description": "DeepSeek 旗舰对话模型（V4），通用文本生成",
            "supports_reasoning": True,
            "max_context_length": 131072,
        },
        "deepseek-reasoner": {
            "display_name": "DeepSeek-R1 Reasoner",
            "type": "llm",
            "description": "DeepSeek 推理模型（R1），擅长复杂逻辑推理与数学",
            "supports_reasoning": True,
            "max_context_length": 65536,
        },
    }

    def __init__(
        self,
        api_key: str,
        api_base: str = "https://api.deepseek.com/v1",
        timeout: float = 120.0,
        max_retries: int = 5,
        default_model: str = DeepSeekModel.DEFAULT_CHAT,
        default_reasoning_effort: Optional[str] = None,
        include_reasoning: bool = False,
        **kwargs,
    ):
        """
        Args:
            api_key: DeepSeek API 密钥（sk- 开头）
            api_base: API 地址（默认 https://api.deepseek.com/v1）
            timeout: 单次请求超时秒数（推理模型建议 >= 120s）
            max_retries: 最大重试次数
            default_model: 默认使用的模型名称
            default_reasoning_effort: 默认推理强度（None 表示不启用，兼容普通模型）
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
        self._default_reasoning_effort = default_reasoning_effort
        self._include_reasoning = include_reasoning

    # ============================================================
    # 模型列表
    # ============================================================

    def list_models(self) -> list[ModelInfo]:
        """
        列出 DeepSeek 可用模型。

        优先从 API GET /v1/models 获取实际可用模型列表；
        若失败，回退到内置 KNOWN_MODELS 常量。

        Returns:
            list[ModelInfo]: 模型信息列表
        """
        models: list[ModelInfo] = []
        tried_api = False
        try:
            resp = self._get_client().get(f"{self.api_base}/models")
            if resp.status_code == 200:
                tried_api = True
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
            # 回退到内置已知模型
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
        """
        DeepSeek 是云端 API，无"已加载"概念。
        返回所有已知可用模型（等同于 list_models）。
        """
        return self.list_models()

    def is_model_loaded(self, model_id: str) -> bool:
        """检查模型是否可用（云端 API 始终返回 True）"""
        return True

    def ensure_model_loaded(self, model_name: str) -> bool:
        """云端 API 无需加载，始终返回 True"""
        return True

    # ============================================================
    # 核心 Chat 方法 — 支持 reasoning_effort
    # ============================================================

    def _build_payload(
        self,
        system_prompt: str,
        user_prompt: str,
        model: Optional[str],
        temperature: float,
        max_tokens: int,
        reasoning_effort: Optional[str] = None,
    ) -> dict:
        """
        构建 DeepSeek chat 请求体。

        在 OpenAI 兼容格式基础上，添加：
        - reasoning_effort: 推理/思考深度控制（仅 DeepSeek V4 / R1 支持）

        Args:
            system_prompt: 系统提示词
            user_prompt: 用户提示词
            model: 模型名称
            temperature: 温度
            max_tokens: 最大输出 token
            reasoning_effort: 推理强度 ("low" | "medium" | "high")，None 表示不启用
        """
        payload = super()._build_payload(system_prompt, user_prompt, model, temperature, max_tokens)

        # 推理模型特殊参数
        effective_effort = reasoning_effort or self._default_reasoning_effort
        if effective_effort:
            # reasoning_effort 对 deepseek-chat 和 deepseek-reasoner 均有效
            payload["reasoning_effort"] = effective_effort

        return payload

    def _extract_response_content(self, data: dict) -> str:
        """
        从 API 响应中提取文本内容。

        如果 include_reasoning=True，会将 reasoning_content 拼接到回复前。
        DeepSeek R1 模型中，message 可能同时包含：
        - content: 最终回复
        - reasoning_content: 内部思考过程
        """
        choice = data["choices"][0]
        message = choice["message"]
        content = message.get("content", "") or ""

        if self._include_reasoning:
            reasoning = message.get("reasoning_content", "") or ""
            if reasoning:
                content = f"[思考过程]\n{reasoning}\n\n[回复]\n{content}"

        return content

    def chat_sync(
        self,
        system_prompt: str,
        user_prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 2048,
        reasoning_effort: Optional[str] = None,
    ) -> str:
        """
        同步对话。

        Args:
            system_prompt: 系统提示词
            user_prompt: 用户提示词
            model: 模型名称（默认使用 default_model）
            temperature: 温度
            max_tokens: 最大输出 token
            reasoning_effort: 推理强度 ("low" | "medium" | "high")，None 使用默认

        Returns:
            str: LLM 回复文本（可能包含思考过程）
        """
        effective_model = model or self.default_model
        payload = self._build_payload(system_prompt, user_prompt, effective_model, temperature, max_tokens, reasoning_effort)

        logger.debug(
            "DeepSeek sync chat: model=%s reasoning_effort=%s max_tokens=%d",
            effective_model,
            payload.get("reasoning_effort", "N/A"),
            max_tokens,
        )

        import time
        last_error = ""
        for attempt in range(self.max_retries):
            try:
                resp = self._get_client().post(
                    f"{self.api_base}/chat/completions",
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
                return self._extract_response_content(data)
            except httpx.HTTPStatusError as e:
                last_error = f"HTTP {e.response.status_code}: {e.response.text[:300]}"
                logger.warning(
                    "DeepSeek API 调用失败 (attempt %d/%d): %s",
                    attempt + 1, self.max_retries, last_error,
                )
                if e.response.status_code in (401, 403):
                    raise RuntimeError(f"DeepSeek API 认证失败: {last_error}") from e
                if e.response.status_code == 429:
                    # 速率限制 — 指数退避延长
                    wait = 3 * (2 ** attempt)
                    logger.warning("速率限制，等待 %ds 后重试", wait)
                    time.sleep(wait)
                    continue
            except httpx.RequestError as e:
                last_error = str(e)
                logger.warning(
                    "DeepSeek 网络错误 (attempt %d/%d): %s",
                    attempt + 1, self.max_retries, last_error,
                )
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
        reasoning_effort: Optional[str] = None,
    ) -> str:
        """
        异步对话。

        Args:
            system_prompt: 系统提示词
            user_prompt: 用户提示词
            model: 模型名称（默认使用 default_model）
            temperature: 温度
            max_tokens: 最大输出 token
            reasoning_effort: 推理强度 ("low" | "medium" | "high")，None 使用默认

        Returns:
            str: LLM 回复文本（可能包含思考过程）
        """
        effective_model = model or self.default_model
        payload = self._build_payload(system_prompt, user_prompt, effective_model, temperature, max_tokens, reasoning_effort)

        logger.debug(
            "DeepSeek async chat: model=%s reasoning_effort=%s max_tokens=%d",
            effective_model,
            payload.get("reasoning_effort", "N/A"),
            max_tokens,
        )

        import asyncio
        last_error = ""
        for attempt in range(self.max_retries):
            try:
                resp = await self._get_async_client().post(
                    f"{self.api_base}/chat/completions",
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
                return self._extract_response_content(data)
            except httpx.HTTPStatusError as e:
                last_error = f"HTTP {e.response.status_code}: {e.response.text[:300]}"
                logger.warning(
                    "DeepSeek API 异步调用失败 (attempt %d/%d): %s",
                    attempt + 1, self.max_retries, last_error,
                )
                if e.response.status_code in (401, 403):
                    raise RuntimeError(f"DeepSeek API 认证失败: {last_error}") from e
                if e.response.status_code == 429:
                    wait = 3 * (2 ** attempt)
                    logger.warning("速率限制，等待 %ds 后重试", wait)
                    await asyncio.sleep(wait)
                    continue
            except httpx.RequestError as e:
                last_error = str(e)
                logger.warning(
                    "DeepSeek 网络错误 (attempt %d/%d): %s",
                    attempt + 1, self.max_retries, last_error,
                )
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
        """
        获取指定模型的元数据（用于前端展示）。

        Args:
            model_id: 模型名称，None 时返回所有已知模型元数据

        Returns:
            dict: 模型元数据（display_name, type, description, supports_reasoning, max_context_length）
        """
        if model_id:
            meta = self.KNOWN_MODELS.get(model_id, {})
            return {
                "model_id": model_id,
                "display_name": meta.get("display_name", model_id),
                "type": meta.get("type", "llm"),
                "description": meta.get("description", ""),
                "supports_reasoning": meta.get("supports_reasoning", False),
                "max_context_length": meta.get("max_context_length", 131072),
            }
        return {
            mid: {
                "model_id": mid,
                "display_name": meta.get("display_name", mid),
                "type": meta.get("type", "llm"),
                "description": meta.get("description", ""),
                "supports_reasoning": meta.get("supports_reasoning", False),
                "max_context_length": meta.get("max_context_length", 131072),
            }
            for mid, meta in self.KNOWN_MODELS.items()
        }

    def get_backend_info(self) -> dict:
        """
        获取后端运行信息（用于前端状态面板）。

        Returns:
            dict: 包含 api_base、default_model、reasoning_effort 设置等
        """
        return {
            "backend_type": "deepseek",
            "api_base": self.api_base,
            "default_model": self.default_model,
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
    "DeepSeekModel",
    "ReasoningEffort",
]