"""
OpenAI 兼容 API 后端
====================
支持 OpenAI、Azure OpenAI、以及任何兼容 /v1/chat/completions 的服务。
"""

import asyncio
import logging
from typing import Optional

import httpx

from .base import BaseLLMBackend

logger = logging.getLogger(__name__)


class OpenAIBackend(BaseLLMBackend):
    """
    OpenAI 兼容后端。
    支持 api_base 自定义，可对接任何兼容服务。
    """

    def __init__(
        self,
        api_base: str = "https://api.openai.com/v1",
        api_key: str = "",
        timeout: float = 60.0,
        max_retries: int = 3,
        default_model: str = "gpt-4o-mini",
    ):
        self.api_base = api_base.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.default_model = default_model
        self._client: Optional[httpx.Client] = None
        self._async_client: Optional[httpx.AsyncClient] = None

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                timeout=httpx.Timeout(self.timeout),
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
            )
        return self._client

    def _get_async_client(self) -> httpx.AsyncClient:
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
            )
        return self._async_client

    def _build_payload(
        self, system_prompt: str, user_prompt: str,
        model: Optional[str], temperature: float, max_tokens: int,
    ) -> dict:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})
        return {
            "model": model or self.default_model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

    def chat_sync(
        self,
        system_prompt: str,
        user_prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ) -> str:
        payload = self._build_payload(system_prompt, user_prompt, model, temperature, max_tokens)
        last_error = ""
        for attempt in range(self.max_retries):
            try:
                resp = self._get_client().post(
                    f"{self.api_base}/chat/completions",
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
                return data["choices"][0]["message"]["content"]
            except httpx.HTTPStatusError as e:
                last_error = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
                logger.warning("OpenAI API 调用失败 (attempt %d/%d): %s",
                               attempt + 1, self.max_retries, last_error)
                if e.response.status_code in (401, 403):
                    raise RuntimeError(f"API 认证失败: {last_error}") from e
            except httpx.RequestError as e:
                last_error = str(e)
                logger.warning("网络错误 (attempt %d/%d): %s",
                               attempt + 1, self.max_retries, last_error)
            if attempt < self.max_retries - 1:
                import time
                time.sleep(2 ** attempt)
        raise RuntimeError(f"OpenAI API 调用失败，已重试 {self.max_retries} 次: {last_error}")

    async def chat(
        self,
        system_prompt: str,
        user_prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ) -> str:
        payload = self._build_payload(system_prompt, user_prompt, model, temperature, max_tokens)
        last_error = ""
        for attempt in range(self.max_retries):
            try:
                resp = await self._get_async_client().post(
                    f"{self.api_base}/chat/completions",
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
                return data["choices"][0]["message"]["content"]
            except httpx.HTTPStatusError as e:
                last_error = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
                logger.warning("OpenAI API 异步调用失败 (attempt %d/%d): %s",
                               attempt + 1, self.max_retries, last_error)
                if e.response.status_code in (401, 403):
                    raise RuntimeError(f"API 认证失败: {last_error}") from e
            except httpx.RequestError as e:
                last_error = str(e)
                logger.warning("网络错误 (attempt %d/%d): %s",
                               attempt + 1, self.max_retries, last_error)
            if attempt < self.max_retries - 1:
                await asyncio.sleep(2 ** attempt)
        raise RuntimeError(f"OpenAI API 调用失败，已重试 {self.max_retries} 次: {last_error}")

    def is_available(self) -> bool:
        try:
            resp = self._get_client().get(f"{self.api_base}/models")
            return resp.status_code == 200
        except Exception:
            return False

    def close(self) -> None:
        if self._client:
            self._client.close()
            self._client = None
        if self._async_client:
            # async 客户端用 asyncio.run 来关闭不太优雅；提供显式 close
            pass

    async def aclose(self) -> None:
        if self._async_client:
            await self._async_client.aclose()
            self._async_client = None


__all__ = ["OpenAIBackend"]
