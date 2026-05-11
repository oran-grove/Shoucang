"""
LLM 后端抽象接口
================
定义所有后端的公共接口，支持同步/异步调用。
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class ModelInfo:
    """模型信息数据结构（通用）"""
    model_id: str                          # 模型唯一标识符
    type: str = "llm"                      # "llm" | "embedding"
    status: str = "not-loaded"             # "loaded" | "not-loaded" | "loading"
    instance_id: str = ""                  # 加载后的实例 ID
    context_length: int = 4096             # 上下文长度
    load_time_seconds: float = 0.0         # 加载耗时


@dataclass
class LoadModelConfig:
    """模型加载配置"""
    model: str = ""                        # 模型标识符
    context_length: Optional[int] = None   # 最大 token 数
    eval_batch_size: Optional[int] = None  # 批处理 token 数
    flash_attention: Optional[bool] = None # 是否启用 Flash Attention
    num_experts: Optional[int] = None      # MoE 专家数
    offload_kv_cache_to_gpu: Optional[bool] = None  # KV 缓存是否放 GPU
    echo_load_config: bool = False         # 是否在响应中回显最终加载配置


class BaseLLMBackend(ABC):
    """
    LLM 后端抽象基类。
    所有后端（OpenAI API / LM Studio / 其他）均需实现此接口。
    """

    def __init__(self):
        self.default_model: str = ""

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

    # ——— 模型管理接口（可选实现）———

    def list_models(self) -> list[ModelInfo]:
        """
        列出所有可用的模型（包括已加载和未加载的）。
        默认返回空列表，子类可按需覆写。
        """
        return []

    def list_loaded_models(self) -> list[ModelInfo]:
        """
        列出当前已加载的模型。
        默认返回空列表，子类可按需覆写。
        """
        return []

    def load_model(self, config: LoadModelConfig) -> ModelInfo:
        """
        加载指定模型。返回加载后的 ModelInfo。
        默认抛出 NotImplementedError，子类可按需覆写。
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} 不支持 load_model 操作"
        )

    def unload_model(self, model_id: str) -> bool:
        """
        卸载指定模型。返回是否成功。
        默认抛出 NotImplementedError，子类可按需覆写。
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} 不支持 unload_model 操作"
        )

    def ensure_model_loaded(self, model_name: str) -> bool:
        """
        确保指定模型已加载，未加载时自动加载。
        返回是否就绪。默认直接返回 True（对于不支持加载的后端）。
        """
        return True

    def close(self) -> None:
        """关闭后端连接（同步）"""
        pass

    async def aclose(self) -> None:
        """关闭后端连接（异步）"""
        pass


__all__ = ["BaseLLMBackend", "ModelInfo", "LoadModelConfig"]