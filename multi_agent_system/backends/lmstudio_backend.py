"""
LM Studio 本地 AI 后端
======================
LM Studio 暴露 OpenAI 兼容 API，默认地址 http://localhost:1234/v1。
此外 LM Studio 0.3+ 提供 /api/v1/models/load 等模型管理接口。

此后端继承 OpenAIBackend，新增：
- 智能自动加载模型（auto_load）
- 列出可用模型列表
- 加载/卸载模型
- 模型加载状态缓存
"""

import logging
import time
from threading import Lock
from typing import Any, Optional

import httpx

from .base import BaseLLMBackend, ModelInfo, LoadModelConfig
from .openai_backend import OpenAIBackend

logger = logging.getLogger(__name__)


class LMStudioBackend(OpenAIBackend):
    """
    LM Studio 后端。

    特性：
    - 完全兼容 OpenAI API (/v1/chat/completions)
    - 自动加载模型（启用 auto_load 时，调用前检测目标模型是否已加载）
    - 支持 /api/v1/models 列出模型
    - 支持 /api/v1/models/load 加载模型（带配置）
    - 支持 POST /api/v1/models/unload 卸载模型

    LM Studio API 参考：
    - 管理 API 根路径：http://localhost:1234/api/v1
    - 推理 API 根路径：http://localhost:1234/v1（OpenAI 兼容）
    """

    def __init__(
        self,
        api_base: str = "http://localhost:1234/v1",
        api_key: str = "lm-studio",
        timeout: float = 120.0,
        max_retries: int = 2,
        default_model: str = "qwen3.5-9b",
        auto_load: bool = True,
        default_load_config: Optional[LoadModelConfig] = None,
    ):
        """
        Args:
            api_base: LM Studio OpenAI 兼容 API 地址
            api_key: API 密钥（LM Studio 默认 "lm-studio"）
            timeout: 请求超时秒数
            max_retries: 最大重试次数
            default_model: 默认模型名称
            auto_load: 是否在调用前自动加载未就绪的模型
            default_load_config: 模型加载默认配置，None 则用内置默认值
        """
        super().__init__(
            api_base=api_base,
            api_key=api_key,
            timeout=timeout,
            max_retries=max_retries,
            default_model=default_model,
        )
        self.auto_load = auto_load
        self.default_load_config = default_load_config or LoadModelConfig()
        # 管理 API 地址（LM Studio 从 0.3 起管理 API 在 /api/v1，推理 API 在 /v1）
        # api_base 形如 http://localhost:1234/v1，管理根目录需去掉尾部 /v1
        _mgmt = api_base.rstrip("/").rstrip()
        if _mgmt.endswith("/v1"):
            _mgmt = _mgmt[:-3]  # 去掉尾部的 "/v1" → 如 "http://localhost:1234"
        self._mgmt_api_base = _mgmt
        logger.debug("LM Studio 管理 API 基础地址: %s", self._mgmt_api_base)
        # 已加载模型缓存
        self._loaded_models: dict[str, ModelInfo] = {}  # model_id -> ModelInfo
        self._loaded_models_lock = Lock()

    # ============================================================
    # 模型管理 API
    # ============================================================

    def _fetch_and_cache_loaded_models(self) -> dict[str, ModelInfo]:
        """
        从管理 API 获取已加载模型并更新内部缓存。
        返回服务端当前已加载的模型 {model_id: ModelInfo}。
        同时会尝试通过 /v1/models (OpenAI 兼容) 作为辅助确认。
        """
        loaded: dict[str, ModelInfo] = {}
        # 主路径：管理 API GET /api/v1/models
        # 实际返回格式: {"models": [{"key": "...", "loaded_instances": [...], "type": "llm", ...}]}
        # 加载状态: "loaded_instances" 非空数组表示已加载
        try:
            resp = self._do_mgmt_get("/api/v1/models")
            data = resp.json()
            # 兼容 {"models": [...]} 和 {"data": [...]} 两种格式
            model_list: Any = (
                data.get("models") if isinstance(data, dict) and "models" in data
                else data.get("data") if isinstance(data, dict) and "data" in data
                else data
            )
            if isinstance(model_list, dict):
                model_list = [model_list]
            if not isinstance(model_list, list):
                model_list = []
            for m in model_list:
                if not isinstance(m, dict):
                    continue
                # 模型 ID: LM Studio 用 "key"，兼容 "id"
                mid = m.get("key") or m.get("id", "")
                if not mid:
                    continue
                # 判断是否已加载: loaded_instances 非空数组 > status > state > loaded 字段
                loaded_insts = m.get("loaded_instances", [])
                is_loaded = bool(loaded_insts)  # 有一个及以上实例即已加载
                if not is_loaded:
                    is_loaded = (
                        m.get("status") == "loaded"
                        or m.get("state") == "loaded"
                        or m.get("loaded") is True
                    )
                if is_loaded:
                    # 提取已加载实例信息
                    inst = loaded_insts[0] if loaded_insts else {}
                    info = ModelInfo(
                        model_id=mid,
                        type=m.get("type", "llm"),
                        status="loaded",
                        instance_id=(
                            inst.get("instance_id")
                            or m.get("instance_id")
                            or mid
                        ),
                        load_time_seconds=float(
                            inst.get("load_time_seconds") or m.get("load_time_seconds", 0.0)
                        ),
                        context_length=(
                            m.get("max_context_length")
                            or m.get("context_length")
                            or inst.get("context_length", 4096)
                        ),
                    )
                    loaded[mid] = info
        except Exception as e:
            logger.debug("管理 API /api/v1/models 查询失败: %s", e)

        # 辅助路径：OpenAI 兼容 GET /v1/models（通常只返回已加载模型）
        if not loaded:
            try:
                resp = self._get_client().get(f"{self.api_base}/models")
                if resp.status_code == 200:
                    data = resp.json()
                    # 兼容 {"data": [...]} 和 {"models": [...]}
                    v1_data: Any = (
                        data.get("data") if isinstance(data, dict) and "data" in data
                        else data.get("models") if isinstance(data, dict) and "models" in data
                        else data
                    )
                    if isinstance(v1_data, dict):
                        v1_data = [v1_data]
                    if isinstance(v1_data, list):
                        for m in v1_data:
                            if not isinstance(m, dict):
                                continue
                            mid = m.get("key") or m.get("id", str(m))
                            if mid:
                                loaded[mid] = ModelInfo(
                                    model_id=mid,
                                    type="llm",
                                    status="loaded",
                                    instance_id=mid,
                                )
            except Exception as e:
                logger.debug("OpenAI /v1/models 查询失败: %s", e)

        # 写入缓存
        with self._loaded_models_lock:
            for mid, info in loaded.items():
                self._loaded_models[mid] = info
        return loaded

    def list_models(self) -> list[ModelInfo]:
        """
        列出所有可用的模型（包括已下载可加载的所有模型）。

        GET /api/v1/models (LM Studio management API)

        Returns:
            list[ModelInfo]: 模型信息列表，包含 loaded / not-loaded 状态
        """
        try:
            resp = self._do_mgmt_get("/api/v1/models")
            data = resp.json()
            models: list[ModelInfo] = []
            # 兼容 {"models": [...]} 和 {"data": [...]} 两种格式
            model_list: Any = (
                data.get("models") if isinstance(data, dict) and "models" in data
                else data.get("data") if isinstance(data, dict) and "data" in data
                else data
            )
            if isinstance(model_list, dict):
                model_list = [model_list]
            if not isinstance(model_list, list):
                model_list = []

            # 先刷新已加载缓存
            loaded_map = self._fetch_and_cache_loaded_models()

            for m in model_list:
                if not isinstance(m, dict):
                    continue
                # 模型 ID: LM Studio 用 "key"，兼容 "id"
                mid = m.get("key") or m.get("id", str(m))
                if not mid:
                    continue
                cached = loaded_map.get(mid)
                model_type = m.get("type", "llm")
                models.append(ModelInfo(
                    model_id=mid,
                    type=model_type,
                    status=cached.status if cached else "not-loaded",
                    context_length=(
                        m.get("max_context_length")
                        or m.get("context_length", 4096)
                    ),
                    instance_id=getattr(cached, "instance_id", None)
                    or m.get("instance_id", mid),
                    load_time_seconds=float(getattr(cached, "load_time_seconds", 0.0) or 0.0),
                ))
            return models
        except Exception as e:
            logger.warning("列出模型失败: %s", e)
            return []

    def list_loaded_models(self) -> list[ModelInfo]:
        """
        列出当前已加载的模型（从加载缓存 + 服务端确认）。

        Returns:
            list[ModelInfo]: 已加载模型列表
        """
        with self._loaded_models_lock:
            # 返回缓存的副本
            return list(self._loaded_models.values())

    def load_model(self, config: LoadModelConfig) -> ModelInfo:
        """
        加载模型。

        POST /api/v1/models/load (LM Studio management API)

        Args:
            config: 加载配置（model, context_length, flash_attention 等）

        Returns:
            ModelInfo: 加载后的模型信息
        """
        model_id = config.model
        if not model_id:
            raise ValueError("load_model 需要指定 model 名称")

        logger.info("正在加载模型: %s (context_length=%s, flash_attention=%s)",
                     model_id, config.context_length, config.flash_attention)

        payload: dict[str, Any] = {"model": model_id}
        if config.context_length is not None:
            payload["context_length"] = config.context_length
        if config.eval_batch_size is not None:
            payload["eval_batch_size"] = config.eval_batch_size
        if config.flash_attention is not None:
            payload["flash_attention"] = config.flash_attention
        if config.num_experts is not None:
            payload["num_experts"] = config.num_experts
        if config.offload_kv_cache_to_gpu is not None:
            payload["offload_kv_cache_to_gpu"] = config.offload_kv_cache_to_gpu
        if config.echo_load_config:
            payload["echo_load_config"] = True

        start = time.time()
        try:
            resp = self._do_mgmt_post("/api/v1/models/load", payload)
            data = resp.json()
            load_time = data.get("load_time_seconds", time.time() - start)

            info = ModelInfo(
                model_id=model_id,
                type=data.get("type", "llm"),
                status=data.get("status", "loaded"),
                instance_id=data.get("instance_id", model_id),
                context_length=data.get("load_config", {}).get("context_length", 4096),
                load_time_seconds=round(load_time, 3),
            )
            with self._loaded_models_lock:
                self._loaded_models[model_id] = info
            logger.info("模型加载完成: %s (耗时 %.1fs)", model_id, load_time)
            return info
        except Exception as e:
            logger.error("加载模型失败 [%s]: %s", model_id, e)
            raise

    def unload_model(self, model_id: str) -> bool:
        """
        卸载模型。

        POST /api/v1/models/unload (如果 LM Studio 支持该接口)
        同时尝试 LM Studio 原生卸载（通过管理 API）。

        Args:
            model_id: 模型标识符或 instance_id

        Returns:
            bool: 是否成功卸载
        """
        logger.info("正在卸载模型: %s", model_id)
        try:
            # 尝试标准卸载接口
            payload = {"model": model_id}
            resp = self._do_mgmt_post("/api/v1/models/unload", payload)
            if resp.status_code == 200:
                with self._loaded_models_lock:
                    self._loaded_models.pop(model_id, None)
                logger.info("模型已卸载: %s", model_id)
                return True
            else:
                logger.warning("卸载模型返回非 200: %s %s", resp.status_code, resp.text[:200])
        except Exception as e:
            logger.debug("POST /api/v1/models/unload 失败: %s (可能该接口未实现)", e)

        # 如果 unload 不可用，从缓存移除并返回 True
        with self._loaded_models_lock:
            removed = self._loaded_models.pop(model_id, None)
        if removed:
            logger.warning("模型 %s 已从本地缓存卸载（LM Studio 可能需手动卸载）", model_id)
            return True
        return False

    def ensure_model_loaded(self, model_name: str) -> bool:
        """
        确保指定模型已加载；若未加载且 auto_load 开启，则自动加载。

        Args:
            model_name: 模型名称

        Returns:
            bool: 模型是否就绪
        """
        if not model_name:
            model_name = self.default_model

        # 检查缓存
        status = self._get_model_status(model_name)
        if status == "loaded":
            return True

        if not self.auto_load:
            logger.warning(
                "模型 [%s] 未加载，且 auto_load=False，可能无法响应。"
                "请在 LM Studio 中手动加载该模型。", model_name
            )
            return False

        # 自动加载
        logger.info("auto_load 模式：正在自动加载模型 [%s]...", model_name)
        config = LoadModelConfig(
            model=model_name,
            context_length=self.default_load_config.context_length,
            flash_attention=self.default_load_config.flash_attention,
            eval_batch_size=self.default_load_config.eval_batch_size,
            num_experts=self.default_load_config.num_experts,
            offload_kv_cache_to_gpu=self.default_load_config.offload_kv_cache_to_gpu,
        )
        try:
            self.load_model(config)
            return True
        except Exception as e:
            logger.error("自动加载模型 [%s] 失败: %s", model_name, e)
            return False

    # ============================================================
    # 重写 chat 方法 — 加入自动加载逻辑
    # ============================================================

    def _require_model(self, model_name: str) -> None:
        """确保模型就绪，否则抛出明确错误。"""
        ok = self.ensure_model_loaded(model_name)
        if not ok:
            msg = (
                f"模型 [{model_name}] 未加载。"
                f"请在 LM Studio 中手动加载该模型，"
                f"或调用 system.load_lm_model('{model_name}') / 设置 auto_load=True"
            )
            logger.error(msg)
            raise RuntimeError(msg)

    def chat_sync(
        self,
        system_prompt: str,
        user_prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ) -> str:
        effective_model = model or self.default_model
        self._require_model(effective_model)
        return super().chat_sync(system_prompt, user_prompt, model, temperature, max_tokens)

    async def chat(
        self,
        system_prompt: str,
        user_prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ) -> str:
        effective_model = model or self.default_model
        self._require_model(effective_model)
        return await super().chat(system_prompt, user_prompt, model, temperature, max_tokens)

    # ============================================================
    # 状态查询辅助
    # ============================================================

    def is_model_loaded(self, model_id: str) -> bool:
        """检查指定模型是否已加载"""
        return self._get_model_status(model_id) == "loaded"

    def get_model_info(self, model_id: str) -> Optional[ModelInfo]:
        """获取指定模型的缓存信息"""
        with self._loaded_models_lock:
            return self._loaded_models.get(model_id)

    def refresh_loaded_models(self) -> dict[str, ModelInfo]:
        """
        从服务端刷新加载状态，更新缓存。返回最新加载列表。
        优先通过管理 API (GET /api/v1/models) 获取完整状态，
        回退到 /v1/models (OpenAI 兼容)。
        """
        # 主路径：管理 API + 缓存刷新
        try:
            self._fetch_and_cache_loaded_models()
        except Exception as e:
            logger.debug("管理 API 刷新失败: %s", e)
        # 辅助：OpenAI 兼容 /v1/models
        try:
            resp = self._get_client().get(f"{self.api_base}/models")
            resp.raise_for_status()
            data = resp.json()
            # 兼容 {"data": [...]} 和 {"models": [...]}
            v1_data2: Any = (
                data.get("data") if isinstance(data, dict) and "data" in data
                else data.get("models") if isinstance(data, dict) and "models" in data
                else data
            )
            if isinstance(v1_data2, dict):
                v1_data2 = [v1_data2]
            if isinstance(v1_data2, list):
                with self._loaded_models_lock:
                    for m in v1_data2:
                        if not isinstance(m, dict):
                            continue
                        mid = m.get("key") or m.get("id", str(m))
                        if mid and mid not in self._loaded_models:
                            self._loaded_models[mid] = ModelInfo(
                                model_id=mid,
                                type="llm",
                                status="loaded",
                                instance_id=mid,
                            )
        except Exception as e:
            logger.debug("OpenAI /v1/models 刷新失败: %s", e)
        with self._loaded_models_lock:
            return dict(self._loaded_models)

    def _resolve_model_id(self, model_id: str) -> Optional[str]:
        """
        按模糊匹配解析模型 ID。
        
        LM Studio 管理 API 返回的 ID 可能带有前缀（如 "qwen/qwen3.5-9b"），
        而用户配置可能是短名（如 "qwen3.5-9b"）。
        此方法会尝试精确匹配、末尾匹配、包含匹配等策略。
        
        Args:
            model_id: 用户提供的模型标识符 (或短名)
        
        Returns:
            服务端返回的完整 model_id，未找到则返回 None
        """
        # 1) 缓存精确命中
        with self._loaded_models_lock:
            if model_id in self._loaded_models:
                return model_id
        # 2) 从服务端查询然后模糊匹配
        try:
            all_models = self.list_models()
        except Exception:
            all_models = []
        for m in all_models:
            mid = m.model_id
            if not mid:
                continue
            if mid == model_id:
                return mid
            if mid.endswith("/" + model_id) or mid.endswith("\\" + model_id):
                return mid
        # 3) 包含匹配（最宽松）
        for m in all_models:
            mid = m.model_id
            if mid and model_id in mid:
                return mid
        return None

    def _get_model_status(self, model_id: str) -> str:
        """获取模型加载状态（优先查缓存，其次通过管理 API 查询），支持模糊匹配。"""
        # 先尝试解析完整模型ID
        resolved = self._resolve_model_id(model_id)
        if resolved:
            model_id = resolved
        with self._loaded_models_lock:
            if model_id in self._loaded_models:
                return self._loaded_models[model_id].status
        # 首次查询时尝试通过管理 API 获取模型状态
        # 使用 /api/v1/models (管理API) 获取更准确的 loaded 状态
        try:
            resp = self._do_mgmt_get("/api/v1/models")
            data = resp.json()
            # 兼容 {"models": [...]} 和 {"data": [...]} 两种格式
            model_list: Any = (
                data.get("models") if isinstance(data, dict) and "models" in data
                else data.get("data") if isinstance(data, dict) and "data" in data
                else data
            )
            if isinstance(model_list, dict):
                model_list = [model_list]
            if not isinstance(model_list, list):
                model_list = []
            found_loaded = False
            for m in model_list:
                if not isinstance(m, dict):
                    continue
                # 模型 ID: LM Studio 用 "key"，兼容 "id"
                mid = m.get("key") or m.get("id", str(m))
                # 管理 API 判断已加载状态: loaded_instances 非空数组
                loaded_insts = m.get("loaded_instances", [])
                is_loaded = bool(loaded_insts)
                if not is_loaded:
                    is_loaded = (
                        m.get("status") == "loaded"
                        or m.get("state") == "loaded"
                        or m.get("loaded") is True
                    )
                if is_loaded:
                    info = ModelInfo(
                        model_id=mid,
                        type=m.get("type", "llm"),
                        status="loaded",
                        instance_id=m.get("instance_id", mid),
                    )
                    with self._loaded_models_lock:
                        self._loaded_models[mid] = info
                    if mid == model_id:
                        found_loaded = True
            # 再次尝试模糊匹配
            if not found_loaded:
                with self._loaded_models_lock:
                    for mid, _ in self._loaded_models.items():
                        if mid.endswith("/" + model_id) or mid.endswith("\\" + model_id) or model_id in mid:
                            found_loaded = True
                            break
            if found_loaded:
                return "loaded"
        except Exception as e:
            logger.debug("通过管理 API 查询模型状态失败: %s，回退到 OpenAI 兼容接口", e)
            # 回退到 /v1/models (OpenAI 兼容)
            try:
                resp = self._get_client().get(f"{self.api_base}/models")
                if resp.status_code == 200:
                    data = resp.json()
                    fallback_data: Any = (
                        data.get("data") if isinstance(data, dict) and "data" in data
                        else data.get("models") if isinstance(data, dict) and "models" in data
                        else data
                    )
                    if isinstance(fallback_data, dict):
                        fallback_data = [fallback_data]
                    if isinstance(fallback_data, list):
                        for m in fallback_data:
                            if not isinstance(m, dict):
                                continue
                            mid = m.get("key") or m.get("id", str(m))
                            # /v1/models 通常只返回已加载模型
                            info = ModelInfo(
                                model_id=mid,
                                type="llm",
                                status="loaded",
                                instance_id=mid,
                            )
                            with self._loaded_models_lock:
                                self._loaded_models[mid] = info
                        with self._loaded_models_lock:
                            if model_id in self._loaded_models:
                                return "loaded"
            except Exception:
                pass
        return "not-loaded"

    # ============================================================
    # 管理 API HTTP 辅助
    # ============================================================

    def _do_mgmt_get(self, path: str) -> httpx.Response:
        """向 LM Studio 管理 API 发 GET 请求"""
        url = f"{self._mgmt_api_base}{path}"
        resp = self._get_client().get(url)
        resp.raise_for_status()
        return resp

    def _do_mgmt_post(self, path: str, data: dict) -> httpx.Response:
        """向 LM Studio 管理 API 发 POST 请求"""
        url = f"{self._mgmt_api_base}{path}"
        resp = self._get_client().post(url, json=data)
        resp.raise_for_status()
        return resp

    # ============================================================
    # 资源清理
    # ============================================================

    def close(self) -> None:
        """关闭连接"""
        super().close()
        with self._loaded_models_lock:
            self._loaded_models.clear()

    async def aclose(self) -> None:
        """异步关闭连接"""
        await super().aclose()
        with self._loaded_models_lock:
            self._loaded_models.clear()


__all__ = ["LMStudioBackend"]