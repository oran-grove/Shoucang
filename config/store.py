"""
ConfigStore — 统一配置存储单例
===============================

职责:
  1. 单次文件加载，合并默认配置与用户配置
  2. 将配置存储为类型化结构体（dataclass），无字典缓存
  3. 所有配置读写的唯一入口

用法:
    from config import get_config, save_config, reset_config

    db = get_config("database")              # → DatabaseConfig
    be, scr = get_config("backends", "screening")  # → (BackendsConfig, ScreeningAgentConfig)
    full = get_config()                      # → FullConfig

    save_config(database=db)                 # 保存指定节
    save_config(screening=scr, backtrack=bk)  # 保存多个节
    reset_config()                           # 重置为默认
"""

import json
import logging
import threading
from copy import deepcopy
from pathlib import Path
from typing import Any, Literal, Optional, Union, overload

from .schema import (
    AdjudicationAgentConfig,
    BackendsConfig,
    BackendType,
    BacktrackAgentConfig,
    DatabaseConfig,
    FeedbackAgentConfig,
    FullConfig,
    GeoipConfig,
    LLMBackendConfig,
    LiveScanConfig,
    ScreeningAgentConfig,
)
from .shared_config import DEFAULT_CONFIG_PATH, USER_CONFIG_PATH
from .loader import _compute_delta, _deep_merge, _validate, _coerce_types

logger = logging.getLogger(__name__)

# ── 节名 → 内部属性名 ──────────────────────────────
_SECTION_ATTRS = {
    "database":    "_database",
    "backends":    "_backends",
    "screening":   "_screening",
    "backtrack":   "_backtrack",
    "adjudication": "_adjudication",
    "feedback":    "_feedback",
    "live_scan":   "_live_scan",
    "geoip":       "_geoip",
}


class ConfigNotLoadedError(RuntimeError):
    """配置在加载前被访问时抛出。"""
    pass


# ============================================================
# 从 dict 构建结构体的内部辅助
# ============================================================

def _build_llm_backend(d: dict) -> LLMBackendConfig:
    return LLMBackendConfig(
        model_name=d.get("model_name", "gpt-4o-mini"),
        api_base=d.get("api_base", "https://api.openai.com/v1"),
        api_key=d.get("api_key", ""),
        temperature=d.get("temperature", 0.3),
        max_tokens=d.get("max_tokens", 2048),
        max_context_tokens=d.get("max_context_tokens", 4096),
        timeout=d.get("timeout", 60.0),
        max_retries=d.get("max_retries", 3),
        auto_load=d.get("auto_load", True),
        load_config=d.get("load_config", {}) or {},
        thinking_enabled=d.get("thinking_enabled"),
        reasoning_effort=d.get("reasoning_effort"),
        include_reasoning=d.get("include_reasoning", False),
    )


def _build_backends(d: dict) -> BackendsConfig:
    be = d.get("backends", {})
    return BackendsConfig(
        openai=_build_llm_backend(be.get("openai", {})),
        lmstudio=_build_llm_backend(be.get("lmstudio", {})),
        deepseek=_build_llm_backend(be.get("deepseek", {})),
    )


def _build_database(d: dict) -> DatabaseConfig:
    db = d.get("database", {})
    return DatabaseConfig(
        host=db.get("host", "localhost"),
        port=db.get("port", 3306),
        user=db.get("user", "root"),
        password=db.get("password", ""),
        database=db.get("database", "insider_threat_db"),
        charset=db.get("charset", "utf8mb4"),
    )


def _build_screening(d: dict) -> ScreeningAgentConfig:
    s = d.get("screening", {})
    return ScreeningAgentConfig(
        enabled=s.get("enabled", True),
        backend=BackendType(s.get("backend", "deepseek")),
        model_name=s.get("model_name", "deepseek-v4-flash"),
        system_prompt=s.get("system_prompt", ScreeningAgentConfig.system_prompt),
        temperature=s.get("temperature", 0.3),
        max_tokens=s.get("max_tokens", 1024),
        max_context_tokens=s.get("max_context_tokens", 4096),
        confidence_threshold_dangerous=s.get("confidence_threshold_dangerous", 0.85),
        confidence_threshold_suspicious=s.get("confidence_threshold_suspicious", 0.50),
    )


def _build_backtrack(d: dict) -> BacktrackAgentConfig:
    b = d.get("backtrack", {})
    return BacktrackAgentConfig(
        enabled=b.get("enabled", True),
        backend=BackendType(b.get("backend", "deepseek")),
        model_name=b.get("model_name", "deepseek-v4-flash"),
        system_prompt=b.get("system_prompt", BacktrackAgentConfig.system_prompt),
        temperature=b.get("temperature", 0.3),
        max_tokens=b.get("max_tokens", 2048),
        lookback_windows=b.get("lookback_windows", [0.5, 24, 168, 720, 2160]),
        relevance_threshold=b.get("relevance_threshold", 0.6),
        batch_context_ratio=b.get("batch_context_ratio", 0.125),
    )


def _build_adjudication(d: dict) -> AdjudicationAgentConfig:
    a = d.get("adjudication", {})
    return AdjudicationAgentConfig(
        enabled=a.get("enabled", True),
        backend=BackendType(a.get("backend", "deepseek")),
        model_name=a.get("model_name", "deepseek-v4-flash"),
        system_prompt=a.get("system_prompt", AdjudicationAgentConfig.system_prompt),
        temperature=a.get("temperature", 0.3),
        max_tokens=a.get("max_tokens", 2048),
    )


def _build_feedback(d: dict) -> FeedbackAgentConfig:
    f = d.get("feedback", {})
    return FeedbackAgentConfig(
        enabled=f.get("enabled", True),
        backend=BackendType(f.get("backend", "deepseek")),
        model_name=f.get("model_name", "deepseek-v4-flash"),
        system_prompt=f.get("system_prompt", FeedbackAgentConfig.system_prompt),
        temperature=f.get("temperature", 0.2),
        max_tokens=f.get("max_tokens", 1024),
    )


def _build_live_scan(d: dict) -> LiveScanConfig:
    ls = d.get("live_scan", {})
    return LiveScanConfig(
        enabled=ls.get("enabled", True),
        idle_poll_interval_seconds=ls.get("idle_poll_interval_seconds", 600.0),
        batch_size_multiplier=ls.get("batch_size_multiplier", 6.0),
        max_concurrent_analyses=ls.get("max_concurrent_analyses", 8),
        start_from=ls.get("start_from", "oldest"),
    )


def _build_geoip(d: dict) -> GeoipConfig:
    g = d.get("geoip", {})
    return GeoipConfig(
        enabled=g.get("enabled", True),
        update_interval_hours=g.get("update_interval_hours", 168),
        download_url=g.get(
            "download_url",
            "https://cdn.jsdelivr.net/npm/geolite2-city/GeoLite2-City.mmdb.gz",
        ),
        db_path=g.get("db_path", "data_gateway/GeoLite2-City.mmdb"),
    )


# ============================================================
# 结构体 → dict 序列化（save 时临时使用）
# ============================================================

def _backend_to_dict(be: LLMBackendConfig) -> dict:
    return {
        "model_name": be.model_name,
        "api_base": be.api_base,
        "api_key": be.api_key,
        "temperature": be.temperature,
        "max_tokens": be.max_tokens,
        "max_context_tokens": be.max_context_tokens,
        "timeout": be.timeout,
        "max_retries": be.max_retries,
        "auto_load": be.auto_load,
        "load_config": be.load_config,
        "thinking_enabled": be.thinking_enabled,
        "reasoning_effort": be.reasoning_effort,
        "include_reasoning": be.include_reasoning,
    }


def _structs_to_dict(store: "ConfigStore") -> dict:
    """将所有结构体序列化为合并字典（仅在 save 时临时使用）。"""
    return {
        "database": {
            "host": store._database.host,
            "port": store._database.port,
            "user": store._database.user,
            "password": store._database.password,
            "database": store._database.database,
            "charset": store._database.charset,
        },
        "backends": {
            "openai": _backend_to_dict(store._backends.openai),
            "lmstudio": _backend_to_dict(store._backends.lmstudio),
            "deepseek": _backend_to_dict(store._backends.deepseek),
        },
        "screening": {
            "enabled": store._screening.enabled,
            "backend": store._screening.backend.value,
            "model_name": store._screening.model_name,
            "system_prompt": store._screening.system_prompt,
            "temperature": store._screening.temperature,
            "max_tokens": store._screening.max_tokens,
            "max_context_tokens": store._screening.max_context_tokens,
            "confidence_threshold_dangerous": store._screening.confidence_threshold_dangerous,
            "confidence_threshold_suspicious": store._screening.confidence_threshold_suspicious,
        },
        "backtrack": {
            "enabled": store._backtrack.enabled,
            "backend": store._backtrack.backend.value,
            "model_name": store._backtrack.model_name,
            "system_prompt": store._backtrack.system_prompt,
            "temperature": store._backtrack.temperature,
            "max_tokens": store._backtrack.max_tokens,
            "lookback_windows": store._backtrack.lookback_windows,
            "relevance_threshold": store._backtrack.relevance_threshold,
            "batch_context_ratio": store._backtrack.batch_context_ratio,
        },
        "adjudication": {
            "enabled": store._adjudication.enabled,
            "backend": store._adjudication.backend.value,
            "model_name": store._adjudication.model_name,
            "system_prompt": store._adjudication.system_prompt,
            "temperature": store._adjudication.temperature,
            "max_tokens": store._adjudication.max_tokens,
        },
        "feedback": {
            "enabled": store._feedback.enabled,
            "backend": store._feedback.backend.value,
            "model_name": store._feedback.model_name,
            "system_prompt": store._feedback.system_prompt,
            "temperature": store._feedback.temperature,
            "max_tokens": store._feedback.max_tokens,
        },
        "live_scan": {
            "enabled": store._live_scan.enabled,
            "idle_poll_interval_seconds": store._live_scan.idle_poll_interval_seconds,
            "batch_size_multiplier": store._live_scan.batch_size_multiplier,
            "max_concurrent_analyses": store._live_scan.max_concurrent_analyses,
            "start_from": store._live_scan.start_from,
        },
        "geoip": {
            "enabled": store._geoip.enabled,
            "update_interval_hours": store._geoip.update_interval_hours,
            "download_url": store._geoip.download_url,
            "db_path": store._geoip.db_path,
        },
    }


# ============================================================
# ConfigStore 单例
# ============================================================

# 可保存的节类型
ConfigSection = Union[
    DatabaseConfig,
    BackendsConfig,
    ScreeningAgentConfig,
    BacktrackAgentConfig,
    AdjudicationAgentConfig,
    FeedbackAgentConfig,
    LiveScanConfig,
    GeoipConfig,
]


class ConfigStore:
    """线程安全的配置存储单例。"""

    def __init__(self):
        self._lock = threading.Lock()
        self._loaded = False

        # ── 各节结构体缓存 ──
        self._database: DatabaseConfig = DatabaseConfig()
        self._backends: BackendsConfig = BackendsConfig()
        self._screening: ScreeningAgentConfig = ScreeningAgentConfig()
        self._backtrack: BacktrackAgentConfig = BacktrackAgentConfig()
        self._adjudication: AdjudicationAgentConfig = AdjudicationAgentConfig()
        self._feedback: FeedbackAgentConfig = FeedbackAgentConfig()
        self._live_scan: LiveScanConfig = LiveScanConfig()
        self._geoip: GeoipConfig = GeoipConfig()

        # 缓存的默认配置 dict（用于 delta 计算，仅 load 时写入一次）
        self._default_dict: dict = {}

    # ========== 生命周期 ==========

    def load(self) -> None:
        """从磁盘加载配置（单次读取）。"""
        if not DEFAULT_CONFIG_PATH.exists():
            raise FileNotFoundError(
                f"默认配置文件不存在: {DEFAULT_CONFIG_PATH}"
            )

        with open(DEFAULT_CONFIG_PATH, "r", encoding="utf-8") as f:
            self._default_dict = json.load(f)

        merged = deepcopy(self._default_dict)
        if USER_CONFIG_PATH.exists():
            with open(USER_CONFIG_PATH, "r", encoding="utf-8") as f:
                user_dict = json.load(f)
            merged = _deep_merge(merged, user_dict)

        # 校验
        warnings = _validate(merged)
        for w in warnings:
            logger.warning("[config] ⚠ %s", w)

        # 构建所有结构体
        self._database = _build_database(merged)
        self._backends = _build_backends(merged)
        self._screening = _build_screening(merged)
        self._backtrack = _build_backtrack(merged)
        self._adjudication = _build_adjudication(merged)
        self._feedback = _build_feedback(merged)
        self._live_scan = _build_live_scan(merged)
        self._geoip = _build_geoip(merged)

        self._loaded = True
        logger.info("[config] 配置已加载 (来源: %s)",
                     USER_CONFIG_PATH if USER_CONFIG_PATH.exists() else "默认")

    def _ensure_loaded(self) -> None:
        """按需自动加载（双重检查锁定）。"""
        if not self._loaded:
            with self._lock:
                if not self._loaded:
                    self.load()

    # ========== 读取 ==========

    def _get_section(self, name: str) -> Any:
        """获取单个配置节。"""
        self._ensure_loaded()
        attr = _SECTION_ATTRS.get(name)
        if attr is None:
            raise ValueError(f"未知的配置节: '{name}'。可选: {list(_SECTION_ATTRS.keys())}")
        return getattr(self, attr)

    def get(self, *sections: str) -> Any:
        """
        获取请求的配置节。

        无参调用返回 FullConfig。
        单个参数返回单个结构体。
        多个参数返回元组。
        """
        if not sections:
            self._ensure_loaded()
            return FullConfig(
                database=self._database,
                backends=self._backends,
                screening=self._screening,
                backtrack=self._backtrack,
                adjudication=self._adjudication,
                feedback=self._feedback,
                live_scan=self._live_scan,
                geoip=self._geoip,
            )

        results = tuple(self._get_section(s) for s in sections)
        return results[0] if len(results) == 1 else results

    # ========== 写入 ==========

    def save(self, **sections: ConfigSection) -> None:
        """
        保存配置更新。

        更新内存中的结构体，序列化全部为 dict，计算增量，
        写入 config_user.json。
        """
        self._ensure_loaded()
        with self._lock:
            for name, value in sections.items():
                attr = _SECTION_ATTRS.get(name)
                if attr is None:
                    raise ValueError(
                        f"未知的配置节: '{name}'。可选: {list(_SECTION_ATTRS.keys())}"
                    )
                setattr(self, attr, value)

            # 序列化 → 计算增量 → 写入
            current_dict = _structs_to_dict(self)
            delta = _compute_delta(self._default_dict, current_dict)
            USER_CONFIG_PATH.write_text(
                json.dumps(delta, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            logger.info("[config] 配置已保存到 %s", USER_CONFIG_PATH)

    def save_dict(self, updates: dict) -> None:
        """
        以字典形式保存部分配置更新。

        将 updates 深合并到当前配置，计算增量，写入 config_user.json，
        然后重新加载（重建所有结构体）。

        此方法供 WebUI 的通用配置保存端点使用。
        """
        self._ensure_loaded()
        with self._lock:
            current_dict = _structs_to_dict(self)
            merged = _deep_merge(current_dict, updates)
            # 将前端表单的字符串值强制转换为与默认配置相同的类型
            # （如 "0.3" → 0.3, "1024" → 1024），避免类型差异导致
            # _compute_delta 输出未实际变更的字段
            normalized = _coerce_types(merged, self._default_dict)
            delta = _compute_delta(self._default_dict, normalized)
            USER_CONFIG_PATH.write_text(
                json.dumps(delta, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            logger.info("[config] 配置已保存到 %s (dict 部分更新)", USER_CONFIG_PATH)
        # 释放锁后重新加载，避免死锁
        self._loaded = False
        self.load()

    def reset(self, *sections: str) -> None:
        """
        重置配置。

        - 无参：删除整个 config_user.json，恢复全部默认值。
        - 指定节名：只从 config_user.json 中移除对应节，保留其他节的用户覆盖。
        """
        self._ensure_loaded()
        if not sections:
            # 全量重置
            if USER_CONFIG_PATH.exists():
                USER_CONFIG_PATH.unlink()
                logger.info("[config] 已删除 %s，重新加载默认配置", USER_CONFIG_PATH)
            self._loaded = False
            self.load()
            return

        # 部分重置：移除指定节
        valid = set(_SECTION_ATTRS.keys())
        invalid = [s for s in sections if s not in valid]
        if invalid:
            raise ValueError(
                f"未知的配置节: {invalid}。可选: {sorted(valid)}"
            )

        if not USER_CONFIG_PATH.exists():
            logger.info("[config] %s 不存在，无配置需要重置", USER_CONFIG_PATH)
            self._loaded = False
            self.load()
            return

        with self._lock:
            with open(USER_CONFIG_PATH, "r", encoding="utf-8") as f:
                user_dict = json.load(f)

            removed = []
            for sec in sections:
                if sec in user_dict:
                    del user_dict[sec]
                    removed.append(sec)

            if removed:
                USER_CONFIG_PATH.write_text(
                    json.dumps(user_dict, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                logger.info("[config] 已重置配置节: %s", removed)
            else:
                logger.info("[config] 指定的配置节 %s 无用户覆盖，无需重置",
                            list(sections))

        self._loaded = False
        self.load()

    def is_loaded(self) -> bool:
        return self._loaded


# ============================================================
# 模块级单例
# ============================================================

_store = ConfigStore()


# ============================================================
# 公开 API 函数
# ============================================================

@overload
def get_config() -> FullConfig: ...
@overload
def get_config(__section: Literal["database"]) -> DatabaseConfig: ...
@overload
def get_config(__section: Literal["backends"]) -> BackendsConfig: ...
@overload
def get_config(__section: Literal["screening"]) -> ScreeningAgentConfig: ...
@overload
def get_config(__section: Literal["backtrack"]) -> BacktrackAgentConfig: ...
@overload
def get_config(__section: Literal["adjudication"]) -> AdjudicationAgentConfig: ...
@overload
def get_config(__section: Literal["feedback"]) -> FeedbackAgentConfig: ...
@overload
def get_config(__section: Literal["live_scan"]) -> LiveScanConfig: ...
@overload
def get_config(__section: Literal["geoip"]) -> GeoipConfig: ...
@overload
def get_config(__section: str) -> Any: ...
@overload
def get_config(__s1: str, __s2: str, *sections: str) -> tuple: ...
def get_config(*sections: str) -> Any:
    """
    获取配置节。

    用法:
        db = get_config("database")              # → DatabaseConfig
        be, scr = get_config("backends", "screening")  # → (BackendsConfig, ScreeningAgentConfig)
        full = get_config()                      # → FullConfig
    """
    return _store.get(*sections)


def save_config(**sections: ConfigSection) -> None:
    """
    保存配置节。

    用法:
        save_config(database=db_cfg)
        save_config(screening=scr_cfg, backtrack=bk_cfg)
    """
    _store.save(**sections)


def save_config_dict(updates: dict) -> None:
    """
    以字典形式保存部分配置更新（供 WebUI 通用保存端点使用）。

    用法:
        save_config_dict({"database": {"password": "new"}})
    """
    _store.save_dict(updates)


def reset_config(*sections: str) -> None:
    """
    重置配置。

    - reset_config()          → 全量重置
    - reset_config("screening", "backtrack") → 只重置指定节
    """
    _store.reset(*sections)
