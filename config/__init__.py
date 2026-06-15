"""
统一配置管理模块
================

公开 API:
    get_config(*sections) → 按节请求配置结构体
    save_config(**sections) → 保存配置节
    reset_config() → 重置为默认配置

用法:
    from config import get_config, save_config

    db = get_config("database")                     # → DatabaseConfig
    be, scr = get_config("backends", "screening")   # → (BackendsConfig, ScreeningAgentConfig)
    full = get_config()                             # → FullConfig

    save_config(database=db)
    save_config(screening=scr, backtrack=bk)
"""

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

from .store import (
    ConfigNotLoadedError,
    get_config,
    reset_config,
    save_config,
    save_config_dict,
)

__all__ = [
    # 数据模型
    "BackendType",
    "DatabaseConfig",
    "LLMBackendConfig",
    "BackendsConfig",
    "ScreeningAgentConfig",
    "BacktrackAgentConfig",
    "AdjudicationAgentConfig",
    "FeedbackAgentConfig",
    "LiveScanConfig",
    "GeoipConfig",
    "FullConfig",
    # API
    "get_config",
    "save_config",
    "save_config_dict",
    "reset_config",
    "ConfigNotLoadedError",
]
