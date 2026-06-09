"""
统一配置管理模块
================
项目所有模块的配置均在此模块中集中管理。

结构:
 - schema.py: 纯数据模型定义（LLM后端、智能体配置结构等）
 - loader.py: JSON 文件加载器（读取、合并、校验、保存）
 - shared_config.py: 系统共享常量（数据库连接、路径等）
 
 用法:
     from config import load_config, save_config, OrchestratorConfig
     from config.shared_config import DB_CONFIG
"""

from .schema import (
    BackendType,
    LLMBackendConfig,
    ScreeningAgentConfig,
    BacktrackAgentConfig,
    AdjudicationAgentConfig,
    FeedbackAgentConfig,
    GeoipConfig,
    LiveScanAgentConfig,
    OrchestratorConfig,
)

from .active import (
    get_active_config,
    set_active_config,
    is_config_loaded,
)

from .loader import (
    load_config,
    save_config,
    load_config_dict,
    load_default_config_dict,
    save_config_dict,
    reset_user_config,
)

__all__ = [
    # 数据模型
    "BackendType",
    "LLMBackendConfig",
    "ScreeningAgentConfig",
    "BacktrackAgentConfig",
    "AdjudicationAgentConfig",
    "FeedbackAgentConfig",
    "GeoipConfig",
    "LiveScanAgentConfig",
    "OrchestratorConfig",
    # 加载器
    "load_config",
    "save_config",
    "load_config_dict",
    "load_default_config_dict",
    "save_config_dict",
    "reset_user_config",
    # 活跃配置单例
    "get_active_config",
    "set_active_config",
    "is_config_loaded",
]
