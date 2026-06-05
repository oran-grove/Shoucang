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
    DetectionAgentConfig,
    CorrelationAgentConfig,
    JudgmentAgentConfig,
    FeedbackAgentConfig,
    BaselineProfilingAgentConfig,
    TemporalAnomalyAgentConfig,
    SlowBrainConfig,
    KnowledgeBaseConfig,
    OrchestratorConfig,
)

from .loader import (
    load_config,
    save_config,
    load_config_dict,
    load_default_config_dict,
    save_config_dict,
    quick_all_local,
    quick_all_deepseek,
)

__all__ = [
    # 数据模型
    "BackendType",
    "LLMBackendConfig",
    "DetectionAgentConfig",
    "CorrelationAgentConfig",
    "JudgmentAgentConfig",
    "FeedbackAgentConfig",
    "BaselineProfilingAgentConfig",
    "TemporalAnomalyAgentConfig",
    "SlowBrainConfig",
    "KnowledgeBaseConfig",
    "OrchestratorConfig",
    # 加载器
    "load_config",
    "save_config",
    "load_config_dict",
    "load_default_config_dict",
    "save_config_dict",
    "quick_all_local",
    "quick_all_deepseek",
]
