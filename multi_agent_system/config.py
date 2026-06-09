"""
多智能体系统配置模块 (兼容层)
==========================
本模块现已收敛到项目根目录下的 `config/` 统一配置模块。

为向后兼容，保留此文件作为重定向层。
新代码请直接使用：
    from config import BackendType, OrchestratorConfig, ...
"""

# 从统一 config 包导出所有数据模型（相对导入绕过 sys.path 依赖）
from config.schema import (  # noqa: F401
    BackendType,
    LLMBackendConfig,
    ScreeningAgentConfig,
    BacktrackAgentConfig,
    AdjudicationAgentConfig,
    FeedbackAgentConfig,
    OrchestratorConfig,
)
