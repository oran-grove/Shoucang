"""
多智能体系统配置模块 (兼容层)
==========================
本模块现已收敛到项目根目录下的 `config/` 统一配置模块。

为向后兼容，保留此文件作为重定向层。
新代码请直接使用：
    from config import BackendType, OrchestratorConfig, ...
"""

import sys
from pathlib import Path

# 将项目根目录加入 sys.path 以便导入 config 包
_PROJECT_ROOT = Path(__file__).parent.parent.resolve()
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# 从统一 config 包导出所有数据模型
from config.schema import (  # noqa: F401, E402
    BackendType,
    LLMBackendConfig,
    DetectionAgentConfig,
    CorrelationAgentConfig,
    JudgmentAgentConfig,
    FeedbackAgentConfig,
    BaselineProfilingAgentConfig,
    TemporalAnomalyAgentConfig,
    DeepAnalysisConfig,
    KnowledgeBaseConfig,
    OrchestratorConfig,
)