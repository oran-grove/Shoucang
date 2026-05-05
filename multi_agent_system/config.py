"""
多智能体系统配置模块
====================
定义 LLM 后端配置、智能体配置、规则库配置等数据结构。
支持在线 API 和 LM Studio 本地 AI 两种后端。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class BackendType(Enum):
    """LLM 后端类型"""
    OPENAI = "openai"
    LMSTUDIO = "lmstudio"


@dataclass
class LLMBackendConfig:
    """
    LLM 后端通用配置。
    用于 OpenAI 兼容 API 或 LM Studio 本地模型。
    """
    backend_type: BackendType
    model_name: str = "gpt-4o-mini"
    api_base: str = "https://api.openai.com/v1"
    api_key: str = ""
    temperature: float = 0.3
    max_tokens: int = 2048
    timeout: float = 60.0
    max_retries: int = 3
    # LM Studio 通常部署在 localhost
    # api_base: "http://localhost:1234/v1"
    # api_key: "lm-studio"（占位即可）


@dataclass
class DetectionAgentConfig:
    """检测智能体配置"""
    enabled: bool = True
    backend: BackendType = BackendType.LMSTUDIO    # 默认用本地模型做快速检测
    model_name: str = "qwen2.5-7b-instruct"
    system_prompt: str = (
        "你是一个网络安全流量分析专家。请根据提供的流量元数据，判断该流量是否为恶意。"
        "回复格式：{ verdict: 'malicious'|'suspicious'|'safe', "
        "confidence: 0.0-1.0, reasoning: '简短理由', "
        "threat_type: '数据泄露'|'C2通信'|'扫描'|'正常'|'未知' }"
    )
    max_context_tokens: int = 4096


@dataclass
class CorrelationAgentConfig:
    """关联智能体配置"""
    enabled: bool = True
    backend: BackendType = BackendType.OPENAI     # 关联分析可用更强大的在线模型
    model_name: str = "gpt-4o"
    system_prompt: str = (
        "你是一个网络安全关联分析专家。给定一组来自同一源IP或同类特征的流量记录，"
        "请判断它们之间是否存在关联的恶意行为模式。"
        "回复格式：{ is_correlated: true|false, "
        "correlation_type: '数据外传'|'横向移动'|'C2心跳'|'无关联', "
        "confidence: 0.0-1.0, reasoning: '分析逻辑' }"
    )
    correlation_window_minutes: int = 30
    min_records_to_correlate: int = 5


@dataclass
class JudgmentAgentConfig:
    """研判智能体配置"""
    enabled: bool = True
    backend: BackendType = BackendType.OPENAI
    model_name: str = "gpt-4o"
    system_prompt: str = (
        "你是一个网络安全威胁研判专家。请综合单流检测结果和关联分析结果，"
        "给出最终的威胁判定和处置建议。"
        "回复格式：{ verdict: 'malicious'|'suspicious'|'safe', "
        "severity: 'critical'|'high'|'medium'|'low'|'info', "
        "confidence: 0.0-1.0, "
        "recommended_action: 'block'|'monitor'|'allow'|'quarantine', "
        "reasoning: '综合研判逻辑', "
        "evidence_summary: ['证据1', '证据2'] }"
    )


@dataclass
class FeedbackAgentConfig:
    """反馈智能体配置"""
    enabled: bool = True
    backend: BackendType = BackendType.LMSTUDIO
    model_name: str = "qwen2.5-7b-instruct"
    system_prompt: str = (
        "你是一个网络安全规则优化专家。根据管理员反馈和历史判定记录，"
        "提出规则调整建议。"
        "回复格式：{ action: 'upgrade_to_blacklist'|'downgrade_to_whitelist'|"
        "'adjust_confidence'|'no_change', "
        "rule_id: '规则ID', new_confidence: 0.0-1.0, "
        "ttl_minutes: 整数, reasoning: '理由' }"
    )


@dataclass
class KnowledgeBaseConfig:
    """知识库配置"""
    max_rules: int = 100000
    blacklist_default_ttl_minutes: int = 1440   # 黑名单默认 24h
    whitelist_default_ttl_minutes: int = 10080  # 白名单默认 7 天
    cleanup_interval_seconds: int = 300         # 清理间隔
    confidence_threshold_block: float = 0.85    # 超过此置信度自动阻断
    confidence_threshold_suspect: float = 0.50  # 低于此为安全


@dataclass
class OrchestratorConfig:
    """编排器总配置"""
    detection: DetectionAgentConfig = field(default_factory=DetectionAgentConfig)
    correlation: CorrelationAgentConfig = field(default_factory=CorrelationAgentConfig)
    judgment: JudgmentAgentConfig = field(default_factory=JudgmentAgentConfig)
    feedback: FeedbackAgentConfig = field(default_factory=FeedbackAgentConfig)
    knowledge_base: KnowledgeBaseConfig = field(default_factory=KnowledgeBaseConfig)
    # 全局后端连接池配置
    default_backends: dict[BackendType, LLMBackendConfig] = field(default_factory=dict)
    # 消息队列配置
    max_queue_size: int = 10000

    def __post_init__(self):
        if BackendType.OPENAI not in self.default_backends:
            self.default_backends[BackendType.OPENAI] = LLMBackendConfig(
                backend_type=BackendType.OPENAI,
                model_name="gpt-4o-mini",
                api_base="https://api.openai.com/v1",
                api_key="",
            )
        if BackendType.LMSTUDIO not in self.default_backends:
            self.default_backends[BackendType.LMSTUDIO] = LLMBackendConfig(
                backend_type=BackendType.LMSTUDIO,
                model_name="qwen2.5-7b-instruct",
                api_base="http://localhost:1234/v1",
                api_key="lm-studio",
            )