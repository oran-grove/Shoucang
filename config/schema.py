"""
多智能体系统配置数据模型
========================
定义 LLM 后端配置、智能体配置、规则库配置等数据结构。
支持在线 API 和 LM Studio 本地 AI 两种后端。

本模块是纯数据模型定义，不涉及文件 I/O。
文件 I/O 由 config/loader.py 负责。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class BackendType(Enum):
    """LLM 后端类型"""
    OPENAI = "openai"
    LMSTUDIO = "lmstudio"
    DEEPSEEK = "deepseek"


@dataclass
class LLMBackendConfig:
    """
    LLM 后端通用配置。
    用于 OpenAI 兼容 API、LM Studio 本地模型、DeepSeek API 等。
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

    # —— 模型智能加载（仅 LM Studio 后端有效）——
    auto_load: bool = True                  # 是否在调用前自动加载模型
    load_config: dict[str, Any] = field(default_factory=dict)  # 模型加载参数
    # load_config 可包含: context_length, eval_batch_size, flash_attention,
    #                     num_experts, offload_kv_cache_to_gpu, echo_load_config

    # —— DeepSeek V4 专有参数 ——
    thinking_enabled: Optional[bool] = None   # 思考模式开关 (True/False)，None 表示不显式设置
    reasoning_effort: Optional[str] = None    # 推理强度: "high" | "max"
    include_reasoning: bool = False           # 是否在回复中包含思考过程


@dataclass
class DetectionAgentConfig:
    """检测智能体配置"""
    enabled: bool = True
    backend: BackendType = BackendType.DEEPSEEK
    model_name: str = "deepseek-v4-flash"
    system_prompt: str = (
        "你是一个网络安全流量分析专家。请根据提供的流量元数据，判断该流量是否为恶意。"
        "回复格式：{ verdict: 'malicious'|'suspicious'|'safe', "
        "confidence: 0.0-1.0, reasoning: '简短理由', "
        "threat_type: '数据泄露'|'C2通信'|'扫描'|'正常'|'未知' }"
    )
    temperature: float = 0.3
    max_tokens: int = 1024
    max_context_tokens: int = 4096
    confidence_threshold_malicious: float = 0.85
    confidence_threshold_suspect: float = 0.50


@dataclass
class CorrelationAgentConfig:
    """关联智能体配置"""
    enabled: bool = True
    backend: BackendType = BackendType.DEEPSEEK
    model_name: str = "deepseek-v4-flash"
    system_prompt: str = (
        "你是一个网络安全关联分析专家。给定一组来自同一源IP或同类特征的流量记录，"
        "请判断它们之间是否存在关联的恶意行为模式。"
        "回复格式：{ is_correlated: true|false, "
        "correlation_type: '数据外传'|'横向移动'|'C2心跳'|'无关联', "
        "confidence: 0.0-1.0, reasoning: '分析逻辑' }"
    )
    temperature: float = 0.3
    max_tokens: int = 2048
    correlation_window_minutes: int = 30
    min_records_to_correlate: int = 5
    max_buffer_per_src: int = 100
    cleanup_interval_seconds: int = 60


@dataclass
class JudgmentAgentConfig:
    """研判智能体配置"""
    enabled: bool = True
    backend: BackendType = BackendType.DEEPSEEK
    model_name: str = "deepseek-v4-flash"
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
    temperature: float = 0.3
    max_tokens: int = 2048


@dataclass
class FeedbackAgentConfig:
    """反馈智能体配置"""
    enabled: bool = True
    backend: BackendType = BackendType.DEEPSEEK
    model_name: str = "deepseek-v4-flash"
    system_prompt: str = (
        "你是一个内部威胁检测系统的规则优化与自适应学习专家。根据管理员反馈和历史判定记录，"
        "提出规则调整建议，确保系统在内部泄密检测中持续降低误报、减少漏报。\n\n"
        "## 优化策略\n"
        "1. **误报分析**：分析误报特征，调整检测阈值或添加白名单规则\n"
        "2. **漏报分析**：逆向分析漏报案例，确定哪些弱信号组合被遗漏\n"
        "3. **用户画像更新**：根据同类用户的实际行为，动态调整个人/部门基线容差\n"
        "4. **TTL自适应**：根据反馈确认的威胁严重度，自适应调整规则有效期\n"
        "5. **长周期模式学习**：记录管理员确认的长周期泄密案例，提取低慢外传的模式特征\n\n"
        "回复格式：{ action: 'upgrade_to_blacklist'|'downgrade_to_whitelist'|"
        "'adjust_confidence'|'adjust_threshold'|'update_baseline'|'no_change', "
        "rule_id: '规则ID', new_confidence: 0.0-1.0, "
        "ttl_minutes: 整数, reasoning: '调整理由（含模式学习结论）', "
        "learned_pattern: '从案例中学到的模式特征（可选）' }"
    )
    temperature: float = 0.2
    max_tokens: int = 1024


@dataclass
class BaselineProfilingAgentConfig:
    """行为基线画像智能体配置"""
    enabled: bool = True
    backend: BackendType = BackendType.DEEPSEEK
    model_name: str = "deepseek-v4-flash"
    system_prompt: str = (
        "你是一个用户行为基线分析专家。请根据用户的长期历史流量记录，"
        "构建正常行为画像并识别异常偏离。\n\n"
        "## 分析维度\n"
        "1. **频率基线**：该用户/部门在不同时段的正常网络请求频率\n"
        "2. **数据量基线**：正常的数据传输量分布（单次/每小时/每天）\n"
        "3. **协议习惯**：通常使用的网络协议和应用类型\n"
        "4. **目标资产画像**：正常访问的服务器类型和频率\n"
        "5. **数据密级访问模式**：与角色关联的数据密级\n"
        "6. **周期性模式**：按小时/天/周的行为规律\n\n"
        "回复格式：{ \"baseline_summary\": \"基线总结\", "
        "\"anomaly_detected\": true|false, "
        "\"anomaly_details\": [\"异常点描述\"], "
        "\"baseline_shift_detected\": true|false, "
        "\"confidence\": 0.0-1.0 }"
    )
    temperature: float = 0.2
    max_tokens: int = 2048
    update_interval_hours: int = 24
    max_baseline_age_days: int = 90


@dataclass
class TemporalAnomalyAgentConfig:
    """时序异常智能体配置"""
    enabled: bool = True
    backend: BackendType = BackendType.DEEPSEEK
    model_name: str = "deepseek-v4-flash"
    system_prompt: str = (
        "你是一个时序异常分析专家，专门从长时间窗口（7天-90天）的网络日志中，"
        "识别隐蔽的内部威胁行为模式。\n\n"
        "## 重点检测的时序模式\n"
        "1. **周期性低频传输**：每天/每周固定时间的小量数据传输（<5MB），间隔稳定\n"
        "2. **渐进式递增**：每日数据传输量呈稳步上升趋势，表明攻击者逐渐试探监控阈值\n"
        "3. **信标/心跳**：严格定间隔的极小包（<1KB），如每15min/每1h/每24h\n"
        "4. **静默-活跃交替**：活动几天后突然静默数日再恢复\n"
        "5. **目标切换模式**：目标IP/端口周期性地轮换，使用分段外传策略\n"
        "6. **衰减模式**：活动频率逐渐降低但每次传输数据量增加\n"
        "7. **突发后静默**：一次性大量数据传输后长期无活动\n\n"
        "回复格式：{ \"temporal_anomaly_detected\": true|false, "
        "\"pattern_type\": \"周期性低频\"|\"渐进递增\"|\"信标心跳\"|\"静默交替\"|"
        "\"目标轮换\"|\"衰减收尾\"|\"突发后静默\"|\"无异常\", "
        "\"confidence\": 0.0-1.0, "
        "\"reasoning\": \"时序分析逻辑（请引用具体的时间窗口和数据点）\", "
        "\"period_estimated_minutes\": 0, "
        "\"trend_description\": \"趋势描述\" }"
    )
    temperature: float = 0.3
    max_tokens: int = 2048
    default_window_days: int = 30
    slice_size_hours: int = 6


@dataclass
class SlowBrainConfig:
    """慢脑层总配置"""
    analysis_interval_hours: int = 24
    baseline_profiling: BaselineProfilingAgentConfig = field(default_factory=BaselineProfilingAgentConfig)
    temporal_anomaly: TemporalAnomalyAgentConfig = field(default_factory=TemporalAnomalyAgentConfig)


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
    slow_brain: SlowBrainConfig = field(default_factory=SlowBrainConfig)
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
                model_name="qwen3.5-9b",
                api_base="http://localhost:1234/v1",
                api_key="lm-studio",
            )
        if BackendType.DEEPSEEK not in self.default_backends:
            self.default_backends[BackendType.DEEPSEEK] = LLMBackendConfig(
                backend_type=BackendType.DEEPSEEK,
                model_name="deepseek-v4-flash",
                api_base="https://api.deepseek.com",
                api_key="",
                timeout=120.0,
                max_retries=5,
            )