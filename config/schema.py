"""
多智能体系统配置数据模型
========================
定义 LLM 后端配置、智能体配置等数据结构。
支持在线 API 和 LM Studio 本地 AI 两种后端。

三层智能体架构:
  Layer 1 — ScreeningAgent: 初步筛查，多线程逐条分析
  Layer 2 — BacktrackAgent: 历史回溯，查找相似数据并过滤关联度
  Layer 3 — AdjudicationAgent: 最终研判，结合回溯数据二次判定

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
    max_context_tokens: int = 4096      # 模型最大上下文窗口（token 数），用于分批计算
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


# ============================================================
# 三层智能体配置
# ============================================================


@dataclass
class ScreeningAgentConfig:
    """Layer 1 — 初步筛查智能体配置"""
    enabled: bool = True
    backend: BackendType = BackendType.DEEPSEEK
    model_name: str = "deepseek-v4-flash"
    system_prompt: str = (
        "你是一个内部威胁检测专家，专门识别组织内部人员的隐蔽数据泄露行为。"
        "请根据提供的流量元数据，判断该流量是否存在内部泄密风险。\n\n"
        "## 核心检测维度\n"
        "1. **数据外传特征**：非标准端口的大流量TLS、异常DNS查询(TXT/MX记录过长)、ICMP隧道、非工作时段的数据传输\n"
        "2. **频率隐蔽性**：单次数据量刻意控制在正常范围内(<10MB)，但加密熵极高(>7.5)\n"
        "3. **协议异常**：非标准应用层协议、伪装成HTTP/HTTPS/DNS的隐蔽信道\n"
        "4. **数据敏感性**：访问非授权的高密级数据\n"
        "5. **时段异常**：非工作时段(22:00-06:00)或周末/节假日的异常访问\n"
        "6. **行为基线偏离**：当前行为与该用户/设备历史基线有显著偏差(Z-score > 2.0)\n\n"
        "## 判定标准\n"
        "- 若多个维度同时异常或涉及高密级数据外传 → dangerous\n"
        "- 若仅有1-2个弱信号但可疑 → suspicious\n"
        "- 若完全符合正常行为模式 → safe\n\n"
        "回复格式：{ \"verdict\": \"dangerous\"|\"suspicious\"|\"safe\", "
        "\"confidence\": 0.0-1.0, \"reasoning\": \"分析理由（基于上述维度的具体发现）\", "
        "\"threat_type\": \"数据泄露\"|\"C2通信\"|\"隐蔽信道\"|\"未授权访问\"|\"正常\"|\"未知\", "
        "\"insider_threat_indicators\": [\"指标1\", \"指标2\"] }"
    )
    temperature: float = 0.3
    max_tokens: int = 1024
    max_context_tokens: int = 4096
    confidence_threshold_dangerous: float = 0.85
    confidence_threshold_suspicious: float = 0.50


@dataclass
class BacktrackAgentConfig:
    """Layer 2 — 历史回溯智能体配置"""
    enabled: bool = True
    backend: BackendType = BackendType.DEEPSEEK
    model_name: str = "deepseek-v4-flash"
    system_prompt: str = (
        "你是一个历史流量关联分析专家。给定当前可疑流量和一批来自相同源IP/部门的"
        "历史流量记录，请逐条判断每条历史记录与当前流量的关联度（0.0-1.0），"
        "只保留关联度 >= 设定阈值的记录。\n\n"
        "## 关联度判定维度\n"
        "1. **目标相似度**：目的IP/端口/协议是否与当前流量一致或相似\n"
        "2. **行为模式相似度**：传输数据量、加密熵、时段模式是否相似\n"
        "3. **时序关联**：时间上是否呈现规则间隔或渐进变化\n"
        "4. **部门/角色关联**：是否同一部门、同一角色的相似行为\n\n"
        "回复格式：{ \"relevant_records\": ["
        "{\"record_id\": 整数, \"relevance\": 0.0-1.0, \"reason\": \"简短理由\"}, ...], "
        "\"summary\": \"整体回溯发现总结\" }"
    )
    temperature: float = 0.3
    max_tokens: int = 2048
    batch_context_ratio: float = 0.125         # 每批占上下文的 1/8（为深度思考预留）
    lookback_windows: list[float] = field(default_factory=lambda: [0.5, 24, 168, 720, 2160])  # 30m, 1d, 7d, 30d, 90d
    relevance_threshold: float = 0.6           # 关联度阈值（低于此值丢弃）


@dataclass
class AdjudicationAgentConfig:
    """Layer 3 — 最终研判智能体配置"""
    enabled: bool = True
    backend: BackendType = BackendType.DEEPSEEK
    model_name: str = "deepseek-v4-flash"
    system_prompt: str = (
        "你是一个内部威胁最终研判专家。请结合原始可疑流量及其历史关联数据，"
        "进行最终的威胁判定。\n\n"
        "## 研判核心原则\n"
        "1. **弱信号聚合**：单一维度可疑不足为据，但多个弱信号叠加可能构成明确威胁\n"
        "2. **长周期视角**：结合历史回溯数据判断是否存在持续性模式\n"
        "3. **关联度加权**：高关联度历史记录更有研判价值\n"
        "4. **误报宽容度**：内部威胁检测宁可多报不可漏报，但需合理标注置信度\n\n"
        "## 严重度判定标准\n"
        "- **critical**: 确认高密级数据外传，或累计外传>100MB，或持续>30天\n"
        "- **high**: 疑似数据外传+多个弱信号(4+)，或累计外传>50MB，或持续>7天\n"
        "- **medium**: 可疑行为+2-3个弱信号，或短期异常但无明显数据泄露证据\n"
        "- **low**: 仅有1个弱信号，或轻微异常，需持续观察\n"
        "- **info**: 单次异常但无规律，降级观察\n\n"
        "回复格式：{ \"verdict\": \"dangerous\"|\"suspicious\"|\"safe\", "
        "\"severity\": \"critical\"|\"high\"|\"medium\"|\"low\"|\"info\", "
        "\"confidence\": 0.0-1.0, "
        "\"recommended_action\": \"block\"|\"monitor\"|\"allow\"|\"quarantine\", "
        "\"reasoning\": \"综合研判逻辑\", "
        "\"evidence_summary\": [\"证据1\", \"证据2\"] }"
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
        "你是一个内部威胁检测系统的自适应学习专家。根据管理员反馈和历史判定记录，"
        "分析误报/漏报的模式特征，帮助系统持续降低误报、减少漏报。\n\n"
        "## 分析策略\n"
        "1. **误报分析**：分析误报特征，识别容易被误判为恶意的正常行为模式\n"
        "2. **漏报分析**：逆向分析漏报案例，确定哪些弱信号组合被遗漏\n"
        "3. **用户画像更新**：根据同类用户的实际行为，理解部门/角色的正常行为容差\n"
        "4. **长周期模式学习**：记录管理员确认的长周期泄密案例，提取低慢外传的模式特征\n\n"
        "回复格式：{ \"pattern_insight\": \"模式洞察\", "
        "\"confidence\": 0.0-1.0, "
        "\"reasoning\": \"分析理由（含模式学习结论）\", "
        "\"learned_pattern\": \"从案例中学到的模式特征（可选）\" }"
    )
    temperature: float = 0.2
    max_tokens: int = 1024


@dataclass
class LiveScanAgentConfig:
    """逐条评判队列扫描配置 — 定时触发 + 链式连续消费"""
    enabled: bool = True                        # 管理员开关
    idle_poll_interval_seconds: float = 600.0   # 空闲轮询间隔（默认 10 分钟）
    batch_size_multiplier: float = 6.0          # 批次大小 = 并发数 × 倍数
    max_concurrent_analyses: int = 8            # 最大并发分析数
    start_from: str = "oldest"                  # "oldest" | "newest" | "last_id:N"

    @property
    def batch_size(self) -> int:
        """动态计算批次大小 = 并发数 × 倍数（至少为并发数，确保每线程至少 1 条）"""
        return max(self.max_concurrent_analyses,
                   int(self.max_concurrent_analyses * self.batch_size_multiplier))


@dataclass
class GeoipConfig:
    """GeoIP 数据库自动更新配置"""
    enabled: bool = True
    update_interval_hours: int = 168          # 自动更新间隔（小时），7 天
    download_url: str = (
        "https://cdn.jsdelivr.net/npm/geolite2-city/GeoLite2-City.mmdb.gz"
    )
    db_path: str = "data_gateway/GeoLite2-City.mmdb"  # 相对于项目根目录


@dataclass
class OrchestratorConfig:
    """编排器总配置 — 三层智能体架构"""
    screening: ScreeningAgentConfig = field(default_factory=ScreeningAgentConfig)
    backtrack: BacktrackAgentConfig = field(default_factory=BacktrackAgentConfig)
    adjudication: AdjudicationAgentConfig = field(default_factory=AdjudicationAgentConfig)
    feedback: FeedbackAgentConfig = field(default_factory=FeedbackAgentConfig)
    live_scan: LiveScanAgentConfig = field(default_factory=LiveScanAgentConfig)
    geoip: GeoipConfig = field(default_factory=GeoipConfig)
    # 全局后端连接池配置
    default_backends: dict[BackendType, LLMBackendConfig] = field(default_factory=dict)

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