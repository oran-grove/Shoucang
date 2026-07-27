"""
配置数据模型 — 纯结构体定义
===========================
每个 JSON 配置节对应一个 dataclass，所有默认值在 dataclass 字段中定义。

本模块是纯数据模型定义，不涉及文件 I/O。
文件 I/O 由 config/store.py 负责。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class BackendType(Enum):
    """LLM 后端类型"""
    OPENAI = "openai"
    LMSTUDIO = "lmstudio"
    DEEPSEEK = "deepseek"


# ============================================================
# 数据库配置
# ============================================================

@dataclass
class DatabaseConfig:
    """数据库连接配置"""
    host: str = "localhost"
    port: int = 3306
    user: str = "root"
    password: str = ""
    database: str = "insider_threat_db"
    charset: str = "utf8mb4"


# ============================================================
# LLM 后端配置
# ============================================================

@dataclass
class LLMBackendConfig:
    """单个 LLM 后端的配置字段（OpenAI / LM Studio / DeepSeek 通用）"""
    model_name: str = "gpt-4o-mini"
    api_base: str = "https://api.openai.com/v1"
    api_key: str = ""
    temperature: float = 0.3
    max_tokens: int = 2048
    max_context_tokens: int = 4096
    timeout: float = 60.0
    max_retries: int = 3
    # —— LM Studio 专有 ——
    auto_load: bool = True
    load_config: dict = field(default_factory=dict)
    # —— DeepSeek 专有 ——
    thinking_enabled: Optional[bool] = None
    reasoning_effort: Optional[str] = None
    include_reasoning: bool = False


@dataclass
class BackendsConfig:
    """三个 LLM 后端的配置集合"""
    openai: LLMBackendConfig = field(default_factory=LLMBackendConfig)
    lmstudio: LLMBackendConfig = field(default_factory=LLMBackendConfig)
    deepseek: LLMBackendConfig = field(default_factory=LLMBackendConfig)


# ============================================================
# 三层智能体配置
# ============================================================

@dataclass
class ScreeningAgentConfig:
    """Layer 1 — 初步筛查智能体"""
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
    """Layer 2 — 历史回溯智能体"""
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
    batch_context_ratio: float = 0.125
    lookback_windows: list[float] = field(default_factory=lambda: [0.5, 24, 168, 720, 2160])
    relevance_threshold: float = 0.6


@dataclass
class AdjudicationAgentConfig:
    """Layer 3 — 最终研判智能体"""
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
    """反馈智能体"""
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


# ============================================================
# 逐条扫描 / GeoIP 配置
# ============================================================

@dataclass
class LiveScanConfig:
    """逐条评判队列扫描配置"""
    enabled: bool = True
    idle_poll_interval_seconds: float = 600.0
    batch_size_multiplier: float = 6.0
    max_concurrent_analyses: int = 8
    start_from: str = "oldest"

    @property
    def batch_size(self) -> int:
        return max(self.max_concurrent_analyses,
                   int(self.max_concurrent_analyses * self.batch_size_multiplier))


@dataclass
class GeoipConfig:
    """GeoIP 数据库自动更新配置"""
    enabled: bool = True
    update_interval_hours: int = 168
    download_url: str = "https://cdn.jsdelivr.net/npm/geolite2-city/GeoLite2-City.mmdb.gz"
    db_path: str = "data_gateway/GeoLite2-City.mmdb"


# ============================================================
# WebUI 鉴权配置
# ============================================================

@dataclass
class WebuiAuthConfig:
    """WebUI 管理员登录鉴权配置"""
    admin_user: str = "admin"
    admin_password_hash: str = ""   # scrypt hash:salt，空=首次启动自动生成
    jwt_secret: str = ""            # JWT 签名密钥，空=首次启动自动生成
    jwt_expiry_hours: int = 24


# ============================================================
# 总配置（所有节的聚合）
# ============================================================

@dataclass
class FullConfig:
    """所有配置节的聚合 — get_config() 无参调用时返回"""
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    backends: BackendsConfig = field(default_factory=BackendsConfig)
    screening: ScreeningAgentConfig = field(default_factory=ScreeningAgentConfig)
    backtrack: BacktrackAgentConfig = field(default_factory=BacktrackAgentConfig)
    adjudication: AdjudicationAgentConfig = field(default_factory=AdjudicationAgentConfig)
    feedback: FeedbackAgentConfig = field(default_factory=FeedbackAgentConfig)
    live_scan: LiveScanConfig = field(default_factory=LiveScanConfig)
    geoip: GeoipConfig = field(default_factory=GeoipConfig)
    webui_auth: WebuiAuthConfig = field(default_factory=WebuiAuthConfig)

    def to_dict(self) -> dict:
        """序列化为 JSON 兼容的字典（枚举转字符串）。"""
        return {
            "database": {
                "host": self.database.host,
                "port": self.database.port,
                "user": self.database.user,
                "password": self.database.password,
                "database": self.database.database,
                "charset": self.database.charset,
            },
            "backends": {
                "openai": _backend_to_dict(self.backends.openai),
                "lmstudio": _backend_to_dict(self.backends.lmstudio),
                "deepseek": _backend_to_dict(self.backends.deepseek),
            },
            "screening": _screening_to_dict(self.screening),
            "backtrack": _backtrack_to_dict(self.backtrack),
            "adjudication": _adjudication_to_dict(self.adjudication),
            "feedback": _feedback_to_dict(self.feedback),
            "live_scan": {
                "enabled": self.live_scan.enabled,
                "idle_poll_interval_seconds": self.live_scan.idle_poll_interval_seconds,
                "batch_size_multiplier": self.live_scan.batch_size_multiplier,
                "max_concurrent_analyses": self.live_scan.max_concurrent_analyses,
                "start_from": self.live_scan.start_from,
            },
            "geoip": {
                "enabled": self.geoip.enabled,
                "update_interval_hours": self.geoip.update_interval_hours,
                "download_url": self.geoip.download_url,
                "db_path": self.geoip.db_path,
            },
            "webui_auth": {
                "admin_user": self.webui_auth.admin_user,
                "admin_password_hash": self.webui_auth.admin_password_hash,
                "jwt_secret": self.webui_auth.jwt_secret,
                "jwt_expiry_hours": self.webui_auth.jwt_expiry_hours,
            },
        }


def _backend_to_dict(be):
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


def _screening_to_dict(s):
    return {
        "enabled": s.enabled,
        "backend": s.backend.value,
        "model_name": s.model_name,
        "system_prompt": s.system_prompt,
        "temperature": s.temperature,
        "max_tokens": s.max_tokens,
        "max_context_tokens": s.max_context_tokens,
        "confidence_threshold_dangerous": s.confidence_threshold_dangerous,
        "confidence_threshold_suspicious": s.confidence_threshold_suspicious,
    }


def _backtrack_to_dict(b):
    return {
        "enabled": b.enabled,
        "backend": b.backend.value,
        "model_name": b.model_name,
        "system_prompt": b.system_prompt,
        "temperature": b.temperature,
        "max_tokens": b.max_tokens,
        "lookback_windows": b.lookback_windows,
        "relevance_threshold": b.relevance_threshold,
        "batch_context_ratio": b.batch_context_ratio,
    }


def _adjudication_to_dict(a):
    return {
        "enabled": a.enabled,
        "backend": a.backend.value,
        "model_name": a.model_name,
        "system_prompt": a.system_prompt,
        "temperature": a.temperature,
        "max_tokens": a.max_tokens,
    }


def _feedback_to_dict(f):
    return {
        "enabled": f.enabled,
        "backend": f.backend.value,
        "model_name": f.model_name,
        "system_prompt": f.system_prompt,
        "temperature": f.temperature,
        "max_tokens": f.max_tokens,
    }


__all__ = [
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
    "WebuiAuthConfig",
    "FullConfig",
]
