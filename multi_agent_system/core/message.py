"""
消息与数据结构定义
==================
包括智能体间消息、流量事件、威胁判定结果、规则条目。
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4


def fmt_window(hours: float) -> str:
    """格式化回溯窗口为人类可读字符串 (e.g. 0.5→30m, 24→1d, 168→7d)"""
    if hours < 1:
        return f"{int(hours * 60)}m"
    if hours < 24:
        return f"{hours:.0f}h"
    if hours % 24 == 0:
        return f"{hours // 24:.0f}d"
    d = int(hours // 24)
    h = int(hours % 24)
    return f"{d}d{h}h"


class TrafficVerdict(Enum):
    """流量判定"""
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    SAFE = "safe"
    UNKNOWN = "unknown"
    FALSE_POSITIVE = "false_positive"


class SeverityLevel(Enum):
    """威胁严重度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class FlowEvent:
    """
    流量事件：从 P4 交换机镜像/遥测获得的单流元数据。

    2026-05 增强：新增内部威胁检测所需字段
    - 用户/部门/数据密级维度
    - 行为基线偏离度量
    """
    flow_id: str = field(default_factory=lambda: uuid4().hex[:12])
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "TCP"             # TCP / UDP / ICMP
    app_protocol: str = "unknown"     # HTTP / TLS / DNS / SMTP / unknown
    # P4 提取的元数据特征
    pkt_count: int = 0
    byte_count: int = 0
    duration_seconds: float = 0.0
    avg_pkt_size: float = 0.0
    entropy_score: float = 0.0        # 载荷熵（0-8）
    tls_sni: Optional[str] = None
    ja4_fingerprint: Optional[str] = None
    dns_query: Optional[str] = None

    # === 内部威胁检测扩展字段（2026-05） ===
    user_id: str = ""                 # 关联用户 / 员工 ID（如 LDAP/SSO 账号）
    department: str = ""              # 所属部门（研发/财务/人事/运维…）
    data_sensitivity: str = ""        # 访问/传输数据的密级标签（公开/内部/机密/绝密/DLP标签）
    asset_type: str = ""              # 目标资产类型（文件服务器/数据库/邮件系统/云存储/SaaS）
    work_hours_violation: bool = False  # 是否在非工作时段（如 22:00–06:00 或周末）
    historical_frequency_zscore: float = 0.0  # 频率与历史基线的 Z-score 偏离度
    historical_volume_zscore: float = 0.0     # 数据量与历史基线的 Z-score 偏离度

    # 扩展字段（向后兼容）
    extra: dict[str, Any] = field(default_factory=dict)

    def to_prompt_text(self) -> str:
        """转为 LLM 提示文本（含内部威胁扩展字段）"""
        lines = [
            f"流量ID: {self.flow_id}",
            f"时间: {self.timestamp.isoformat()}",
            f"源IP: {self.src_ip}:{self.src_port}",
            f"目的IP: {self.dst_ip}:{self.dst_port}",
            f"协议: {self.protocol}/{self.app_protocol}",
            f"报文数: {self.pkt_count}, 字节数: {self.byte_count}",
            f"持续时间: {self.duration_seconds:.2f}s",
            f"平均包长: {self.avg_pkt_size:.1f} bytes",
            f"载荷熵: {self.entropy_score:.2f}",
        ]
        if self.tls_sni:
            lines.append(f"TLS SNI: {self.tls_sni}")
        if self.ja4_fingerprint:
            lines.append(f"JA4: {self.ja4_fingerprint}")
        if self.dns_query:
            lines.append(f"DNS查询: {self.dns_query}")

        # 内部威胁扩展字段（仅非空时输出）
        if self.user_id:
            lines.append(f"用户ID: {self.user_id}")
        if self.department:
            lines.append(f"部门: {self.department}")
        if self.data_sensitivity:
            lines.append(f"数据密级: {self.data_sensitivity}")
        if self.asset_type:
            lines.append(f"目标资产: {self.asset_type}")
        if self.work_hours_violation:
            lines.append("⚠ 非工作时段操作")
        if self.historical_frequency_zscore != 0.0:
            lines.append(f"频率偏离(Z): {self.historical_frequency_zscore:.2f}")
        if self.historical_volume_zscore != 0.0:
            lines.append(f"数据量偏离(Z): {self.historical_volume_zscore:.2f}")

        return "\n".join(lines)


@dataclass
class ThreatVerdict:
    """
    威胁判定结果。
    """
    verdict_id: str = field(default_factory=lambda: uuid4().hex[:8])
    flow_ids: list[str] = field(default_factory=list)
    verdict: TrafficVerdict = TrafficVerdict.UNKNOWN
    severity: SeverityLevel = SeverityLevel.LOW
    confidence: float = 0.0
    threat_type: str = "未知"
    reasoning: str = ""
    evidence_summary: list[str] = field(default_factory=list)
    recommended_action: str = "allow"    # block / monitor / allow / quarantine
    # 关联的检测/研判结果ID
    detection_result_id: Optional[str] = None
    correlation_result_id: Optional[str] = None
    judgment_result_id: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    extra: dict[str, Any] = field(default_factory=dict)


def get_pattern_context(flow) -> str:
    """从记忆系统查询匹配的历史模式，返回提示词注入文本。"""
    try:
        from ..memory import get_index
        index = get_index()
        features = {
            "department": getattr(flow, "department", ""),
            "protocol": getattr(flow, "protocol", "TCP"),
            "direction": (
                "internal" if getattr(flow, "dst_ip", "").startswith(
                    ("10.", "192.168.", "172.")
                ) else "outbound"
            ),
            "encryption": getattr(flow, "entropy_score", 0) > 7.0,
        }
        return index.format_context(features)
    except Exception:
        return ""


__all__ = [
    "fmt_window",
    "get_pattern_context",
    "TrafficVerdict",
    "SeverityLevel",
    "FlowEvent",
    "ThreatVerdict",
]
