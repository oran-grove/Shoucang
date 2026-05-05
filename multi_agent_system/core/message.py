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


class MessageType(Enum):
    """消息类型"""
    FLOW_EVENT = "flow_event"
    DETECTION_RESULT = "detection_result"
    CORRELATION_REQUEST = "correlation_request"
    CORRELATION_RESULT = "correlation_result"
    JUDGMENT_REQUEST = "judgment_request"
    THREAT_VERDICT = "threat_verdict"
    FEEDBACK_REQUEST = "feedback_request"
    RULE_UPDATE = "rule_update"
    ADMIN_FEEDBACK = "admin_feedback"
    SYSTEM_ALERT = "system_alert"
    HEARTBEAT = "heartbeat"


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


class RuleAction(Enum):
    """规则动作"""
    BLOCK = "block"
    ALLOW = "allow"
    MIRROR = "mirror"
    THROTTLE = "throttle"


@dataclass
class FlowEvent:
    """
    流量事件：从 P4 交换机镜像/遥测获得的单流元数据。
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
    # 扩展字段
    extra: dict[str, Any] = field(default_factory=dict)

    def to_prompt_text(self) -> str:
        """转为 LLM 提示文本"""
        return (
            f"流量ID: {self.flow_id}\n"
            f"时间: {self.timestamp.isoformat()}\n"
            f"源IP: {self.src_ip}:{self.src_port}\n"
            f"目的IP: {self.dst_ip}:{self.dst_port}\n"
            f"协议: {self.protocol}/{self.app_protocol}\n"
            f"报文数: {self.pkt_count}, 字节数: {self.byte_count}\n"
            f"持续时间: {self.duration_seconds:.2f}s\n"
            f"平均包长: {self.avg_pkt_size:.1f} bytes\n"
            f"载荷熵: {self.entropy_score:.2f}\n"
            + (f"TLS SNI: {self.tls_sni}\n" if self.tls_sni else "")
            + (f"JA4: {self.ja4_fingerprint}\n" if self.ja4_fingerprint else "")
            + (f"DNS查询: {self.dns_query}\n" if self.dns_query else "")
        )


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


@dataclass
class RuleEntry:
    """
    黑白名单规则条目。
    """
    rule_id: str = field(default_factory=lambda: uuid4().hex[:8])
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""
    action: RuleAction = RuleAction.BLOCK
    confidence: float = 0.0
    source: str = "auto"              # auto / manual / admin_feedback
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_hit_at: Optional[datetime] = None
    hit_count: int = 0
    ttl_minutes: int = 1440           # 过期时间（分钟）
    comment: str = ""

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        if now is None:
            now = datetime.now(timezone.utc)
        if self.ttl_minutes <= 0:
            return False
        elapsed = (now - self.created_at).total_seconds() / 60.0
        return elapsed > self.ttl_minutes


@dataclass
class AgentMessage:
    """
    智能体间通信的通用消息封装。
    """
    msg_id: str = field(default_factory=lambda: uuid4().hex[:8])
    msg_type: MessageType = MessageType.FLOW_EVENT
    sender: str = ""                  # 发送方智能体名称
    recipient: str = ""              # 接收方智能体名称（空 = 广播）
    payload: Any = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    correlation_id: str = ""         # 关联同一分析管线的ID


__all__ = [
    "MessageType",
    "TrafficVerdict",
    "SeverityLevel",
    "RuleAction",
    "FlowEvent",
    "ThreatVerdict",
    "RuleEntry",
    "AgentMessage",
]
