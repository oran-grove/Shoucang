"""
慢脑层：行为基线画像智能体
========================
基于历史日志数据库，为每个用户/部门/资产构建正常行为基线画像。
定期（每日）更新基线，检测时提供基线偏离度（Z-score）给快脑层使用。

设计目标：
- 长周期视角：分析7d/30d/90d的行为模式
- 多维度画像：流量频率、数据量、协议偏好、时间分布、目标资产
- 自适应：根据角色和部门自动调整正常范围
"""

import logging
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from typing import Any, Optional
import json

from ..core.agent import BaseAgent
from ..core.message import FlowEvent, ThreatVerdict, TrafficVerdict, SeverityLevel

logger = logging.getLogger(__name__)


@dataclass
class BehaviorBaseline:
    """用户/部门行为基线"""
    entity_id: str = ""              # user_id 或 department
    entity_type: str = "user"        # "user" / "department" / "asset"
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # 流量频率统计
    avg_flows_per_hour: float = 0.0
    std_flows_per_hour: float = 0.0
    avg_flows_per_day: float = 0.0

    # 数据量统计
    avg_bytes_per_hour: float = 0.0
    std_bytes_per_hour: float = 0.0
    avg_bytes_per_flow: float = 0.0

    # 时段分布（按小时分桶 0-23）
    hour_distribution: list[float] = field(default_factory=lambda: [0.0] * 24)

    # 协议偏好 (protocol -> proportion)
    protocol_distribution: dict[str, float] = field(default_factory=dict)

    # 目标资产偏好 (asset_type -> proportion)
    asset_distribution: dict[str, float] = field(default_factory=dict)

    # 数据密级访问分布 (sensitivity -> proportion)
    sensitivity_distribution: dict[str, float] = field(default_factory=dict)

    # 非工作时段占比 (22:00-06:00)
    off_hours_ratio: float = 0.0

    # 元数据
    sample_count: int = 0
    sample_period_days: int = 0

    def compute_frequency_zscore(self, count: float, period_hours: float = 1.0) -> float:
        """计算频率的 Z-score 偏离度"""
        expected = self.avg_flows_per_hour * period_hours
        std = max(self.std_flows_per_hour * (period_hours ** 0.5), 1.0)
        return (count - expected) / std if std > 0 else 0.0

    def compute_volume_zscore(self, total_bytes: float) -> float:
        """计算数据量的 Z-score 偏离度"""
        std = max(self.std_bytes_per_hour, 1.0)
        return (total_bytes - self.avg_bytes_per_hour) / std if std > 0 else 0.0

    def is_off_hours(self, hour: int) -> bool:
        """判断是否为非工作时段"""
        return hour < 6 or hour >= 22

    def to_dict(self) -> dict:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "last_updated": self.last_updated.isoformat(),
            "avg_flows_per_hour": self.avg_flows_per_hour,
            "std_flows_per_hour": self.std_flows_per_hour,
            "avg_flows_per_day": self.avg_flows_per_day,
            "avg_bytes_per_hour": self.avg_bytes_per_hour,
            "std_bytes_per_hour": self.std_bytes_per_hour,
            "avg_bytes_per_flow": self.avg_bytes_per_flow,
            "off_hours_ratio": self.off_hours_ratio,
            "sample_count": self.sample_count,
            "sample_period_days": self.sample_period_days,
        }


class BaselineProfilingAgent(BaseAgent):
    """
    行为基线画像智能体（慢脑层核心组件）：
    - 从历史日志数据库读取流量记录
    - 按 user_id / department / asset 构建行为基线
    - 定期更新基线（默认每24h）
    - 为快脑层提供实时基线偏离评估（Z-score）
    - 使用 LLM 分析异常基线变化（如角色变更导致的行为模式改变）
    """

    def __init__(
        self,
        name: str = "BaselineProfilingAgent",
        system_prompt: str = "",
        model_name: str = "deepseek-v4-flash",
        temperature: float = 0.2,
        max_tokens: int = 2048,
        update_interval_hours: int = 24,
    ):
        default_prompt = (
            "你是一个用户行为基线分析专家。请根据用户的长期历史流量记录，"
            "构建正常行为画像并识别异常偏离。\n\n"
            "## 分析维度\n"
            "1. **频率基线**：该用户/部门在不同时段（工作时间/非工作时间）的"
            "正常网络请求频率\n"
            "2. **数据量基线**：正常的数据传输量分布（单次/每小时/每天）\n"
            "3. **协议习惯**：通常使用的网络协议和应用类型\n"
            "4. **目标资产画像**：正常访问的服务器类型和频率\n"
            "5. **数据密级访问模式**：与角色关联的数据密级，例如：\n"
            "   - 研发人员：通常访问内部/机密代码库\n"
            "   - 财务人员：通常访问内部财务系统\n"
            "   - 行政人员：通常访问公开/内部文档\n"
            "6. **周期性模式**：按小时/天/周的行为规律\n\n"
            "回复格式：{ \"baseline_summary\": \"基线总结\", "
            "\"anomaly_detected\": true|false, "
            "\"anomaly_details\": [\"异常点描述\"], "
            "\"baseline_shift_detected\": true|false, "
            "\"confidence\": 0.0-1.0 }"
        )
        super().__init__(
            name=name,
            system_prompt=system_prompt or default_prompt,
            model_name=model_name,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        self.update_interval_hours = update_interval_hours

        # 基线存储: entity_id -> BehaviorBaseline
        self._baselines: dict[str, BehaviorBaseline] = {}

    def build_or_update_baseline(
        self,
        entity_id: str,
        entity_type: str,
        historical_flows: list[FlowEvent],
    ) -> BehaviorBaseline:
        """
        从历史流量记录构建/更新行为基线。
        使用统计方法（均值、标准差、分布），不依赖 LLM 以保证确定性。
        """
        if not historical_flows:
            return self._baselines.get(
                entity_id,
                BehaviorBaseline(entity_id=entity_id, entity_type=entity_type)
            )

        # 按小时聚合
        hourly_flows: dict[int, list[FlowEvent]] = {}
        total_flows = len(historical_flows)
        total_bytes = 0
        protocol_counts: dict[str, int] = {}
        asset_counts: dict[str, int] = {}
        sensitivity_counts: dict[str, int] = {}
        off_hours_count = 0

        for flow in historical_flows:
            hour = flow.timestamp.hour
            hourly_flows.setdefault(hour, []).append(flow)
            total_bytes += flow.byte_count

            prot = flow.app_protocol or flow.protocol
            protocol_counts[prot] = protocol_counts.get(prot, 0) + 1

            if flow.asset_type:
                asset_counts[flow.asset_type] = asset_counts.get(flow.asset_type, 0) + 1
            if flow.data_sensitivity:
                sensitivity_counts[flow.data_sensitivity] = sensitivity_counts.get(flow.data_sensitivity, 0) + 1
            if flow.work_hours_violation:
                off_hours_count += 1

        # 统计小时分布
        hour_dist = [len(hourly_flows.get(h, [])) for h in range(24)]
        total_hour_flows = sum(hour_dist)
        hour_dist_norm = [c / max(total_hour_flows, 1) for c in hour_dist]

        # 计算时间跨度
        timestamps = [f.timestamp for f in historical_flows]
        time_span_days = (max(timestamps) - min(timestamps)).total_seconds() / 86400.0 if len(timestamps) >= 2 else 1.0
        time_span_days = max(time_span_days, 1.0)

        # 均值和标准差
        flows_per_hour = total_flows / max(time_span_days * 24, 1)
        flows_per_day = total_flows / max(time_span_days, 1)

        # 计算每小时流量的标准差
        hourly_counts = [len(hourly_flows.get(h, [])) for h in range(24)]
        mean_hourly = sum(hourly_counts) / 24.0
        std_hourly = (sum((c - mean_hourly) ** 2 for c in hourly_counts) / 24.0) ** 0.5

        bytes_per_hour = total_bytes / max(time_span_days * 24, 1)
        bytes_per_flow = total_bytes / max(total_flows, 1)

        # 计算每小时字节量的标准差（简化：按天聚合）
        daily_bytes: dict[int, int] = {}
        for flow in historical_flows:
            day = flow.timestamp.toordinal()
            daily_bytes[day] = daily_bytes.get(day, 0) + flow.byte_count

        if daily_bytes:
            hourly_bytes_list = [v / 24.0 for v in daily_bytes.values()]
            mean_hourly_bytes = sum(hourly_bytes_list) / len(hourly_bytes_list)
            std_hourly_bytes = (
                sum((b - mean_hourly_bytes) ** 2 for b in hourly_bytes_list)
                / max(len(hourly_bytes_list), 1)
            ) ** 0.5
        else:
            mean_hourly_bytes = 0.0
            std_hourly_bytes = 1.0

        # 协议分布
        total_prot = sum(protocol_counts.values())
        protocol_dist = {k: v / max(total_prot, 1) for k, v in protocol_counts.items()}

        # 资产分布
        total_asset = sum(asset_counts.values())
        asset_dist = {k: v / max(total_asset, 1) for k, v in asset_counts.items()}

        # 数据密级分布
        total_sens = sum(sensitivity_counts.values())
        sensitivity_dist = {k: v / max(total_sens, 1) for k, v in sensitivity_counts.items()}

        baseline = BehaviorBaseline(
            entity_id=entity_id,
            entity_type=entity_type,
            last_updated=datetime.now(timezone.utc),
            avg_flows_per_hour=flows_per_hour,
            std_flows_per_hour=max(std_hourly, 0.1),
            avg_flows_per_day=flows_per_day,
            avg_bytes_per_hour=bytes_per_hour,
            std_bytes_per_hour=max(std_hourly_bytes, 1000.0),
            avg_bytes_per_flow=bytes_per_flow,
            hour_distribution=hour_dist_norm,
            protocol_distribution=protocol_dist,
            asset_distribution=asset_dist,
            sensitivity_distribution=sensitivity_dist,
            off_hours_ratio=off_hours_count / max(total_flows, 1),
            sample_count=total_flows,
            sample_period_days=int(time_span_days),
        )

        self._baselines[entity_id] = baseline
        logger.info(
            "[%s] 基线已更新: entity=%s(%s), samples=%d, period=%dd",
            self.name, entity_id, entity_type, total_flows, int(time_span_days)
        )
        return baseline

    def get_baseline(self, entity_id: str) -> Optional[BehaviorBaseline]:
        """获取指定实体的行为基线"""
        return self._baselines.get(entity_id)

    def evaluate_flow(
        self, flow: FlowEvent, baseline: Optional[BehaviorBaseline] = None
    ) -> ThreatVerdict:
        """
        根据行为基线评估单条流量的偏离度。
        将 Z-score 写回 flow 对象，并生成 ThreatVerdict。
        """
        if baseline is None:
            if flow.user_id:
                baseline = self._baselines.get(f"user:{flow.user_id}")
            if baseline is None and flow.src_ip:
                baseline = self._baselines.get(f"ip:{flow.src_ip}")

        if baseline is None:
            return ThreatVerdict(
                verdict=TrafficVerdict.UNKNOWN,
                severity=SeverityLevel.LOW,
                confidence=0.0,
                reasoning="无可用基线数据",
                recommended_action="monitor",
            )

        # 计算频率偏离
        freq_z = baseline.compute_frequency_zscore(
            count=1.0 if flow.pkt_count < 100 else flow.pkt_count / 100.0,
            period_hours=flow.duration_seconds / 3600.0 if flow.duration_seconds > 0 else 1.0 / 3600.0
        )
        flow.historical_frequency_zscore = freq_z

        # 计算数据量偏离
        vol_z = baseline.compute_volume_zscore(flow.byte_count)
        flow.historical_volume_zscore = vol_z

        # 检查是否为非工作时段
        if baseline.is_off_hours(flow.timestamp.hour):
            flow.work_hours_violation = True

        # 偏离度评估
        reason_parts = []
        escalated = False

        if freq_z > 3.0:
            reason_parts.append(f"频率极度偏离基线(Z={freq_z:.1f})")
            escalated = True
        elif freq_z > 2.0:
            reason_parts.append(f"频率显著偏离基线(Z={freq_z:.1f})")

        if vol_z > 3.0:
            reason_parts.append(f"数据量极度偏离基线(Z={vol_z:.1f})")
            escalated = True
        elif vol_z > 2.0:
            reason_parts.append(f"数据量显著偏离基线(Z={vol_z:.1f})")

        if flow.work_hours_violation and baseline.off_hours_ratio < 0.05:
            reason_parts.append("非工作时段异常操作（历史占比<5%）")
            escalated = True

        if not reason_parts:
            return ThreatVerdict(
                verdict=TrafficVerdict.SAFE,
                severity=SeverityLevel.INFO,
                confidence=0.9,
                reasoning="行为符合历史基线",
                recommended_action="allow",
            )

        if escalated:
            return ThreatVerdict(
                flow_ids=[flow.flow_id],
                verdict=TrafficVerdict.SUSPICIOUS,
                severity=SeverityLevel.MEDIUM,
                confidence=min(0.5 + max(abs(freq_z), abs(vol_z)) * 0.1, 0.85),
                reasoning="; ".join(reason_parts),
                recommended_action="monitor",
                extra={
                    "freq_zscore": freq_z,
                    "vol_zscore": vol_z,
                    "baseline_entity": baseline.entity_id,
                },
            )

        return ThreatVerdict(
            flow_ids=[flow.flow_id],
            verdict=TrafficVerdict.SAFE,
            severity=SeverityLevel.LOW,
            confidence=0.8,
            reasoning="; ".join(reason_parts) if reason_parts else "行为在正常范围",
            recommended_action="allow",
        )

    async def analyze_baseline_shift(
        self, entity_id: str, recent_flows: list[FlowEvent]
    ) -> ThreatVerdict:
        """
        使用 LLM 分析基线是否发生了显著变化（如角色变更、权限变更）。
        长周期（7d+）调用，非实时。
        """
        baseline = self._baselines.get(entity_id)
        if not baseline:
            return ThreatVerdict(
                verdict=TrafficVerdict.UNKNOWN,
                severity=SeverityLevel.LOW,
                confidence=0.0,
                reasoning="无历史基线，无法评估基线变化",
            )

        prompt_lines = [
            f"实体: {entity_id} (类型: {baseline.entity_type})",
            f"历史基线样本数: {baseline.sample_count} (周期: {baseline.sample_period_days}d)",
            f"历史平均流/小时: {baseline.avg_flows_per_hour:.1f}",
            f"历史平均字节/小时: {baseline.avg_bytes_per_hour:.1f}",
            f"历史非工作时段占比: {baseline.off_hours_ratio:.1%}",
            "---",
            f"近期（最近24h）样本数: {len(recent_flows)}",
        ]

        if recent_flows:
            recent_bytes = sum(f.byte_count for f in recent_flows)
            recent_off_hours = sum(1 for f in recent_flows if f.work_hours_violation)
            prompt_lines.extend([
                f"近期总字节数: {recent_bytes}",
                f"近期非工作时段操作数: {recent_off_hours}/{len(recent_flows)}",
                f"近期活跃时段: {', '.join(str(f.timestamp.hour) for f in recent_flows[:10])}",
            ])

        prompt_lines.append("\n请分析该实体行为是否有基线层面的显著变化。")
        prompt = "\n".join(prompt_lines)

        try:
            response = await self.call_llm(prompt)
            parsed = self.extract_json_from_response(response)
            if parsed.get("baseline_shift_detected"):
                return ThreatVerdict(
                    verdict=TrafficVerdict.SUSPICIOUS,
                    severity=SeverityLevel.MEDIUM,
                    confidence=float(parsed.get("confidence", 0.6)),
                    reasoning=parsed.get("anomaly_details", {}).get("description", "基线显著变化"),
                    recommended_action="monitor",
                )
        except Exception as e:
            logger.error("[%s] LLM 基线变化分析失败: %s", self.name, e)

        return ThreatVerdict(
            verdict=TrafficVerdict.SAFE,
            severity=SeverityLevel.LOW,
            confidence=0.9,
            reasoning="基线未检测到显著变化",
        )

    def clear_expired_baselines(self, max_age_days: int = 90) -> int:
        """清理过期基线"""
        cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
        expired = [
            k for k, b in self._baselines.items()
            if b.last_updated < cutoff
        ]
        for k in expired:
            del self._baselines[k]
        if expired:
            logger.info("[%s] 清理了 %d 个过期基线", self.name, len(expired))
        return len(expired)

    # ----- BaseAgent 抽象方法实现 -----
    async def process(self, *args: Any, **kwargs: Any) -> Any:
        """
        处理消息总线发来的请求。
        由消息总线回调，根据消息类型路由到对应逻辑。

        支持的消息：
        - "build_baseline": 构建/更新基线 (kwargs: entity_id, entity_type, historical_flows)
        - "evaluate_flow": 评估单条流量偏离 (kwargs: flow, baseline)
        - "analyze_shift": LLM分析基线变化 (kwargs: entity_id, recent_flows)
        - "get_baseline": 查询基线 (kwargs: entity_id)
        """
        action = kwargs.get("action", "")
        if action == "build_baseline":
            return self.build_or_update_baseline(
                entity_id=str(kwargs.get("entity_id", "")),
                entity_type=str(kwargs.get("entity_type", "user")),
                historical_flows=kwargs.get("historical_flows", []),
            )
        elif action == "evaluate_flow":
            return self.evaluate_flow(
                flow=kwargs["flow"],
                baseline=kwargs.get("baseline"),
            )
        elif action == "analyze_shift":
            return await self.analyze_baseline_shift(
                entity_id=str(kwargs.get("entity_id", "")),
                recent_flows=kwargs.get("recent_flows", []),
            )
        elif action == "get_baseline":
            return self.get_baseline(str(kwargs.get("entity_id", "")))
        else:
            logger.warning("[%s] 未知 action: %s", self.name, action)
            return None


__all__ = ["BaselineProfilingAgent", "BehaviorBaseline"]