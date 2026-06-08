"""
深度分析：时序异常智能体
============================
专门负责长周期（7d/30d/90d）的时序异常检测。
使用 LLM 分析较长时间窗口内的行为趋势，识别"低慢"模式。

检测维度：
- 周期性低频活动（每天/每周固定时间的小量传输）
- 渐进式数据量增长（每天多一点点）
- 心跳/信标间隔（严格定时的极小包）
- 时序衰减/突然消失（长期活跃后突然静默-反检测）

与实时关联智能体的分工：
- 关联智能体：实时-24h 的短期关联
- 时序异常智能体：7d-90d 的长期趋势分析
"""

import logging
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
from statistics import mean, stdev, median

from ..core.agent import BaseAgent
from ..core.message import FlowEvent, ThreatVerdict, TrafficVerdict, SeverityLevel

logger = logging.getLogger(__name__)


@dataclass
class TimeSeriesSlice:
    """时序切片"""
    start_time: datetime
    end_time: datetime
    flow_count: int = 0
    total_bytes: int = 0
    avg_entropy: float = 0.0
    unique_dst_ips: int = 0
    unique_dst_ports: int = 0


class TemporalAnomalyAgent(BaseAgent):
    """
    时序异常智能体（深度分析专用）：
    - 对长周期历史日志进行时间序列分析
    - 识别周期性、趋势性、突变性异常
    - 输出长周期时序异常评估
    - 使用 LLM 进行模式分析和异常解释
    """

    def __init__(
        self,
        name: str = "TemporalAnomalyAgent",
        system_prompt: str = "",
        model_name: str = "deepseek-v4-flash",
        temperature: float = 0.3,
        max_tokens: int = 2048,
        default_window_days: int = 30,
        slice_size_hours: int = 6,
    ):
        default_prompt = (
            "你是一个时序异常分析专家，专门从长时间窗口（7天-90天）的网络日志中，"
            "识别隐蔽的内部威胁行为模式。\n\n"
            "## 重点检测的时序模式\n"
            "1. **周期性低频传输**：每天/每周固定时间的小量数据传输(<5MB)，"
            "间隔稳定（如每日02:00±5min），持续数周\n"
            "2. **渐进式递增**：每日数据传输量呈稳步上升趋势（如5MB→8MB→12MB→20MB），"
            "表明攻击者逐渐试探监控阈值\n"
            "3. **信标/心跳**：严格定间隔的极小包(<1KB)，如每15min、每1h、每24h，"
            "持续维持与C2的通信\n"
            "4. **静默-活跃交替**：活动几天后突然静默数日再恢复，"
            "可能是在规避检测或等待新指令\n"
            "5. **目标切换模式**：目标IP/端口周期性地轮换，每次传输数据量相似，"
            "使用分段外传策略\n"
            "6. **衰减模式**：活动频率逐渐降低但每次传输数据量增加，"
            "可能是已获取所需资料后的收尾阶段\n"
            "7. **突发后静默**：一次性大量数据传输后长期无活动，"
            "可能是已完成窃取后撤离\n\n"
            "## 判定标准\n"
            "- 若存在>=2周的稳定周期性模式 → 高风险\n"
            "- 若存在明显递增/递减趋势 + 高熵加密 → 高风险\n"
            "- 若存在严格信标间隔(偏差<5%) → 中高风险(疑似C2)\n"
            "- 若仅有轻微不规则波动 → 安全\n\n"
            "回复格式：{ \"temporal_anomaly_detected\": true|false, "
            "\"pattern_type\": \"周期性低频\"|\"渐进递增\"|\"信标心跳\"|\"静默交替\"|"
            "\"目标轮换\"|\"衰减收尾\"|\"突发后静默\"|\"无异常\", "
            "\"confidence\": 0.0-1.0, "
            "\"reasoning\": \"时序分析逻辑（请引用具体的时间窗口和数据点）\", "
            "\"period_estimated_minutes\": 0, "
            "\"trend_description\": \"趋势描述\" }"
        )
        super().__init__(
            name=name,
            system_prompt=system_prompt or default_prompt,
            model_name=model_name,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        self.default_window_days = default_window_days
        self.slice_size_hours = slice_size_hours

    def slice_time_series(
        self,
        flows: list[FlowEvent],
        window_days: Optional[int] = None,
    ) -> list[TimeSeriesSlice]:
        """
        将流量记录按时序切片，生成统计摘要。
        """
        if not flows:
            return []

        window_days = window_days or self.default_window_days
        slice_hours = self.slice_size_hours

        # 按时间排序
        sorted_flows = sorted(flows, key=lambda f: f.timestamp)
        now = sorted_flows[-1].timestamp
        cutoff = now - timedelta(days=window_days)

        # 过滤到时间窗口内
        window_flows = [f for f in sorted_flows if f.timestamp >= cutoff]
        if not window_flows:
            return []

        # 创建时间槽
        start_time = window_flows[0].timestamp.replace(minute=0, second=0, microsecond=0)
        end_time = window_flows[-1].timestamp

        slices: list[TimeSeriesSlice] = []
        current_start = start_time
        while current_start <= end_time:
            current_end = current_start + timedelta(hours=slice_hours)
            slot_flows = [
                f for f in window_flows
                if current_start <= f.timestamp < current_end
            ]
            dst_ips = set(f.dst_ip for f in slot_flows if f.dst_ip)
            dst_ports = set(f.dst_port for f in slot_flows if f.dst_port)

            slices.append(TimeSeriesSlice(
                start_time=current_start,
                end_time=current_end,
                flow_count=len(slot_flows),
                total_bytes=sum(f.byte_count for f in slot_flows),
                avg_entropy=sum(f.entropy_score for f in slot_flows) / max(len(slot_flows), 1),
                unique_dst_ips=len(dst_ips),
                unique_dst_ports=len(dst_ports),
            ))
            current_start = current_end

        return slices

    def detect_periodicity(self, slices: list[TimeSeriesSlice]) -> tuple[bool, float, str]:
        """
        检测周期性模式。
        分析活跃时段之间的间隔是否稳定。
        """
        active_slices = [s for s in slices if s.flow_count > 0 and s.total_bytes > 1000]
        if len(active_slices) < 4:  # 需要至少4个活跃点才能判断周期性
            return False, 0.0, "活跃数据点不足"

        # 计算活跃时段之间的间隔
        intervals: list[float] = []
        for i in range(1, len(active_slices)):
            delta = (active_slices[i].start_time - active_slices[i-1].start_time).total_seconds() / 3600.0
            intervals.append(delta)

        if not intervals:
            return False, 0.0, "无有效间隔"

        avg_interval = mean(intervals)
        if len(intervals) >= 2:
            std_interval = stdev(intervals) if len(intervals) >= 2 else 0
        else:
            std_interval = 0

        # 变异系数（CV）= 标准差/均值，越小越稳定
        cv = std_interval / avg_interval if avg_interval > 0 else float('inf')

        # 如果变异系数 < 0.2（即间隔非常稳定），且平均间隔在合理范围内
        if cv < 0.2 and 1.0 <= avg_interval <= 48.0:
            confidence = max(0.5, 1.0 - cv * 5)  # cv=0 -> 1.0, cv=0.2 -> 0.0
            desc = f"检测到稳定周期: ~{avg_interval:.1f}h (CV={cv:.3f})"
            return True, confidence, desc
        elif cv < 0.5 and 1.0 <= avg_interval <= 48.0:
            desc = f"弱周期信号: ~{avg_interval:.1f}h (CV={cv:.3f})"
            return True, 0.3, desc

        return False, 0.0, f"无显著周期性 (CV={cv:.3f})"

    def detect_trend(self, slices: list[TimeSeriesSlice]) -> tuple[str, float, str]:
        """
        检测数据量递增/递减趋势。
        """
        active_slices = [s for s in slices if s.total_bytes > 0]
        if len(active_slices) < 6:
            return "stable", 0.0, "数据点不足，无法判断趋势"

        # 简单线性回归：bytes vs index
        n = len(active_slices)
        indices = list(range(n))
        bytes_values = [s.total_bytes for s in active_slices]

        mean_x = mean(indices)
        mean_y = mean(bytes_values)
        numerator = sum((x - mean_x) * (y - mean_y) for x, y in zip(indices, bytes_values))
        denominator = sum((x - mean_x) ** 2 for x in indices)

        if denominator == 0:
            return "stable", 0.0, "无变化趋势"

        slope = numerator / denominator

        # 用 R^2 评估趋势强度
        y_mean = mean(bytes_values)
        ss_res = sum((y - (slope * x + (mean_y - slope * mean_x))) ** 2 for x, y in zip(indices, bytes_values))
        ss_tot = sum((y - y_mean) ** 2 for y in bytes_values)
        r_squared = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0

        threshold = mean_y * 0.1  # 10% 的均值变化才算显著
        if abs(slope * n) > threshold and r_squared > 0.5:
            direction = "递增" if slope > 0 else "递减"
            return direction, min(r_squared, 0.9), f"检测到数据量{direction}趋势 (R^2={r_squared:.3f})"

        return "stable", 0.0, f"数据量无明显趋势 (R^2={r_squared:.3f})"

    def build_analysis_prompt(
        self,
        entity_id: str,
        slices: list[TimeSeriesSlice],
        raw_flows_count: int,
    ) -> str:
        """构建 LLM 提示"""
        if not slices:
            return f"实体 {entity_id}: 无可分析的时间序列数据"

        active_count = sum(1 for s in slices if s.total_bytes > 0)
        total_bytes = sum(s.total_bytes for s in slices)
        avg_flow_per_slice = sum(s.flow_count for s in slices) / max(len(slices), 1)

        lines = [
            f"实体: {entity_id}",
            f"时间窗口: {slices[0].start_time.isoformat()} ~ {slices[-1].end_time.isoformat()}",
            f"时间切片数: {len(slices)} (每片{self.slice_size_hours}h)",
            f"活跃切片数: {active_count}/{len(slices)}",
            f"总流量数: {raw_flows_count}",
            f"累计数据量: {total_bytes} bytes ({total_bytes / 1_000_000:.1f} MB)",
            f"平均每片流量: {avg_flow_per_slice:.1f}",
            "---",
            "时序摘要（前 20 个切片）：",
        ]

        for i, s in enumerate(slices[:20]):
            lines.append(
                f"  [{i}] {s.start_time.strftime('%m-%d %H:%M')}: "
                f"{s.flow_count} flows, {s.total_bytes} bytes, "
                f"entropy={s.avg_entropy:.2f}, "
                f"dst_ips={s.unique_dst_ips}"
            )

        if len(slices) > 20:
            lines.append(f"  ... (省略 {len(slices) - 20} 个切片)")

        # 预分析
        has_periodicity, period_conf, period_desc = self.detect_periodicity(slices)
        trend_dir, trend_conf, trend_desc = self.detect_trend(slices)

        lines.extend([
            "---",
            f"周期检测: {period_desc} (置信度: {period_conf:.2f})",
            f"趋势检测: {trend_desc} (置信度: {trend_conf:.2f})",
            "---",
            "请结合以上数据评判该实体是否存在隐蔽的时序异常行为。",
        ])

        return "\n".join(lines)

    async def analyze(
        self,
        entity_id: str,
        historical_flows: list[FlowEvent],
        window_days: Optional[int] = None,
    ) -> ThreatVerdict:
        """
        对实体进行时序异常分析。
        """
        slices = self.slice_time_series(historical_flows, window_days)
        if not slices:
            return ThreatVerdict(
                verdict=TrafficVerdict.SAFE,
                severity=SeverityLevel.LOW,
                confidence=0.9,
                reasoning="无可用时序数据",
                recommended_action="allow",
            )

        prompt = self.build_analysis_prompt(entity_id, slices, len(historical_flows))

        try:
            response = await self.call_llm(prompt)
            parsed = self.extract_json_from_response(response)

            anomaly_detected = parsed.get("temporal_anomaly_detected", False)
            confidence = float(parsed.get("confidence", 0.0))
            pattern_type = parsed.get("pattern_type", "无异常")
            reasoning = parsed.get("reasoning", response[:500])
            period_minutes = int(parsed.get("period_estimated_minutes", 0))

            if anomaly_detected and confidence >= 0.55:
                return ThreatVerdict(
                    flow_ids=[],
                    verdict=TrafficVerdict.SUSPICIOUS,
                    severity=SeverityLevel.MEDIUM,
                    confidence=confidence,
                    threat_type=f"时序异常: {pattern_type}",
                    reasoning=reasoning,
                    recommended_action="monitor",
                    extra={
                        "llm_raw": response,
                        "pattern_type": pattern_type,
                        "period_minutes": period_minutes,
                        "slices_analyzed": len(slices),
                        "window_days": window_days or self.default_window_days,
                    },
                )

            return ThreatVerdict(
                flow_ids=[],
                verdict=TrafficVerdict.SAFE,
                severity=SeverityLevel.LOW,
                confidence=0.85,
                reasoning="未检测到时序异常",
                recommended_action="allow",
            )

        except Exception as e:
            logger.error("[%s] LLM 时序分析失败: %s", self.name, e)
            return ThreatVerdict(
                flow_ids=[],
                verdict=TrafficVerdict.UNKNOWN,
                severity=SeverityLevel.LOW,
                confidence=0.0,
                reasoning=f"时序分析失败: {e}",
                recommended_action="monitor",
            )

    async def process(self, historical_flows: list[FlowEvent]) -> ThreatVerdict:
        """通用处理入口"""
        if historical_flows:
            entity_id = (
                historical_flows[0].user_id
                or historical_flows[0].src_ip
                or "unknown"
            )
        else:
            entity_id = "unknown"
        return await self.analyze(entity_id, historical_flows)


__all__ = ["TemporalAnomalyAgent", "TimeSeriesSlice"]