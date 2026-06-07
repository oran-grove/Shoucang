"""
深度分析编排器
==================
协调深度分析子模块的三个核心智能体：
1. BaselineProfilingAgent — 行为基线画像
2. TemporalAnomalyAgent — 时序异常检测
3. 关联智能体+研判智能体 — 深度分析

负责：
- 定期批量分析历史日志
- 生成长周期威胁报告
- 反馈给检测管线（策略/基线更新）
- 推送告警到WebUI
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from ..agents.baseline_profiling_agent import BaselineProfilingAgent, BehaviorBaseline
from ..agents.temporal_anomaly_agent import TemporalAnomalyAgent
from ..agents.correlation_agent import CorrelationAgent
from ..agents.judgment_agent import JudgmentAgent
from ..core.message import (
    FlowEvent, ThreatVerdict, TrafficVerdict, SeverityLevel,
)

logger = logging.getLogger(__name__)


class DeepAnalysisOrchestrator:
    """
    深度分析编排器 — 负责长周期异步深度分析。

    工作流程：
    1. 从历史日志数据库拉取用户/部门的长期流量记录
    2. BaselineProfilingAgent 更新行为基线
    3. TemporalAnomalyAgent 扫描时序异常
    4. 基线偏离+时序异常的结果交汇给研判智能体综合判定
    5. 生成告警和策略更新建议
    """

    def __init__(
        self,
        baseline_agent: BaselineProfilingAgent,
        temporal_agent: TemporalAnomalyAgent,
        judgment_agent: JudgmentAgent,
        analysis_interval_hours: int = 24,
    ):
        self.baseline_agent = baseline_agent
        self.temporal_agent = temporal_agent
        self.judgment_agent = judgment_agent
        self.analysis_interval_hours = analysis_interval_hours

        self._last_analysis_time: Optional[datetime] = None
        self._analysis_task: Optional[asyncio.Task] = None

        # 最近的分析结果缓存
        self._recent_alerts: list[ThreatVerdict] = []

    async def analyze_entity(
        self,
        entity_id: str,
        entity_type: str,
        historical_flows: list[FlowEvent],
        recent_flows: list[FlowEvent],
    ) -> list[ThreatVerdict]:
        """
        对单个实体执行完整的慢脑分析流程。

        返回：生成的威胁判定列表（用于告警和策略更新）
        """
        alerts: list[ThreatVerdict] = []

        # Step 1: 更新行为基线
        baseline = self.baseline_agent.build_or_update_baseline(
            entity_id=entity_id,
            entity_type=entity_type,
            historical_flows=historical_flows,
        )

        # Step 2: 时序异常检测（30d窗口）
        temporal_result = await self.temporal_agent.analyze(
            entity_id=entity_id,
            historical_flows=historical_flows,
            window_days=30,
        )

        if temporal_result.verdict in (TrafficVerdict.SUSPICIOUS, TrafficVerdict.MALICIOUS):
            alerts.append(temporal_result)

        # Step 3: 基线偏离评估（最近24h的流量）
        baseline_deviation_alerts = []
        for flow in recent_flows:
            dev_result = self.baseline_agent.evaluate_flow(flow, baseline)
            if dev_result.verdict == TrafficVerdict.SUSPICIOUS:
                baseline_deviation_alerts.append(dev_result)

        # Step 4: 基线变化分析（如果有显著偏离）
        if baseline_deviation_alerts:
            shift_result = await self.baseline_agent.analyze_baseline_shift(
                entity_id, recent_flows
            )
            if shift_result.verdict != TrafficVerdict.SAFE:
                alerts.append(shift_result)

        # Step 5: 综合研判（时序异常 + 基线偏离 + 行为特征）
        if alerts:
            combined_prompt_lines = [
                f"实体: {entity_id} ({entity_type})",
                f"最近分析时间: {datetime.now(timezone.utc).isoformat()}",
                "=== 时序异常检测结果 ===",
            ]
            for a in alerts:
                combined_prompt_lines.append(
                    f"- [{a.threat_type}] conf={a.confidence:.2f}: {a.reasoning}"
                )

            combined_prompt_lines.extend([
                "=== 基线偏离评估 ===",
                f"基线样本数: {baseline.sample_count}",
                f"最近24h偏离事件数: {len(baseline_deviation_alerts)}",
            ])

            for a in baseline_deviation_alerts[:5]:
                combined_prompt_lines.append(f"- {a.reasoning}")

            # 使用研判智能体做综合判定
            try:
                detection = ThreatVerdict(
                    verdict=TrafficVerdict.SUSPICIOUS,
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.6,
                    threat_type="深度综合分析",
                    reasoning="\n".join(combined_prompt_lines),
                    recommended_action="monitor",
                )
                final_judgment = await self.judgment_agent.process(
                    detection_result=detection,
                    correlation_result=None,
                )
                if final_judgment.verdict != TrafficVerdict.SAFE:
                    alerts.append(final_judgment)
            except Exception as e:
                logger.error("[DeepAnalysis] 研判失败: %s", e)

        return alerts

    async def batch_analyze(
        self,
        entity_flows: dict[str, tuple[str, list[FlowEvent]]],
        recent_flows: dict[str, list[FlowEvent]],
    ) -> list[ThreatVerdict]:
        """
        批量分析多个实体。
        entity_flows: entity_id -> (entity_type, historical_flows)
        recent_flows: entity_id -> recent_flows
        """
        all_alerts: list[ThreatVerdict] = []
        tasks = []

        for entity_id, (entity_type, hist_flows) in entity_flows.items():
            rec_flows = recent_flows.get(entity_id, [])
            tasks.append(
                self.analyze_entity(entity_id, entity_type, hist_flows, rec_flows)
            )

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error("[DeepAnalysis] 分析实体失败: %s", result)
            elif isinstance(result, list):
                all_alerts.extend(result)

        # 缓存最新的告警
        self._recent_alerts = all_alerts
        self._last_analysis_time = datetime.now(timezone.utc)

        return all_alerts

    def get_recent_alerts(self, severity_min: SeverityLevel = SeverityLevel.MEDIUM) -> list[ThreatVerdict]:
        """获取最近的告警"""
        return [
            a for a in self._recent_alerts
            if a.severity.value >= severity_min.value
            # SeverityLevel order: INFO < LOW < MEDIUM < HIGH < CRITICAL
        ]

    def get_statistics(self) -> dict:
        """返回分析统计"""
        return {
            "last_analysis_time": self._last_analysis_time.isoformat() if self._last_analysis_time else None,
            "total_recent_alerts": len(self._recent_alerts),
            "high_severity_alerts": len([a for a in self._recent_alerts
                                        if a.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)]),
            "baselines_tracked": len(self.baseline_agent._baselines),
        }


__all__ = ["DeepAnalysisOrchestrator"]