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
- 提供 from_config() 工厂方法和 run_background_loop() 后台循环
"""

import asyncio
import logging
import threading
from datetime import datetime, timezone, timedelta
from typing import Optional

from ..agents.baseline_profiling_agent import BaselineProfilingAgent, BehaviorBaseline
from ..agents.temporal_anomaly_agent import TemporalAnomalyAgent
from ..agents.correlation_agent import CorrelationAgent
from ..agents.judgment_agent import JudgmentAgent
from ..core.message import (
    FlowEvent, ThreatVerdict, TrafficVerdict, SeverityLevel,
)
from . import row_to_flow_event  # 共享的 DB row → FlowEvent 转换

# 严重度排序映射（数值越大越严重，用于可靠比较）
_SEVERITY_RANK = {
    SeverityLevel.INFO: 0,
    SeverityLevel.LOW: 1,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.HIGH: 3,
    SeverityLevel.CRITICAL: 4,
}

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
        """获取最近的分析告警（严重度 >= severity_min）"""
        min_rank = _SEVERITY_RANK.get(severity_min, 2)  # 默认 MEDIUM
        return [
            a for a in self._recent_alerts
            if _SEVERITY_RANK.get(a.severity, 0) >= min_rank
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

    # ================================================================
    # 工厂方法
    # ================================================================

    @classmethod
    def from_config(cls, config):
        """
        从 OrchestratorConfig 构建 DeepAnalysisOrchestrator 及其内部智能体。

        封装了 agent 创建、backend 注入等组装逻辑，使 main.py 只需一行调用。
        """
        from ..backends import LMStudioBackend, OpenAIBackend, DeepSeekBackend
        from ..config import BackendType

        deep_cfg = config.deep_analysis

        # -- 构建智能体 --
        bcfg = deep_cfg.baseline_profiling
        baseline_agent = BaselineProfilingAgent(
            name="BaselineProfilingAgent",
            system_prompt=bcfg.system_prompt,
            model_name=bcfg.model_name,
            temperature=bcfg.temperature,
            max_tokens=bcfg.max_tokens,
        )

        tcfg = deep_cfg.temporal_anomaly
        temporal_agent = TemporalAnomalyAgent(
            name="TemporalAnomalyAgent",
            system_prompt=tcfg.system_prompt,
            model_name=tcfg.model_name,
            temperature=tcfg.temperature,
            max_tokens=tcfg.max_tokens,
        )

        jcfg = config.judgment
        judgment_agent = JudgmentAgent(
            name="SlowJudgmentAgent",
            system_prompt=jcfg.system_prompt,
            model_name=jcfg.model_name,
            temperature=jcfg.temperature,
            max_tokens=jcfg.max_tokens,
        )

        # -- 后端类型 → 类映射 --
        _BACKEND_CLASS_MAP = {
            BackendType.DEEPSEEK: DeepSeekBackend,
            BackendType.OPENAI: OpenAIBackend,
            BackendType.LMSTUDIO: LMStudioBackend,
        }

        def _build_backend(backend_type: BackendType):
            be_cfg = config.default_backends[backend_type]
            cls_be = _BACKEND_CLASS_MAP[backend_type]
            kwargs = dict(
                api_base=be_cfg.api_base,
                api_key=be_cfg.api_key,
                timeout=be_cfg.timeout,
                max_retries=be_cfg.max_retries,
                default_model=be_cfg.model_name,
            )
            if backend_type == BackendType.LMSTUDIO:
                kwargs["auto_load"] = be_cfg.auto_load
            if backend_type == BackendType.DEEPSEEK:
                if be_cfg.thinking_enabled is not None:
                    kwargs["default_thinking_enabled"] = be_cfg.thinking_enabled
                if be_cfg.reasoning_effort is not None:
                    kwargs["default_reasoning_effort"] = be_cfg.reasoning_effort
                kwargs["include_reasoning"] = be_cfg.include_reasoning
            return cls_be(**kwargs)

        # -- 注入后端 --
        bt = bcfg.backend
        if bt not in _BACKEND_CLASS_MAP:
            raise ValueError(f"不支持的后端类型: {bt}")
        slow_backend = _build_backend(bt)
        baseline_agent.set_backend(slow_backend)
        baseline_agent.model_name = bcfg.model_name
        logger.info("[DeepAnalysis] 基线画像后端: %s/%s", bt.value, bcfg.model_name)

        tt = tcfg.backend
        temporal_backend = slow_backend if tt == bt else _build_backend(tt)
        temporal_agent.set_backend(temporal_backend)
        temporal_agent.model_name = tcfg.model_name
        logger.info("[DeepAnalysis] 时序异常后端: %s/%s", tt.value, tcfg.model_name)

        jt = jcfg.backend
        judgment_backend = slow_backend if jt == bt else _build_backend(jt)
        judgment_agent.set_backend(judgment_backend)
        judgment_agent.model_name = jcfg.model_name
        logger.info("[DeepAnalysis] 研判后端: %s/%s", jt.value, jcfg.model_name)

        return cls(
            baseline_agent=baseline_agent,
            temporal_agent=temporal_agent,
            judgment_agent=judgment_agent,
            analysis_interval_hours=deep_cfg.analysis_interval_hours,
        )

    # ================================================================
    # 数据预处理
    # ================================================================

    @staticmethod
    def _group_flows_for_analysis(
        rows: list, recent_hours: int = 24,
    ) -> tuple:
        """
        按 src_ip 分组，拆分为历史流(>recent_hours)和近期流(≤recent_hours)。

        Returns:
            (entity_flows, entity_recent)
            entity_flows:  {src_ip: (entity_type, [FlowEvent, ...])}  ← 历史基线
            entity_recent: {src_ip: [FlowEvent, ...]}                  ← 近期待评估
        """
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=recent_hours)

        # 按 src_ip 分组
        grouped: dict[str, list] = {}
        for row in rows:
            src_ip = row.get("src_ip", "")
            if not src_ip:
                continue
            grouped.setdefault(src_ip, []).append(row)

        entity_flows: dict[str, tuple[str, list]] = {}
        entity_recent: dict[str, list] = {}

        for src_ip, ip_rows in grouped.items():
            hist_flows = []
            recent_flows = []
            entity_type = "user"

            for row in ip_rows:
                flow = row_to_flow_event(row)
                pkt_time = row.get("packet_time")

                is_recent = False
                if pkt_time is not None:
                    if isinstance(pkt_time, datetime):
                        is_recent = pkt_time >= cutoff
                    else:
                        try:
                            ts = datetime.strptime(
                                str(pkt_time), "%Y-%m-%d %H:%M:%S"
                            )
                            is_recent = ts >= cutoff
                        except (ValueError, TypeError):
                            pass

                if is_recent:
                    recent_flows.append(flow)
                else:
                    hist_flows.append(flow)

                dept = row.get("department", "")
                if dept:
                    entity_type = dept

            if hist_flows:
                entity_flows[src_ip] = (entity_type, hist_flows)
            if recent_flows:
                entity_recent[src_ip] = recent_flows

        return entity_flows, entity_recent

    # ================================================================
    # 告警推送
    # ================================================================

    @staticmethod
    def _push_alerts_to_frontend(alerts: list):
        """将深度分析告警推送到前端告警缓冲区"""
        if not alerts:
            return
        try:
            from backend.api_server import push_alert

            pushed = 0
            for alert in alerts:
                if _SEVERITY_RANK.get(alert.severity, 0) >= _SEVERITY_RANK[SeverityLevel.HIGH]:
                    src_ip = alert.extra.get("src_ip", "") if alert.extra else ""
                    push_alert(
                        ip=src_ip,
                        label=(
                            f"[慢脑] {alert.threat_type} "
                            f"(置信度:{alert.confidence:.0%})"
                        ),
                        details={
                            "verdict": alert.verdict.value,
                            "severity": alert.severity.value,
                            "confidence": alert.confidence,
                            "reasoning": alert.reasoning[:300],
                            "threat_type": alert.threat_type,
                            "flow_ids": alert.flow_ids[:5],
                        },
                    )
                    pushed += 1

            if pushed:
                logger.info(
                    "[DeepAnalysis] 已推送 %d 条高危告警到前端", pushed,
                )
        except Exception as e:
            logger.warning("[DeepAnalysis] 推送告警到前端失败: %s", e)

    # ================================================================
    # 后台循环
    # ================================================================

    @staticmethod
    async def _sleep_or_shutdown(
        shutdown_event: threading.Event, seconds: float,
    ) -> bool:
        """Async-safe sleep that returns True if shutdown was requested."""
        for _ in range(int(seconds)):
            if shutdown_event.is_set():
                return True
            await asyncio.sleep(1)
        return False

    async def run_background_loop(
        self, shutdown_event: threading.Event,
    ):
        """
        深度分析后台循环：每 analysis_interval_hours 小时执行一次。

        工作流程：
          1. 从 traffic_log 拉取长周期历史数据
          2. 按 src_ip 分组，切分为历史基线流 + 近期流
          3. 选择最活跃的 N 个实体送入 batch_analyze()
          4. 基线画像 → 时序异常检测 → 综合研判
          5. 高危告警推送到前端，等待管理员审批
        """
        interval_seconds = self.analysis_interval_hours * 3600
        logger.info(
            "[DeepAnalysis] 后台循环已启动 (间隔 %ds)", interval_seconds,
        )

        # 首次延迟 60s，给系统留出预热时间
        await asyncio.sleep(60)

        while not shutdown_event.is_set():
            try:
                logger.info("[DeepAnalysis] 开始执行长周期深度分析...")

                # ---- 读取回溯配置 ----
                try:
                    from config.loader import load_config
                    cfg = load_config()
                    retro_cfg = cfg.retrospective_scan
                    lookback_days = retro_cfg.lookback_days
                    entities_per_cycle = retro_cfg.entities_per_cycle
                except Exception:
                    lookback_days = 30
                    entities_per_cycle = 10

                # ---- 从数据库拉取历史流量 ----
                from database import get_traffic_for_deep_analysis

                rows = await asyncio.to_thread(
                    get_traffic_for_deep_analysis, lookback_days,
                )
                if not rows:
                    logger.info("[DeepAnalysis] 无历史流量数据，跳过本轮")
                    if await self._sleep_or_shutdown(
                        shutdown_event, interval_seconds,
                    ):
                        break
                    continue

                logger.info(
                    "[DeepAnalysis] 拉取 %d 条历史流量记录 (回溯 %d 天)",
                    len(rows), lookback_days,
                )

                # ---- 按实体分组，切分历史/近期 ----
                entity_flows, entity_recent = await asyncio.to_thread(
                    self._group_flows_for_analysis, rows,
                )
                if not entity_flows:
                    logger.info("[DeepAnalysis] 无可分析的实体分组，跳过本轮")
                    if await self._sleep_or_shutdown(
                        shutdown_event, interval_seconds,
                    ):
                        break
                    continue

                # ---- 按活跃度排序，选取 Top-N 实体 ----
                ranked = sorted(
                    entity_flows.items(),
                    key=lambda kv: sum(
                        f.byte_count for f in kv[1][1]
                    ),
                    reverse=True,
                )
                selected = dict(ranked[:entities_per_cycle])
                selected_recent = {
                    k: v for k, v in entity_recent.items() if k in selected
                }

                logger.info(
                    "[DeepAnalysis] 选中 %d/%d 个实体进行深度分析",
                    len(selected), len(entity_flows),
                )

                # ---- 执行批量深度分析 ----
                alerts = await self.batch_analyze(
                    entity_flows=selected,
                    recent_flows=selected_recent,
                )
                logger.info(
                    "[DeepAnalysis] 完成，生成 %d 条告警 "
                    "(高危=%d, 严重=%d)",
                    len(alerts),
                    sum(1 for a in alerts
                        if a.severity == SeverityLevel.HIGH),
                    sum(1 for a in alerts
                        if a.severity == SeverityLevel.CRITICAL),
                )

                # ---- 推送高危告警到前端 ----
                if alerts:
                    await asyncio.to_thread(
                        self._push_alerts_to_frontend, alerts,
                    )

                # ---- 打印统计 ----
                stats = self.get_statistics()
                logger.info("[DeepAnalysis] 当前统计: %s", stats)

            except Exception as e:
                logger.error(
                    "[DeepAnalysis] 后台循环异常: %s", e, exc_info=True,
                )

            if await self._sleep_or_shutdown(
                shutdown_event, interval_seconds,
            ):
                break


__all__ = ["DeepAnalysisOrchestrator"]