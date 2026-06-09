"""
多智能体编排器 — 三层架构
==========================
Orchestrator 是整个系统的入口。
- 根据配置创建 LLM 后端实例
- 初始化三层智能体并注入后端
- 管理完整的分析管线（筛查 → 回溯 ⇄ 研判循环）

三层管线:
  Layer 1 — ScreeningAgent: 初步筛查，dangerous→前端, safe→丢弃, suspicious→L2
  Layer 2 — BacktrackAgent: 历史回溯，查询DB相似记录，LLM过滤关联度
  Layer 3 — AdjudicationAgent: 最终研判，safe→丢弃, dangerous→前端, suspicious→L2扩展窗口
"""

import logging
from typing import Callable, Optional, cast
from uuid import uuid4

from .config import (
    BackendType,
    OrchestratorConfig,
)
from .backends.base import LoadModelConfig
from .core.message import (
    FlowEvent, ThreatVerdict, TrafficVerdict,
)
from .backends import OpenAIBackend, LMStudioBackend, DeepSeekBackend, BaseLLMBackend
from .agents.screening_agent import ScreeningAgent
from .agents.backtrack_agent import BacktrackAgent
from .agents.adjudication_agent import AdjudicationAgent
from .agents.feedback_agent import FeedbackAgent, AdminFeedback

logger = logging.getLogger(__name__)


def _fmt_window(hours: float) -> str:
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


class Orchestrator:
    """
    多智能体编排器。

    使用方式：
        orchestrator = Orchestrator(config)
        await orchestrator.start()

        # 分析单条流量
        verdict = await orchestrator.analyze_flow(flow_event)

        # 管理员反馈
        fb_result = await orchestrator.admin_feedback(feedback)

        await orchestrator.stop()
    """

    def __init__(
        self,
        config: Optional[OrchestratorConfig] = None,
        alert_callback: Optional[Callable[[ThreatVerdict, FlowEvent], None]] = None,
        db_query_callback: Optional[Callable[[str, int, int, int], list[dict]]] = None,
    ):
        self.config = config or OrchestratorConfig()
        self._backends: dict[BackendType, BaseLLMBackend] = {}
        self._agents: dict[str, object] = {}
        self._running = False
        self.alert_callback: Optional[Callable[[ThreatVerdict, FlowEvent], None]] = alert_callback
        # DB查询回调：供 Layer 2 查询历史相似记录
        # 签名: (src_ip: str, lookback_hours: int, max_records: int, min_similarity: float) -> list[dict]
        self._db_query_callback: Optional[Callable[..., list[dict]]] = db_query_callback

    # ========== 初始化 ==========

    def _init_backends(self) -> None:
        """根据配置创建 LLM 后端实例"""
        for backend_type, backend_cfg in self.config.default_backends.items():
            if backend_type in (BackendType.OPENAI, BackendType.DEEPSEEK):
                if not backend_cfg.api_key or not backend_cfg.api_key.strip():
                    logger.warning(
                        "后端 [%s] 缺少 API Key，跳过初始化。"
                        "请在 config_user.json 的 backends.%s.api_key 中填入有效密钥。",
                        backend_type.value, backend_type.value,
                    )
                    continue

            if backend_type == BackendType.OPENAI:
                backend = OpenAIBackend(
                    api_base=backend_cfg.api_base,
                    api_key=backend_cfg.api_key,
                    timeout=backend_cfg.timeout,
                    max_retries=backend_cfg.max_retries,
                    default_model=backend_cfg.model_name,
                )
            elif backend_type == BackendType.LMSTUDIO:
                lc = backend_cfg.load_config
                default_load_config = LoadModelConfig(
                    model=backend_cfg.model_name,
                    context_length=lc.get("context_length"),
                    eval_batch_size=lc.get("eval_batch_size"),
                    flash_attention=lc.get("flash_attention"),
                    num_experts=lc.get("num_experts"),
                    offload_kv_cache_to_gpu=lc.get("offload_kv_cache_to_gpu"),
                    echo_load_config=lc.get("echo_load_config", False),
                )
                backend = LMStudioBackend(
                    api_base=backend_cfg.api_base,
                    api_key=backend_cfg.api_key,
                    timeout=backend_cfg.timeout,
                    max_retries=backend_cfg.max_retries,
                    default_model=backend_cfg.model_name,
                    auto_load=backend_cfg.auto_load,
                    default_load_config=default_load_config,
                )
            elif backend_type == BackendType.DEEPSEEK:
                backend = DeepSeekBackend(
                    api_base=backend_cfg.api_base,
                    api_key=backend_cfg.api_key,
                    timeout=backend_cfg.timeout,
                    max_retries=backend_cfg.max_retries,
                    default_model=backend_cfg.model_name,
                    default_thinking_enabled=backend_cfg.thinking_enabled,
                    default_reasoning_effort=backend_cfg.reasoning_effort,
                    include_reasoning=backend_cfg.include_reasoning,
                )
            else:
                raise ValueError(f"不支持的后端类型: {backend_type}")
            self._backends[backend_type] = backend
            logger.info("后端注册: %s -> %s", backend_type.value, backend_cfg.model_name)

    def _init_agents(self) -> None:
        """创建三层智能体并注入依赖"""

        # --- Layer 1: 筛查智能体 ---
        scr_cfg = self.config.screening
        screening_agent = ScreeningAgent(
            name="ScreeningAgent",
            system_prompt=scr_cfg.system_prompt,
            model_name=scr_cfg.model_name,
            temperature=scr_cfg.temperature,
            max_tokens=scr_cfg.max_tokens,
            confidence_threshold_dangerous=scr_cfg.confidence_threshold_dangerous,
            confidence_threshold_suspicious=scr_cfg.confidence_threshold_suspicious,
        )
        self._inject_agent_deps(screening_agent, scr_cfg.backend)
        self._agents["screening"] = screening_agent

        # --- Layer 2: 回溯智能体 ---
        bk_cfg = self.config.backtrack
        bk_ctx = self._get_backend_context_tokens(bk_cfg.backend)
        backtrack_agent = BacktrackAgent(
            name="BacktrackAgent",
            system_prompt=bk_cfg.system_prompt,
            model_name=bk_cfg.model_name,
            temperature=bk_cfg.temperature,
            max_tokens=bk_cfg.max_tokens,
            relevance_threshold=bk_cfg.relevance_threshold,
            max_context_tokens=bk_ctx,
            batch_context_ratio=bk_cfg.batch_context_ratio,
        )
        self._inject_agent_deps(backtrack_agent, bk_cfg.backend)
        self._agents["backtrack"] = backtrack_agent

        # --- Layer 3: 研判智能体 ---
        adj_cfg = self.config.adjudication
        adj_ctx = self._get_backend_context_tokens(adj_cfg.backend)
        adjudication_agent = AdjudicationAgent(
            name="AdjudicationAgent",
            system_prompt=adj_cfg.system_prompt,
            model_name=adj_cfg.model_name,
            temperature=adj_cfg.temperature,
            max_tokens=adj_cfg.max_tokens,
            max_context_tokens=adj_ctx,
            batch_context_ratio=bk_cfg.batch_context_ratio,
        )
        self._inject_agent_deps(adjudication_agent, adj_cfg.backend)
        self._agents["adjudication"] = adjudication_agent

        # --- 反馈智能体 ---
        fb_cfg = self.config.feedback
        feedback_agent = FeedbackAgent(
            name="FeedbackAgent",
            system_prompt=fb_cfg.system_prompt,
            model_name=fb_cfg.model_name,
            temperature=fb_cfg.temperature,
            max_tokens=fb_cfg.max_tokens,
        )
        self._inject_agent_deps(feedback_agent, fb_cfg.backend)
        self._agents["feedback"] = feedback_agent

    def _get_backend_context_tokens(self, backend_type: BackendType) -> int:
        """获取指定后端的 max_context_tokens，降级到默认值。"""
        backend = self._backends.get(backend_type)
        if backend and hasattr(backend, 'default_model'):
            # 从 LLMBackendConfig 读取（_inject_agent_deps 会同步模型名）
            pass
        # 直接从 config 读取（初始化阶段 backend 可能尚未构建）
        be_cfg = self.config.default_backends.get(backend_type)
        if be_cfg:
            return be_cfg.max_context_tokens
        return 4096

    def _inject_agent_deps(self, agent, backend_type: BackendType) -> None:
        """向智能体注入 LLM 后端"""
        backend = self._backends.get(backend_type)
        if not backend:
            # 降级到任意可用后端
            if self._backends:
                backend = next(iter(self._backends.values()))
                logger.warning(
                    "智能体 [%s] 指定的后端 %s 不可用，降级使用 %s",
                    agent.name, backend_type.value,
                    next(iter(self._backends.keys())).value,
                )
            else:
                raise RuntimeError(f"智能体 [{agent.name}] 无可用后端")
        agent.set_backend(backend)
        # 同步模型名称：确保智能体发送给后端的模型名与实际后端匹配
        if hasattr(backend, 'default_model') and backend.default_model:
            agent.model_name = backend.default_model
        logger.debug(
            "智能体 [%s] -> 后端 %s, 模型: %s",
            agent.name, backend_type.value, agent.model_name,
        )

    # ========== 生命周期 ==========

    async def start(self) -> None:
        """启动编排器"""
        logger.info("Orchestrator 启动中...")
        self._init_backends()
        self._init_agents()
        self._running = True
        logger.info("Orchestrator 启动完成，智能体: %s", list(self._agents.keys()))

    async def stop(self) -> None:
        """停止编排器"""
        logger.info("Orchestrator 停止中...")
        self._running = False

        for backend in self._backends.values():
            if hasattr(backend, "close"):
                backend.close()
            if hasattr(backend, "aclose"):
                try:
                    await backend.aclose()
                except Exception:
                    pass
        logger.info("Orchestrator 已停止")

    # ========== 核心三层分析管线 ==========

    async def analyze_flow(self, flow: FlowEvent) -> ThreatVerdict:
        """
        三层分析管线:
          Layer 1: 初步筛查
            - dangerous → 告警回调 + 返回
            - safe → 直接返回（丢弃）
            - suspicious → 进入 Layer 2
          Layer 2: 历史回溯 (查询DB相似记录 + LLM过滤关联度)
          Layer 3: 最终研判
            - dangerous → 告警回调 + 返回
            - safe → 返回（丢弃）
            - suspicious → 若未超过最大回溯次数，扩展窗口回到 Layer 2
                          若已达上限，降级告警 + 返回

        Args:
            flow: 待分析的流量事件

        Returns:
            ThreatVerdict: 最终威胁判定
        """
        if not self._running:
            raise RuntimeError("Orchestrator 未启动")

        pipeline_id = f"pipe-{uuid4().hex[:8]}"
        logger.info(
            "[%s] 开始三层分析: %s:%d -> %s:%d",
            pipeline_id, flow.src_ip, flow.src_port,
            flow.dst_ip, flow.dst_port,
        )

        # ========== Layer 1: 初步筛查 ==========
        screening_agent = cast(ScreeningAgent, self._agents["screening"])
        screening_result = await screening_agent.process(flow)
        logger.info(
            "[%s] L1-筛查: %s (置信度: %.2f)",
            pipeline_id, screening_result.verdict.value,
            screening_result.confidence,
        )

        # 使用阈值校准
        calibrated = screening_agent.classify_threshold(screening_result)

        if calibrated == "safe":
            logger.info("[%s] L1 判定安全，丢弃", pipeline_id)
            return screening_result

        if calibrated == "dangerous":
            logger.info("[%s] L1 判定危险，直接上报", pipeline_id)
            self._alert_if_needed(screening_result, flow, pipeline_id)
            self._record_to_memory(screening_result, flow)
            return screening_result

        # calibrated == "suspicious" — 进入 Layer 2/3 循环
        logger.info("[%s] L1 判定可疑，进入 L2 历史回溯...", pipeline_id)

        # ========== Layer 2 ⇄ Layer 3 循环 ==========
        backtrack_cfg = self.config.backtrack
        lookback_windows = list(backtrack_cfg.lookback_windows)
        total_windows = len(lookback_windows)
        all_related_records: list[dict] = []
        seen_record_ids: set = set()  # 已见过的记录ID，用于判定本轮是否有新增数据
        final_adjudication: Optional[ThreatVerdict] = None

        for win_idx, lookback_hours in enumerate(lookback_windows):
            window_label = _fmt_window(lookback_hours)
            logger.info(
                "[%s] L2-回溯 第%d/%d轮 窗口=%s",
                pipeline_id, win_idx + 1, total_windows, window_label,
            )

            # ---- Layer 2: 历史回溯 ----
            similar_records = self._query_similar_flows(
                flow_src_ip=flow.src_ip,
                lookback_hours=lookback_hours,
                max_records=backtrack_cfg.max_similar_records,
            )

            new_matched: list[dict] = []
            if not similar_records:
                logger.info("[%s] L2 窗口=%s 内未找到相似记录", pipeline_id, window_label)
            else:
                backtrack_agent = cast(BacktrackAgent, self._agents["backtrack"])
                backtrack_result = await backtrack_agent.process(
                    flow, similar_records, lookback_window_hours=lookback_hours,
                )

                matched = backtrack_result.get("matched_records", [])
                new_matched = [m for m in matched if m.get("id") not in seen_record_ids]
                for m in matched:
                    record_id = m.get("id")
                    if record_id is not None:
                        seen_record_ids.add(record_id)
                all_related_records.extend(matched)

                logger.info(
                    "[%s] L2-回溯结果(窗口=%s): 总相似=%d → 高关联=%d (新增%d, 阈值=%.2f)",
                    pipeline_id, window_label, len(similar_records), len(matched),
                    len(new_matched), backtrack_cfg.relevance_threshold,
                )

            # 本轮无新增关联数据 → 跳过 L3，直接进入下一轮更长窗口回溯
            if win_idx > 0 and not new_matched:
                logger.info(
                    "[%s] 窗口=%s 无新增关联记录，跳过 L3 研判，扩展窗口继续",
                    pipeline_id, window_label,
                )
                if win_idx < total_windows - 1:
                    next_label = _fmt_window(lookback_windows[win_idx + 1])
                    logger.info(
                        "[%s] 回溯窗口 %s → %s (无新增数据)",
                        pipeline_id, window_label, next_label,
                    )
                else:
                    logger.info(
                        "[%s] 已遍历全部回溯窗口(最大=%s)且无新增，"
                        "降级上报告警将在管线结束后处理",
                        pipeline_id, _fmt_window(lookback_windows[-1]),
                    )
                continue

            # ---- Layer 3: 最终研判 ----
            adjudication_agent = cast(AdjudicationAgent, self._agents["adjudication"])
            final_adjudication = await adjudication_agent.process(
                flow=flow,
                related_context=all_related_records,
                lookback_window_hours=lookback_hours,
                screening_result=screening_result,
            )

            logger.info(
                "[%s] L3-研判 (窗口=%s): %s | 严重度: %s | 置信度: %.2f",
                pipeline_id, window_label,
                final_adjudication.verdict.value,
                final_adjudication.severity.value,
                final_adjudication.confidence,
            )

            # safe → 停止循环，丢弃
            if final_adjudication.verdict == TrafficVerdict.SAFE:
                logger.info("[%s] L3 在窗口=%s 判定安全，停止回溯", pipeline_id, window_label)
                break

            # dangerous → 停止循环，上报
            if final_adjudication.verdict == TrafficVerdict.MALICIOUS:
                logger.info("[%s] L3 在窗口=%s 判定危险，上报前端", pipeline_id, window_label)
                self._alert_if_needed(final_adjudication, flow, pipeline_id)
                break

            # suspicious → 扩展窗口继续回溯
            if win_idx < total_windows - 1:
                next_label = _fmt_window(lookback_windows[win_idx + 1])
                logger.info(
                    "[%s] L3 仍可疑，扩展回溯窗口 %s → %s 继续...",
                    pipeline_id, window_label, next_label,
                )
            else:
                logger.info(
                    "[%s] L3 已遍历全部回溯窗口(最大=%s)，降级上报告警",
                    pipeline_id, _fmt_window(lookback_windows[-1]),
                )

        # ---- 循环结束后的处理 ----
        if final_adjudication is None:
            final_adjudication = screening_result

        # 若最终仍是可疑且遍历完所有窗口，告警
        if (final_adjudication.verdict == TrafficVerdict.SUSPICIOUS
                and lookback_windows and lookback_hours == lookback_windows[-1]):
            self._alert_if_needed(final_adjudication, flow, pipeline_id)

        # 写入记忆系统
        if final_adjudication.verdict in (TrafficVerdict.MALICIOUS, TrafficVerdict.SUSPICIOUS):
            self._record_to_memory(final_adjudication, flow)

        return final_adjudication

    def analyze_flow_sync(self, flow: FlowEvent) -> ThreatVerdict:
        """同步版本的流量分析"""
        import asyncio
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.analyze_flow(flow))
        else:
            raise RuntimeError(
                "在已有事件循环中无法使用同步方法，请使用 await orchestrator.analyze_flow()"
            )

    # ========== 历史相似流量查询 ==========

    def _query_similar_flows(
        self,
        flow_src_ip: str,
        lookback_hours: int,
        max_records: int = 20,
    ) -> list[dict]:
        """
        从数据库查询与当前流量相似的历史记录。

        查询策略：
        - 同源IP的记录
        - 在 lookback_hours 时间窗口内
        - 按时间降序排列（最近的优先）

        Args:
            flow_src_ip: 源IP
            lookback_hours: 回溯时间窗口（小时）
            max_records: 最大返回记录数

        Returns:
            list[dict]: 相似历史记录列表
        """
        if self._db_query_callback:
            return self._db_query_callback(flow_src_ip, lookback_hours, max_records)

        # 委托 database 模块执行查询（统一数据库访问入口）
        try:
            from database import get_similar_flows_by_src_ip
            return get_similar_flows_by_src_ip(
                flow_src_ip, lookback_hours, max_records
            )
        except Exception:
            logger.exception("[Orchestrator] 查询历史相似流量失败")
            return []

    # ========== 管理员反馈 ==========

    async def admin_feedback(
        self,
        feedback_type: str,
        src_ip: str = "",
        dst_ip: str = "",
        verdict_id: str = "",
        admin_note: str = "",
    ) -> dict:
        """管理员标记反馈"""
        feedback = AdminFeedback(
            verdict_id=verdict_id,
            feedback_type=feedback_type,
            admin_note=admin_note,
            src_ip=src_ip,
            dst_ip=dst_ip,
        )
        feedback_agent = cast(FeedbackAgent, self._agents.get("feedback"))
        if not feedback_agent:
            return {"error": "反馈智能体不可用"}
        result = await feedback_agent.process(feedback=feedback)
        logger.info("管理员反馈处理结果: %s", result)
        return result

    def admin_feedback_sync(
        self,
        feedback_type: str,
        src_ip: str = "",
        dst_ip: str = "",
        verdict_id: str = "",
        admin_note: str = "",
    ) -> dict:
        import asyncio
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(
                self.admin_feedback(feedback_type, src_ip, dst_ip,
                                    verdict_id, admin_note)
            )
        else:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(
                    lambda: asyncio.run(
                        self.admin_feedback(feedback_type, src_ip, dst_ip,
                                           verdict_id, admin_note)
                    )
                ).result()

    def get_statistics(self) -> dict:
        """获取系统统计信息"""
        feedback_agent = cast(FeedbackAgent, self._agents.get("feedback"))
        return {
            "running": self._running,
            "agents": list(self._agents.keys()),
            "backends": {k.value: getattr(v, 'default_model', str(v))
                        for k, v in self._backends.items()},
            "feedback_stats": feedback_agent.get_statistics() if feedback_agent else {},
        }

    # ========== 内部辅助 ==========

    def _alert_if_needed(self, verdict: ThreatVerdict, flow: FlowEvent, pipeline_id: str) -> None:
        """推送高危/可疑告警到前端"""
        if self.alert_callback and verdict.verdict in (
            TrafficVerdict.MALICIOUS, TrafficVerdict.SUSPICIOUS,
        ):
            try:
                self.alert_callback(verdict, flow)
            except Exception:
                logger.exception("[%s] 告警回调异常", pipeline_id)

    def _record_to_memory(self, verdict: ThreatVerdict, flow: FlowEvent) -> None:
        """将判定结果写入记忆系统"""
        try:
            from .memory import get_store, get_index
            store = get_store()
            index = get_index()

            features = {
                "department": getattr(flow, "department", ""),
                "protocol": getattr(flow, "protocol", "TCP"),
                "direction": (
                    "internal" if getattr(flow, "dst_ip", "").startswith(("10.", "192.168.", "172."))
                    else "outbound"
                ),
                "encryption": getattr(flow, "entropy_score", 0) > 7.0,
            }
            matching = index.query(features, min_match=0.5)
            matched_ids = [c.card_id for c in matching]

            store.record_feedback(
                ai_verdict=verdict.verdict.value,
                ai_confidence=verdict.confidence,
                ai_reasoning=verdict.reasoning[:500],
                ai_threat_type=verdict.threat_type,
                admins_action="",
                ai_correct=False,
                admin_note="",
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                src_port=flow.src_port,
                dst_port=flow.dst_port,
                department=getattr(flow, "department", ""),
                protocol=flow.protocol,
                flow_features={
                    "entropy": getattr(flow, "entropy_score", 0),
                    "byte_count": getattr(flow, "byte_count", 0),
                    "pkt_count": getattr(flow, "pkt_count", 0),
                    "avg_pkt_size": getattr(flow, "avg_pkt_size", 0),
                    "src_port": flow.src_port,
                    "dst_port": flow.dst_port,
                },
                matched_pattern_ids=matched_ids,
            )
        except Exception:
            pass


__all__ = ["Orchestrator"]
