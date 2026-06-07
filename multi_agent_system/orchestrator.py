"""
多智能体编排器
=============
Orchestrator 是整个系统的入口。
- 根据配置创建 LLM 后端实例
- 初始化所有智能体并注入后端/总线/知识库
- 提供同步/异步的流量分析入口
- 管理完整的分析管线（检测 → 关联 → 研判 → 反馈）
"""

import logging
from typing import Callable, Optional, cast
from uuid import uuid4

from .config import (
    BackendType,
    OrchestratorConfig,
)
from .backends.base import LoadModelConfig, ModelInfo
from .core.message import (
    FlowEvent, ThreatVerdict, TrafficVerdict,
    AgentMessage, MessageType, RuleEntry, RuleAction,
)
from .core.knowledge import KnowledgeBase
from .backends import OpenAIBackend, LMStudioBackend, DeepSeekBackend, BaseLLMBackend
from .bus.message_bus import MessageBus
from .agents.detection_agent import DetectionAgent
from .agents.correlation_agent import CorrelationAgent
from .agents.judgment_agent import JudgmentAgent
from .agents.feedback_agent import FeedbackAgent, AdminFeedback

logger = logging.getLogger(__name__)


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

        # 获取同步到 P4 的规则列表
        rules = orchestrator.get_sync_rules()

        await orchestrator.stop()
    """

    def __init__(
        self,
        config: Optional[OrchestratorConfig] = None,
        alert_callback: Optional[Callable[[ThreatVerdict, FlowEvent], None]] = None,
    ):
        self.config = config or OrchestratorConfig()
        self._backends: dict[BackendType, BaseLLMBackend] = {}
        self._knowledge_base: Optional[KnowledgeBase] = None
        self._message_bus: Optional[MessageBus] = None
        self._agents: dict[str, object] = {}
        self._running = False
        self._correlation_id_counter = 0
        # 告警回调：当产生高危判定时调用，用于推送前端
        self.alert_callback: Optional[Callable[[ThreatVerdict, FlowEvent], None]] = alert_callback

    # ========== 初始化 ==========

    def _init_backends(self) -> None:
        """根据配置创建 LLM 后端实例"""
        for backend_type, backend_cfg in self.config.default_backends.items():
            # ── 云端后端需要 API Key，若为空则跳过 ──
            if backend_type in (BackendType.OPENAI, BackendType.DEEPSEEK):  # type: ignore[attr-defined]
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
            elif backend_type == BackendType.LMSTUDIO:  # type: ignore[attr-defined]  # cSpell:disable-line
                # 从 load_config 字典提取加载参数
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
            elif backend_type == BackendType.DEEPSEEK:  # type: ignore[attr-defined]
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

    def _init_knowledge_base(self) -> None:
        kb_cfg = self.config.knowledge_base
        self._knowledge_base = KnowledgeBase(
            max_rules=kb_cfg.max_rules,
            cleanup_interval_seconds=kb_cfg.cleanup_interval_seconds,
        )

    def _init_message_bus(self) -> None:
        self._message_bus = MessageBus(
            max_queue_size=self.config.max_queue_size,
        )

    def _init_agents(self) -> None:
        """创建智能体并注入依赖"""
        # --- 检测智能体 ---
        det_cfg = self.config.detection
        detection_agent = DetectionAgent(
            name="DetectionAgent",
            system_prompt=det_cfg.system_prompt,
            model_name=det_cfg.model_name,
            temperature=det_cfg.temperature,
            max_tokens=det_cfg.max_tokens,
            confidence_threshold_malicious=det_cfg.confidence_threshold_malicious,
            confidence_threshold_suspect=det_cfg.confidence_threshold_suspect,
        )
        self._inject_agent_deps(detection_agent, det_cfg.backend)
        self._agents["detection"] = detection_agent

        # --- 关联智能体 ---
        corr_cfg = self.config.correlation
        correlation_agent = CorrelationAgent(
            name="CorrelationAgent",
            system_prompt=corr_cfg.system_prompt,
            model_name=corr_cfg.model_name,
            temperature=corr_cfg.temperature,
            max_tokens=corr_cfg.max_tokens,
            correlation_window_minutes=corr_cfg.correlation_window_minutes,
            min_records_to_correlate=corr_cfg.min_records_to_correlate,
        )
        self._inject_agent_deps(correlation_agent, corr_cfg.backend)
        self._agents["correlation"] = correlation_agent

        # --- 研判智能体 ---
        judgment_cfg = self.config.judgment
        judgment_agent = JudgmentAgent(
            name="JudgmentAgent",
            system_prompt=judgment_cfg.system_prompt,
            model_name=judgment_cfg.model_name,
            temperature=judgment_cfg.temperature,
            max_tokens=judgment_cfg.max_tokens,
        )
        self._inject_agent_deps(judgment_agent, judgment_cfg.backend)
        self._agents["judgment"] = judgment_agent

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

        # 注册到消息总线
        assert self._message_bus is not None
        for name in self._agents:
            self._message_bus.register_agent(name)

    def _inject_agent_deps(self, agent, backend_type: BackendType) -> None:
        """向智能体注入后端、消息总线、知识库"""
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
        agent.set_message_bus(self._message_bus)
        agent.set_knowledge_base(self._knowledge_base)
        # 同步模型名称：确保智能体发送给后端的模型名与实际后端匹配
        # （例如切换到 DeepSeek 后端时，不再使用 LMStudio 的 "qwen3.5-9b"）
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
        self._init_knowledge_base()
        self._init_message_bus()
        self._init_agents()

        # 启动关联智能体后台任务
        corr_agent = cast(CorrelationAgent, self._agents.get("correlation"))
        if corr_agent and self.config.correlation.enabled:
            await corr_agent.start_background_cleanup()

        self._running = True
        logger.info("Orchestrator 启动完成，智能体: %s", list(self._agents.keys()))

    async def stop(self) -> None:
        """停止编排器"""
        logger.info("Orchestrator 停止中...")
        self._running = False

        corr_agent = cast(CorrelationAgent, self._agents.get("correlation"))
        if corr_agent:
            await corr_agent.stop_background_cleanup()

        # 关闭后端连接
        for backend in self._backends.values():
            if hasattr(backend, "close"):
                backend.close()  # type: ignore[attr-defined]
            if hasattr(backend, "aclose"):
                try:
                    await backend.aclose()  # type: ignore[attr-defined]
                except Exception:
                    pass
        logger.info("Orchestrator 已停止")

    # ========== 核心分析管线 ==========

    async def analyze_flow(self, flow: FlowEvent) -> ThreatVerdict:
        """
        分析单条流量，执行完整管线：
        检测 → 关联分析 → 综合研判 → 反馈记录。

        Args:
            flow: 从 P4 交换机获取的流量元数据

        Returns:
            ThreatVerdict: 综合威胁判定
        """
        if not self._running:
            raise RuntimeError("Orchestrator 未启动")

        correlation_id = f"pipe-{uuid4().hex[:8]}"
        logger.info(
            "开始分析管线 [%s]: %s:%d -> %s:%d",
            correlation_id, flow.src_ip, flow.src_port,
            flow.dst_ip, flow.dst_port,
        )

        # ---- 阶段1: 检测 ----
        detection_agent = cast(DetectionAgent, self._agents["detection"])
        detection_result = await detection_agent.process(flow)
        logger.info(
            "[%s] 检测结果: %s (置信度: %.2f)",
            correlation_id, detection_result.verdict.value,
            detection_result.confidence,
        )

        # 明确安全 → 快速返回
        if detection_result.verdict == TrafficVerdict.SAFE:
            self._publish_verdict(detection_result, correlation_id)
            return detection_result

        # ---- 阶段2: 关联分析 ----
        correlation_result: Optional[ThreatVerdict] = None
        corr_agent = cast(CorrelationAgent, self._agents["correlation"])
        if self.config.correlation.enabled and detection_result.verdict in (
            TrafficVerdict.SUSPICIOUS, TrafficVerdict.MALICIOUS
        ):
            triggered = corr_agent.add_flow(flow, detection_result)
            if triggered:
                group_key = flow.src_ip or flow.dst_ip
                correlation_result = await corr_agent.process_group(group_key)
                if correlation_result:
                    logger.info(
                        "[%s] 关联结果: %s (置信度: %.2f)",
                        correlation_id,
                        correlation_result.verdict.value,
                        correlation_result.confidence,
                    )

        # ---- 阶段3: 综合研判 ----
        judgment_agent = cast(JudgmentAgent, self._agents["judgment"])
        if self.config.judgment.enabled:
            final_verdict = await judgment_agent.process(
                detection_result=detection_result,
                correlation_result=correlation_result,
                _correlation_id=correlation_id,
            )
        else:
            final_verdict = detection_result

        logger.info(
            "[%s] 最终判定: %s | 严重度: %s | 置信度: %.2f | 动作: %s",
            correlation_id,
            final_verdict.verdict.value,
            final_verdict.severity.value,
            final_verdict.confidence,
            final_verdict.recommended_action,
        )

        # ---- 阶段4: 规则生成与写入 ----
        if final_verdict.verdict == TrafficVerdict.MALICIOUS and \
           final_verdict.confidence >= self.config.knowledge_base.confidence_threshold_block:
            rule = judgment_agent.create_rule_from_verdict(final_verdict, flow)
            if rule:
                assert self._knowledge_base is not None
                self._knowledge_base.add_rule(rule)
                logger.info(
                    "[%s] 自动生成黑名单规则: %s -> %s",
                    correlation_id, rule.src_ip, rule.dst_ip,
                )

        # ---- 阶段5: 反馈记录 ----
        feedback_agent = cast(FeedbackAgent, self._agents.get("feedback"))
        if feedback_agent and self.config.feedback.enabled:
            await feedback_agent.process(verdict=final_verdict)

        # ---- 阶段5.5: 推送高危告警到前端 (管理员审批链路入口) ----
        if self.alert_callback and final_verdict.verdict in (
            TrafficVerdict.MALICIOUS, TrafficVerdict.SUSPICIOUS,
        ):
            try:
                self.alert_callback(final_verdict, flow)
            except Exception:
                logger.exception("[%s] 告警回调异常", correlation_id)

        # ---- 阶段6: 写入记忆系统 (自适应) ----
        self._record_to_memory(final_verdict, flow)

        self._publish_verdict(final_verdict, correlation_id)
        return final_verdict

    def analyze_flow_sync(self, flow: FlowEvent) -> ThreatVerdict:
        """
        同步版本的流量分析（用于非异步环境）。
        """
        import asyncio
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.analyze_flow(flow))
        else:
            raise RuntimeError(
                "在已有事件循环中无法使用同步方法，请使用 await orchestrator.analyze_flow()"
            )

    # ========== 管理员反馈 ==========

    async def admin_feedback(
        self,
        feedback_type: str,
        src_ip: str = "",
        dst_ip: str = "",
        verdict_id: str = "",
        admin_note: str = "",
    ) -> dict:
        """
        管理员标记反馈。

        Args:
            feedback_type: 'false_positive' / 'false_negative' / 'confirm_malicious'
            src_ip: 源 IP
            dst_ip: 目的 IP
            verdict_id: 关联的判定 ID
            admin_note: 管理员备注

        Returns:
            dict: 规则变更结果
        """
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

    # ========== 规则管理与同步 ==========

    def get_sync_rules(self, max_rules: int = 100) -> list[dict]:
        """
        获取应同步到 P4 交换机的规则列表。
        """
        if not self._knowledge_base:
            return []
        return self._knowledge_base.to_sync_payload(max_rules)

    def add_manual_rule(
        self,
        src_ip: str = "",
        dst_ip: str = "",
        src_port: int = 0,
        dst_port: int = 0,
        protocol: str = "TCP",
        action: str = "block",
        ttl_minutes: int = 1440,
        comment: str = "",
    ) -> str:
        """手动添加规则"""
        action_map = {
            "block": RuleAction.BLOCK,
            "allow": RuleAction.ALLOW,
            "mirror": RuleAction.MIRROR,
            "throttle": RuleAction.THROTTLE,
        }
        rule = RuleEntry(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            action=action_map.get(action, RuleAction.BLOCK),
            confidence=1.0,
            source="manual",
            ttl_minutes=ttl_minutes,
            comment=comment or f"手动添加: {action}",
        )
        assert self._knowledge_base is not None
        return self._knowledge_base.add_rule(rule)

    def remove_rule(self, rule_id: str) -> bool:
        """删除规则"""
        assert self._knowledge_base is not None
        return self._knowledge_base.remove_rule(rule_id)

    def match_rule(
        self, src_ip: str, dst_ip: str = "",
        src_port: int = 0, dst_port: int = 0,
        protocol: str = "",
    ) -> Optional[RuleEntry]:
        """查询匹配的规则"""
        assert self._knowledge_base is not None
        return self._knowledge_base.match(
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
            protocol=protocol,
        )

    # ========== 模型管理（LM Studio）==========

    def _get_lm_backend(self) -> LMStudioBackend:
        """获取 LM Studio 后端实例"""
        backend = self._backends.get(BackendType.LMSTUDIO)
        if backend is None:
            raise RuntimeError("LM Studio 后端未配置")
        return cast(LMStudioBackend, backend)

    def list_lm_models(self) -> list[ModelInfo]:
        """
        列出 LM Studio 中所有可用的模型（包括已加载和未加载）。
        对应 LM Studio GET /api/v1/models 管理接口。
        """
        try:
            return self._get_lm_backend().list_models()
        except RuntimeError:
            return []

    def list_lm_loaded_models(self) -> list[ModelInfo]:
        """列出 LM Studio 中当前已加载的模型"""
        try:
            return self._get_lm_backend().list_loaded_models()
        except RuntimeError:
            return []

    def load_lm_model(
        self,
        model: str,
        context_length: Optional[int] = None,
        eval_batch_size: Optional[int] = None,
        flash_attention: Optional[bool] = None,
        num_experts: Optional[int] = None,
        offload_kv_cache_to_gpu: Optional[bool] = None,
        echo_load_config: bool = False,
    ) -> ModelInfo:
        """
        通过 LM Studio 管理 API 加载指定模型。
        POST /api/v1/models/load
        """
        backend = self._get_lm_backend()
        config = LoadModelConfig(
            model=model,
            context_length=context_length,
            eval_batch_size=eval_batch_size,
            flash_attention=flash_attention,
            num_experts=num_experts,
            offload_kv_cache_to_gpu=offload_kv_cache_to_gpu,
            echo_load_config=echo_load_config,
        )
        return backend.load_model(config)

    def unload_lm_model(self, model_id: str) -> bool:
        """卸载 LM Studio 中指定的模型"""
        try:
            return self._get_lm_backend().unload_model(model_id)
        except RuntimeError:
            return False

    def is_lm_model_loaded(self, model_id: str) -> bool:
        """检查指定模型是否已在 LM Studio 中加载"""
        try:
            return self._get_lm_backend().is_model_loaded(model_id)
        except RuntimeError:
            return False

    def refresh_lm_models(self) -> list[ModelInfo]:
        """从 LM Studio 服务端刷新已加载模型缓存"""
        try:
            updated = self._get_lm_backend().refresh_loaded_models()
            return list(updated.values())
        except RuntimeError:
            return []

    def set_lm_auto_load(self, enabled: bool) -> None:
        """设置是否在调用前自动加载未就绪的模型"""
        try:
            self._get_lm_backend().auto_load = enabled
        except RuntimeError:
            pass

    def get_lm_backend_info(self) -> dict:
        """获取 LM Studio 后端运行信息（用于前端状态面板）"""
        try:
            backend = self._get_lm_backend()
            return {
                "api_base": backend.api_base,
                "mgmt_api_base": backend._mgmt_api_base,
                "default_model": backend.default_model,
                "auto_load": backend.auto_load,
                "loaded_models": [
                    {
                        "model_id": m.model_id,
                        "type": m.type,
                        "status": m.status,
                        "instance_id": m.instance_id,
                        "context_length": m.context_length,
                        "load_time_seconds": m.load_time_seconds,
                    }
                    for m in backend.list_loaded_models()
                ],
                "is_available": backend.is_available(),
            }
        except RuntimeError:
            return {"error": "LM Studio 后端未配置"}

    def get_statistics(self) -> dict:
        """获取系统统计信息"""
        feedback_agent = cast(FeedbackAgent, self._agents.get("feedback"))
        return {
            "running": self._running,
            "agents": list(self._agents.keys()),
            "backends": {k.value: getattr(v, 'default_model', str(v))
                        for k, v in self._backends.items()},
            "knowledge_base_size": self._knowledge_base.size() if self._knowledge_base else 0,
            "feedback_stats": feedback_agent.get_statistics() if feedback_agent else {},
        }

    def _record_to_memory(self, verdict: ThreatVerdict, flow: FlowEvent) -> None:
        """将判定结果写入记忆系统（自适应 Tier 0 案例记录）"""
        try:
            from .memory import get_store, get_index
            store = get_store()
            index = get_index()

            # 查询当时匹配的模式卡片
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
                admins_action="",      # 尚未经管理员确认
                ai_correct=False,      # 默认为 False，等管理员反馈后更正
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
            pass  # 记忆系统不可用不影响研判

    def _publish_verdict(self, verdict: ThreatVerdict, correlation_id: str) -> None:
        """发布最终判定到消息总线"""
        if not self._message_bus:
            return
        msg = AgentMessage(
            msg_type=MessageType.THREAT_VERDICT,
            sender="Orchestrator",
            recipient="",  # 广播
            payload=verdict,
            correlation_id=correlation_id,
        )
        self._message_bus.publish(msg)


__all__ = ["Orchestrator"]
