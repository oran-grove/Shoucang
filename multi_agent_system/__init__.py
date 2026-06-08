"""
多智能体流量分析系统 — 三层架构
================================
Layer 1 — ScreeningAgent:    初步筛查 (多线程逐条分析)
Layer 2 — BacktrackAgent:    历史回溯 (DB查询 + LLM关联过滤)
Layer 3 — AdjudicationAgent: 最终研判 (结合回溯数据二次判定)

快速使用：

    from multi_agent_system import MultiAgentSystem

    # 创建系统
    system = MultiAgentSystem()

    # 添加后端
    system.add_lmstudio_backend("http://localhost:1234/v1")
    system.add_openai_backend("sk-xxx")

    # 分析流量
    verdict = system.analyze(flow_event)

    # 管理员反馈
    system.feedback("false_positive", src_ip="10.0.0.5")
"""

from typing import Optional

from .config import (
    BackendType,
    LLMBackendConfig,
    ScreeningAgentConfig,
    BacktrackAgentConfig,
    AdjudicationAgentConfig,
    FeedbackAgentConfig,
    OrchestratorConfig,
)
from .core.message import (
    FlowEvent,
    ThreatVerdict,
    TrafficVerdict,
    SeverityLevel,
)
from .backends import OpenAIBackend, LMStudioBackend
from .agents.screening_agent import ScreeningAgent
from .agents.backtrack_agent import BacktrackAgent
from .agents.adjudication_agent import AdjudicationAgent
from .agents.feedback_agent import FeedbackAgent, AdminFeedback
from .orchestrator import Orchestrator

# ============================================================
# 便捷主类 — 对主程序暴露的最简接口
# ============================================================


class MultiAgentSystem:
    """
    多智能体分析系统主类。

    设计目标：对主调程序暴露最简洁的接口，
    屏蔽内部 LLM 后端、三层管线等细节。

    —— 典型使用方式 ——

        系统 = MultiAgentSystem()
        系统.add_deepseek_backend("sk-your-key")
        系统.set_screening_backend(BackendType.DEEPSEEK)

        # 流量事件（来自 P4 交换机镜像）
        flow = FlowEvent(
            src_ip="192.168.1.100", dst_ip="8.8.8.8",
            src_port=54321, dst_port=443,
            protocol="TCP", app_protocol="TLS",
            byte_count=1500000, avg_pkt_size=1200,
            entropy_score=7.2, tls_sni="evil.example.com",
        )

        verdict = 系统.analyze_sync(flow)
        if verdict.verdict == TrafficVerdict.MALICIOUS:
            print(f"检测到恶意流量！建议{verdict.recommended_action}")

        # 管理员反馈
        系统.feedback_sync("false_positive", src_ip="192.168.1.100")
    """

    def __init__(self, orchestrator_config: Optional[OrchestratorConfig] = None):
        self._config = orchestrator_config or OrchestratorConfig()
        self._orchestrator = Orchestrator(config=self._config)
        self._started = False

    # --- 后端配置 ---

    def add_openai_backend(
        self,
        api_key: str,
        api_base: str = "https://api.openai.com/v1",
        model_name: str = "gpt-4o-mini",
        timeout: float = 60.0,
        max_retries: int = 3,
    ) -> None:
        """添加 OpenAI 兼容 API 后端"""
        self._config.default_backends[BackendType.OPENAI] = LLMBackendConfig(
            backend_type=BackendType.OPENAI,
            api_base=api_base,
            api_key=api_key,
            model_name=model_name,
            timeout=timeout,
            max_retries=max_retries,
        )

    def add_lmstudio_backend(
        self,
        api_base: str = "http://localhost:1234/v1",
        model_name: str = "qwen3.5-9b",
        timeout: float = 120.0,
        auto_load: bool = True,
        load_config: Optional[dict] = None,
    ) -> None:
        """添加 LM Studio 本地 AI 后端"""
        self._config.default_backends[BackendType.LMSTUDIO] = LLMBackendConfig(
            backend_type=BackendType.LMSTUDIO,
            api_base=api_base,
            api_key="lm-studio",
            model_name=model_name,
            timeout=timeout,
            max_retries=2,
            auto_load=auto_load,
            load_config=load_config or {},
        )

    def add_deepseek_backend(
        self,
        api_key: str,
        api_base: str = "https://api.deepseek.com",
        model_name: str = "deepseek-v4-flash",
        timeout: float = 120.0,
        max_retries: int = 5,
        thinking_enabled: Optional[bool] = None,
        reasoning_effort: Optional[str] = None,
        include_reasoning: bool = False,
    ) -> None:
        """添加 DeepSeek V4 API 后端"""
        self._config.default_backends[BackendType.DEEPSEEK] = LLMBackendConfig(
            backend_type=BackendType.DEEPSEEK,
            api_base=api_base,
            api_key=api_key,
            model_name=model_name,
            timeout=timeout,
            max_retries=max_retries,
            thinking_enabled=thinking_enabled,
            reasoning_effort=reasoning_effort,
            include_reasoning=include_reasoning,
        )

    def set_screening_backend(self, backend: BackendType = BackendType.DEEPSEEK) -> None:
        """设置 Layer 1 筛查智能体使用的后端"""
        self._config.screening.backend = backend

    def set_backtrack_backend(self, backend: BackendType = BackendType.DEEPSEEK) -> None:
        """设置 Layer 2 回溯智能体使用的后端"""
        self._config.backtrack.backend = backend

    def set_adjudication_backend(self, backend: BackendType = BackendType.DEEPSEEK) -> None:
        """设置 Layer 3 研判智能体使用的后端"""
        self._config.adjudication.backend = backend

    def set_feedback_backend(self, backend: BackendType = BackendType.DEEPSEEK) -> None:
        """设置反馈智能体使用的后端"""
        self._config.feedback.backend = backend

    # --- 生命周期 ---

    async def start(self) -> None:
        """异步启动系统"""
        if self._started:
            return
        await self._orchestrator.start()
        self._started = True

    async def stop(self) -> None:
        """异步停止系统"""
        if not self._started:
            return
        await self._orchestrator.stop()
        self._started = False

    def _ensure_started(self) -> None:
        """懒启动（同步场景）"""
        if self._started:
            return
        import asyncio
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(self._orchestrator.start())
            self._started = True

    # --- 流量分析 ---

    async def analyze(self, flow: FlowEvent) -> ThreatVerdict:
        """异步分析流量"""
        if not self._started:
            raise RuntimeError("系统未启动，请先调用 await system.start()")
        return await self._orchestrator.analyze_flow(flow)

    def analyze_sync(self, flow: FlowEvent) -> ThreatVerdict:
        """同步分析流量（线程安全）"""
        self._ensure_started()
        return self._orchestrator.analyze_flow_sync(flow)

    # --- 管理员反馈 ---

    async def feedback(
        self,
        feedback_type: str,
        src_ip: str = "",
        dst_ip: str = "",
        verdict_id: str = "",
        admin_note: str = "",
    ) -> dict:
        """异步管理员反馈"""
        if not self._started:
            raise RuntimeError("系统未启动")
        return await self._orchestrator.admin_feedback(
            feedback_type=feedback_type,
            src_ip=src_ip,
            dst_ip=dst_ip,
            verdict_id=verdict_id,
            admin_note=admin_note,
        )

    def feedback_sync(
        self,
        feedback_type: str,
        src_ip: str = "",
        dst_ip: str = "",
        verdict_id: str = "",
        admin_note: str = "",
    ) -> dict:
        """同步管理员反馈"""
        self._ensure_started()
        return self._orchestrator.admin_feedback_sync(
            feedback_type=feedback_type,
            src_ip=src_ip,
            dst_ip=dst_ip,
            verdict_id=verdict_id,
            admin_note=admin_note,
        )

    def get_statistics(self) -> dict:
        """获取系统统计"""
        return self._orchestrator.get_statistics()


__all__ = [
    # 主类
    "MultiAgentSystem",
    "Orchestrator",
    # 配置
    "OrchestratorConfig",
    "LLMBackendConfig",
    "ScreeningAgentConfig",
    "BacktrackAgentConfig",
    "AdjudicationAgentConfig",
    "FeedbackAgentConfig",
    "BackendType",
    # 数据结构
    "FlowEvent",
    "ThreatVerdict",
    "TrafficVerdict",
    "SeverityLevel",
    # 后端
    "OpenAIBackend",
    "LMStudioBackend",
    # 智能体
    "ScreeningAgent",
    "BacktrackAgent",
    "AdjudicationAgent",
    "FeedbackAgent",
    "AdminFeedback",
]
