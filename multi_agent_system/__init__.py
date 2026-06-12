"""
多智能体流量分析系统 — 三层架构
================================
Layer 1 — ScreeningAgent:    初步筛查 (多线程逐条分析)
Layer 2 — BacktrackAgent:    历史回溯 (DB查询 + LLM关联过滤)
Layer 3 — AdjudicationAgent: 最终研判 (结合回溯数据二次判定)

快速使用：

    from multi_agent_system import MultiAgentSystem

    # 创建系统（配置自动从 config 模块加载）
    system = MultiAgentSystem()

    # 分析流量
    verdict = system.analyze(flow_event)

    # 管理员反馈
    system.feedback("false_positive", src_ip="10.0.0.5")
"""

from config.schema import (
    BackendType,
    LLMBackendConfig,
    ScreeningAgentConfig,
    BacktrackAgentConfig,
    AdjudicationAgentConfig,
    FeedbackAgentConfig,
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

    对主调程序暴露最简洁的接口，屏蔽内部 LLM 后端、三层管线等细节。
    配置自动从 config 模块加载（通过 get_config()）。

    —— 典型使用方式 ——

        system = MultiAgentSystem()
        await system.start()

        verdict = await system.analyze(flow)
        if verdict.verdict == TrafficVerdict.MALICIOUS:
            print(f"检测到恶意流量！建议{verdict.recommended_action}")

        await system.stop()
    """

    def __init__(self):
        from config import get_config
        self._orchestrator = Orchestrator(
            backends=get_config("backends"),
            screening=get_config("screening"),
            backtrack=get_config("backtrack"),
            adjudication=get_config("adjudication"),
            feedback=get_config("feedback"),
        )
        self._started = False

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
    # 配置类型
    "ScreeningAgentConfig",
    "BacktrackAgentConfig",
    "AdjudicationAgentConfig",
    "FeedbackAgentConfig",
    "LLMBackendConfig",
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
