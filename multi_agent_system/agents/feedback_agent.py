"""
反馈智能体
==========
接收管理员反馈（误报/漏报标记），写入记忆系统进行自适应学习。
通过 Tier 0 案例记录 + Tier 1 模式卡片强化，持续优化系统分析质量。
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from ..core.agent import BaseAgent
from ..core.message import (
    ThreatVerdict,
    TrafficVerdict, SeverityLevel,
)

logger = logging.getLogger(__name__)


class AdminFeedback:
    """管理员反馈数据结构"""

    def __init__(
        self,
        verdict_id: str = "",
        feedback_type: str = "false_positive",  # false_positive / false_negative / confirm_malicious
        admin_note: str = "",
        src_ip: str = "",
        dst_ip: str = "",
    ):
        self.verdict_id = verdict_id
        self.feedback_type = feedback_type
        self.admin_note = admin_note
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.timestamp = datetime.now(timezone.utc)


class FeedbackAgent(BaseAgent):
    """
    反馈智能体：
    - 接收管理员反馈（确认恶意/误报/漏报）
    - 查询历史判定记录
    - 写入记忆系统（Tier 0 反馈案例 + Tier 1 模式卡片强化）
    - 可选 LLM 增强分析用于提取模式洞察
    """

    def __init__(
        self,
        name: str = "FeedbackAgent",
        system_prompt: str = "",
        model_name: str = "deepseek-v4-flash",
        temperature: float = 0.2,
        max_tokens: int = 1024,
    ):
        default_prompt = (
            "你是一个内部威胁检测系统的自适应学习专家。"
            "根据管理员反馈和历史判定记录，分析误报/漏报的模式特征，"
            "帮助系统持续降低误报、减少漏报。\n\n"
            "## 分析策略\n"
            "1. **误报分析**：分析误报特征，识别容易被误判为恶意的正常行为模式\n"
            "2. **漏报分析**：逆向分析漏报案例，确定哪些弱信号组合被遗漏\n"
            "3. **用户画像更新**：根据同类用户的实际行为，理解部门/角色的正常行为容差\n"
            "4. **长周期模式学习**：记录管理员确认的长周期泄密案例，"
            "提取低慢外传的模式特征\n\n"
            "回复格式：{ \"pattern_insight\": \"模式洞察\", "
            "\"confidence\": 0.0-1.0, "
            "\"reasoning\": \"分析理由（含模式学习结论）\", "
            "\"learned_pattern\": \"从案例中学到的模式特征（可选）\" }"
        )
        super().__init__(
            name=name,
            system_prompt=system_prompt or default_prompt,
            model_name=model_name,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        # 存储最近的判定历史（用于学习）
        self._verdict_history: dict[str, ThreatVerdict] = {}  # verdict_id -> ThreatVerdict
        self._feedback_history: list[AdminFeedback] = []
        self._max_history = 1000

    def record_verdict(self, verdict: ThreatVerdict) -> None:
        """记录判定结果"""
        self._verdict_history[verdict.verdict_id] = verdict
        if len(self._verdict_history) > self._max_history:
            oldest = next(iter(self._verdict_history))
            del self._verdict_history[oldest]

    async def process(
        self,
        feedback: Optional[AdminFeedback] = None,
        verdict: Optional[ThreatVerdict] = None,
    ) -> dict:
        """
        处理管理员反馈，返回规则变更建议。
        """
        if feedback is None and verdict is not None:
            # 仅记录判定
            self.record_verdict(verdict)
            return {"action": "no_change", "reasoning": "记录判定结果"}

        if feedback is None:
            return {"action": "no_change", "reasoning": "无反馈"}

        self._feedback_history.append(feedback)
        if len(self._feedback_history) > self._max_history:
            self._feedback_history.pop(0)

        # 查找历史判定
        hist_verdict = self._verdict_history.get(feedback.verdict_id)

        # 规则化处理
        result = self._apply_feedback_rules(feedback, hist_verdict)

        # 更新记忆系统（Tier 0 反馈案例 + Tier 1 模式强化）
        self._update_memory(feedback, hist_verdict, result)

        # 同时生成 LLM 增强建议
        if hist_verdict:
            try:
                llm_result = await self._llm_enhance(feedback, hist_verdict)
                if llm_result:
                    result["llm_suggestion"] = llm_result
            except Exception as e:
                logger.warning("[%s] LLM 增强失败: %s", self.name, e)

        return result

    def _apply_feedback_rules(
        self, feedback: AdminFeedback, hist_verdict: Optional[ThreatVerdict]
    ) -> dict:
        """
        基于规则的反馈处理（确定性行为，不依赖 LLM）。
        反馈写入记忆系统（Tier 0 案例 + Tier 1 模式强化），
        由记忆系统的自适应演化驱动未来分析质量提升。
        """
        # 写入记忆系统
        self._update_memory(feedback, hist_verdict, {})

        action_map = {
            "confirm_malicious": "recorded_confirmed",
            "false_positive": "recorded_false_positive",
            "false_negative": "recorded_false_negative",
        }
        return {
            "action": action_map.get(feedback.feedback_type, "no_change"),
            "reasoning": f"管理员反馈已记录到记忆系统: {feedback.feedback_type}",
        }

    async def _llm_enhance(
        self, feedback: AdminFeedback, hist_verdict: ThreatVerdict
    ) -> Optional[dict]:
        """使用 LLM 增强反馈处理"""
        prompt = (
            f"管理员反馈: {feedback.feedback_type}\n"
            f"管理员备注: {feedback.admin_note}\n"
            f"源IP: {feedback.src_ip}, 目的IP: {feedback.dst_ip}\n"
            f"原判定: {hist_verdict.verdict.value} "
            f"(置信度: {hist_verdict.confidence})\n"
            f"原威胁类型: {hist_verdict.threat_type}\n"
            f"原理由: {hist_verdict.reasoning}\n"
        )
        try:
            response = await self.call_llm(prompt)
            return self.extract_json_from_response(response)
        except Exception as e:
            logger.error("[%s] LLM 增强调用失败: %s", self.name, e)
            return None

    def _update_memory(
        self,
        feedback: AdminFeedback,
        hist_verdict: Optional[ThreatVerdict],
        result: dict,
    ) -> None:
        """将管理员反馈写入记忆系统，强化匹配的模式卡片"""
        try:
            from ..memory import get_store, get_index

            store = get_store()
            index = get_index()

            # 判断 AI 是否正确
            if feedback.feedback_type == "confirm_malicious":
                ai_correct = True
            elif feedback.feedback_type in ("false_positive", "false_negative"):
                ai_correct = False
            else:
                ai_correct = False

            ai_verdict = ""
            ai_confidence = 0.0
            ai_reasoning = ""
            ai_threat_type = ""
            if hist_verdict:
                ai_verdict = hist_verdict.verdict.value
                ai_confidence = hist_verdict.confidence
                ai_reasoning = hist_verdict.reasoning
                ai_threat_type = hist_verdict.threat_type

            # 写入 Tier 0 反馈案例
            store.record_feedback(
                ai_verdict=ai_verdict,
                ai_confidence=ai_confidence,
                ai_reasoning=ai_reasoning,
                ai_threat_type=ai_threat_type,
                admins_action=feedback.feedback_type,
                ai_correct=ai_correct,
                admin_note=feedback.admin_note,
                src_ip=feedback.src_ip,
                dst_ip=feedback.dst_ip,
            )

            # 强化匹配的 Tier 1 模式卡片
            if feedback.src_ip:
                features = {"src_ip": feedback.src_ip}
                matching = index.query(features, min_match=0.3, status=None)
                for card in matching:
                    # 根据反馈类型决定强化方向
                    if feedback.feedback_type == "confirm_malicious":
                        index.reinforce_card(card.card_id, confirmed=True,
                                            admin_note=feedback.admin_note)
                    elif feedback.feedback_type == "false_positive":
                        index.reinforce_card(card.card_id, confirmed=False,
                                            admin_note=feedback.admin_note)
                    elif feedback.feedback_type == "false_negative":
                        # 漏报=AI判安全但实际恶意，对匹配到的正常模式卡片是打击
                        index.reinforce_card(card.card_id, confirmed=False,
                                            admin_note=feedback.admin_note)

        except Exception:
            pass  # 记忆系统不可用不影响反馈处理

    def get_statistics(self) -> dict:
        """返回统计信息"""
        fb_types = {}
        for fb in self._feedback_history[-200:]:
            fb_types[fb.feedback_type] = fb_types.get(fb.feedback_type, 0) + 1
        return {
            "total_feedbacks": len(self._feedback_history),
            "recent_feedback_types": fb_types,
            "total_verdicts_recorded": len(self._verdict_history),
        }


__all__ = ["FeedbackAgent", "AdminFeedback"]
