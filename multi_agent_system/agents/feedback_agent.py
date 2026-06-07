"""
反馈智能体
==========
接收管理员反馈（误报/漏报标记），结合历史判定记录，调整知识库规则。
支持规则升级、降级、调整置信度和TTL，以及学习管理员偏好。
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from ..core.agent import BaseAgent
from ..core.message import (
    AgentMessage, FlowEvent, MessageType, ThreatVerdict,
    TrafficVerdict, SeverityLevel, RuleEntry, RuleAction,
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
    - 接收管理员反馈
    - 查询历史判定记录
    - 调整知识库规则权重/TTL/动作
    - 输出规则变更建议
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
            "你是一个内部威胁检测系统的规则优化与自适应学习专家。"
            "根据管理员反馈和历史判定记录，提出规则调整建议，"
            "确保系统在内部泄密检测中持续降低误报、减少漏报。\n\n"
            "## 优化策略\n"
            "1. **误报分析**：分析误报特征，调整检测阈值（如提高可疑置信度门槛）"
            "或添加白名单规则（如特定部门的常规数据传输模式）\n"
            "2. **漏报分析**：逆向分析漏报案例，确定哪些弱信号组合被遗漏，"
            "建议降低相关维度阈值或增加新的检测模式\n"
            "3. **用户画像更新**：根据同类用户的实际行为，动态调整个人/部门的"
            "基线容差（如财务部门的大文件传输可能是正常的月末报表）\n"
            "4. **TTL自适应**：根据反馈确认的威胁严重度和用户历史记录，"
            "自适应调整规则有效期\n"
            "5. **长周期模式学习**：记录管理员确认的长周期泄密案例，"
            "提取低慢外传的模式特征，反馈给检测和关联智能体\n\n"
            "回复格式：{ \"action\": \"upgrade_to_blacklist\"|\"downgrade_to_whitelist\"|"
            "\"adjust_confidence\"|\"adjust_threshold\"|\"update_baseline\"|\"no_change\", "
            "\"rule_id\": \"规则ID\", \"new_confidence\": 0.0-1.0, "
            "\"ttl_minutes\": 整数, "
            "\"reasoning\": \"调整理由（含模式学习结论）\", "
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

    def process_sync(
        self,
        feedback: Optional[AdminFeedback] = None,
        verdict: Optional[ThreatVerdict] = None,
    ) -> dict:
        import asyncio
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.process(feedback, verdict))
        else:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(
                    lambda: asyncio.run(self.process(feedback, verdict))
                ).result()

    def _apply_feedback_rules(
        self, feedback: AdminFeedback, hist_verdict: Optional[ThreatVerdict]
    ) -> dict:
        """
        基于规则的反馈处理（确定性行为，不依赖 LLM）。
        """
        if feedback.feedback_type == "confirm_malicious":
            # 管理员确认恶意 → 直接加入黑名单
            rule = RuleEntry(
                src_ip=feedback.src_ip,
                dst_ip=feedback.dst_ip,
                action=RuleAction.BLOCK,
                confidence=1.0,
                source="admin",
                ttl_minutes=10080,  # 管理员确认的规则保留 7 天
                comment=f"管理员确认: {feedback.admin_note}",
            )
            if self._knowledge_base:
                self._knowledge_base.add_rule(rule)
            return {
                "action": "upgrade_to_blacklist",
                "rule_id": rule.rule_id,
                "new_confidence": 1.0,
                "ttl_minutes": 10080,
                "reasoning": "管理员确认恶意，已生成黑名单规则",
            }

        elif feedback.feedback_type == "false_positive":
            # 误报 → 查找并降级/删除相关规则
            if self._knowledge_base and feedback.src_ip:
                rules = self._knowledge_base.query_by_src_ip(
                    feedback.src_ip, action=RuleAction.BLOCK
                )
                removed = []
                for rule in rules:
                    if rule.source in ("auto", "admin"):
                        self._knowledge_base.remove_rule(rule.rule_id)
                        removed.append(rule.rule_id)
                if hist_verdict:
                    hist_verdict.verdict = TrafficVerdict.FALSE_POSITIVE
                return {
                    "action": "downgrade_to_whitelist",
                    "rule_id": removed[0] if removed else "",
                    "new_confidence": 0.0,
                    "ttl_minutes": 0,
                    "reasoning": f"管理员标记误报，已移除 {len(removed)} 条规则: {removed}",
                }
            return {
                "action": "downgrade_to_whitelist",
                "reasoning": "管理员标记误报，无匹配规则",
            }

        elif feedback.feedback_type == "false_negative":
            # 漏报 → 将目标IP加入黑名单
            rule = RuleEntry(
                src_ip=feedback.src_ip,
                dst_ip=feedback.dst_ip,
                action=RuleAction.BLOCK,
                confidence=0.90,
                source="auto",
                ttl_minutes=4320,
                comment=f"管理员标记漏报: {feedback.admin_note}",
            )
            if self._knowledge_base:
                self._knowledge_base.add_rule(rule)
            return {
                "action": "upgrade_to_blacklist",
                "rule_id": rule.rule_id,
                "new_confidence": 0.90,
                "ttl_minutes": 4320,
                "reasoning": "管理员标记漏报，已生成黑名单规则",
            }

        return {"action": "no_change", "reasoning": f"未知反馈类型: {feedback.feedback_type}"}

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
