"""
检测智能体
==========
对单条流量的元数据进行快速分析，输出恶意/可疑/安全的初步判定。
优先使用本地模型（低延迟），支持降级到在线 API。
"""

import logging
from typing import Optional

from ..core.agent import BaseAgent
from ..core.message import (
    AgentMessage, FlowEvent, MessageType, ThreatVerdict,
    TrafficVerdict, SeverityLevel,
)

logger = logging.getLogger(__name__)


class DetectionAgent(BaseAgent):
    """
    检测智能体：
    - 接收 FlowEvent
    - 调用 LLM 做单流分类
    - 输出 DETECTION_RESULT 消息
    - 已知黑名单命中时直接返回恶意（不走 LLM）
    """

    def __init__(
        self,
        name: str = "DetectionAgent",
        system_prompt: str = "",
        model_name: str = "qwen2.5-7b-instruct",
        temperature: float = 0.3,
        max_tokens: int = 1024,
        confidence_threshold_malicious: float = 0.85,
        confidence_threshold_suspect: float = 0.50,
    ):
        default_prompt = (
            "你是一个网络安全流量分析专家。请根据提供的流量元数据，判断该流量是否为恶意。"
            "回复格式：{ \"verdict\": \"malicious\"|\"suspicious\"|\"safe\", "
            "\"confidence\": 0.0-1.0, \"reasoning\": \"简短理由\", "
            "\"threat_type\": \"数据泄露\"|\"C2通信\"|\"扫描\"|\"正常\"|\"未知\" }"
        )
        super().__init__(
            name=name,
            system_prompt=system_prompt or default_prompt,
            model_name=model_name,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        self.confidence_threshold_malicious = confidence_threshold_malicious
        self.confidence_threshold_suspect = confidence_threshold_suspect

    async def process(self, flow_event: FlowEvent) -> ThreatVerdict:
        """
        处理单条流量事件，返回 ThreatVerdict。
        """
        # 1. 先查知识库
        if self._knowledge_base:
            rule = self._knowledge_base.match(
                src_ip=flow_event.src_ip,
                dst_ip=flow_event.dst_ip,
                src_port=flow_event.src_port,
                dst_port=flow_event.dst_port,
                protocol=flow_event.protocol,
            )
            if rule is not None:
                from ..core.message import RuleAction
                self._knowledge_base.update_rule_hit(rule.rule_id)
                if rule.action == RuleAction.BLOCK:
                    return ThreatVerdict(
                        flow_ids=[flow_event.flow_id],
                        verdict=TrafficVerdict.MALICIOUS,
                        severity=SeverityLevel.HIGH,
                        confidence=rule.confidence,
                        threat_type="已知黑名单命中",
                        reasoning=f"匹配规则 {rule.rule_id}: {rule.comment}",
                        recommended_action="block",
                        detection_result_id=self.name,
                    )
                elif rule.action == RuleAction.ALLOW:
                    return ThreatVerdict(
                        flow_ids=[flow_event.flow_id],
                        verdict=TrafficVerdict.SAFE,
                        severity=SeverityLevel.INFO,
                        confidence=rule.confidence,
                        threat_type="已知白名单",
                        reasoning=f"匹配规则 {rule.rule_id}: {rule.comment}",
                        recommended_action="allow",
                        detection_result_id=self.name,
                    )

        # 2. 调用 LLM 分析
        prompt = f"请分析以下流量：\n{flow_event.to_prompt_text()}"
        try:
            response = await self.call_llm(prompt)
        except Exception as e:
            logger.error("[%s] LLM 调用失败: %s", self.name, e)
            return ThreatVerdict(
                flow_ids=[flow_event.flow_id],
                verdict=TrafficVerdict.UNKNOWN,
                severity=SeverityLevel.LOW,
                confidence=0.0,
                threat_type="分析失败",
                reasoning=f"LLM 调用异常: {e}",
                recommended_action="monitor",
                detection_result_id=self.name,
            )

        # 3. 解析 LLM 回复
        parsed = self.extract_json_from_response(response)
        raw_verdict = parsed.get("verdict", "unknown")
        confidence = float(parsed.get("confidence", 0.0))
        threat_type = parsed.get("threat_type", "未知")
        reasoning = parsed.get("reasoning", response[:500])

        verdict_map = {
            "malicious": TrafficVerdict.MALICIOUS,
            "suspicious": TrafficVerdict.SUSPICIOUS,
            "safe": TrafficVerdict.SAFE,
        }
        verdict = verdict_map.get(raw_verdict, TrafficVerdict.UNKNOWN)

        severity = SeverityLevel.LOW
        if verdict == TrafficVerdict.MALICIOUS and confidence >= self.confidence_threshold_malicious:
            severity = SeverityLevel.HIGH
        elif verdict == TrafficVerdict.SUSPICIOUS and confidence >= self.confidence_threshold_suspect:
            severity = SeverityLevel.MEDIUM

        action = "allow"
        if verdict == TrafficVerdict.MALICIOUS:
            action = "block"
        elif verdict == TrafficVerdict.SUSPICIOUS:
            action = "monitor"

        return ThreatVerdict(
            flow_ids=[flow_event.flow_id],
            verdict=verdict,
            severity=severity,
            confidence=confidence,
            threat_type=threat_type,
            reasoning=reasoning,
            recommended_action=action,
            detection_result_id=self.name,
            extra={"llm_raw": response},
        )

    def process_sync(self, flow_event: FlowEvent) -> ThreatVerdict:
        """同步版本"""
        import asyncio
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.process(flow_event))
        else:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(lambda: asyncio.run(self.process(flow_event))).result()


__all__ = ["DetectionAgent"]
