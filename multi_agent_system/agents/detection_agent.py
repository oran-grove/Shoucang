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
        model_name: str = "deepseek-v4-flash",
        temperature: float = 0.3,
        max_tokens: int = 1024,
        confidence_threshold_malicious: float = 0.85,
        confidence_threshold_suspect: float = 0.50,
    ):
        default_prompt = (
            "你是一个内部威胁检测专家，专门识别组织内部人员的隐蔽数据泄露行为。"
            "请根据提供的流量元数据，判断该流量是否存在内部泄密风险。\n\n"
            "## 核心检测维度\n"
            "1. **数据外传特征**：非标准端口的大流量TLS、异常DNS查询(TXT/MX记录过长)、"
            "ICMP隧道、非工作时段的数据传输\n"
            "2. **频率隐蔽性**：单次数据量刻意控制在正常范围内(<10MB)，但加密熵极高(>7.5)\n"
            "3. **协议异常**：非标准应用层协议、伪装成HTTP/HTTPS/DNS的隐蔽信道\n"
            "4. **数据敏感性**：访问非授权的高密级数据（如普通员工访问机密文件服务器）\n"
            "5. **时段异常**：非工作时段(22:00-06:00)或周末/节假日的异常访问\n"
            "6. **行为基线偏离**：当前行为与该用户/设备历史基线有显著偏差(Z-score > 2.0)\n\n"
            "## 判定标准\n"
            "- 若多个维度同时异常或涉及高密级数据外传 → malicious\n"
            "- 若仅有1-2个弱信号但可疑 → suspicious\n"
            "- 若完全符合正常行为模式 → safe\n\n"
            "回复格式：{ \"verdict\": \"malicious\"|\"suspicious\"|\"safe\", "
            "\"confidence\": 0.0-1.0, \"reasoning\": \"分析理由（基于上述维度的具体发现）\", "
            "\"threat_type\": \"数据泄露\"|\"C2通信\"|\"隐蔽信道\"|\"内部越权\"|\"正常\"|\"未知\", "
            "\"insider_threat_indicators\": [\"指标1\", \"指标2\"] }"
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
