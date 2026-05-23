"""
研判智能体
==========
综合单流检测结果和关联分析结果，给出最终威胁判定、严重程度和处置建议。
是决策链的最终环节（反馈智能体除外）。
"""

import logging
from typing import Optional, cast

from ..core.agent import BaseAgent
from ..core.message import (
    FlowEvent, ThreatVerdict,
    TrafficVerdict, SeverityLevel, RuleEntry, RuleAction,
)

logger = logging.getLogger(__name__)


class JudgmentAgent(BaseAgent):
    """
    研判智能体：
    - 接收 DETECTION_RESULT + CORRELATION_RESULT
    - 综合判定威胁等级
    - 生成 RuleEntry 写入知识库
    - 输出最终的 THREAT_VERDICT
    """

    def __init__(
        self,
        name: str = "JudgmentAgent",
        system_prompt: str = "",
        model_name: str = "deepseek-v4-flash",
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ):
        default_prompt = (
            "你是一个内部威胁综合研判专家，专门评估长周期、低频率、高隐蔽性的内部泄密行为。"
            "请综合单流检测结果、关联分析结果、行为基线偏离度、时序异常评分，"
            "给出最终的威胁判定和处置建议。\n\n"
            "## 研判核心原则\n"
            "1. **弱信号聚合**：单一维度可疑不足为据，但多个弱信号叠加可能构成明确威胁。"
            "例如：非工作时段(1分) + 高熵加密(1分) + 访问高密级数据(1分) + 频率Z-score>2(1分) → 综合研判升级\n"
            "2. **长周期视角**：短时间窗口看不出问题不代表安全，需结合7d/30d的基线偏离和时序异常。"
            "单次传输5MB可能是正常，连续30天每晚传输5MB就是明显的泄密\n"
            "3. **用户画像**：同一行为对开发人员正常，对财务人员异常。结合部门/角色/数据密级维度判定\n"
            "4. **误报宽容度**：内部威胁检测宁可多报不可漏报，但需合理标注置信度\n\n"
            "## 严重度判定标准\n"
            "- **critical**: 确认高密级(机密/绝密)数据外传，或累计外传>100MB，或持续>30天\n"
            "- **high**: 疑似数据外传+多个弱信号(4+)，或累计外传>50MB，或持续>7天\n"
            "- **medium**: 可疑行为+2-3个弱信号，或短期异常但无明显数据泄露证据\n"
            "- **low**: 仅有1个弱信号，或轻微偏离基线，需持续观察\n"
            "- **info**: 单次异常但无规律，降级观察\n\n"
            "回复格式：{ \"verdict\": \"malicious\"|\"suspicious\"|\"safe\", "
            "\"severity\": \"critical\"|\"high\"|\"medium\"|\"low\"|\"info\", "
            "\"confidence\": 0.0-1.0, "
            "\"recommended_action\": \"block\"|\"monitor\"|\"allow\"|\"quarantine\", "
            "\"reasoning\": \"综合研判逻辑（请逐一列出各维度评分和最终聚合逻辑）\", "
            "\"evidence_summary\": [\"证据1\", \"证据2\"], "
            "\"weak_signal_score\": 整数(0-10), "
            "\"rule_ttl_minutes\": 整数 }"
        )
        super().__init__(
            name=name,
            system_prompt=system_prompt or default_prompt,
            model_name=model_name,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        

    async def process(
        self,
        detection_result: Optional[ThreatVerdict] = None,
        correlation_result: Optional[ThreatVerdict] = None,
        _correlation_id: str = "",
    ) -> ThreatVerdict:
        """
        综合 detect + correlate 的结果，生成最终判定。
        """
        # 如果只有检测结果且已是 Safe，直接放行
        if detection_result and not correlation_result:
            if detection_result.verdict == TrafficVerdict.SAFE:
                return detection_result
            # 可疑/恶意但无关联结果——直接以检测结果为准
            return self._fallback_judgment(detection_result)

        if not detection_result and correlation_result:
            return self._fallback_judgment(correlation_result)

        if not detection_result and not correlation_result:
            return ThreatVerdict(
                verdict=TrafficVerdict.UNKNOWN,
                severity=SeverityLevel.LOW,
                confidence=0.0,
                reasoning="无可用分析结果",
                recommended_action="monitor",
            )
        # Both results exist now — type-narrow for Pyright
        assert detection_result is not None and correlation_result is not None

        # -- 两条结果都有，构建综合提示 --
        prompt_parts = [
            "请综合以下两条分析结果给出最终研判：",
            "==== 单流检测结果 ====",
            f"判定: {detection_result.verdict.value}",
            f"威胁类型: {detection_result.threat_type}",
            f"置信度: {detection_result.confidence}",
            f"理由: {detection_result.reasoning}",
            "==== 关联分析结果 ====",
            f"判定: {correlation_result.verdict.value}",
            f"威胁类型: {correlation_result.threat_type}",
            f"置信度: {correlation_result.confidence}",
            f"理由: {correlation_result.reasoning}",
        ]
        prompt = "\n".join(prompt_parts)

        try:
            response = await self.call_llm(prompt)
        except Exception as e:
            logger.error("[%s] LLM 研判失败: %s", self.name, e)
            return self._rule_based_fallback(cast(ThreatVerdict, detection_result), cast(ThreatVerdict, correlation_result))

        parsed = self.extract_json_from_response(response)
        return self._build_verdict(parsed, cast(ThreatVerdict, detection_result), cast(ThreatVerdict, correlation_result), response)

    def process_sync(
        self,
        detection_result: Optional[ThreatVerdict] = None,
        correlation_result: Optional[ThreatVerdict] = None,
        _correlation_id: str = "",
    ) -> ThreatVerdict:
        import asyncio
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(
                self.process(detection_result, correlation_result, _correlation_id)
            )
        else:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(
                    lambda: asyncio.run(
                        self.process(detection_result, correlation_result, _correlation_id)
                    )
                ).result()

    def _build_verdict(
        self,
        parsed: dict,
        detection: ThreatVerdict,
        correlation: ThreatVerdict,
        raw_response: str,
    ) -> ThreatVerdict:
        """从解析的 JSON 构建 ThreatVerdict"""
        verdict_map = {
            "malicious": TrafficVerdict.MALICIOUS,
            "suspicious": TrafficVerdict.SUSPICIOUS,
            "safe": TrafficVerdict.SAFE,
        }
        severity_map = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.INFO,
        }
        verdict = verdict_map.get(parsed.get("verdict", "suspicious"), TrafficVerdict.SUSPICIOUS)
        severity = severity_map.get(parsed.get("severity", "medium"), SeverityLevel.MEDIUM)
        confidence = float(parsed.get("confidence", 0.5))
        reasoning = parsed.get("reasoning", raw_response[:500])
        action = parsed.get("recommended_action", "monitor")
        evidence = parsed.get("evidence_summary", [])
        ttl = int(parsed.get("rule_ttl_minutes", 1440))

        # 合并 flow_ids
        all_flow_ids = list(detection.flow_ids or [])
        for fid in (correlation.flow_ids or []):
            if fid not in all_flow_ids:
                all_flow_ids.append(fid)

        return ThreatVerdict(
            flow_ids=all_flow_ids,
            verdict=verdict,
            severity=severity,
            confidence=confidence,
            threat_type=(
                detection.threat_type
                if detection.threat_type != "未知"
                else correlation.threat_type
            ),
            reasoning=reasoning,
            evidence_summary=evidence,
            recommended_action=action,
            detection_result_id=detection.verdict_id,
            correlation_result_id=correlation.verdict_id,
            judgment_result_id=self.name,
            extra={"llm_raw": raw_response, "suggested_ttl": ttl},
        )

    def _fallback_judgment(self, result: ThreatVerdict) -> ThreatVerdict:
        """无 LLM 参与的直接判断"""
        return result

    def _rule_based_fallback(
        self, detection: ThreatVerdict, correlation: ThreatVerdict
    ) -> ThreatVerdict:
        """
        基于规则的降级判定（当 LLM 不可用时）。
        规则：二者皆恶意 → 恶意；任一恶意 → 可疑；其余 → 检测结果为主。
        """
        if detection.verdict == TrafficVerdict.MALICIOUS and \
           correlation.verdict == TrafficVerdict.MALICIOUS:
            return ThreatVerdict(
                flow_ids=list(set(detection.flow_ids + correlation.flow_ids)),
                verdict=TrafficVerdict.MALICIOUS,
                severity=SeverityLevel.HIGH,
                confidence=max(detection.confidence, correlation.confidence),
                threat_type=detection.threat_type,
                reasoning=f"检测和关联均判定为恶意（降级规则）",
                recommended_action="block",
            )
        if TrafficVerdict.MALICIOUS in (detection.verdict, correlation.verdict):
            return ThreatVerdict(
                flow_ids=list(set(detection.flow_ids + correlation.flow_ids)),
                verdict=TrafficVerdict.SUSPICIOUS,
                severity=SeverityLevel.MEDIUM,
                confidence=max(detection.confidence, correlation.confidence) * 0.8,
                threat_type=detection.threat_type,
                reasoning="单源判定为恶意，降级规则标记为可疑",
                recommended_action="monitor",
            )
        return detection

    def create_rule_from_verdict(
        self,
        verdict: ThreatVerdict,
        flow: Optional[FlowEvent] = None,
    ) -> Optional[RuleEntry]:
        """
        将研判结果转换为知识库规则。
        只有置信度足够的恶意判定才生成黑名单规则。
        """
        if verdict.verdict != TrafficVerdict.MALICIOUS:
            return None
        if verdict.confidence < 0.70:
            return None
        if not flow:
            return None
        ttl = int(verdict.extra.get("suggested_ttl", 1440)) if verdict.extra else 1440
        return RuleEntry(
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port if flow.src_port else 0,
            dst_port=flow.dst_port if flow.dst_port else 0,
            protocol=flow.protocol,
            action=RuleAction.BLOCK,
            confidence=verdict.confidence,
            source="auto",
            ttl_minutes=ttl,
            comment=f"研判生成: {verdict.threat_type} | {verdict.reasoning[:200]}",
        )


__all__ = ["JudgmentAgent"]

