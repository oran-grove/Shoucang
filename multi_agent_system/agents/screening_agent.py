"""
Layer 1 — 初步筛查智能体
========================
对单条流量进行快速研判，输出 dangerous/suspicious/safe 判定。
危险流量直接上报前端，安全流量丢弃，可疑流量进入 Layer 2。
"""

import logging
from typing import Any

from ..core.agent import BaseAgent
from ..core.message import FlowEvent, ThreatVerdict, TrafficVerdict, SeverityLevel

logger = logging.getLogger(__name__)


class ScreeningAgent(BaseAgent):
    """
    初步筛查智能体 (Layer 1)

    对单条流量进行快速威胁分类：
    - dangerous → 直接上报前端（高危告警）
    - suspicious → 进入 Layer 2 历史回溯
    - safe → 丢弃，不进入后续处理
    """

    def __init__(
        self,
        name: str = "ScreeningAgent",
        system_prompt: str = "",
        model_name: str = "deepseek-v4-flash",
        temperature: float = 0.3,
        max_tokens: int = 1024,
        confidence_threshold_dangerous: float = 0.85,
        confidence_threshold_suspicious: float = 0.50,
    ):
        super().__init__(
            name=name,
            system_prompt=system_prompt,
            model_name=model_name,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        self.confidence_threshold_dangerous = confidence_threshold_dangerous
        self.confidence_threshold_suspicious = confidence_threshold_suspicious
        if not system_prompt:
            self.system_prompt = (
                "你是一个内部威胁检测专家，专门识别组织内部人员的隐蔽数据泄露行为。"
                "请根据提供的流量元数据，判断该流量是否存在内部泄密风险。\n\n"
                "## 核心检测维度\n"
                "1. **数据外传特征**：非标准端口的大流量TLS、异常DNS查询(TXT/MX记录过长)、ICMP隧道、非工作时段的数据传输\n"
                "2. **频率隐蔽性**：单次数据量刻意控制在正常范围内(<10MB)，但加密熵极高(>7.5)\n"
                "3. **协议异常**：非标准应用层协议、伪装成HTTP/HTTPS/DNS的隐蔽信道\n"
                "4. **数据敏感性**：访问非授权的高密级数据\n"
                "5. **时段异常**：非工作时段(22:00-06:00)或周末/节假日的异常访问\n"
                "6. **行为基线偏离**：当前行为与该用户/设备历史基线有显著偏差(Z-score > 2.0)\n\n"
                "## 判定标准\n"
                "- 若多个维度同时异常或涉及高密级数据外传 → dangerous\n"
                "- 若仅有1-2个弱信号但可疑 → suspicious\n"
                "- 若完全符合正常行为模式 → safe\n\n"
                "回复格式：{ \"verdict\": \"dangerous\"|\"suspicious\"|\"safe\", "
                "\"confidence\": 0.0-1.0, \"reasoning\": \"分析理由（基于上述维度的具体发现）\", "
                "\"threat_type\": \"数据泄露\"|\"C2通信\"|\"隐蔽信道\"|\"未授权访问\"|\"正常\"|\"未知\", "
                "\"insider_threat_indicators\": [\"指标1\", \"指标2\"] }"
            )

    async def process(self, flow: FlowEvent) -> ThreatVerdict:
        """
        对单条流量执行初步筛查。

        Args:
            flow: 待分析的流量事件

        Returns:
            ThreatVerdict: 威胁判定结果
        """
        # 查询记忆系统中的匹配模式，注入提示词
        pattern_context = self._get_pattern_context(flow)
        user_prompt = f"请分析以下流量：\n{flow.to_prompt_text()}"
        if pattern_context:
            user_prompt = (
                f"=== 历史模式参考（来自自适应学习系统） ===\n"
                f"{pattern_context}\n\n"
                f"{user_prompt}"
            )
        try:
            raw = await self.call_llm(user_prompt)
            parsed = self.extract_json_from_response(raw)

            if "error" in parsed:
                logger.warning("[%s] LLM 解析失败，标记为可疑: %s", self.name, parsed.get("raw", "")[:100])
                return self._fallback_verdict(flow, "LLM解析失败，标记为可疑")

            verdict_raw = parsed.get("verdict", "suspicious").lower()

            if verdict_raw == "dangerous":
                verdict = TrafficVerdict.MALICIOUS
            elif verdict_raw == "suspicious":
                verdict = TrafficVerdict.SUSPICIOUS
            else:
                verdict = TrafficVerdict.SAFE

            # 严重度：初步筛查统一标记为 medium，由 Layer 3 最终研判升级
            severity = SeverityLevel.MEDIUM

            return ThreatVerdict(
                flow_ids=[flow.flow_id],
                verdict=verdict,
                severity=severity,
                confidence=float(parsed.get("confidence", 0.5)),
                threat_type=parsed.get("threat_type", "未知"),
                reasoning=parsed.get("reasoning", ""),
                recommended_action="monitor",
                extra={"screening_raw": parsed},
            )

        except Exception as e:
            logger.exception("[%s] 分析异常: %s", self.name, e)
            return self._fallback_verdict(flow, f"分析异常: {str(e)}")

    def _fallback_verdict(self, flow: FlowEvent, reason: str) -> ThreatVerdict:
        """LLM 不可用或解析失败时的降级判定"""
        return ThreatVerdict(
            flow_ids=[flow.flow_id],
            verdict=TrafficVerdict.SUSPICIOUS,
            severity=SeverityLevel.LOW,
            confidence=0.3,
            threat_type="未知",
            reasoning=reason,
            recommended_action="monitor",
        )

    def classify_threshold(self, verdict: ThreatVerdict) -> str:
        """
        使用置信度阈值重新校准判定。

        Returns:
            "dangerous" / "suspicious" / "safe"
        """
        if verdict.verdict == TrafficVerdict.SAFE:
            return "safe"
        if verdict.confidence >= self.confidence_threshold_dangerous:
            return "dangerous"
        if verdict.confidence >= self.confidence_threshold_suspicious:
            return "suspicious"
        return "safe"

    @staticmethod
    def _get_pattern_context(flow: FlowEvent) -> str:
        """从记忆系统查询匹配的历史模式，返回提示词注入文本。"""
        try:
            from ..memory import get_index
            index = get_index()
            features = {
                "department": getattr(flow, "department", ""),
                "protocol": getattr(flow, "protocol", "TCP"),
                "direction": (
                    "internal" if getattr(flow, "dst_ip", "").startswith(
                        ("10.", "192.168.", "172.")
                    ) else "outbound"
                ),
                "encryption": getattr(flow, "entropy_score", 0) > 7.0,
            }
            return index.format_context(features)
        except Exception:
            return ""


__all__ = ["ScreeningAgent"]
