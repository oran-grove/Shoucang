"""
Layer 3 — 最终研判智能体
=========================
结合原始可疑流量和 Layer 2 回溯后的关联数据，
进行最终威胁判定：safe / dangerous / suspicious。

- safe → 丢弃
- dangerous → 上报前端
- suspicious → 循环回到 Layer 2，扩展回溯窗口重新分析
  直到遍历完所有回溯窗口，或判定为 safe/dangerous
"""

import logging
import random
from typing import Any

from ..core.agent import BaseAgent
from ..core.message import FlowEvent, ThreatVerdict, TrafficVerdict, SeverityLevel
from .backtrack_agent import TOKENS_PER_RECORD  # 复用 L2 的 token 估算常量

logger = logging.getLogger(__name__)


class AdjudicationAgent(BaseAgent):
    """最终研判智能体 (Layer 3)"""

    def __init__(
        self,
        name: str = "AdjudicationAgent",
        system_prompt: str = "",
        model_name: str = "deepseek-v4-flash",
        temperature: float = 0.3,
        max_tokens: int = 2048,
        max_context_tokens: int = 4096,
        batch_context_ratio: float = 0.125,
    ):
        super().__init__(
            name=name,
            system_prompt=system_prompt,
            model_name=model_name,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        self.max_context_tokens = max_context_tokens
        self.batch_context_ratio = batch_context_ratio
        if not system_prompt:
            self.system_prompt = (
                "你是一个内部威胁最终研判专家。请结合原始可疑流量及其历史关联数据，"
                "进行最终的威胁判定。\n\n"
                "## 研判核心原则\n"
                "1. **弱信号聚合**：单一维度可疑不足为据，但多个弱信号叠加可能构成明确威胁\n"
                "2. **长周期视角**：结合历史回溯数据判断是否存在持续性模式\n"
                "3. **关联度加权**：高关联度历史记录更有研判价值\n"
                "4. **误报宽容度**：内部威胁检测宁可多报不可漏报，但需合理标注置信度\n\n"
                "## 严重度判定标准\n"
                "- **critical**: 确认高密级数据外传，或累计外传>100MB，或持续>30天\n"
                "- **high**: 疑似数据外传+多个弱信号(4+)，或累计外传>50MB，或持续>7天\n"
                "- **medium**: 可疑行为+2-3个弱信号，或短期异常但无明显数据泄露证据\n"
                "- **low**: 仅有1个弱信号，或轻微异常，需持续观察\n"
                "- **info**: 单次异常但无规律，降级观察\n\n"
                "回复格式：{ \"verdict\": \"dangerous\"|\"suspicious\"|\"safe\", "
                "\"severity\": \"critical\"|\"high\"|\"medium\"|\"low\"|\"info\", "
                "\"confidence\": 0.0-1.0, "
                "\"recommended_action\": \"block\"|\"monitor\"|\"allow\"|\"quarantine\", "
                "\"reasoning\": \"综合研判逻辑\", "
                "\"evidence_summary\": [\"证据1\", \"证据2\"], "
                "\"weak_signal_score\": 整数(0-10) }"
            )

    @staticmethod
    def _fmt_window(hours: float) -> str:
        if hours < 1:
            return f"{int(hours * 60)}m"
        if hours < 24:
            return f"{hours:.0f}h"
        if hours % 24 == 0:
            return f"{hours // 24:.0f}d"
        d = int(hours // 24)
        h = int(hours % 24)
        return f"{d}d{h}h"

    async def process(
        self,
        flow: FlowEvent,
        related_context: list[dict],
        lookback_window_hours: float = 0,
        screening_result: ThreatVerdict | None = None,
    ) -> ThreatVerdict:
        """
        综合研判。

        Args:
            flow: 原始流量事件
            related_context: Layer 2 回溯后保留的高关联历史记录
            lookback_window_hours: 当前回溯窗口（小时），0 表示未经过回溯
            screening_result: Layer 1 筛查结果

        Returns:
            ThreatVerdict: 最终威胁判定
        """
        # 复用 L2 公式计算最大展示数，超出则随机抽样
        max_show = max(
            1,
            int(self.max_context_tokens * self.batch_context_ratio / TOKENS_PER_RECORD),
        )
        display_context = related_context
        if lookback_window_hours > 0 and len(related_context) > max_show:
            display_context = random.sample(related_context, max_show)
            logger.info(
                "[%s] 抽样: %s条关联 → 随机抽取 %s条 (上限=%s)",
                self.name, len(related_context), len(display_context), max_show,
            )

        context_lines = []
        if screening_result:
            context_lines.append(f"L1筛查结果: {screening_result.verdict.value} "
                               f"(置信度: {screening_result.confidence:.2f})")
            context_lines.append(f"筛查推理: {screening_result.reasoning[:200]}")

        if lookback_window_hours > 0:
            context_lines.append(f"当前回溯窗口: {self._fmt_window(lookback_window_hours)}")
            context_lines.append(f"关联历史记录总数: {len(related_context)}"
                               f"{' (展示抽样' + str(len(display_context)) + '条)' if len(related_context) > len(display_context) else ''}")

            if display_context:
                context_lines.append("\n--- 高关联历史记录 ---")
                for i, r in enumerate(display_context):
                    context_lines.append(
                        f"[{i + 1}] {r.get('src_ip', '?')} -> {r.get('dst_ip', '?')} | "
                        f"协议={r.get('protocol', '?')} | "
                        f"字节={r.get('accumulated_bytes', r.get('byte_count', 0))} | "
                        f"时间={r.get('created_at', r.get('packet_time', '?'))} | "
                        f"关联度={r.get('relevance', 0):.2f} | "
                        f"理由={r.get('match_reason', '')}"
                    )
            else:
                context_lines.append("无高关联历史记录")
        else:
            context_lines.append("未经过历史回溯（L1直接判断为可疑）")

        pattern_context = self._get_pattern_context(flow)
        user_prompt = (
            f"=== 原始流量 ===\n"
            f"{flow.to_prompt_text()}\n\n"
            f"=== 研判背景 ===\n" + "\n".join(context_lines) + "\n"
        )
        if pattern_context:
            user_prompt += (
                f"\n=== 历史模式参考（来自自适应学习系统） ===\n"
                f"{pattern_context}\n"
            )
        user_prompt += "\n请结合以上信息给出最终威胁研判。"

        last_error = ""
        for attempt in range(3):
            try:
                raw = await self.call_llm(user_prompt)
                parsed = self.extract_json_from_response(raw)

                if "error" in parsed:
                    last_error = f"JSON解析失败: {parsed.get('raw', '')[:100]}"
                    logger.warning(
                        "[%s] 第%d次解析失败: %s",
                        self.name, attempt + 1, last_error,
                    )
                    continue

                verdict_raw = parsed.get("verdict", "suspicious").lower()
                severity_raw = parsed.get("severity", "medium").lower()

                verdict_map = {
                    "dangerous": TrafficVerdict.MALICIOUS,
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

                verdict = verdict_map.get(verdict_raw, TrafficVerdict.SUSPICIOUS)
                severity = severity_map.get(severity_raw, SeverityLevel.MEDIUM)

                return ThreatVerdict(
                    flow_ids=[flow.flow_id],
                    verdict=verdict,
                    severity=severity,
                    confidence=float(parsed.get("confidence", 0.5)),
                    threat_type=parsed.get("threat_type", screening_result.threat_type if screening_result else "未知"),
                    reasoning=parsed.get("reasoning", ""),
                    evidence_summary=parsed.get("evidence_summary", []),
                    recommended_action=parsed.get("recommended_action", "monitor"),
                    extra={
                        "adjudication_raw": parsed,
                        "lookback_window_hours": lookback_window_hours,
                        "related_record_count": len(related_context),
                    },
                )

            except RuntimeError as e:
                logger.exception("[%s] LLM 调用失败: %s", self.name, e)
                raise

            except Exception as e:
                last_error = str(e)
                logger.warning(
                    "[%s] 第%d次调用异常: %s",
                    self.name, attempt + 1, last_error,
                )

        raise RuntimeError(
            f"[{self.name}] 3 次重试全部失败: {last_error}"
        )

    def _fallback_verdict(self, flow: FlowEvent, reason: str) -> ThreatVerdict:
        return ThreatVerdict(
            flow_ids=[flow.flow_id],
            verdict=TrafficVerdict.SUSPICIOUS,
            severity=SeverityLevel.LOW,
            confidence=0.3,
            threat_type="未知",
            reasoning=reason,
            recommended_action="monitor",
        )

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


__all__ = ["AdjudicationAgent"]
