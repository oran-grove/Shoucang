"""
Layer 2 — 历史回溯智能体
=========================
从数据库调取一定周期内的相似流量记录，
由大模型判断每条记录的关联度，剔除低关联记录，
将高关联记录与原始流量数据合并送入 Layer 3。
"""

import logging
from typing import Any

from ..core.agent import BaseAgent
from ..core.message import FlowEvent

logger = logging.getLogger(__name__)


class BacktrackAgent(BaseAgent):
    """
    历史回溯智能体 (Layer 2)

    接收一条可疑流量 + 一批历史相似流量记录，
    调用 LLM 逐条判断关联度，返回高关联记录列表。
    """

    def __init__(
        self,
        name: str = "BacktrackAgent",
        system_prompt: str = "",
        model_name: str = "deepseek-v4-flash",
        temperature: float = 0.3,
        max_tokens: int = 2048,
        relevance_threshold: float = 0.6,
    ):
        super().__init__(
            name=name,
            system_prompt=system_prompt,
            model_name=model_name,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        self.relevance_threshold = relevance_threshold
        if not system_prompt:
            self.system_prompt = (
                "你是一个历史流量关联分析专家。给定当前可疑流量和一批来自相同源IP/部门"
                "的历史流量记录，请逐条判断每条历史记录与当前流量的关联度（0.0-1.0），"
                "只保留关联度 >= 设定阈值的记录。\n\n"
                "## 关联度判定维度\n"
                "1. **目标相似度**：目的IP/端口/协议是否与当前流量一致或相似\n"
                "2. **行为模式相似度**：传输数据量、加密熵、时段模式是否相似\n"
                "3. **时序关联**：时间上是否呈现规则间隔或渐进变化\n"
                "4. **部门/角色关联**：是否同一部门、同一角色的相似行为\n\n"
                "回复格式：{ \"relevant_records\": ["
                "{\"record_id\": 整数, \"relevance\": 0.0-1.0, \"reason\": \"简短理由\"}, ...], "
                "\"summary\": \"整体回溯发现总结\" }"
            )

    async def process(
        self,
        flow: FlowEvent,
        similar_records: list[dict],
        lookback_window_hours: int = 24,
    ) -> dict[str, Any]:
        """
        对一批历史相似记录执行关联度分析。

        Args:
            flow: 当前待分析的可疑流量
            similar_records: 从数据库拉取的历史相似记录列表
            lookback_window_hours: 当前回溯时间窗口（小时）

        Returns:
            dict: {
                "matched_records": [filtered list with relevance scores],
                "summary": "整体回溯发现总结"
            }
        """
        if not similar_records:
            return {"matched_records": [], "summary": f"近{self._fmt_window(lookback_window_hours)}内无历史相似记录"}

        history_text = self._format_similar_records(similar_records)
        window_label = self._fmt_window(lookback_window_hours)
        user_prompt = (
            f"=== 当前待分析流量 ===\n"
            f"{flow.to_prompt_text()}\n\n"
            f"=== 历史相似流量记录 (回溯窗口: {window_label}, 共{len(similar_records)}条) ===\n"
            f"{history_text}\n\n"
            f"请逐条分析每条历史记录与当前流量的关联度，"
            f"只保留关联度 >= {self.relevance_threshold} 的记录。"
        )

        try:
            raw = await self.call_llm(user_prompt)
            parsed = self.extract_json_from_response(raw)

            if "error" in parsed:
                logger.warning("[%s] LLM 解析失败: %s", self.name, parsed.get("raw", "")[:100])
                return {"matched_records": [], "summary": "LLM解析失败，回溯结果不可用"}

            relevant = []
            all_records = parsed.get("relevant_records", [])
            if not isinstance(all_records, list):
                all_records = []

            id_map = {r.get("id", i): r for i, r in enumerate(similar_records)}

            for item in all_records:
                relevance = float(item.get("relevance", 0))
                if relevance >= self.relevance_threshold:
                    record_id = item.get("record_id")
                    matched = id_map.get(record_id, {})
                    matched["relevance"] = relevance
                    matched["match_reason"] = item.get("reason", "")
                    relevant.append(matched)

            logger.info(
                "[%s] 回溯结果(%s): 总相似=%d → 高关联=%d (阈值=%.2f)",
                self.name, window_label, len(similar_records), len(relevant), self.relevance_threshold,
            )

            return {
                "matched_records": relevant,
                "summary": parsed.get("summary", ""),
            }

        except Exception as e:
            logger.exception("[%s] 回溯分析异常: %s", self.name, e)
            return {"matched_records": [], "summary": f"回溯分析异常: {str(e)}"}

    def _format_similar_records(self, records: list[dict]) -> str:
        lines = []
        for i, r in enumerate(records):
            lines.append(
                f"[{i + 1}] ID={r.get('id', '?')} | "
                f"时间={r.get('created_at', r.get('packet_time', '?'))} | "
                f"源={r.get('src_ip', '?')} -> 目标={r.get('dst_ip', '?')} | "
                f"协议={r.get('protocol', '?')} | "
                f"字节={r.get('traffic_size', r.get('byte_count', 0))} | "
                f"熵={r.get('entropy', r.get('entropy_score', 0))} | "
                f"部门={r.get('department', '?')}"
            )
        return "\n".join(lines)

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


__all__ = ["BacktrackAgent"]
