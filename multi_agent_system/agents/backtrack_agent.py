"""
Layer 2 — 历史回溯智能体
=========================
从数据库调取一定周期内的相似流量记录，
自动编号后分批发送给大模型，由大模型返回低关联记录编号（反向筛选），
剔除低关联后，保留高关联记录送入 Layer 3。

核心改进：
- 自动编号：每条记录分配临时 ID（1..N），避免 LLM 输出遗漏
- 反向筛选：LLM 只列出低关联编号，宁可多保留不可漏报
- 基于上下文分批：每批 ≤ max_context_tokens × ratio / 120 条
"""

import logging
from typing import Any

from ..core.agent import BaseAgent
from ..core.message import FlowEvent

logger = logging.getLogger(__name__)

# 每条格式化记录的粗略 token 预估值（硬编码，向上取整）
TOKENS_PER_RECORD = 120


class BacktrackAgent(BaseAgent):
    """
    历史回溯智能体 (Layer 2)

    接收一条可疑流量 + 一批历史相似流量记录，
    自动编号、分批送入 LLM，反向筛选低关联记录。
    """

    def __init__(
        self,
        name: str = "BacktrackAgent",
        system_prompt: str = "",
        model_name: str = "deepseek-v4-flash",
        temperature: float = 0.3,
        max_tokens: int = 2048,
        relevance_threshold: float = 0.6,
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
        self.relevance_threshold = relevance_threshold
        self.max_context_tokens = max_context_tokens
        self.batch_context_ratio = batch_context_ratio
        if not system_prompt:
            self.system_prompt = (
                "你是一个历史流量关联分析专家。给定当前可疑流量和一批编号的历史记录，"
                "请逐条判断每条历史记录与当前流量的关联度（0.0-1.0），"
                f"列出关联度 < {self.relevance_threshold} 的记录编号（这些将被剔除）。\n\n"
                "## 关联度判定维度\n"
                "1. **目标相似度**：目的IP/端口/协议是否与当前流量一致或相似\n"
                "2. **行为模式相似度**：传输数据量、加密熵、时段模式是否相似\n"
                "3. **时序关联**：时间上是否呈现规则间隔或渐进变化\n"
                "4. **部门/角色关联**：是否同一部门、同一角色的相似行为\n\n"
                "回复格式：{ \"low_relevance_ids\": [1, 5, 12], "
                "\"summary\": \"整体回溯发现总结\" }\n"
                "注意：仅列出需剔除的低关联编号；高关联记录无需列出，会自动保留。"
            )

    # ========== 主入口 ==========

    async def process(
        self,
        flow: FlowEvent,
        similar_records: list[dict],
        lookback_window_hours: float = 24,
    ) -> dict[str, Any]:
        """
        分批反向筛选：自动编号 → 分批 → LLM 返回低关联编号 → 剔除。

        Args:
            flow: 当前待分析的可疑流量
            similar_records: 从数据库拉取的历史相似记录列表
            lookback_window_hours: 当前回溯时间窗口（小时）

        Returns:
            dict: {"matched_records": [...], "summary": "..."}
        """
        if not similar_records:
            window_label = _fmt_window(lookback_window_hours)
            return {
                "matched_records": [],
                "summary": f"近{window_label}内无历史相似记录",
            }

        # 1. 分配临时编号 1..N，建立 temp_id → record 映射
        temp_map: dict[int, dict] = {
            i + 1: r for i, r in enumerate(similar_records)
        }
        total = len(temp_map)

        # 2. 计算每批上限
        max_per_batch = max(
            1,
            int(self.max_context_tokens * self.batch_context_ratio / TOKENS_PER_RECORD),
        )

        # 3. 拆分批次
        all_ids = list(temp_map.keys())
        batches = [
            all_ids[i : i + max_per_batch]
            for i in range(0, total, max_per_batch)
        ]

        window_label = _fmt_window(lookback_window_hours)
        if len(batches) > 1:
            logger.info(
                "[%s] 分批: %s条 → %s批 (每批≤%s条, 窗口=%s)",
                self.name, total, len(batches), max_per_batch, window_label,
            )

        # 4. 逐批调用 LLM，收集低关联编号
        low_ids: set[int] = set()
        all_summaries: list[str] = []

        for batch_idx, batch_ids in enumerate(batches):
            batch_records = [temp_map[tid] for tid in batch_ids]
            batch_text = self._format_batch(batch_ids, batch_records)

            user_prompt = (
                f"=== 当前待分析流量 ===\n"
                f"{flow.to_prompt_text()}\n\n"
                f"=== 历史相似流量记录 (回溯窗口: {window_label}, "
                f"第{batch_idx + 1}/{len(batches)}批, "
                f"本批{len(batch_ids)}条) ===\n"
                f"{batch_text}\n\n"
                f"请逐条分析，列出关联度 < {self.relevance_threshold} 的记录编号。"
            )

            try:
                raw = await self.call_llm(user_prompt)
                parsed = self.extract_json_from_response(raw)

                if "error" in parsed:
                    logger.warning(
                        "[%s] 第%d批 LLM 解析失败，保守保留全部: %s",
                        self.name, batch_idx + 1, parsed.get("raw", "")[:100],
                    )
                    continue  # 解析失败 → 保守：不剔除任何记录

                batch_low = parsed.get("low_relevance_ids", [])
                if isinstance(batch_low, list):
                    low_ids.update(int(x) for x in batch_low if isinstance(x, (int, float)))

                summary = parsed.get("summary", "")
                if summary:
                    all_summaries.append(summary)

                logger.debug(
                    "[%s] 第%d批: %s条 → 低关联%s条",
                    self.name, batch_idx + 1, len(batch_ids), len(batch_low),
                )

            except Exception as e:
                logger.exception("[%s] 第%d批分析异常，保守保留全部: %s",
                                 self.name, batch_idx + 1, e)
                continue

        # 5. 保留高关联记录（= 全部 - 低关联）
        matched = [temp_map[tid] for tid in all_ids if tid not in low_ids]

        logger.info(
            "[%s] 反向筛选(%s): 总计%s条 → 排除%s条低关联 → 保留%s条 (阈值=%.2f)",
            self.name, window_label, total, len(low_ids), len(matched),
            self.relevance_threshold,
        )

        return {
            "matched_records": matched,
            "summary": "; ".join(all_summaries) if all_summaries else "",
        }

    # ========== 格式化 ==========

    def _format_batch(
        self, batch_ids: list[int], records: list[dict]
    ) -> str:
        """将一批记录格式化为编号文本（仅含临时 ID，不含原始 DB ID）。"""
        lines = []
        for tid, r in zip(batch_ids, records):
            lines.append(
                f"[{tid}] "
                f"时间={r.get('created_at', r.get('packet_time', '?'))} | "
                f"源={r.get('src_ip', '?')} -> 目标={r.get('dst_ip', '?')} | "
                f"协议={r.get('protocol', '?')} | "
                f"字节={r.get('accumulated_bytes', r.get('byte_count', 0))} | "
                f"熵={r.get('entropy', r.get('entropy_score', 0))} | "
                f"部门={r.get('department', '?')}"
            )
        return "\n".join(lines)


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


__all__ = ["BacktrackAgent", "TOKENS_PER_RECORD"]
