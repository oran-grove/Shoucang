"""
关联智能体
==========
收集可疑流量，按源IP/目的IP/用户ID特征分组。
支持多层时间窗口：实时(5min) + 短期(1h) + 中期(24h)。
长周期(7d/30d)窗口由深度分析子模块的时序异常智能体承担。

2026-05 重构：
- 从单一30分钟窗口扩展为多层窗口
- 支持按 user_id / department / asset_type 多维分组
- 提示词增加长周期隐蔽泄密的关联维度
"""

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from typing import Optional

from ..core.agent import BaseAgent
from ..core.message import (
    FlowEvent, ThreatVerdict,
    TrafficVerdict, SeverityLevel,
)

logger = logging.getLogger(__name__)


@dataclass
class CorrelationWindowConfig:
    """多层时间窗口配置"""
    realtime_minutes: int = 5
    short_minutes: int = 60
    medium_minutes: int = 1440  # 24h
    min_records_realtime: int = 2
    min_records_short: int = 3
    min_records_medium: int = 5


class CorrelationAgent(BaseAgent):
    """
    关联智能体（多层窗口重构版）：
    - 内部维护按多种键（src_ip / user_id / department）分组的流量缓冲区
    - 支持实时(5m)、短期(1h)、中期(24h)三层窗口
    - 当某组记录数达到对应窗口阈值时触发关联分析
    - 输出 CORRELATION_RESULT 消息
    """

    def __init__(
        self,
        name: str = "CorrelationAgent",
        system_prompt: str = "",
        model_name: str = "deepseek-v4-flash",
        temperature: float = 0.3,
        max_tokens: int = 2048,
        window_config: Optional[CorrelationWindowConfig] = None,
        # 向后兼容的参数（已废弃，由 window_config 替代）
        correlation_window_minutes: int = 30,
        min_records_to_correlate: int = 5,
        max_buffer_per_src: int = 100,
        cleanup_interval_seconds: int = 60,
    ):
        default_prompt = (
            "你是一个长周期威胁关联分析专家。请分析以下来自同一实体的历史流量序列，"
            "判断是否存在隐蔽的数据泄露模式。\n\n"
            "## 重点关注的隐蔽泄密模式\n"
            "1. **周期性低频外传**：每天/每周固定时间的小量数据传输（<5MB），"
            "尤其注意非工作时段的规律性传输\n"
            "2. **渐进式数据窃取**：目标IP或端口随时间变化但数据流特征相似"
            "（相同协议、相似熵值、相同JA4指纹）\n"
            "3. **\"低慢\"(Low-and-Slow)模式**：每次传输量刻意控制在阈值以下"
            "（如<10MB），避开流量告警，但累计跨越数天/数周\n"
            "4. **分段式外传**：将大文件拆分到多个时间点、多个目标IP分别传输，"
            "单次流看不出问题，聚合后呈现完整的数据窃取链条\n"
            "5. **C2信标/心跳**：定时间隔的极小数据包（<1KB），维持与外部C2的连接，"
            "等待指令下发\n"
            "6. **跨资产访问模式**：同一用户在短时间内访问多个高密级数据资产，"
            "呈现「收集后外传」的行为链条\n\n"
            "## 判定标准\n"
            "- 若存在周期性低频外传 + 高熵加密 + 非工作时段 → 数据外传\n"
            "- 若存在固定间隔极小包 + 持久连接 → C2心跳\n"
            "- 若存在多资产跨越 + 随后大流量外传 → 数据收集后泄露\n"
            "- 若仅有轻微异常但未形成明确模式 → 无关联\n\n"
            "回复格式：{ \"is_correlated\": true|false, "
            "\"correlation_type\": \"数据外传\"|\"横向移动\"|\"C2心跳\"|\"端口扫描\"|"
            "\"低慢泄密\"|\"分段外传\"|\"周期性异常\"|\"无关联\", "
            "\"confidence\": 0.0-1.0, "
            "\"reasoning\": \"关联分析逻辑（请明确指出时间模式/数据量模式/行为模式）\", "
            "\"pattern_indicators\": [\"指标1\", \"指标2\"] }"
        )
        super().__init__(
            name=name,
            system_prompt=system_prompt or default_prompt,
            model_name=model_name,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        self.window_config = window_config or CorrelationWindowConfig()
        self.max_buffer_per_key = max_buffer_per_src
        self.cleanup_interval = cleanup_interval_seconds

        # 多键多窗口缓冲区: group_key -> list[(FlowEvent, verdict, timestamp)]
        self._buffer: dict[str, list[tuple[FlowEvent, ThreatVerdict]]] = defaultdict(list)
        # 已触发的关联ID（避免重复触发同一组在短时间内的多次分析）
        self._triggered_groups: dict[str, datetime] = {}
        self._triggered_cooldown = timedelta(minutes=10)
        self._cleanup_task: Optional[asyncio.Task] = None

    async def start_background_cleanup(self) -> None:
        """启动后台清理协程"""
        async def cleanup_loop():
            while True:
                await asyncio.sleep(self.cleanup_interval)
                self._cleanup_expired()
                self._cleanup_triggered_cooldown()
        self._cleanup_task = asyncio.create_task(cleanup_loop())
        logger.info("[%s] 后台清理任务已启动", self.name)

    async def stop_background_cleanup(self) -> None:
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None

    def _cleanup_expired(self) -> None:
        """清理超过中期窗口的过期记录"""
        now = datetime.now(timezone.utc)
        medium_window = timedelta(minutes=self.window_config.medium_minutes)
        expired_keys = []
        for key, records in self._buffer.items():
            records[:] = [(f, v) for f, v in records
                          if now - f.timestamp < medium_window]
            if not records:
                expired_keys.append(key)
        for key in expired_keys:
            del self._buffer[key]
        if expired_keys:
            logger.debug("[%s] 清理了 %d 个过期缓冲区", self.name, len(expired_keys))

    def _cleanup_triggered_cooldown(self) -> None:
        """清理过期的冷却记录"""
        now = datetime.now(timezone.utc)
        expired = [k for k, t in self._triggered_groups.items()
                   if now - t > self._triggered_cooldown]
        for k in expired:
            del self._triggered_groups[k]

    def _make_group_keys(self, flow: FlowEvent) -> list[str]:
        """
        生成多维分组键：
        - src_ip（主要）
        - user_id（如果存在）
        - department（如果存在）
        """
        keys = []
        if flow.src_ip:
            keys.append(f"ip:{flow.src_ip}")
        if flow.user_id:
            keys.append(f"user:{flow.user_id}")
        if flow.department:
            keys.append(f"dept:{flow.department}")
        if flow.dst_ip:
            # 相同目标IP的关联也可能有意义（多个用户向同一外部地址传输）
            keys.append(f"dst:{flow.dst_ip}")
        return keys

    def add_flow(self, flow: FlowEvent, verdict: ThreatVerdict) -> tuple[bool, str]:
        """
        向缓冲区添加一条可疑流量记录。
        返回 (是否触发, 触发的分组键)。

        触发条件（多层窗口）：
        - 实时窗口(5min): >= 2条记录
        - 短期窗口(1h): >= 3条记录
        - 中期窗口(24h): >= 5条记录
        """
        if verdict.verdict not in (TrafficVerdict.SUSPICIOUS, TrafficVerdict.MALICIOUS):
            return False, ""

        group_keys = self._make_group_keys(flow)
        if not group_keys:
            return False, ""

        triggered_key = ""
        now = datetime.now(timezone.utc)

        for key in group_keys:
            buf = self._buffer[key]
            buf.append((flow, verdict))

            # 限制缓冲区大小
            if len(buf) > self.max_buffer_per_key:
                buf.pop(0)

            # 检查是否已触发且仍在冷却中
            if key in self._triggered_groups:
                continue

            # 计算各窗口内的记录数
            count_realtime = sum(1 for f, _ in buf
                                 if now - f.timestamp < timedelta(minutes=self.window_config.realtime_minutes))
            count_short = sum(1 for f, _ in buf
                              if now - f.timestamp < timedelta(minutes=self.window_config.short_minutes))
            count_medium = sum(1 for f, _ in buf
                               if now - f.timestamp < timedelta(minutes=self.window_config.medium_minutes))

            triggered = (
                count_realtime >= self.window_config.min_records_realtime or
                count_short >= self.window_config.min_records_short or
                count_medium >= self.window_config.min_records_medium
            )

            if triggered:
                self._triggered_groups[key] = now
                triggered_key = key
                window_name = (
                    "realtime" if count_realtime >= self.window_config.min_records_realtime
                    else "short" if count_short >= self.window_config.min_records_short
                    else "medium"
                )
                logger.info(
                    "[%s] 触发关联分析: key=%s, window=%s, records=%d",
                    self.name, key, window_name, len(buf)
                )
                return True, key

        return False, ""

    def get_group(self, key: str) -> list[tuple[FlowEvent, ThreatVerdict]]:
        return self._buffer.get(key, [])

    async def process_group(self, key: str) -> Optional[ThreatVerdict]:
        """
        对指定分组的流量进行关联分析。
        """
        records = self._buffer.get(key, [])
        if not records:
            return None

        flow_ids = [f.flow_id for f, _ in records]

        # 丰富提示：包含时间跨度、频次统计等
        now = datetime.now(timezone.utc)
        timestamps = [f.timestamp for f, _ in records]
        time_span = (max(timestamps) - min(timestamps)) if len(timestamps) >= 2 else timedelta(0)
        total_bytes = sum(f.byte_count for f, _ in records)
        avg_entropy = sum(f.entropy_score for f, _ in records) / len(records) if records else 0

        prompt_lines = [
            f"关联键: {key}",
            f"分析记录数: {len(records)}",
            f"时间跨度: {time_span}",
            f"累计数据量: {total_bytes} bytes ({total_bytes / 1_000_000:.1f} MB)",
            f"平均载荷熵: {avg_entropy:.2f}",
            "---",
            "=== 各记录详情 ===",
        ]
        for i, (flow, verdict) in enumerate(records, 1):
            prompt_lines.append(f"\n记录{i}: {flow.to_prompt_text()}")
            prompt_lines.append(f"  检测判定: {verdict.verdict.value} (置信度: {verdict.confidence})")
            if verdict.threat_type:
                prompt_lines.append(f"  检测威胁类型: {verdict.threat_type}")

        # 追加模式分析提示
        prompt_lines.append("\n=== 请重点分析以下模式 ===")
        prompt_lines.append("1. 时间分布：是否存在固定周期或非工作时段聚集？")
        prompt_lines.append("2. 数据量模式：单次均小但累计可观？是否存在渐变趋势？")
        prompt_lines.append("3. 目标特征：是否存在目标IP/端口的规律性切换？")
        prompt_lines.append("4. 整体研判：综合以上，是否存在隐蔽泄密链条？")

        prompt = "\n".join(prompt_lines)

        try:
            response = await self.call_llm(prompt)
        except Exception as e:
            logger.error("[%s] LLM 关联分析失败: %s", self.name, e)
            return ThreatVerdict(
                flow_ids=flow_ids,
                verdict=TrafficVerdict.UNKNOWN,
                severity=SeverityLevel.LOW,
                confidence=0.0,
                threat_type="关联分析失败",
                reasoning=f"LLM 异常: {e}",
                recommended_action="monitor",
                correlation_result_id=self.name,
            )

        parsed = self.extract_json_from_response(response)
        is_correlated = parsed.get("is_correlated", False)
        correlation_type = parsed.get("correlation_type", "无关联")
        confidence = float(parsed.get("confidence", 0.0))
        reasoning = parsed.get("reasoning", response[:500])
        pattern_indicators = parsed.get("pattern_indicators", [])

        if is_correlated and confidence >= 0.55:
            return ThreatVerdict(
                flow_ids=flow_ids,
                verdict=TrafficVerdict.SUSPICIOUS,
                severity=SeverityLevel.MEDIUM,
                confidence=confidence,
                threat_type=f"关联: {correlation_type}",
                reasoning=reasoning,
                recommended_action="monitor",
                correlation_result_id=self.name,
                extra={
                    "llm_raw": response,
                    "group_key": key,
                    "record_count": len(records),
                    "time_span_minutes": time_span.total_seconds() / 60,
                    "total_bytes": total_bytes,
                    "pattern_indicators": pattern_indicators,
                },
            )
        return ThreatVerdict(
            flow_ids=flow_ids,
            verdict=TrafficVerdict.SAFE,
            severity=SeverityLevel.LOW,
            confidence=confidence,
            threat_type="未发现关联威胁",
            reasoning=reasoning,
            recommended_action="allow",
            correlation_result_id=self.name,
        )

    async def process(self, *args, **kwargs) -> Optional[ThreatVerdict]:
        """
        BaseAgent 抽象方法实现。
        编排器通过 add_flow() + process_group() 直接调用，
        此方法作为消息总线兼容入口保留。
        """
        return None


__all__ = ["CorrelationAgent"]