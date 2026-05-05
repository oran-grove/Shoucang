"""
关联智能体
==========
收集可疑流量，按源IP/目的IP/行为特征分组。
当某组的流量记录达到阈值或时间窗口到期时，调用 LLM 进行关联分析。
"""

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Optional

from ..core.agent import BaseAgent
from ..core.message import (
    AgentMessage, FlowEvent, MessageType, ThreatVerdict,
    TrafficVerdict, SeverityLevel,
)

logger = logging.getLogger(__name__)


class CorrelationAgent(BaseAgent):
    """
    关联智能体：
    - 内部维护按 src_ip 分组的流量缓冲区
    - 当某组记录数 >= min_records_to_correlate 时触发关联分析
    - 同时有定时任务清理过期记录
    - 输出 CORRELATION_RESULT 消息
    """

    def __init__(
        self,
        name: str = "CorrelationAgent",
        system_prompt: str = "",
        model_name: str = "gpt-4o",
        temperature: float = 0.3,
        max_tokens: int = 2048,
        correlation_window_minutes: int = 30,
        min_records_to_correlate: int = 5,
        max_buffer_per_src: int = 100,
        cleanup_interval_seconds: int = 60,
    ):
        default_prompt = (
            "你是一个网络安全关联分析专家。给定一组来自同一源IP或同类特征的流量记录，"
            "请判断它们之间是否存在关联的恶意行为模式。"
            "回复格式：{ \"is_correlated\": true|false, "
            "\"correlation_type\": \"数据外传\"|\"横向移动\"|\"C2心跳\"|\"端口扫描\"|\"无关联\", "
            "\"confidence\": 0.0-1.0, \"reasoning\": \"分析逻辑\" }"
        )
        super().__init__(
            name=name,
            system_prompt=system_prompt or default_prompt,
            model_name=model_name,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        self.correlation_window = timedelta(minutes=correlation_window_minutes)
        self.min_records = min_records_to_correlate
        self.max_buffer_per_src = max_buffer_per_src
        self.cleanup_interval = cleanup_interval_seconds
        # 缓冲区: src_ip -> list[(FlowEvent, verdict)]
        self._buffer: dict[str, list[tuple[FlowEvent, ThreatVerdict]]] = defaultdict(list)
        self._cleanup_task: Optional[asyncio.Task] = None

    async def start_background_cleanup(self) -> None:
        """启动后台清理协程"""
        async def cleanup_loop():
            while True:
                await asyncio.sleep(self.cleanup_interval)
                self._cleanup_expired()
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
        now = datetime.now(timezone.utc)
        expired_keys = []
        for src_ip, records in self._buffer.items():
            records[:] = [(f, v) for f, v in records
                          if now - f.timestamp < self.correlation_window]
            if not records:
                expired_keys.append(src_ip)
        for key in expired_keys:
            del self._buffer[key]
        if expired_keys:
            logger.debug("[%s] 清理了 %d 个过期缓冲区", self.name, len(expired_keys))

    def add_flow(self, flow: FlowEvent, verdict: ThreatVerdict) -> bool:
        """
        向缓冲区添加一条可疑流量记录。
        返回 True 表示该组达到关联阈值，应触发分析。
        """
        # 只关注可疑/恶意的流
        if verdict.verdict not in (TrafficVerdict.SUSPICIOUS, TrafficVerdict.MALICIOUS):
            return False
        key = flow.src_ip or flow.dst_ip
        if not key:
            return False
        buf = self._buffer[key]
        buf.append((flow, verdict))
        # 限制缓冲区大小
        if len(buf) > self.max_buffer_per_src:
            buf.pop(0)
        return len(buf) >= self.min_records

    def get_group(self, key: str) -> list[tuple[FlowEvent, ThreatVerdict]]:
        return self._buffer.get(key, [])

    async def process_group(self, key: str) -> Optional[ThreatVerdict]:
        """
        对指定分组的流量进行关联分析。
        """
        records = self._buffer.get(key, [])
        if not records:
            return None
        # 构造提示
        flow_ids = [f.flow_id for f, _ in records]
        prompt_lines = [f"源标识: {key}", f"时间窗口: {self.correlation_window}",
                        f"关联记录数: {len(records)}", "---"]
        for i, (flow, verdict) in enumerate(records, 1):
            prompt_lines.append(f"记录{i}: {flow.to_prompt_text()}")
            prompt_lines.append(f"  检测判定: {verdict.verdict.value} (置信度: {verdict.confidence})")
        prompt = "\n".join(prompt_lines)

        try:
            response = await self.call_llm(prompt)
        except Exception as e:
            logger.error("[%s] LLM 相关分析失败: %s", self.name, e)
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

        if is_correlated and confidence >= 0.60:
            return ThreatVerdict(
                flow_ids=flow_ids,
                verdict=TrafficVerdict.SUSPICIOUS,
                severity=SeverityLevel.MEDIUM,
                confidence=confidence,
                threat_type=f"关联: {correlation_type}",
                reasoning=reasoning,
                recommended_action="monitor",
                correlation_result_id=self.name,
                extra={"llm_raw": response, "group_key": key,
                       "record_count": len(records)},
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

    async def process(self, event: AgentMessage) -> Optional[ThreatVerdict]:
        """
        接收 FlowEvent 或 DetectionResult，做缓冲后触发关联分析。
        """
        if event.msg_type == MessageType.FLOW_EVENT:
            flow = event.payload
            # 没有检测结果时先做一个简易判断
            temp_v = ThreatVerdict(verdict=TrafficVerdict.SUSPICIOUS, confidence=0.5)
            triggered = self.add_flow(flow, temp_v)
            if triggered:
                return await self.process_group(flow.src_ip or flow.dst_ip)
        elif event.msg_type == MessageType.DETECTION_RESULT:
            verdict: ThreatVerdict = event.payload
            if verdict.flow_ids and verdict.verdict in (TrafficVerdict.SUSPICIOUS,
                                                           TrafficVerdict.MALICIOUS):
                # 需要一个 FlowEvent 上下文——从 extra 中找
                pass
        return None


__all__ = ["CorrelationAgent"]
