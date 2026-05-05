"""
异步消息总线
============
基于 asyncio.Queue 实现的发布/订阅消息总线。
支持按收件人路由、广播和回调注册。
"""

import asyncio
import logging
from collections import defaultdict
from typing import Any, Callable, Optional

from ..core.message import AgentMessage

logger = logging.getLogger(__name__)


class MessageBus:
    """
    消息总线：
    - 每个智能体注册一个队列
    - 按 recipient 精确投递，空 recipient 为广播
    - 支持协程回调，用于下游自动处理
    """

    def __init__(self, max_queue_size: int = 10000):
        self._queues: dict[str, asyncio.Queue] = {}
        self._max_queue_size = max_queue_size
        self._callbacks: dict[str, list[Callable]] = defaultdict(list)
        self._running = False

    def register_agent(self, agent_name: str) -> asyncio.Queue:
        if agent_name not in self._queues:
            self._queues[agent_name] = asyncio.Queue(maxsize=self._max_queue_size)
            logger.info("智能体 [%s] 注册到消息总线", agent_name)
        return self._queues[agent_name]

    def unregister_agent(self, agent_name: str) -> None:
        self._queues.pop(agent_name, None)
        self._callbacks.pop(agent_name, None)

    def subscribe(self, agent_name: str, callback: Callable) -> None:
        """注册回调：当有新消息投递到该智能体时自动调用"""
        self._callbacks[agent_name].append(callback)

    def publish(self, msg: AgentMessage) -> None:
        """发布消息（同步入队，异步消费）"""
        if msg.recipient:
            # 精确投递
            q = self._queues.get(msg.recipient)
            if q is not None:
                try:
                    q.put_nowait(msg)
                except asyncio.QueueFull:
                    logger.warning("智能体 [%s] 队列已满，丢弃消息: %s",
                                   msg.recipient, msg.msg_type.value)
        else:
            # 广播
            for name, q in self._queues.items():
                if name != msg.sender:
                    try:
                        q.put_nowait(msg)
                    except asyncio.QueueFull:
                        logger.warning("智能体 [%s] 队列已满，丢弃广播消息", name)

        # 触发回调
        for cb in self._callbacks.get(msg.recipient or "__broadcast__", []):
            try:
                cb(msg)
            except Exception:
                logger.exception("回调异常")

    async def consume(self, agent_name: str, timeout: float = 1.0) -> Optional[AgentMessage]:
        """异步消费一条消息（带超时）"""
        q = self._queues.get(agent_name)
        if q is None:
            return None
        try:
            return await asyncio.wait_for(q.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    def pending_count(self, agent_name: str) -> int:
        q = self._queues.get(agent_name)
        return q.qsize() if q else 0

    @property
    def agent_names(self) -> list[str]:
        return list(self._queues.keys())


__all__ = ["MessageBus"]
