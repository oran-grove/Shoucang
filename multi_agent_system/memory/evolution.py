# -*- coding: utf-8 -*-
"""
自适应系统后台循环
==================
- Loop 2: 每小时运行模式聚类 (零 LLM 成本)
- Loop 3: 每周日凌晨 3:00 运行 LLM 模式提取

从 main.py 中抽取，降低入口文件的业务逻辑复杂度。
"""

import asyncio
import logging
import threading
import time as _time
from datetime import datetime as _dt

from .clustering import run_hourly_clustering
from .weekly_extract import run_weekly_extraction

logger = logging.getLogger(__name__)


async def _sleep_or_shutdown(
    shutdown_event: threading.Event, seconds: float,
) -> bool:
    """Async-safe sleep that returns True if shutdown was requested."""
    for _ in range(int(seconds)):
        if shutdown_event.is_set():
            return True
        await asyncio.sleep(1)
    return False


async def run_evolution_loop(shutdown_event: threading.Event):
    """
    自适应系统后台循环。

    Args:
        shutdown_event: 当事件被 set 时退出循环
    """
    logger.info("[Evolution] 自适应系统后台任务就绪")

    # 首次延迟 120s，给系统启动留时间
    await asyncio.sleep(120)

    last_hourly = None
    last_weekly_check = None

    while not shutdown_event.is_set():
        try:
            now = _time.time()

            # ---- Loop 2: 每小时聚类 ----
            if last_hourly is None or (now - last_hourly) >= 3600:
                logger.info("[Evolution:Loop2] 执行小时聚类...")
                result = await asyncio.to_thread(run_hourly_clustering)
                logger.info(
                    "[Evolution:Loop2] 完成: 新卡片=%d 退役=%d",
                    result.get("generated", 0),
                    result.get("skipped_groups", 0),
                )
                last_hourly = now

            # ---- Loop 3: 每日凌晨 3:00 LLM 模式提取 ----
            if last_weekly_check is None or (now - last_weekly_check) >= 3600:
                dt = _dt.now()
                if dt.hour == 3:
                    logger.info(
                        "[Evolution:Loop3] 执行每日 LLM 模式提取..."
                    )
                    try:
                        from config import get_config
                        from config.schema import BackendType
                        backends = get_config("backends")
                        # 按优先级选择可用后端: deepseek > openai > lmstudio
                        llm = None
                        chosen_backend = ""
                        for be_type, be_cfg in [
                            (BackendType.DEEPSEEK, backends.deepseek),
                            (BackendType.OPENAI, backends.openai),
                            (BackendType.LMSTUDIO, backends.lmstudio),
                        ]:
                            if be_cfg.api_key:
                                chosen_backend = be_type.value
                                if be_type == BackendType.DEEPSEEK:
                                    from ..backends.deepseek_backend import (
                                        DeepSeekBackend,
                                    )
                                    llm = DeepSeekBackend(
                                        api_base=be_cfg.api_base,
                                        api_key=be_cfg.api_key,
                                        timeout=be_cfg.timeout,
                                        max_retries=be_cfg.max_retries,
                                        default_model=be_cfg.model_name,
                                    )
                                elif be_type == BackendType.OPENAI:
                                    from ..backends import OpenAIBackend
                                    llm = OpenAIBackend(
                                        api_base=be_cfg.api_base,
                                        api_key=be_cfg.api_key,
                                        timeout=be_cfg.timeout,
                                        max_retries=be_cfg.max_retries,
                                        default_model=be_cfg.model_name,
                                    )
                                elif be_type == BackendType.LMSTUDIO:
                                    from ..backends import LMStudioBackend
                                    llm = LMStudioBackend(
                                        api_base=be_cfg.api_base,
                                        api_key=be_cfg.api_key,
                                        timeout=be_cfg.timeout,
                                        max_retries=be_cfg.max_retries,
                                        default_model=be_cfg.model_name,
                                    )
                                break
                        if llm:
                            result3 = await run_weekly_extraction(llm)
                            logger.info(
                                "[Evolution:Loop3] 完成: 候选原则=%d, 后端=%s",
                                result3.get("candidates_generated", 0),
                                chosen_backend,
                            )
                        else:
                            logger.info(
                                "[Evolution:Loop3] 无可用后端 (API Key 均未配置), 跳过"
                            )
                    except Exception as e:
                        logger.warning(
                            "[Evolution:Loop3] 执行失败: %s", e,
                        )
                    last_weekly_check = now

        except Exception as e:
            logger.error(
                "[Evolution] 后台循环异常: %s", e, exc_info=True,
            )

        if await _sleep_or_shutdown(shutdown_event, 60):
            break

    logger.info("[Evolution] 自适应后台任务已停止")


__all__ = ["run_evolution_loop"]
