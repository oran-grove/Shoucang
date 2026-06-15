"""
多智能体逐条扫描调度器
======================
实时从 traffic_log 数据库拉取未分析的流量记录，
逐条送入检测→关联→研判管线，并持久化分析结果。

特性：
- 双模式驱动：定时触发（默认 10 分钟） + 链式连续消费（直到清空）
- 批次大小动态计算 = 并发数 × 倍数（2-3x）
- 支持从指定位置开始扫描（oldest / newest / last_id:N）
- 支持并发分析多条流量（max_concurrent_analyses 控制）
- 支持管理员运行时开关（enabled 字段）
- 分析结果回写 traffic_log（可疑/恶意）或直接删除（安全）
- 上次处理 ID 持久化到文件，重启后断点续扫

用法:
    from multi_agent_system.orchestrators.live_scan_orchestrator import (
        LiveScanOrchestrator
    )

    orchestrator = Orchestrator(config)
    await orchestrator.start()

    live_scanner = LiveScanOrchestrator(
        orchestrator=orchestrator,
        config=config.live_scan,
    )
    await live_scanner.start()
    # ... 系统运行 ...
    await live_scanner.stop()
"""

import asyncio
import json
import logging
import queue
from datetime import datetime, timezone
from typing import Optional

from config.shared_config import PROJECT_ROOT
from ..core.message import FlowEvent
from . import row_to_flow_event  # 共享的 DB row → FlowEvent 转换

logger = logging.getLogger(__name__)

_CHECKPOINT_FILE = PROJECT_ROOT / ".live_scan_checkpoint.json"


class LiveScanOrchestrator:
    """
    多智能体逐条扫描调度器。

    从 traffic_log 表中拉取未分析的流量记录（基于 id 游标），
    送入已启动的 Orchestrator 的 analyze_flow() 管线进行研判。

    启动方式:
        scanner = LiveScanOrchestrator(orchestrator, config.live_scan)
        await scanner.start()
    """

    def __init__(
        self,
        orchestrator,  # Orchestrator 实例
        config,  # LiveScanAgentConfig
        verdict_queue: Optional[queue.Queue] = None,
        deletion_queue: Optional[queue.Queue] = None,
    ):
        self._orchestrator = orchestrator
        self._config = config
        self._verdict_queue: Optional[queue.Queue] = verdict_queue
        self._deletion_queue: Optional[queue.Queue] = deletion_queue

        self._running = False
        self._scan_task: Optional[asyncio.Task] = None
        self._last_processed_id: int = 0  # 上次处理到的 traffic_log.id
        self._stats = {
            "total_scanned": 0,
            "total_malicious": 0,
            "total_suspicious": 0,
            "total_safe": 0,
            "errors": 0,
            "last_scan_time": None,
        }

    # ==================== 生命周期 ====================

    async def start(self) -> None:
        """启动逐条扫描后台任务"""
        if not self._config.enabled:
            logger.info("[LiveScan] 管理员已禁用手动扫描，跳过启动")
            return

        self._running = True
        self._load_checkpoint()
        self._scan_task = asyncio.create_task(self._scan_loop())
        logger.info(
            "[LiveScan] 逐条评判扫描已启动 | 起始ID=%s | 空闲探询=%.0fs | "
            "批次=%s (并发%s×%.1f) | 并发=%s",
            self._last_processed_id,
            self._config.idle_poll_interval_seconds,
            self._config.batch_size,
            self._config.max_concurrent_analyses,
            self._config.batch_size_multiplier,
            self._config.max_concurrent_analyses,
        )

    async def stop(self) -> None:
        """停止扫描后台任务"""
        self._running = False
        if self._scan_task and not self._scan_task.done():
            self._scan_task.cancel()
            try:
                await self._scan_task
            except asyncio.CancelledError:
                pass
        self._save_checkpoint()
        logger.info(
            "[LiveScan] 逐条评判扫描已停止 | 共处理=%s（恶意=%s 可疑=%s 安全=%s 错误=%s）",
            self._stats["total_scanned"],
            self._stats["total_malicious"],
            self._stats["total_suspicious"],
            self._stats["total_safe"],
            self._stats["errors"],
        )

    # ==================== 主循环 ====================

    async def _scan_loop(self) -> None:
        """双模式扫描循环：定时触发 + 链式连续消费"""
        while self._running:
            try:
                # ============================================================
                # 定时器模式：等待 idle_poll_interval_seconds（可中断）
                # ============================================================
                await self._interruptible_sleep(
                    self._config.idle_poll_interval_seconds
                )

                # ============================================================
                # 链式消费模式：连续拉取直到数据库清空
                # ============================================================
                while self._running:
                    rows = self._fetch_unanalyzed_batch()
                    if not rows:
                        logger.debug(
                            "[LiveScan] 无可分析数据，回归定时器模式 "
                            "(下次探询=%s秒后)",
                            self._config.idle_poll_interval_seconds,
                        )
                        break  # 无数据 → 回到外层定时器

                    logger.info(
                        "[LiveScan] 拉取到 %s 条待分析记录，并发分析中 "
                        "(并发上限=%s)...",
                        len(rows),
                        self._config.max_concurrent_analyses,
                    )

                    # 并发分析整批（semaphore 控制并发上限，无逐条节流）
                    semaphore = asyncio.Semaphore(
                        self._config.max_concurrent_analyses
                    )

                    async def analyze_one(row: dict) -> None:
                        async with semaphore:
                            await self._analyze_row(row)

                    tasks = [
                        asyncio.create_task(analyze_one(row))
                        for row in rows
                    ]
                    await asyncio.gather(*tasks, return_exceptions=True)

                    # 批次结束后保存断点
                    self._save_checkpoint()
                    # 立即回到内层 while，尝试拉取下一批

            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("[LiveScan] 扫描循环异常，10秒后重试")
                await asyncio.sleep(10.0)

    async def _interruptible_sleep(self, seconds: float) -> None:
        """分段 sleep，每 1 秒检查 _running，支持快速安全关闭。"""
        remaining = seconds
        while remaining > 0 and self._running:
            await asyncio.sleep(min(1.0, remaining))
            remaining -= 1.0

    # ==================== 数据获取 ====================

    def _fetch_unanalyzed_batch(self) -> list[dict]:
        """
        从 traffic_log 表中拉取一批未分析的记录。
        委托 database 模块执行查询，禁止直接访问 MySQL。
        """
        from database import get_unanalyzed_traffic
        return get_unanalyzed_traffic(
            self._last_processed_id, self._config.batch_size
        )

    # ==================== 逐条分析 ====================

    async def _analyze_row(self, row: dict) -> None:
        """对单条流量日志执行检测→关联→研判管线"""
        row_id = row.get("id", 0)
        try:
            # 构造 FlowEvent（使用共享转换函数）
            flow_event = row_to_flow_event(row)

            # 调用 Orchestrator 的完整分析管线
            result = await self._orchestrator.analyze_flow(flow_event)

            # 更新统计
            self._stats["total_scanned"] += 1
            if result:
                verdict = result.verdict.value
                if verdict == "malicious":
                    self._stats["total_malicious"] += 1
                elif verdict == "suspicious":
                    self._stats["total_suspicious"] += 1
                else:
                    self._stats["total_safe"] += 1

                logger.info(
                    "[LiveScan] id=%s src=%s → %s (置信度=%.2f)",
                    row_id, row.get("src_ip", "?"), verdict, result.confidence,
                )

                if verdict == "safe":
                    self._enqueue_deletion(row_id)
                else:
                    self._enqueue_verdict(row_id, verdict,
                                          reasoning=result.reasoning)
            else:
                self._stats["total_suspicious"] += 1
                self._enqueue_verdict(row_id, "suspicious", reasoning="")
                logger.warning("[LiveScan] id=%s 返回 None，标记为可疑", row_id)

            # 成功 → 推进游标
            if row_id > self._last_processed_id:
                self._last_processed_id = row_id

        except Exception:
            self._stats["errors"] += 1
            logger.exception("[LiveScan] 分析 id=%s 失败，不推进游标等待重试", row_id)
            # 失败不推进游标 → 下次轮询自动重试，不操作数据库

        self._stats["last_scan_time"] = datetime.now(timezone.utc).isoformat()

    def _enqueue_verdict(self, row_id: int, verdict: str,
                         reasoning: str = "") -> None:
        """将判定结果放入队列，供 verdict_writer 批量 UPDATE 数据库。"""
        if self._verdict_queue is None:
            return
        verdict_map = {"safe": 0, "suspicious": 1, "malicious": 2}
        ai_verdict = verdict_map.get(verdict)
        if ai_verdict is None:
            return
        try:
            self._verdict_queue.put_nowait({
                "traffic_id": row_id,
                "ai_verdict": ai_verdict,
                "ai_reasoning": reasoning[:2000],
            })
        except queue.Full:
            pass

    def _enqueue_deletion(self, row_id: int) -> None:
        """将安全流量的 ID 放入删除队列，供 deletion_writer 批量 DELETE。"""
        if self._deletion_queue is None:
            return
        try:
            self._deletion_queue.put_nowait(row_id)
        except queue.Full:
            pass  # 队列满时丢弃，避免阻塞扫描管线

    # ==================== 断点持久化 ====================

    def _load_checkpoint(self) -> None:
        """从检查点文件恢复上次处理位置"""
        try:
            if _CHECKPOINT_FILE.exists():
                data = json.loads(_CHECKPOINT_FILE.read_text(encoding="utf-8"))
                self._last_processed_id = data.get("last_id", 0)
                self._stats = data.get("stats", self._stats)

                # 支持 start_from 配置覆盖
                start_from = self._config.start_from
                if start_from == "oldest":
                    self._last_processed_id = 0
                elif start_from == "newest":
                    self._last_processed_id = self._get_max_id()
                elif start_from.startswith("last_id:"):
                    try:
                        self._last_processed_id = int(start_from.split(":")[1])
                    except (ValueError, IndexError):
                        pass

                logger.info(
                    "[LiveScan] 从断点恢复: last_id=%s, 已处理=%s",
                    self._last_processed_id, self._stats.get("total_scanned", 0),
                )
            else:
                self._init_checkpoint()
        except Exception:
            logger.exception("[LiveScan] 加载断点失败，从头开始")
            self._last_processed_id = 0

    def _init_checkpoint(self) -> None:
        """初始化检查点（首次运行）"""
        start_from = self._config.start_from
        if start_from == "newest":
            self._last_processed_id = self._get_max_id()
        elif start_from.startswith("last_id:"):
            try:
                self._last_processed_id = int(start_from.split(":")[1])
            except (ValueError, IndexError):
                self._last_processed_id = 0
        else:
            self._last_processed_id = 0
        logger.info("[LiveScan] 初始化: 起始ID=%s", self._last_processed_id)

    def _save_checkpoint(self) -> None:
        """持久化当前处理位置到检查点文件"""
        try:
            data = {
                "last_id": self._last_processed_id,
                "stats": self._stats,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            _CHECKPOINT_FILE.write_text(
                json.dumps(data, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception:
            logger.exception("[LiveScan] 保存断点失败")

    def _get_max_id(self) -> int:
        """获取 traffic_log 表当前最大 id（委托 database 模块）。"""
        from database import get_traffic_max_id
        return get_traffic_max_id()

    # ==================== 统计与监控 ====================

    @property
    def stats(self) -> dict:
        """获取当前扫描统计信息"""
        return dict(self._stats)

    @property
    def last_processed_id(self) -> int:
        """获取当前游标位置"""
        return self._last_processed_id

    @property
    def is_running(self) -> bool:
        """扫描任务是否正在运行"""
        return self._running

    def update_config(self, config) -> None:
        """
        运行时更新配置（由管理员通过 WebUI 动态调整）。
        
        注意：节流间隔和批次大小等参数在主循环下一轮生效。
        """
        was_enabled = self._config.enabled
        self._config = config

        if config.enabled and not was_enabled:
            logger.info("[LiveScan] 管理员已启用扫描")
            self._running = True
            if self._scan_task is None or self._scan_task.done():
                self._scan_task = asyncio.create_task(self._scan_loop())
        elif not config.enabled and was_enabled:
            logger.info("[LiveScan] 管理员已禁用扫描，当前批次结束后暂停")
            self._running = False


__all__ = ["LiveScanOrchestrator"]