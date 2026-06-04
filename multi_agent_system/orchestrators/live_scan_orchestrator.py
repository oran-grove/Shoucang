"""
第一类智能体队列调度器 — 逐条评判队列扫描
==========================================
实时从 traffic_log 数据库拉取未分析的流量记录，
逐条送入检测→关联→研判管线，并持久化分析结果。

特性：
- 支持从指定位置开始扫描（oldest / newest / last_id:N）
- 支持并发分析多条流量（max_concurrent_analyses 控制）
- 支持节流间隔（scan_interval_seconds 控制每条分析间隔）
- 支持管理员运行时开关（enabled 字段）
- 分析结果回写 traffic_log（is_blocked / analysis 相关字段）
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
        db_config=DB_CONFIG,
    )
    await live_scanner.start()
    # ... 系统运行 ...
    await live_scanner.stop()
"""

import asyncio
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pymysql

from ..core.message import FlowEvent

logger = logging.getLogger(__name__)

# 确保项目根目录在 sys.path 中
_PROJECT_ROOT = Path(__file__).parent.parent.parent.resolve()
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from config.shared_config import DB_CONFIG, DbConfig  # noqa: E402

_CHECKPOINT_FILE = _PROJECT_ROOT / ".live_scan_checkpoint.json"


class LiveScanOrchestrator:
    """
    第一类智能体队列调度器 — 逐条评判队列扫描。

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
        db_config: Optional[DbConfig] = None,
    ):
        self._orchestrator = orchestrator
        self._config = config
        self._db_config: DbConfig = db_config or DB_CONFIG

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
            "[LiveScan] 逐条评判扫描已启动 | 起始ID=%s | 间隔=%.1fs | 批次=%s | 并发=%s",
            self._last_processed_id,
            self._config.scan_interval_seconds,
            self._config.batch_size,
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
        """主扫描循环：分批拉取 → 逐条分析 → 节流等待"""
        while self._running:
            try:
                # 拉取一批未分析的流量记录
                rows = self._fetch_unanalyzed_batch()
                if not rows:
                    # 没有新记录，休眠间隔后重试
                    await asyncio.sleep(self._config.scan_interval_seconds)
                    continue

                logger.info("[LiveScan] 拉取到 %s 条待分析记录，开始逐条研判...", len(rows))

                # 并发限流分析
                semaphore = asyncio.Semaphore(self._config.max_concurrent_analyses)

                async def analyze_one(row: dict) -> None:
                    async with semaphore:
                        await self._analyze_row(row)

                # 逐条分析（并发控制由 semaphore 保证）
                tasks = []
                for row in rows:
                    if not self._running:
                        break
                    task = asyncio.create_task(analyze_one(row))
                    tasks.append(task)
                    # 节流：每条之间等待 scan_interval_seconds
                    await asyncio.sleep(self._config.scan_interval_seconds)

                # 等待当前批次所有任务完成
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)

                # 批次结束后保存断点
                self._save_checkpoint()

            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("[LiveScan] 扫描循环异常，10秒后重试")
                await asyncio.sleep(10.0)

    # ==================== 数据获取 ====================

    def _fetch_unanalyzed_batch(self) -> list[dict]:
        """
        从 traffic_log 表中拉取一批未分析的记录。
        游标基于 id > _last_processed_id，按 id 升序。
        """
        conn = None
        try:
            conn = pymysql.connect(**self._db_config)
            with conn.cursor(pymysql.cursors.DictCursor) as cursor:
                sql = (
                    "SELECT * FROM traffic_log "
                    "WHERE id > %s "
                    "ORDER BY id ASC "
                    "LIMIT %s"
                )
                cursor.execute(sql, (self._last_processed_id, self._config.batch_size))
                rows = cursor.fetchall()
                return list(rows) if rows else []
        except Exception:
            logger.exception("[LiveScan] 拉取流量日志失败")
            return []
        finally:
            if conn:
                conn.close()

    # ==================== 逐条分析 ====================

    async def _analyze_row(self, row: dict) -> None:
        """对单条流量日志执行检测→关联→研判管线"""
        row_id = row.get("id", 0)
        try:
            # 构造 FlowEvent
            flow_event = self._row_to_flow_event(row)

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
            else:
                self._stats["total_safe"] += 1

        except Exception:
            self._stats["errors"] += 1
            logger.exception("[LiveScan] 分析 id=%s 失败", row_id)

        finally:
            # 无论成功失败都推进游标
            if row_id > self._last_processed_id:
                self._last_processed_id = row_id
            self._stats["last_scan_time"] = datetime.now(timezone.utc).isoformat()

    # ==================== 数据转换 ====================

    @staticmethod
    def _row_to_flow_event(row: dict) -> FlowEvent:
        """
        将 traffic_log 数据库行转换为 FlowEvent。

        traffic_log 表字段:
            id, src_ip, dst_ip, department, protocol, packet_time,
            traffic_size, is_blocked, created_at, entropy, src_port,
            dst_port, src_tag, sp_tag, dp_tag, accumulated_pkts,
            accumulated_bytes, global_pps, global_bps, avg_entropy, ...
        """
        return FlowEvent(
            src_ip=row.get("src_ip", "0.0.0.0"),
            dst_ip=row.get("dst_ip", "0.0.0.0"),
            src_port=row.get("src_port") or 0,
            dst_port=row.get("dst_port") or 0,
            protocol=row.get("protocol", "TCP"),
            department=row.get("department", ""),
            byte_count=row.get("traffic_size") or 0,
            entropy_score=row.get("entropy") or 0.0,
            extra={
                "row_id": row.get("id"),
                "src_tag": row.get("src_tag"),
                "sp_tag": row.get("sp_tag"),
                "dp_tag": row.get("dp_tag"),
                "accumulated_pkts": row.get("accumulated_pkts"),
                "accumulated_bytes": row.get("accumulated_bytes"),
                "global_pps": row.get("global_pps"),
                "global_bps": row.get("global_bps"),
                "avg_entropy": row.get("avg_entropy"),
                "is_blocked": bool(row.get("is_blocked", 0)),
            },
        )

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
        """获取 traffic_log 表当前最大 id"""
        conn = None
        try:
            conn = pymysql.connect(**self._db_config)
            with conn.cursor() as cursor:
                cursor.execute("SELECT MAX(id) FROM traffic_log")
                row = cursor.fetchone()
                return row[0] if row and row[0] else 0
        except Exception:
            logger.exception("[LiveScan] 获取最大ID失败")
            return 0
        finally:
            if conn:
                conn.close()

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