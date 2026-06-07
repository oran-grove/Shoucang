# -*- coding: utf-8 -*-
r"""
SQLite 记忆存储 — 自适应系统的 Tier 0 持久化层
================================================

反馈案例库 (feedback_cases) 是多智能体系统的私有记忆，
使用 SQLite 以保持模块独立，避免与 MySQL 基础设施耦合。

设计原则:
- 零外部依赖 — sqlite3 是 Python 标准库
- 单文件可移植 — 拷贝 data/feedback.db 即完成备份
- WAL 模式 — 支持并发读，写入阻塞极短
- 不可变写入 — 案例一旦记录，只增不删不改
- 元数据与模式索引分离 — 原始案例在 SQLite，模式卡片在 JSON

存储位置:
    multi_agent_system/memory/data/feedback.db

表结构:
    feedback_cases — 管理员反馈案例 (Tier 0)
    pattern_log     — 模式卡片变更审计日志
    last_run        — 定时任务状态记录
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# 数据库文件路径（相对于本模块）
_DB_PATH = Path(__file__).parent / "data" / "feedback.db"

_DDL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS feedback_cases (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    traffic_id      INTEGER,                     -- traffic_log.id，可为空
    ai_verdict      TEXT    NOT NULL,            -- malicious / suspicious / safe
    ai_confidence   REAL    NOT NULL,            -- AI 置信度 0.0-1.0
    ai_reasoning    TEXT,                        -- AI 推理摘要
    ai_threat_type  TEXT,                        -- AI 判定的威胁类型

    admin_action    TEXT    NOT NULL,            -- block / ignore / confirm_safe
    admin_note      TEXT,                        -- 管理员批注
    ai_correct      INTEGER NOT NULL,            -- 0=AI错误 1=AI正确
    category        TEXT,                        -- fp / fn / tp / tn

    -- 流量特征快照 (JSON)
    src_ip          TEXT,
    dst_ip          TEXT,
    src_port        INTEGER DEFAULT 0,
    dst_port        INTEGER DEFAULT 0,
    department      TEXT,
    protocol        TEXT,
    flow_features   TEXT,                        -- JSON: 五元组+熵值等

    matched_pattern_ids TEXT,                    -- 当时匹配到的模式卡片ID列表 (JSON数组)

    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_fb_correct   ON feedback_cases(ai_correct);
CREATE INDEX IF NOT EXISTS idx_fb_category  ON feedback_cases(category);
CREATE INDEX IF NOT EXISTS idx_fb_dept      ON feedback_cases(department);
CREATE INDEX IF NOT EXISTS idx_fb_created   ON feedback_cases(created_at);

CREATE TABLE IF NOT EXISTS pattern_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    card_id     TEXT    NOT NULL,
    event       TEXT    NOT NULL,            -- created / activated / retired / reinforced
    detail      TEXT,                        -- JSON: 变更详情
    snapshot    TEXT,                        -- JSON: 变更前卡片完整快照
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_pl_card ON pattern_log(card_id);

CREATE TABLE IF NOT EXISTS last_run (
    task_name   TEXT    PRIMARY KEY,
    last_at     TEXT    NOT NULL,
    stats       TEXT                         -- JSON: 上次运行的统计信息
);
"""


class MemoryStore:
    """
    SQLite 记忆存储封装。

    线程安全: 每个线程使用独立连接。Python sqlite3 模块在
    check_same_thread=False 模式下自动管理线程间连接共享。

    用法:
        store = MemoryStore()
        store.record_feedback(
            ai_verdict="malicious", ai_confidence=0.92,
            ai_reasoning="高熵加密外传", ai_threat_type="数据泄露",
            admin_action="block", admin_note="确认恶意，已移交安全部",
            ai_correct=True,
            src_ip="10.0.1.15", department="财务部",
            flow_features={"entropy": 7.8, "byte_count": 50000000},
        )
        stats = store.get_stats_for_clustering(hours=24)
    """

    def __init__(self, db_path: Optional[Path] = None):
        self._db_path = db_path or _DB_PATH
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        """初始化数据库和表"""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._get_conn() as conn:
            conn.executescript(_DDL)
            conn.commit()

    def _get_conn(self) -> sqlite3.Connection:
        """获取数据库连接"""
        conn = sqlite3.connect(
            str(self._db_path),
            check_same_thread=False,
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    # ==================== 反馈案例 (Tier 0) ====================

    def record_feedback(
        self,
        *,
        ai_verdict: str,
        ai_confidence: float,
        admins_action: str,
        ai_correct: bool,
        ai_reasoning: str = "",
        ai_threat_type: str = "",
        admin_note: str = "",
        src_ip: str = "",
        dst_ip: str = "",
        src_port: int = 0,
        dst_port: int = 0,
        department: str = "",
        protocol: str = "",
        flow_features: Optional[dict] = None,
        matched_pattern_ids: Optional[list[str]] = None,
        traffic_id: Optional[int] = None,
    ) -> int:
        """
        记录一条管理员反馈案例。

        Returns:
            int: 新案例的 ID
        """
        category_map = {
            (True, True):   "tp",  # AI判恶意, 管理员确认 → true positive
            (True, False):  "fp",  # AI判恶意, 管理员否定 → false positive
            (False, True):  "fn",  # AI判安全, 管理员拉黑 → false negative
            (False, False): "tn",  # AI判安全, 管理员确认安全 → true negative
        }
        is_malicious_ai = ai_verdict in ("malicious", "suspicious")
        category = category_map.get((is_malicious_ai, ai_correct), "unknown")

        row = {
            "traffic_id": traffic_id,
            "ai_verdict": ai_verdict,
            "ai_confidence": round(float(ai_confidence), 4),
            "ai_reasoning": (ai_reasoning or "")[:500],
            "ai_threat_type": ai_threat_type or "",
            "admin_action": admins_action,
            "admin_note": (admin_note or "")[:500],
            "ai_correct": 1 if ai_correct else 0,
            "category": category,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "department": department,
            "protocol": protocol,
            "flow_features": json.dumps(flow_features or {}, ensure_ascii=False),
            "matched_pattern_ids": json.dumps(matched_pattern_ids or [], ensure_ascii=False),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        with self._lock:
            try:
                conn = self._get_conn()
                conn.execute(
                    """INSERT INTO feedback_cases
                       (traffic_id, ai_verdict, ai_confidence, ai_reasoning,
                        ai_threat_type, admin_action, admin_note, ai_correct,
                        category, src_ip, dst_ip, src_port, dst_port,
                        department, protocol, flow_features,
                        matched_pattern_ids, created_at)
                       VALUES
                       (:traffic_id, :ai_verdict, :ai_confidence, :ai_reasoning,
                        :ai_threat_type, :admin_action, :admin_note, :ai_correct,
                        :category, :src_ip, :dst_ip, :src_port, :dst_port,
                        :department, :protocol, :flow_features,
                        :matched_pattern_ids, :created_at)""",
                    row,
                )
                conn.commit()
                case_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                conn.close()
                return int(case_id)
            except Exception as e:
                logger.exception("[MemoryStore] 写入反馈案例失败: %s", e)
                return -1

    def get_stats_for_clustering(self, hours: int = 24) -> dict:
        """
        获取用于模式聚类的统计数据 (Loop 2)。

        Returns:
            dict with keys: cases_by_dept_protocol, fp_cases, fn_cases,
                            department_stats, total_cases
        """
        conn = self._get_conn()
        try:
            cutoff = datetime.now(timezone.utc).isoformat()

            # 按 department + protocol 聚合
            rows = conn.execute(
                """SELECT department, protocol,
                          COUNT(*) as cnt,
                          SUM(CASE WHEN ai_correct=1 THEN 1 ELSE 0 END) as correct_cnt,
                          SUM(CASE WHEN ai_correct=0 THEN 1 ELSE 0 END) as error_cnt
                   FROM feedback_cases
                   WHERE created_at >= datetime(?, ?)
                   GROUP BY department, protocol
                   ORDER BY cnt DESC""",
                (cutoff, f"-{hours} hours"),
            ).fetchall()

            cases_by_group = [
                {
                    "department": r["department"] or "unknown",
                    "protocol": r["protocol"] or "unknown",
                    "count": r["cnt"],
                    "correct": r["correct_cnt"],
                    "error": r["error_cnt"],
                    "error_rate": r["error_cnt"] / r["cnt"] if r["cnt"] > 0 else 0.0,
                }
                for r in rows
            ]

            fp_cases = [
                dict(r) for r in conn.execute(
                    """SELECT * FROM feedback_cases
                       WHERE category='fp' AND created_at >= datetime(?, ?)
                       ORDER BY created_at DESC LIMIT 100""",
                    (cutoff, f"-{hours} hours"),
                ).fetchall()
            ]

            fn_cases = [
                dict(r) for r in conn.execute(
                    """SELECT * FROM feedback_cases
                       WHERE category='fn' AND created_at >= datetime(?, ?)
                       ORDER BY created_at DESC LIMIT 100""",
                    (cutoff, f"-{hours} hours"),
                ).fetchall()
            ]

            dept_stats = [
                dict(r) for r in conn.execute(
                    """SELECT department,
                              COUNT(*) as total,
                              SUM(CASE WHEN ai_correct=0 THEN 1 ELSE 0 END) as errors,
                              SUM(CASE WHEN category='fp' THEN 1 ELSE 0 END) as fp_count,
                              SUM(CASE WHEN category='fn' THEN 1 ELSE 0 END) as fn_count
                       FROM feedback_cases
                       WHERE created_at >= datetime(?, ?)
                       GROUP BY department""",
                    (cutoff, f"-{hours} hours"),
                ).fetchall()
            ]

            total = conn.execute(
                "SELECT COUNT(*) FROM feedback_cases WHERE created_at >= datetime(?, ?)",
                (cutoff, f"-{hours} hours"),
            ).fetchone()[0]

            conn.close()
            return {
                "cases_by_group": cases_by_group,
                "fp_cases": fp_cases,
                "fn_cases": fn_cases,
                "department_stats": dept_stats,
                "total_cases": total,
            }
        except Exception as e:
            logger.exception("[MemoryStore] 获取聚类统计失败: %s", e)
            conn.close()
            return {"cases_by_group": [], "fp_cases": [], "fn_cases": [],
                    "department_stats": [], "total_cases": 0}

    def get_errors_for_llm_extraction(self, days: int = 7) -> list[dict]:
        """获取用于 Loop 3 LLM 模式提取的错误案例"""
        conn = self._get_conn()
        try:
            cutoff = datetime.now(timezone.utc).isoformat()
            rows = conn.execute(
                """SELECT * FROM feedback_cases
                   WHERE ai_correct = 0
                     AND created_at >= datetime(?, ?)
                   ORDER BY created_at DESC""",
                (cutoff, f"-{days} days"),
            ).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.exception("[MemoryStore] 获取错误案例失败: %s", e)
            conn.close()
            return []

    def get_historical_malicious(self, limit: int = 500) -> list[dict]:
        """获取历史确认恶意的案例，用于回归检测"""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                """SELECT * FROM feedback_cases
                   WHERE category = 'tp'
                   ORDER BY created_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.exception("[MemoryStore] 获取历史恶意案例失败: %s", e)
            conn.close()
            return []

    def get_recent_cases(self, limit: int = 50) -> list[dict]:
        """获取最近的反馈案例"""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM feedback_cases ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.exception("[MemoryStore] 获取最近案例失败: %s", e)
            conn.close()
            return []

    # ==================== 模式变更日志 ====================

    def log_pattern_event(
        self, card_id: str, event: str, detail: Optional[dict] = None,
        snapshot: Optional[dict] = None,
    ) -> None:
        """记录模式卡片变更"""
        with self._lock:
            try:
                conn = self._get_conn()
                conn.execute(
                    """INSERT INTO pattern_log (card_id, event, detail, snapshot, created_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (
                        card_id, event,
                        json.dumps(detail or {}, ensure_ascii=False),
                        json.dumps(snapshot or {}, ensure_ascii=False),
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                conn.commit()
                conn.close()
            except Exception as e:
                logger.exception("[MemoryStore] 写入模式日志失败: %s", e)

    # ==================== 定时任务状态 ====================

    def get_last_run(self, task_name: str) -> Optional[str]:
        """获取定时任务上次运行时间"""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT last_at FROM last_run WHERE task_name = ?", (task_name,)
        ).fetchone()
        conn.close()
        return row["last_at"] if row else None

    def set_last_run(self, task_name: str, stats: Optional[dict] = None) -> None:
        """更新定时任务运行时间"""
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                """INSERT OR REPLACE INTO last_run (task_name, last_at, stats)
                   VALUES (?, ?, ?)""",
                (
                    task_name,
                    datetime.now(timezone.utc).isoformat(),
                    json.dumps(stats or {}, ensure_ascii=False),
                ),
            )
            conn.commit()
            conn.close()

    # ==================== 统计概览 ====================

    def get_overview(self) -> dict:
        """获取自适应系统概览（供前端面板使用）"""
        conn = self._get_conn()
        try:
            total = conn.execute("SELECT COUNT(*) FROM feedback_cases").fetchone()[0]
            tp = conn.execute(
                "SELECT COUNT(*) FROM feedback_cases WHERE category='tp'"
            ).fetchone()[0]
            fp = conn.execute(
                "SELECT COUNT(*) FROM feedback_cases WHERE category='fp'"
            ).fetchone()[0]
            fn = conn.execute(
                "SELECT COUNT(*) FROM feedback_cases WHERE category='fn'"
            ).fetchone()[0]
            tn = conn.execute(
                "SELECT COUNT(*) FROM feedback_cases WHERE category='tn'"
            ).fetchone()[0]
            accuracy = (tp + tn) / total if total > 0 else 0.0

            last_7d = conn.execute(
                """SELECT COUNT(*) FROM feedback_cases
                   WHERE created_at >= datetime('now', '-7 days')"""
            ).fetchone()[0]

            last_7d_correct = conn.execute(
                """SELECT COUNT(*) FROM feedback_cases
                   WHERE created_at >= datetime('now', '-7 days') AND ai_correct=1"""
            ).fetchone()[0]

            accuracy_7d = last_7d_correct / last_7d if last_7d > 0 else 0.0

            conn.close()
            return {
                "total_cases": total,
                "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                "overall_accuracy": round(accuracy, 4),
                "last_7d_cases": last_7d,
                "last_7d_accuracy": round(accuracy_7d, 4),
            }
        except Exception as e:
            logger.exception("[MemoryStore] 获取概览失败: %s", e)
            conn.close()
            return {}


# 模块级单例（惰性初始化）
_store: Optional[MemoryStore] = None
_store_lock = threading.Lock()


def get_store() -> MemoryStore:
    """获取 MemoryStore 单例"""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = MemoryStore()
    return _store


__all__ = ["MemoryStore", "get_store"]
