"""
数据库批量写入器 — 通用攒批架构
================================
提供可复用的后台批量写入线程，同时用于：
- traffic_log 批量 INSERT（流量数据入库）
- traffic_log 批量 UPDATE（智能体判定结果回写）

架构：
  queue.Queue + daemon 线程 + 攒批定时刷新
  → 共享的 _batch_writer_worker 循环，不同 flush_fn 注入

用法:
    # 流量数据写入
    from database.writer import start_db_writer, stop_db_writer
    write_queue, stop_event = start_db_writer()
    write_queue.put(row_dict)
    stop_db_writer(stop_event)

    # 判定结果写入
    from database.writer import start_verdict_writer, stop_verdict_writer
    vq, ve = start_verdict_writer()
    vq.put({"traffic_id": 12345, "ai_verdict": 1})
    stop_verdict_writer(ve)
"""

import queue
import threading

from config.shared_config import (
    DB_WRITE_BATCH_SIZE,
    DB_WRITE_FLUSH_INTERVAL,
)
from .connection import db_cursor


# ============================================================================
# 共享的攒批写入循环
# ============================================================================

def _batch_writer_worker(
    name: str,
    write_queue: queue.Queue,
    stop_event: threading.Event,
    flush_fn,
    batch_size: int = DB_WRITE_BATCH_SIZE,
    flush_interval: float = DB_WRITE_FLUSH_INTERVAL,
) -> None:
    """
    通用攒批写入线程。

    从 write_queue 取数据，攒到 batch_size 条或等待 flush_interval 秒后
    调用 flush_fn(buffer) 批量写入数据库。
    """
    buffer: list = []
    print(f"🖊️  {name} 写入线程已启动 (batch={batch_size}, flush={flush_interval}s)")

    while not stop_event.is_set():
        try:
            item = write_queue.get(timeout=flush_interval)
            buffer.append(item)
            if len(buffer) >= batch_size:
                flush_fn(buffer)
                buffer.clear()
        except queue.Empty:
            if buffer:
                flush_fn(buffer)
                buffer.clear()

    if buffer:
        flush_fn(buffer)
        buffer.clear()

    print(f"🛑 {name} 写入线程已停止")


# ============================================================================
# traffic_log 批量 INSERT
# ============================================================================

def _store_batch(packets: list[dict]) -> None:
    """批量 INSERT 多条流量数据到 traffic_log 表。"""
    if not packets:
        return

    try:
        with db_cursor() as (conn, cursor):
            cursor.execute("DESCRIBE traffic_log")
            table_fields = [row["Field"] for row in cursor.fetchall()]

            write_fields = [f for f in packets[0].keys() if f in table_fields]
            if not write_fields:
                print(f"   ⚠️ 批量写入: 无匹配字段，跳过 {len(packets)} 条")
                return

            placeholders = ", ".join(["%s"] * len(write_fields))
            fields_str = ", ".join(write_fields)
            sql = f"INSERT INTO traffic_log ({fields_str}) VALUES ({placeholders})"

            values_list = [[pkt.get(field) for field in write_fields] for pkt in packets]
            cursor.executemany(sql, values_list)
            conn.commit()
            print(f"   📦 批量入库: {len(packets)} 条")
    except Exception as e:
        print(f"   ❌ 批量入库失败: {e}")


def start_db_writer(
    batch_size: int = DB_WRITE_BATCH_SIZE,
    flush_interval: float = DB_WRITE_FLUSH_INTERVAL,
) -> tuple[queue.Queue, threading.Event]:
    """
    启动后台流量数据写入线程。

    Returns:
        (write_queue, stop_event):
            write_queue — put(dict) 即可（dict 键名需匹配 traffic_log 列名）
            stop_event — .set() 停止线程
    """
    write_queue: queue.Queue = queue.Queue(maxsize=10000)
    stop_event = threading.Event()

    thread = threading.Thread(
        target=_batch_writer_worker,
        args=("DB", write_queue, stop_event, _store_batch, batch_size, flush_interval),
        daemon=True,
    )
    thread.start()
    return write_queue, stop_event


def stop_db_writer(stop_event: threading.Event) -> None:
    """停止后台流量数据写入线程。"""
    stop_event.set()


# ============================================================================
# traffic_log 批量 UPDATE（判定结果回写）
# ============================================================================

def _update_verdict_batch(rows: list[dict]) -> None:
    """批量 UPDATE traffic_log，设置 ai_analyzed=1 和 ai_verdict。"""
    if not rows:
        return

    try:
        with db_cursor() as (conn, cursor):
            sql = (
                "UPDATE traffic_log "
                "SET ai_analyzed = 1, ai_verdict = %s "
                "WHERE id = %s"
            )
            values_list = [(r["ai_verdict"], r["traffic_id"]) for r in rows]
            cursor.executemany(sql, values_list)
            conn.commit()
            print(f"   📊 判定批量入库: {len(rows)} 条")
    except Exception as e:
        print(f"   ❌ 判定批量入库失败: {e}")


def start_verdict_writer(
    batch_size: int = DB_WRITE_BATCH_SIZE,
    flush_interval: float = DB_WRITE_FLUSH_INTERVAL,
) -> tuple[queue.Queue, threading.Event]:
    """
    启动后台判定结果写入线程。

    Returns:
        (write_queue, stop_event):
            write_queue — put(dict) 即可，dict 需含 traffic_id 和 ai_verdict
            stop_event — .set() 停止线程
    """
    write_queue: queue.Queue = queue.Queue(maxsize=10000)
    stop_event = threading.Event()

    thread = threading.Thread(
        target=_batch_writer_worker,
        args=("Verdict", write_queue, stop_event, _update_verdict_batch,
              batch_size, flush_interval),
        daemon=True,
    )
    thread.start()
    return write_queue, stop_event


def stop_verdict_writer(stop_event: threading.Event) -> None:
    """停止后台判定写入线程。"""
    stop_event.set()


# ============================================================================
# traffic_log 批量 DELETE（安全流量清理）
# ============================================================================

def _delete_safe_batch(ids: list[int]) -> None:
    """批量 DELETE traffic_log 中已被 AI 判定为安全的记录。"""
    if not ids:
        return
    from .lists_manager import delete_traffic_by_ids
    delete_traffic_by_ids(ids)


def start_deletion_writer(
    batch_size: int = DB_WRITE_BATCH_SIZE,
    flush_interval: float = DB_WRITE_FLUSH_INTERVAL,
) -> tuple[queue.Queue, threading.Event]:
    """
    启动后台安全流量删除线程。

    队列中放入的是单条 traffic_log.id (int)，
    攒批后调用 delete_traffic_by_ids 批量 DELETE。

    Returns:
        (write_queue, stop_event):
            write_queue — put(traffic_id: int) 即可
            stop_event — .set() 停止线程
    """
    write_queue: queue.Queue = queue.Queue(maxsize=10000)
    stop_event = threading.Event()

    thread = threading.Thread(
        target=_batch_writer_worker,
        args=("SafeDelete", write_queue, stop_event, _delete_safe_batch,
              batch_size, flush_interval),
        daemon=True,
    )
    thread.start()
    return write_queue, stop_event


def stop_deletion_writer(stop_event: threading.Event) -> None:
    """停止后台安全流量删除线程。"""
    stop_event.set()


__all__ = [
    "start_db_writer",
    "stop_db_writer",
    "start_verdict_writer",
    "stop_verdict_writer",
    "start_deletion_writer",
    "stop_deletion_writer",
]
