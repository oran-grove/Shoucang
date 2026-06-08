"""
数据库判定结果批量写入器
=========================
从 queue.Queue 消费判定结果并攒批 UPDATE traffic_log 的 ai_analyzed/ai_verdict 列。

复用 database/writer.py 的批写入架构（queue.Queue + daemon 线程 + executemany），
所有 DB 操作必须经过此模块，多智能体模块不得直接访问数据库。

用法:
    from database.verdict_writer import start_verdict_writer, stop_verdict_writer

    vq, ve = start_verdict_writer()
    vq.put({"traffic_id": 12345, "ai_verdict": 1})  # ai_analyzed 自动设为 1
    stop_verdict_writer(ve)
"""

import sys
import threading
import queue
from pathlib import Path

_PROJECT_ROOT = Path(__file__).parent.parent.resolve()
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import pymysql
from config.shared_config import (
    DB_CONFIG,
    DB_WRITE_BATCH_SIZE,
    DB_WRITE_FLUSH_INTERVAL,
)


def _update_verdict_batch(rows: list[dict]) -> None:
    """批量 UPDATE traffic_log，设置 ai_analyzed=1 和 ai_verdict。"""
    if not rows:
        return

    conn = pymysql.connect(**DB_CONFIG)
    try:
        with conn.cursor() as cursor:
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
    finally:
        conn.close()


def _verdict_writer_worker(
    write_queue: queue.Queue,
    stop_event: threading.Event,
    batch_size: int = DB_WRITE_BATCH_SIZE,
    flush_interval: float = DB_WRITE_FLUSH_INTERVAL,
) -> None:
    """后台线程：从 write_queue 取判定结果，攒批 UPDATE。"""
    buffer: list[dict] = []
    print(f"📊 判定写入线程已启动 (batch_size={batch_size}, flush_interval={flush_interval}s)")

    while not stop_event.is_set():
        try:
            item = write_queue.get(timeout=flush_interval)
            buffer.append(item)
            if len(buffer) >= batch_size:
                _update_verdict_batch(buffer)
                buffer.clear()
        except queue.Empty:
            if buffer:
                _update_verdict_batch(buffer)
                buffer.clear()

    if buffer:
        _update_verdict_batch(buffer)
        buffer.clear()

    print("🛑 判定写入线程已停止")


def start_verdict_writer(
    batch_size: int = DB_WRITE_BATCH_SIZE,
    flush_interval: float = DB_WRITE_FLUSH_INTERVAL,
) -> tuple[queue.Queue, threading.Event]:
    """
    启动后台判定写入线程。

    Returns:
        (write_queue, stop_event):
            write_queue — put(dict) 即可，dict 需含 traffic_id 和 ai_verdict
            stop_event — .set() 停止线程
    """
    write_queue: queue.Queue = queue.Queue(maxsize=10000)
    stop_event = threading.Event()

    thread = threading.Thread(
        target=_verdict_writer_worker,
        args=(write_queue, stop_event, batch_size, flush_interval),
        daemon=True,
    )
    thread.start()

    return write_queue, stop_event


def stop_verdict_writer(stop_event: threading.Event) -> None:
    """停止判定写入线程。"""
    stop_event.set()
