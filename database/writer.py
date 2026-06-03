"""
数据库批量写入器 — 零拷贝版本
===============================
从 queue.Queue 消费数据包并攒批写入数据库。

摒弃原有的 shared_memory 多进程方案，改为进程内 queue.Queue +
后台写入线程，实现 dict 直接引用传参，消除 JSON 序列化和
共享内存拷贝的开销（三次拷贝 → 零拷贝）。

用法:
    from database.writer import start_db_writer, stop_db_writer

    # 在 ColdTableProcessor 中获取写入队列
    write_queue = start_db_writer()
    write_queue.put(row_dict)  # dict 直接引用，零拷贝
    stop_db_writer()
"""

import sys
import threading
import queue
from pathlib import Path

# 确保项目根目录在 sys.path 中
_PROJECT_ROOT = Path(__file__).parent.parent.resolve()
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import pymysql
from config.shared_config import (
    DB_CONFIG,
    DB_WRITE_BATCH_SIZE,
    DB_WRITE_FLUSH_INTERVAL,
)

# ==================== 单条写入（兼容旧接口） ====================
def store_packet(packet):
    """存入数据库 - 按写入方字段接收"""
    conn = pymysql.connect(**DB_CONFIG)
    cursor = conn.cursor()
    try:
        # 获取表所有字段
        cursor.execute("DESCRIBE traffic_log")
        table_fields = [row[0] for row in cursor.fetchall()]

        # 取 packet 中所有在表中存在的字段
        write_fields = [f for f in packet.keys() if f in table_fields]

        if not write_fields:
            print(f"   ⚠️ 没有匹配的字段，跳过")
            return

        # 构建 INSERT 语句
        placeholders = ', '.join(['%s'] * len(write_fields))
        fields_str = ', '.join(write_fields)
        sql = f"INSERT INTO traffic_log ({fields_str}) VALUES ({placeholders})"

        # 获取对应的值
        values = [packet.get(field) for field in write_fields]

        cursor.execute(sql, values)
        conn.commit()
        print(f"   ✅ 已入库: {packet.get('src_ip')} -> {packet.get('dst_ip')}")
    except Exception as e:
        print(f"   ❌ 入库失败: {e}")
    finally:
        conn.close()


# ==================== 批量写入 ====================
def _store_batch(packets: list):
    """批量写入多条数据包到数据库，使用单连接 + executemany 提高性能。"""
    if not packets:
        return

    conn = pymysql.connect(**DB_CONFIG)
    cursor = conn.cursor()
    try:
        # 获取表字段
        cursor.execute("DESCRIBE traffic_log")
        table_fields = [row[0] for row in cursor.fetchall()]

        # 以第一条数据的字段为准（所有数据应具有相同结构）
        write_fields = [f for f in packets[0].keys() if f in table_fields]
        if not write_fields:
            print(f"   ⚠️ 批量写入: 没有匹配的字段，跳过 {len(packets)} 条")
            return

        placeholders = ', '.join(['%s'] * len(write_fields))
        fields_str = ', '.join(write_fields)
        sql = f"INSERT INTO traffic_log ({fields_str}) VALUES ({placeholders})"

        # 构建 values 列表
        values_list = []
        for pkt in packets:
            values_list.append([pkt.get(field) for field in write_fields])

        cursor.executemany(sql, values_list)
        conn.commit()
        print(f"   📦 批量入库: {len(packets)} 条")
    except Exception as e:
        print(f"   ❌ 批量入库失败: {e}")
    finally:
        conn.close()


# ==================== 后台写入线程 ====================
def _batch_writer_worker(
    write_queue: queue.Queue,
    stop_event: threading.Event,
    batch_size: int = DB_WRITE_BATCH_SIZE,
    flush_interval: float = DB_WRITE_FLUSH_INTERVAL,
):
    """
    后台线程：从 write_queue 取数据，攒到 batch_size 条或
    等待 flush_interval 秒后批量写入数据库。
    """
    buffer = []
    print(f"🖊️  DB 写入线程已启动 (batch_size={batch_size}, flush_interval={flush_interval}s)")

    while not stop_event.is_set():
        try:
            # 阻塞等待，最多 flush_interval 秒
            packet = write_queue.get(timeout=flush_interval)
            buffer.append(packet)

            # 达到批量阈值 → 立即写入
            if len(buffer) >= batch_size:
                _store_batch(buffer)
                buffer.clear()
        except queue.Empty:
            # 超时 → 强制刷新 buffer
            if buffer:
                _store_batch(buffer)
                buffer.clear()

    # 停止时刷新剩余数据
    if buffer:
        _store_batch(buffer)
        buffer.clear()

    print("🛑 DB 写入线程已停止")


# ==================== 公开接口 ====================
def start_db_writer(
    batch_size: int = DB_WRITE_BATCH_SIZE,
    flush_interval: float = DB_WRITE_FLUSH_INTERVAL,
) -> tuple:
    """
    启动后台数据库写入线程。

    Returns:
        (write_queue, stop_event): 
            write_queue: queue.Queue，生产者 put dict 即可
            stop_event: 调用 .set() 停止写入线程
    """
    write_queue = queue.Queue(maxsize=10000)
    stop_event = threading.Event()

    thread = threading.Thread(
        target=_batch_writer_worker,
        args=(write_queue, stop_event, batch_size, flush_interval),
        daemon=True,
    )
    thread.start()

    return write_queue, stop_event


def stop_db_writer(stop_event: threading.Event):
    """停止后台数据库写入线程。"""
    stop_event.set()