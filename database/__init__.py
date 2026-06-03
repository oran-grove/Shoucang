"""
数据库模块 - 内鬼筛查系统数据持久化层

包含:
- create_database.sql: 数据库DDL建表脚本
- writer.py:          数据库批量写入器（queue.Queue + 后台线程，零拷贝）
- shared_memory_consumer.py: [已废弃] 旧版共享内存消费者

用法:
    from database.writer import start_db_writer, stop_db_writer, store_packet

    # 启动后台写入线程
    write_queue, stop_event = start_db_writer()
    write_queue.put(row_dict)  # dict 直接引用，零拷贝
    stop_db_writer(stop_event)
"""

import sys
from pathlib import Path

# 确保项目根目录在 sys.path 中
_PROJECT_ROOT = Path(__file__).parent.parent.resolve()
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from .writer import (
    store_packet,
    start_db_writer,
    stop_db_writer,
)

from config.shared_config import (
    DB_CONFIG,
    DB_WRITE_BATCH_SIZE,
    DB_WRITE_FLUSH_INTERVAL,
)

__all__ = [
    "DB_CONFIG",
    "DB_WRITE_BATCH_SIZE",
    "DB_WRITE_FLUSH_INTERVAL",
    "store_packet",
    "start_db_writer",
    "stop_db_writer",
]