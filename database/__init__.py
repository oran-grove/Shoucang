"""
数据库模块 - 内鬼筛查系统数据持久化层

包含:
- create_database.sql:       数据库DDL建表脚本
- shared_memory_consumer.py: 共享内存消费者，读取P4数据包并入库
"""

import sys
from pathlib import Path

# 确保项目根目录在 sys.path 中
_PROJECT_ROOT = Path(__file__).parent.parent.resolve()
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from .shared_memory_consumer import (
    store_packet,
    read_from_shared_memory,
)

from config.shared_config import (
    DB_CONFIG,
    SHM_NAME,
    MAX_PACKETS,
    PACKET_SIZE,
    HEADER_SIZE,
)

__all__ = [
    "DB_CONFIG",
    "SHM_NAME",
    "MAX_PACKETS",
    "PACKET_SIZE",
    "HEADER_SIZE",
    "store_packet",
    "read_from_shared_memory",
]