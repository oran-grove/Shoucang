"""
数据库模块 - 内鬼筛查系统数据持久化层

包含:
- create_database.sql:       数据库DDL建表脚本
- shared_memory_consumer.py: 共享内存消费者，读取P4数据包并入库
"""

from .shared_memory_consumer import (
    DB_CONFIG,
    SHM_NAME,
    MAX_PACKETS,
    PACKET_SIZE,
    HEADER_SIZE,
    store_packet,
    read_from_shared_memory,
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