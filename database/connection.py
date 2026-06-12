"""
数据库连接工具 — 供 database/ 内部模块共享使用
================================================
提供统一的 MySQL 连接工厂和游标上下文管理器。

用法:
    from database.connection import db_connect, db_cursor

    # 手动管理连接
    conn = db_connect()
    try:
        ...
    finally:
        conn.close()

    # 上下文管理器（DictCursor，自动关闭）
    with db_cursor() as (conn, cursor):
        cursor.execute("SELECT ...")
        rows = cursor.fetchall()  # list[dict]
"""

import logging
from contextlib import contextmanager

import pymysql
from config.shared_config import DB_CONFIG
from config.loader import get_database_password

logger = logging.getLogger(__name__)

# ── 模块导入时解析一次数据库密码 ────────────────────────────
_DB_PASSWORD = get_database_password()
if _DB_PASSWORD:
    logger.debug("数据库密码来源: config_user.json / config_default.json")
else:
    logger.warning("数据库密码未在配置文件中设置")


def db_connect() -> pymysql.connections.Connection:
    """建立数据库连接（调用方负责关闭）。"""
    password = _DB_PASSWORD or DB_CONFIG["password"]
    return pymysql.connect(
        host=DB_CONFIG["host"],
        user=DB_CONFIG["user"],
        password=password,
        database=DB_CONFIG["database"],
        port=DB_CONFIG["port"],
        charset=DB_CONFIG["charset"],
        connect_timeout=5,
    )


@contextmanager
def db_cursor():
    """
    数据库游标上下文管理器，始终返回 DictCursor。

    用法:
        with db_cursor() as (conn, cursor):
            cursor.execute(sql, params)
            rows = cursor.fetchall()  # 每行为 dict，可用 row["col"] 访问
            conn.commit()
    """
    conn = None
    try:
        conn = db_connect()
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            yield conn, cursor
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


__all__ = ["db_connect", "db_cursor"]
