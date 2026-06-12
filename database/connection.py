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

logger = logging.getLogger(__name__)


def db_connect() -> pymysql.connections.Connection:
    """建立数据库连接（调用方负责关闭）。"""
    from config import get_config
    db = get_config("database")
    return pymysql.connect(
        host=db.host,
        user=db.user,
        password=db.password,
        database=db.database,
        port=db.port,
        charset=db.charset,
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
