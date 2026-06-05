"""
数据库黑白名单 / IP-部门映射管理器
==================================
MySQL 为唯一数据源，常驻内存共享读取。

所有模块请求黑白名单 / IP-部门映射的读写只能通过本模块接口，
不允许私自操作数据库。

用法:
    from database.lists_manager import (
        load_lists_from_db,
        reload_lists_after_change,
        get_blacklist,
        get_whitelist,
        is_blacklisted,
        is_whitelisted,
        get_ip_dept_map,
        lookup_employee,
        add_to_db_blacklist,
        add_to_db_whitelist,
    )
"""

from typing import Optional

import threading

import pymysql
from config.shared_config import DB_CONFIG


# ============================================================================
# 黑白名单常驻内存（只读共享，由本模块内部线程安全地刷新）
# ============================================================================
_blacklist_lock = threading.RLock()
_blacklist: set = set()       # {ip_address, ...}

_whitelist_lock = threading.RLock()
_whitelist: set = set()       # {ip_address, ...}

# IP-部门映射常驻内存
_ip_dept_lock = threading.RLock()
_ip_dept_map: dict = {}       # {ip: (name, department), ...}


# ============================================================================
# 数据库连接
# ============================================================================
def _db_connect():
    """建立数据库连接（调用方负责关闭）。"""
    return pymysql.connect(**DB_CONFIG, connect_timeout=5)


# ============================================================================
# 数据加载 / 刷新
# ============================================================================
def load_lists_from_db() -> None:
    """
    从 MySQL 加载黑白名单及 IP-部门映射到常驻内存。
    系统启动时调用一次，各模块通过 get_* 读取。
    """
    global _blacklist, _whitelist, _ip_dept_map

    conn = None
    try:
        conn = _db_connect()
        with conn.cursor() as cur:
            # 加载黑名单
            cur.execute("SELECT ip_address FROM blacklist")
            new_blacklist = {row[0] for row in cur.fetchall() if row[0]}
            # 加载白名单
            cur.execute("SELECT ip_address FROM whitelist")
            new_whitelist = {row[0] for row in cur.fetchall() if row[0]}
            # 加载 IP-部门映射
            cur.execute("SELECT ip, name, department FROM ip_dept_map")
            new_ip_dept = {}
            for row in cur.fetchall():
                ip, name, dept = row[0], row[1], row[2] or ""
                if ip:
                    new_ip_dept[ip] = (name, dept)
        conn.close()
        conn = None

        with _blacklist_lock:
            _blacklist = new_blacklist
        with _whitelist_lock:
            _whitelist = new_whitelist
        with _ip_dept_lock:
            _ip_dept_map = new_ip_dept

        print(f"🔐 [数据库] 黑白名单 + IP 映射已加载: "
              f"黑名单 {len(_blacklist)} 条, 白名单 {len(_whitelist)} 条, "
              f"IP-员工映射 {len(_ip_dept_map)} 条")
    except Exception as e:
        print(f"⚠️ [数据库] 黑白名单/IP映射加载失败: {e}")
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def reload_lists_after_change() -> None:
    """
    在数据库黑白名单被修改后调用，刷新常驻内存副本。
    线程安全：先获取新数据，然后一次性替换。
    """
    print("🔄 [数据库] 检测到黑白名单变更，刷新常驻内存...")
    load_lists_from_db()


# ============================================================================
# 只读查询
# ============================================================================
def get_blacklist() -> set:
    """返回当前黑名单 IP 集合的副本（只读快照）。"""
    with _blacklist_lock:
        return _blacklist.copy()


def get_whitelist() -> set:
    """返回当前白名单 IP 集合的副本（只读快照）。"""
    with _whitelist_lock:
        return _whitelist.copy()


def is_blacklisted(ip: str) -> bool:
    """判断 IP 是否在黑名单中。"""
    with _blacklist_lock:
        return ip in _blacklist


def is_whitelisted(ip: str) -> bool:
    """判断 IP 是否在白名单中。"""
    with _whitelist_lock:
        return ip in _whitelist


def get_ip_dept_map() -> dict:
    """返回当前 IP→(姓名, 部门) 映射的副本。"""
    with _ip_dept_lock:
        return _ip_dept_map.copy()


def lookup_employee(ip: str) -> tuple:
    """查询 IP 对应的 (姓名, 部门)。"""
    with _ip_dept_lock:
        return _ip_dept_map.get(ip, ("", ""))


# ============================================================================
# 写操作 — 写数据库 → 刷新常驻内存
# ============================================================================
def add_to_db_blacklist(ip: str,
                        threat_level: str = "高",
                        reason: str = "",
                        port: Optional[int] = None,
                        attack_type: Optional[str] = None) -> bool:
    """
    向数据库 blacklist 表新增一条记录，成功后刷新常驻内存。

    所有模块请求黑名单写入只能通过此接口，不允许私自操作数据库。
    """
    conn = None
    try:
        conn = _db_connect()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO blacklist (ip_address, threat_level, reason, port, attack_type) "
                "VALUES (%s, %s, %s, %s, %s) "
                "ON DUPLICATE KEY UPDATE "
                "threat_level = VALUES(threat_level), "
                "reason = VALUES(reason), "
                "port = VALUES(port), "
                "attack_type = VALUES(attack_type)",
                (ip, threat_level, reason, port, attack_type),
            )
            conn.commit()
        conn.close()
        conn = None

        reload_lists_after_change()
        print(f"💀 [数据库] 黑名单已写入: {ip} (威胁等级: {threat_level})")
        return True
    except Exception as e:
        print(f"❌ [数据库] 黑名单写入失败: {e}")
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        return False


def add_to_db_whitelist(ip: str,
                        reason: str = "",
                        port: Optional[int] = None,
                        trust_level: Optional[str] = None) -> bool:
    """
    向数据库 whitelist 表新增一条记录，成功后刷新常驻内存。

    所有模块请求白名单写入只能通过此接口，不允许私自操作数据库。
    """
    conn = None
    try:
        conn = _db_connect()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO whitelist (ip_address, reason, port, trust_level) "
                "VALUES (%s, %s, %s, %s) "
                "ON DUPLICATE KEY UPDATE "
                "reason = VALUES(reason), "
                "port = VALUES(port), "
                "trust_level = VALUES(trust_level)",
                (ip, reason, port, trust_level),
            )
            conn.commit()
        conn.close()
        conn = None

        reload_lists_after_change()
        print(f"🛡️  [数据库] 白名单已写入: {ip}")
        return True
    except Exception as e:
        print(f"❌ [数据库] 白名单写入失败: {e}")
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        return False