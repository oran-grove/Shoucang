"""
数据库管理器 — MySQL 为唯一数据源，常驻内存共享读取
====================================================
所有模块请求黑白名单 / IP-部门映射 / 流量日志的读写只能通过本模块接口，
不允许私自操作数据库。

用法:
    from database import (
        load_lists_from_db,
        get_blacklist,
        get_whitelist,
        is_blacklisted,
        is_whitelisted,
        get_ip_dept_map,
        lookup_employee,
    )
"""

import threading
from typing import Optional

from .connection import db_cursor


# ============================================================================
# 常驻内存缓存（统一锁保护，消除多锁竞争）
# ============================================================================
_cache_lock = threading.RLock()
_blacklist: set = set()       # {ip_address, ...}
_whitelist: set = set()       # {ip_address, ...}
_ip_dept_map: dict = {}       # {ip: (name, department), ...}


# ============================================================================
# 数据加载 / 刷新
# ============================================================================
def load_lists_from_db() -> None:
    """
    从 MySQL 加载黑白名单及 IP-部门映射到常驻内存。
    系统启动时调用一次，各模块通过 get_* 读取。
    写操作（add/remove）内部自动调用此函数刷新缓存。
    """
    global _blacklist, _whitelist, _ip_dept_map

    try:
        with db_cursor() as (conn, cursor):
            cursor.execute("SELECT ip_address FROM blacklist")
            new_blacklist = {row["ip_address"] for row in cursor.fetchall() if row["ip_address"]}
            cursor.execute("SELECT ip_address FROM whitelist")
            new_whitelist = {row["ip_address"] for row in cursor.fetchall() if row["ip_address"]}
            cursor.execute("SELECT ip, name, department FROM ip_dept_map")
            new_ip_dept = {}
            for row in cursor.fetchall():
                ip, name, dept = row["ip"], row["name"], row["department"] or ""
                if ip:
                    new_ip_dept[ip] = (name, dept)

        with _cache_lock:
            _blacklist = new_blacklist
            _whitelist = new_whitelist
            _ip_dept_map = new_ip_dept

        print(f"[数据库] 缓存已刷新: 黑名单 {len(_blacklist)} 条, "
              f"白名单 {len(_whitelist)} 条, IP映射 {len(_ip_dept_map)} 条")
    except Exception as e:
        print(f"⚠️ [数据库] 缓存加载失败: {e}")


# ============================================================================
# 只读查询
# ============================================================================
def get_blacklist() -> set:
    """返回当前黑名单 IP 集合的副本（只读快照）。"""
    with _cache_lock:
        return _blacklist.copy()


def get_whitelist() -> set:
    """返回当前白名单 IP 集合的副本（只读快照）。"""
    with _cache_lock:
        return _whitelist.copy()


def is_blacklisted(ip: str) -> bool:
    """判断 IP 是否在黑名单中。"""
    with _cache_lock:
        return ip in _blacklist


def is_whitelisted(ip: str) -> bool:
    """判断 IP 是否在白名单中。"""
    with _cache_lock:
        return ip in _whitelist


def get_ip_dept_map() -> dict:
    """返回当前 IP→(姓名, 部门) 映射的副本。"""
    with _cache_lock:
        return _ip_dept_map.copy()


def lookup_employee(ip: str) -> tuple:
    """查询 IP 对应的 (姓名, 部门)。"""
    with _cache_lock:
        return _ip_dept_map.get(ip, ("", ""))


# ============================================================================
# 写操作 — 写数据库 → 刷新常驻内存
# ============================================================================
def add_to_db_blacklist(ip: str,
                        threat_level: str = "高",
                        reason: str = "",
                        port: Optional[int] = None,
                        attack_type: Optional[str] = None) -> bool:
    """向数据库 blacklist 表新增一条记录，成功后刷新常驻内存。"""
    try:
        with db_cursor() as (conn, cursor):
            cursor.execute(
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
        load_lists_from_db()
        print(f"[数据库] 黑名单已写入: {ip} (威胁等级: {threat_level})")
        return True
    except Exception as e:
        print(f"❌ [数据库] 黑名单写入失败: {e}")
        return False


def add_to_db_whitelist(ip: str,
                        reason: str = "",
                        port: Optional[int] = None,
                        trust_level: Optional[str] = None) -> bool:
    """向数据库 whitelist 表新增一条记录，成功后刷新常驻内存。"""
    try:
        with db_cursor() as (conn, cursor):
            cursor.execute(
                "INSERT INTO whitelist (ip_address, reason, port, trust_level) "
                "VALUES (%s, %s, %s, %s) "
                "ON DUPLICATE KEY UPDATE "
                "reason = VALUES(reason), "
                "port = VALUES(port), "
                "trust_level = VALUES(trust_level)",
                (ip, reason, port, trust_level),
            )
            conn.commit()
        load_lists_from_db()
        print(f"[数据库] 白名单已写入: {ip}")
        return True
    except Exception as e:
        print(f"❌ [数据库] 白名单写入失败: {e}")
        return False


# ============================================================================
# 明细查询（前端列表展示用 — 返回完整字段）
# ============================================================================
def get_blacklist_detailed() -> list:
    """查询黑名单完整明细列表。"""
    try:
        with db_cursor() as (conn, cursor):
            cursor.execute(
                "SELECT id, ip_address, threat_level, reason, port, attack_type "
                "FROM blacklist ORDER BY id DESC"
            )
            return list(cursor.fetchall())
    except Exception as e:
        print(f"❌ [数据库] 查询黑名单明细失败: {e}")
        return []


def get_whitelist_detailed() -> list:
    """查询白名单完整明细列表。"""
    try:
        with db_cursor() as (conn, cursor):
            cursor.execute(
                "SELECT id, ip_address, reason, port, trust_level "
                "FROM whitelist ORDER BY id DESC"
            )
            return list(cursor.fetchall())
    except Exception as e:
        print(f"❌ [数据库] 查询白名单明细失败: {e}")
        return []


# ============================================================================
# 删除操作
# ============================================================================
def remove_from_blacklist(item_id: int) -> bool:
    """从黑名单删除指定记录（按 id），成功后刷新常驻内存。"""
    try:
        with db_cursor() as (conn, cursor):
            cursor.execute("DELETE FROM blacklist WHERE id = %s", (item_id,))
            conn.commit()
        load_lists_from_db()
        print(f"[数据库] 黑名单记录 id={item_id} 已删除")
        return True
    except Exception as e:
        print(f"❌ [数据库] 黑名单删除失败: {e}")
        return False


def remove_from_whitelist(item_id: int) -> bool:
    """从白名单删除指定记录（按 id），成功后刷新常驻内存。"""
    try:
        with db_cursor() as (conn, cursor):
            cursor.execute("DELETE FROM whitelist WHERE id = %s", (item_id,))
            conn.commit()
        load_lists_from_db()
        print(f"[数据库] 白名单记录 id={item_id} 已删除")
        return True
    except Exception as e:
        print(f"❌ [数据库] 白名单删除失败: {e}")
        return False


# ============================================================================
# 员工 (ip_dept_map) CRUD
# ============================================================================
def get_employees(filters: Optional[dict] = None,
                  page: int = 1,
                  limit: int = 15) -> tuple:
    """查询员工列表（支持过滤 + 分页）。返回: (total_count, rows)"""
    filters = filters or {}
    try:
        with db_cursor() as (conn, cursor):
            conditions = []
            params = []
            for field in ("number", "ip", "department", "name"):
                if filters.get(field):
                    conditions.append(f"{field} = %s")
                    params.append(filters[field])
            where = " WHERE " + " AND ".join(conditions) if conditions else ""

            cursor.execute(f"SELECT COUNT(*) AS cnt FROM ip_dept_map{where}", params)
            total = (cursor.fetchone() or {}).get("cnt", 0)

            start = (page - 1) * limit
            cursor.execute(
                f"SELECT id, number, ip, department, name FROM ip_dept_map{where} "
                "ORDER BY id DESC LIMIT %s OFFSET %s",
                params + [limit, start],
            )
            return total, list(cursor.fetchall())
    except Exception as e:
        print(f"❌ [数据库] 查询员工列表失败: {e}")
        return 0, []


def add_employee(number: str, ip: str, department: str, name: str) -> bool:
    """新增员工记录，成功后刷新常驻内存。"""
    try:
        with db_cursor() as (conn, cursor):
            cursor.execute(
                "INSERT INTO ip_dept_map (number, ip, department, name) "
                "VALUES (%s, %s, %s, %s)",
                (number, ip, department, name),
            )
            conn.commit()
        load_lists_from_db()
        print(f"[数据库] 员工已新增: {name} ({number}) — {ip}")
        return True
    except Exception as e:
        print(f"❌ [数据库] 新增员工失败: {e}")
        return False


def update_employee(emp_id: int, **fields) -> bool:
    """更新员工记录（按 id），成功后刷新常驻内存。"""
    if not fields:
        return False
    try:
        with db_cursor() as (conn, cursor):
            set_clause = ", ".join(f"{k} = %s" for k in fields.keys())
            values = list(fields.values()) + [emp_id]
            cursor.execute(f"UPDATE ip_dept_map SET {set_clause} WHERE id = %s", values)
            conn.commit()
        load_lists_from_db()
        print(f"[数据库] 员工 id={emp_id} 已更新")
        return True
    except Exception as e:
        print(f"❌ [数据库] 更新员工失败: {e}")
        return False


def delete_employee(emp_id: int) -> bool:
    """删除员工记录（按 id），成功后刷新常驻内存。"""
    try:
        with db_cursor() as (conn, cursor):
            cursor.execute("DELETE FROM ip_dept_map WHERE id = %s", (emp_id,))
            conn.commit()
        load_lists_from_db()
        print(f"[数据库] 员工 id={emp_id} 已删除")
        return True
    except Exception as e:
        print(f"❌ [数据库] 删除员工失败: {e}")
        return False


# ============================================================================
# 流量日志查询
# ============================================================================
def get_traffic_logs(limit: int = 200,
                     offset: int = 0,
                     filters: Optional[dict] = None) -> list:
    """查询流量日志表（traffic_log）。返回: list[dict]"""
    filters = filters or {}
    try:
        with db_cursor() as (conn, cursor):
            conditions = []
            params = []
            for field, value in filters.items():
                if value is not None and field in (
                    "src_ip", "dst_ip", "department", "protocol"
                ):
                    conditions.append(f"{field} = %s")
                    params.append(value)
            where = " WHERE " + " AND ".join(conditions) if conditions else ""

            cursor.execute(
                f"SELECT id, src_ip, dst_ip, src_port, dst_port, department, "
                "protocol, packet_time, traffic_size, is_blocked, entropy, "
                "ai_analyzed, ai_verdict "
                f"FROM traffic_log{where} ORDER BY id DESC LIMIT %s OFFSET %s",
                params + [limit, offset],
            )
            return list(cursor.fetchall())
    except Exception as e:
        print(f"❌ [数据库] 查询流量日志失败: {e}")
        return []


def get_traffic_for_deep_analysis(lookback_days: int = 30) -> list:
    """拉取指定天数内的流量数据，用于深度分析（基线画像 + 时序异常）。"""
    try:
        with db_cursor() as (conn, cursor):
            cursor.execute(
                "SELECT id, src_ip, dst_ip, src_port, dst_port, department, "
                "protocol, packet_time, traffic_size, is_blocked, entropy "
                "FROM traffic_log "
                "WHERE packet_time >= DATE_SUB(NOW(), INTERVAL %s DAY) "
                "ORDER BY src_ip, packet_time ASC",
                (lookback_days,),
            )
            return list(cursor.fetchall())
    except Exception as e:
        print(f"❌ [数据库] 深度分析流量拉取失败: {e}")
        return []


def update_traffic_action(traffic_id: int, action: str) -> bool:
    """更新流量记录的拦截状态。"""
    try:
        with db_cursor() as (conn, cursor):
            cursor.execute(
                "UPDATE traffic_log SET is_blocked = %s WHERE id = %s",
                (1 if action in ("拉黑", "block") else 0, traffic_id),
            )
            conn.commit()
        return True
    except Exception as e:
        print(f"❌ [数据库] 更新流量动作失败: {e}")
        return False


def get_employee_count() -> int:
    """获取员工总数。"""
    try:
        with db_cursor() as (conn, cursor):
            cursor.execute("SELECT COUNT(*) AS cnt FROM ip_dept_map")
            row = cursor.fetchone()
        return row["cnt"] if row else 0
    except Exception as e:
        print(f"❌ [数据库] 查询员工总数失败: {e}")
        return 0


# ============================================================================
# 多智能体系统专用查询（供 LiveScanOrchestrator / Orchestrator 调用）
# ============================================================================

def get_unanalyzed_traffic(last_processed_id: int, limit: int) -> list:
    """拉取未分析的流量记录（游标分页，供 LiveScanOrchestrator 调用）。"""
    try:
        with db_cursor() as (conn, cursor):
            cursor.execute(
                "SELECT * FROM traffic_log "
                "WHERE (ai_analyzed IS NULL OR ai_analyzed = 0) "
                "AND id > %s "
                "ORDER BY id ASC "
                "LIMIT %s",
                (last_processed_id, limit),
            )
            return list(cursor.fetchall())
    except Exception:
        print(f"❌ [数据库] 拉取未分析流量失败")
        return []


def get_traffic_max_id() -> int:
    """获取 traffic_log 表当前最大 id。"""
    try:
        with db_cursor() as (conn, cursor):
            cursor.execute("SELECT MAX(id) AS max_id FROM traffic_log")
            row = cursor.fetchone()
            return row["max_id"] if row and row["max_id"] else 0
    except Exception:
        print(f"❌ [数据库] 获取最大ID失败")
        return 0


def get_similar_flows_by_src_ip(
    src_ip: str,
    lookback_hours: float,
    max_records: int = 20,
) -> list:
    """查询同源 IP 的历史记录（供 Layer 2 回溯使用）。"""
    from datetime import datetime, timedelta, timezone

    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
        with db_cursor() as (conn, cursor):
            cursor.execute(
                "SELECT id, src_ip, dst_ip, src_port, dst_port, protocol, "
                "traffic_size, department, entropy, created_at, packet_time "
                "FROM traffic_log "
                "WHERE src_ip = %s AND created_at >= %s "
                "ORDER BY created_at DESC "
                "LIMIT %s",
                (src_ip, cutoff, max_records),
            )
            return list(cursor.fetchall())
    except Exception:
        print(f"❌ [数据库] 查询相似流量失败 (src_ip={src_ip})")
        return []
