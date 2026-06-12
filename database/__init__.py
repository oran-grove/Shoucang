"""
数据库模块 - 守藏 数据持久化层

 包含:
 - create_database.sql: 数据库DDL建表脚本
 - writer.py:           数据库批量写入器（queue.Queue + 后台线程，零拷贝）
                        黑白名单集中管理（MySQL 为唯一数据源，常驻内存共享读取）
                        IP-部门映射集中管理

用法:
    from database.writer import start_db_writer, stop_db_writer

    # 启动后台写入线程
    write_queue, stop_event = start_db_writer()
    write_queue.put(row_dict)  # dict 直接引用，零拷贝
    stop_db_writer(stop_event)

    # 黑白名单操作（统一接口，禁止各模块私自操作数据库）
    from database import add_to_db_blacklist, add_to_db_whitelist
    from database import get_blacklist, get_whitelist, is_blacklisted, is_whitelisted
    from database import load_lists_from_db
    from database import get_ip_dept_map, lookup_employee
"""

from .writer import (
    start_db_writer,
    stop_db_writer,
    start_verdict_writer,
    stop_verdict_writer,
)

from .lists_manager import (
    load_lists_from_db,
    get_blacklist,
    get_whitelist,
    is_blacklisted,
    is_whitelisted,
    get_ip_dept_map,
    lookup_employee,
    add_to_db_blacklist,
    add_to_db_whitelist,
    # 明细查询
    get_blacklist_detailed,
    get_whitelist_detailed,
    # 删除
    remove_from_blacklist,
    remove_from_whitelist,
    # 员工 CRUD
    get_employees,
    add_employee,
    update_employee,
    delete_employee,
    get_employee_count,
    # 流量日志
    get_traffic_logs,
    get_traffic_for_deep_analysis,
    update_traffic_action,
    # 多智能体专用查询
    get_unanalyzed_traffic,
    get_traffic_max_id,
    get_similar_flows_by_src_ip,
)

from config.shared_config import (
    DB_WRITE_BATCH_SIZE,
    DB_WRITE_FLUSH_INTERVAL,
)

__all__ = [
    "DB_WRITE_BATCH_SIZE",
    "DB_WRITE_FLUSH_INTERVAL",
    "start_db_writer",
    "stop_db_writer",
    "start_verdict_writer",
    "stop_verdict_writer",
    "load_lists_from_db",
    "get_blacklist",
    "get_whitelist",
    "is_blacklisted",
    "is_whitelisted",
    "get_ip_dept_map",
    "lookup_employee",
    "add_to_db_blacklist",
    "add_to_db_whitelist",
    # 明细查询
    "get_blacklist_detailed",
    "get_whitelist_detailed",
    # 删除
    "remove_from_blacklist",
    "remove_from_whitelist",
    # 员工 CRUD
    "get_employees",
    "add_employee",
    "update_employee",
    "delete_employee",
    "get_employee_count",
    # 流量日志
    "get_traffic_logs",
    "get_traffic_for_deep_analysis",
    "update_traffic_action",
    # 多智能体专用查询
    "get_unanalyzed_traffic",
    "get_traffic_max_id",
    "get_similar_flows_by_src_ip",
]
