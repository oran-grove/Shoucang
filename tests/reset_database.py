# -*- coding: utf-8 -*-
"""
数据库重置脚本
==============
删除所有运行数据，仅保留 test_data.py 中的初始黑白名单 + 员工映射。
重复执行幂等无副作用。

会清空的表:
  - traffic_log       (流量日志)
  - blacklist         (黑名单，清空后重新注入)
  - whitelist         (白名单，清空后重新注入)
  - ip_dept_map       (员工映射，清空后重新注入)

用法:
    python tests/reset_database.py
"""

import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).parent.parent.resolve()
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from database.connection import db_cursor
from tests.test_data import seed_all


def reset_all():
    print("=" * 50)
    print("  数据库重置 — 清空运行数据，恢复初始状态")
    print("=" * 50)

    with db_cursor() as (conn, cursor):
        # 外键约束暂时关闭，避免表间依赖报错
        cursor.execute("SET FOREIGN_KEY_CHECKS = 0")

        tables = ["traffic_log", "blacklist", "whitelist", "ip_dept_map"]
        for t in tables:
            cursor.execute(f"DELETE FROM {t}")
            print(f"  TRUNCATE {t}: {cursor.rowcount} 行已删除")

        cursor.execute("SET FOREIGN_KEY_CHECKS = 1")
        conn.commit()

    print()
    print("  重新注入初始数据...")
    print()

    result = seed_all()
    print()
    print("=" * 50)
    print(f"  重置完成: 黑名单{result['blacklist']} 白名单{result['whitelist']} 员工{result['ip_dept_map']}")
    print(f"  traffic_log 已清空")
    print("=" * 50)


if __name__ == "__main__":
    reset_all()
