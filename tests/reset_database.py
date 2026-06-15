# -*- coding: utf-8 -*-
"""
数据库重置脚本
==============
删除所有运行数据，仅保留 test_data.py 中的初始黑白名单 + 员工映射。
同时清理告警缓冲区、LiveScan 断点、记忆系统。

会清空的:
  - traffic_log / blacklist / whitelist / ip_dept_map (MySQL)
  - 前端告警内存缓冲区 (调用 /api/clear)
  - LiveScan 断点文件 (.live_scan_checkpoint.json)
  - 多智能体记忆系统 (feedback.db)

用法:
    python tests/reset_database.py
"""

import sys
import os
from pathlib import Path

_PROJECT_ROOT = Path(__file__).parent.parent.resolve()
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from database.connection import db_cursor
from tests.test_data import seed_all
from config.shared_config import PROJECT_ROOT


def reset_all():
    print("=" * 50)
    print("  数据库重置 — 清空运行数据，恢复初始状态")
    print("=" * 50)

    # ---- 1. 清空 MySQL 表 ----
    with db_cursor() as (conn, cursor):
        cursor.execute("SET FOREIGN_KEY_CHECKS = 0")
        for t in ["traffic_log", "blacklist", "whitelist", "ip_dept_map"]:
            cursor.execute(f"DELETE FROM {t}")
            print(f"  DELETE {t}: {cursor.rowcount} 行")
        cursor.execute("SET FOREIGN_KEY_CHECKS = 1")
        conn.commit()

    # ---- 2. 重新注入初始数据 ----
    print()
    result = seed_all()

    # ---- 3. 清除告警缓冲区 ----
    try:
        import requests
        requests.post("http://localhost:8080/api/clear", timeout=5)
        print("  告警缓冲区: 已清除")
    except Exception:
        print("  告警缓冲区: 跳过 (后端未运行)")

    # ---- 4. 删除 LiveScan 断点 ----
    checkpoint = PROJECT_ROOT / ".live_scan_checkpoint.json"
    if checkpoint.exists():
        checkpoint.unlink()
        print("  断点文件: 已删除")

    # ---- 5. 重置记忆系统 (Tier 0 SQLite) ----
    memory_db = _PROJECT_ROOT / "multi_agent_system" / "memory" / "data" / "feedback.db"
    if memory_db.exists():
        os.remove(memory_db)
        print("  记忆系统: 已重置")

    # ---- 6. 清理模式卡片 (Tier 1 JSON) ----
    patterns_dir = _PROJECT_ROOT / "multi_agent_system" / "memory" / "data" / "patterns"
    if patterns_dir.exists():
        for sub in ["active", "shadow", "retired"]:
            sub_dir = patterns_dir / sub
            if sub_dir.exists():
                for f in sub_dir.iterdir():
                    if f.suffix == ".json":
                        f.unlink()
        print("  模式卡片: 已清理")

    print()
    print("=" * 50)
    print(f"  重置完成: 黑名单{result['blacklist']} 白名单{result['whitelist']} 员工{result['ip_dept_map']}")
    print("=" * 50)


if __name__ == "__main__":
    reset_all()
