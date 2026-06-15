# -*- coding: utf-8 -*-
"""
数据库重置脚本
==============
删除并重建整个数据库，然后注入 test_data.py 的初始数据。
每次运行保证和 create_database.sql 的最新表结构一致。

会执行的操作:
  1. DROP DATABASE + 重新执行 database/create_database.sql
  2. 注入黑白名单 + 员工数据 (test_data.py)
  3. 清除前端告警缓冲区
  4. 删除 LiveScan 断点文件
  5. 重置记忆系统 (SQLite + 模式卡片)

用法:
    python tests/reset_database.py
"""

import sys
import os
import re
from pathlib import Path

_PROJECT_ROOT = Path(__file__).parent.parent.resolve()
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


def _run_sql_file(cursor, conn, filepath: Path, db_name: str):
    """执行 SQL 文件：CREATE DATABASE → USE → CREATE TABLE。"""
    sql_text = filepath.read_text(encoding="utf-8")
    lines = []
    for line in sql_text.split("\n"):
        line = line.strip()
        if not line or line.startswith("--"):
            continue
        lines.append(line)
    sql = " ".join(lines)
    for stmt in sql.split(";"):
        stmt = stmt.strip()
        if not stmt:
            continue
        upper = stmt.upper()
        # DROP DATABASE 跳过（已手动执行）
        if upper.startswith("DROP DATABASE"):
            continue
        # CREATE DATABASE — 直接执行
        if upper.startswith("CREATE DATABASE"):
            cursor.execute(stmt)
            print(f"  {stmt[:60]}... OK")
            continue
        # USE — 执行后建表
        if upper.startswith("USE "):
            cursor.execute(stmt)
            continue
        try:
            cursor.execute(stmt)
        except Exception as e:
            print(f"   ⚠ SQL 跳过: {str(e)[:120]}")
    conn.commit()


def reset_all():
    print("=" * 50)
    print("  数据库重置 — 删除并重建，恢复初始状态")
    print("=" * 50)

    sql_file = _PROJECT_ROOT / "database" / "create_database.sql"

    # ---- 1. 读取数据库名 ----
    sql_text = sql_file.read_text(encoding="utf-8")
    m = re.search(r"CREATE\s+DATABASE\s+(\S+)", sql_text, re.IGNORECASE)
    db_name = m.group(1).rstrip(";") if m else "insider_threat_db"
    print(f"  数据库: {db_name}")

    # ---- 2. 连接 MySQL（不指定数据库）----
    import pymysql
    from config import get_config

    cfg = get_config().to_dict()
    db_cfg = cfg.get("database", {})
    conn = pymysql.connect(
        host=db_cfg.get("host", "localhost"),
        port=int(db_cfg.get("port", 3306)),
        user=db_cfg.get("user", "root"),
        password=db_cfg.get("password", ""),
        charset="utf8mb4",
        autocommit=True,
    )
    cursor = conn.cursor()

    try:
        # ---- 3. 删除旧库 ----
        cursor.execute(f"DROP DATABASE IF EXISTS `{db_name}`")
        print(f"  DROP DATABASE {db_name}: OK")
    except Exception as e:
        print(f"  DROP DATABASE 失败: {e}")

    # ---- 4. 重新建库建表 ----
    _run_sql_file(cursor, conn, sql_file, db_name)
    conn.close()
    print(f"  CREATE DATABASE + TABLES: OK")

    # ---- 5. 重新连接（这次指定数据库）----
    from tests.test_data import seed_all

    # ---- 6. 注入初始数据 ----
    print()
    result = seed_all()

    # ---- 7. 清除告警缓冲区 ----
    try:
        import requests
        requests.post("http://localhost:8080/api/clear", timeout=5)
        print("  告警缓冲区: 已清除")
    except Exception:
        print("  告警缓冲区: 跳过 (后端未运行)")

    # ---- 8. 删除 LiveScan 断点 ----
    from config.shared_config import PROJECT_ROOT
    checkpoint = PROJECT_ROOT / ".live_scan_checkpoint.json"
    if checkpoint.exists():
        checkpoint.unlink()
        print("  断点文件: 已删除")

    # ---- 9. 重置记忆系统 ----
    memory_db = _PROJECT_ROOT / "multi_agent_system" / "memory" / "data" / "feedback.db"
    if memory_db.exists():
        os.remove(memory_db)
        print("  记忆系统: 已重置")

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
