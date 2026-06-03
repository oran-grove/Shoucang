"""
统一共享配置
============
项目中所有模块共享的系统级常量与配置。
包含数据库连接、共享内存、系统路径等基础设置。

这些配置项应在部署时根据实际环境修改，
不应硬编码在各业务模块中。
"""

import os
from pathlib import Path
from typing import TypedDict


# ==================== 数据库配置 ====================
class DbConfig(TypedDict):
    """数据库连接参数 —— 精确类型以消除 PyMySQL connect() 的类型误报。"""
    host: str
    user: str
    password: str
    database: str
    port: int
    charset: str


DB_CONFIG: DbConfig = {
    'host': 'localhost',
    'user': 'root',
    'password': '2005jjayyayyAX',
    'database': 'insider_threat_db',
    'port': 3306,
    'charset': 'utf8mb4',
}


# ==================== 数据库批量写入配置 ====================
# 数据标注 → 数据库写入的攒批参数
DB_WRITE_BATCH_SIZE = 100          # 每批最多累积多少条后写入
DB_WRITE_FLUSH_INTERVAL = 5.0      # 最多等待多少秒后强制写入（秒）


# ==================== 共享内存配置（shared_memory_consumer 使用）====================
SHM_NAME = "traffic_shm"           # 共享内存名称
MAX_PACKETS = 1024                 # 最大数据包数量
PACKET_SIZE = 2048                 # 单个数据包大小（字节）
HEADER_SIZE = 128                  # 共享内存头部大小（字节）


# ==================== 配置文件路径 ====================
# 项目根目录（config/ 的父目录）
PROJECT_ROOT = Path(__file__).parent.parent.resolve()

# 默认配置文件
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "config_default.json"

# 用户配置文件
USER_CONFIG_PATH = PROJECT_ROOT / "config" / "config_user.json"


# ==================== 多智能体系统配置路径 ====================
# Python 后端的配置目录
PYTHON_CONFIG_DIR = PROJECT_ROOT / "config"


# ==================== 前端 PHP 配置路径（供 PHP 引用）====================
# 相对于 frontend/api/ 目录的路径
# PHP 中应使用: $configFile = __DIR__ . '/../../config/config_user.json';
FRONTEND_CONFIG_RELATIVE_PATH = "../../config/config_user.json"
FRONTEND_DEFAULT_CONFIG_RELATIVE_PATH = "../../config/config_default.json"
