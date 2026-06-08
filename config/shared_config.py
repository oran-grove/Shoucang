"""
统一共享配置
============
项目中所有模块共享的系统级常量与配置。
包含数据库连接、系统路径等基础设置。

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
    'password': '0918',
    'database': 'insider_threat_db',
    'port': 3306,
    'charset': 'utf8mb4',
}


# ==================== 项目根目录 ====================
# config/ 的父目录，必须在其他路径常量之前定义
PROJECT_ROOT = Path(__file__).parent.parent.resolve()

# ==================== GeoIP 数据库更新配置 ====================
# MaxMind GeoLite2-City.mmdb 自动更新间隔（小时）
# 设为 0 表示禁用自动更新
GEOIP_UPDATE_INTERVAL_HOURS = 168  # 7 天

# GeoIP 数据库文件绝对路径
GEOIP_DB_PATH = str(PROJECT_ROOT / "data_gateway" / "GeoLite2-City.mmdb")

# GeoIP 下载源
GEOIP_DOWNLOAD_URL = "https://cdn.jsdelivr.net/npm/geolite2-city/GeoLite2-City.mmdb.gz"


# ==================== 数据库批量写入配置 ====================
# 数据标注 → 数据库写入的攒批参数
DB_WRITE_BATCH_SIZE = 100          # 每批最多累积多少条后写入
DB_WRITE_FLUSH_INTERVAL = 5.0      # 最多等待多少秒后强制写入（秒）


# ==================== 配置文件路径 ====================

# 默认配置文件
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "config_default.json"

# 用户配置文件
USER_CONFIG_PATH = PROJECT_ROOT / "config" / "config_user.json"


# ==================== 多智能体系统配置路径 ====================
# Python 后端的配置目录
PYTHON_CONFIG_DIR = PROJECT_ROOT / "config"


# ==================== 前端配置路径（供前端 API 跨模块引用）====================
# 前端通过 Python API 后端获取配置，不再直接读取 JSON 文件
# 这些路径供后端 API 提供配置服务时使用
FRONTEND_CONFIG_RELATIVE_PATH = "../../config/config_user.json"
FRONTEND_DEFAULT_CONFIG_RELATIVE_PATH = "../../config/config_default.json"
