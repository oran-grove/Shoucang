"""
统一共享配置
============
项目中所有模块共享的系统级常量与配置。
包含数据库连接、共享内存、系统路径等基础设置。

这些配置项应在部署时根据实际环境修改，
不应硬编码在各业务模块中。
"""

# ==================== 数据库配置 ====================
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '2005jjayyayyAX',
    'database': 'insider_threat_db',
    'charset': 'utf8mb4'
}

# ==================== 数据库批量写入配置 ====================
# 数据标注 → 数据库写入的攒批参数
DB_WRITE_BATCH_SIZE = 100          # 每批最多累积多少条后写入
DB_WRITE_FLUSH_INTERVAL = 5.0      # 最多等待多少秒后强制写入（秒）

# ==================== 配置文件路径 ====================
import os
from pathlib import Path

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
