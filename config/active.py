"""
运行时活跃配置 — 全局单例
==========================
系统启动后由 main.py 调用 set_active_config() 写入，
其他模块通过 get_active_config() 读取，避免多次加载和传递。

用法:
    from config.active import get_active_config, set_active_config

    # 启动时写入
    config = load_config("config/config_user.json")
    set_active_config(config)

    # 任意模块读取
    config = get_active_config()
    print(config.geoip.update_interval_hours)
"""

from typing import Optional

from config.schema import OrchestratorConfig

_active_config: Optional[OrchestratorConfig] = None
_loaded = False


def set_active_config(config: OrchestratorConfig) -> None:
    """设置全局活跃配置（系统启动时调用一次）。"""
    global _active_config, _loaded
    if not isinstance(config, OrchestratorConfig):
        raise TypeError(f"需要 OrchestratorConfig 实例，收到 {type(config)}")
    _active_config = config
    _loaded = True


def get_active_config() -> OrchestratorConfig:
    """
    获取全局活跃配置。

    Raises:
        RuntimeError: 若尚未调用 set_active_config()
    """
    if not _loaded or _active_config is None:
        raise RuntimeError(
            "活跃配置尚未初始化。请在系统启动时调用 set_active_config()。"
        )
    return _active_config


def is_config_loaded() -> bool:
    """检查活跃配置是否已加载。"""
    return _loaded and _active_config is not None


__all__ = ["get_active_config", "set_active_config", "is_config_loaded"]
