# -*- coding: utf-8 -*-
"""
@module: database.py
@description: 黑白名单数据持久化层（文件版）
              提供与 database 包完全兼容的 API，
              独立运行时无需 MySQL / config 依赖。
              融合完整项目时替换为 database/ 包即可。
"""

import os

_BLACKLIST_FILE = "blacklist.txt"
_WHITELIST_FILE = "whitelist.txt"

# 常驻内存高速缓存
_blacklist_cache: set = None
_whitelist_cache: set = None


def _init_cache():
    """延迟初始化缓存（首次调用时从文件加载）"""
    global _blacklist_cache, _whitelist_cache
    if _blacklist_cache is None:
        _blacklist_cache = set()
        if os.path.exists(_BLACKLIST_FILE):
            with open(_BLACKLIST_FILE, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        _blacklist_cache.add(ip)
    if _whitelist_cache is None:
        _whitelist_cache = set()
        if os.path.exists(_WHITELIST_FILE):
            with open(_WHITELIST_FILE, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        _whitelist_cache.add(ip)


# ==========================================
# 查询接口
# ==========================================
def is_blacklisted(ip: str) -> bool:
    """检查 IP 是否在黑名单中"""
    _init_cache()
    return ip in _blacklist_cache


def is_whitelisted(ip: str) -> bool:
    """检查 IP 是否在白名单中"""
    _init_cache()
    return ip in _whitelist_cache


def get_blacklist() -> set:
    """获取全部黑名单 IP 集合"""
    _init_cache()
    return _blacklist_cache.copy()


def get_whitelist() -> set:
    """获取全部白名单 IP 集合"""
    _init_cache()
    return _whitelist_cache.copy()


# ==========================================
# 写入接口（先写文件，再刷新缓存）
# ==========================================
def add_to_db_blacklist(ip: str, threat_level: str = "高", reason: str = "") -> bool:
    """将 IP 写入黑名单（持久化 + 内存缓存）"""
    _init_cache()
    clean_ip = ip.split('/')[0].strip()
    if clean_ip in _blacklist_cache:
        return True
    try:
        with open(_BLACKLIST_FILE, 'a') as f:
            f.write(clean_ip + '\n')
        _blacklist_cache.add(clean_ip)
        # 如果此 IP 恰好在白名单里，移除之（以黑名单为准）
        _whitelist_cache.discard(clean_ip)
        return True
    except Exception:
        return False


def add_to_db_whitelist(ip: str, reason: str = "") -> bool:
    """将 IP 写入白名单（持久化 + 内存缓存）"""
    _init_cache()
    if ip in _whitelist_cache:
        return True
    try:
        with open(_WHITELIST_FILE, 'a') as f:
            f.write(ip + '\n')
        _whitelist_cache.add(ip)
        return True
    except Exception:
        return False


def reload_lists_after_change():
    """强制重新从文件加载（供外部修改文件后调用）"""
    global _blacklist_cache, _whitelist_cache
    _blacklist_cache = None
    _whitelist_cache = None
    _init_cache()


# 兼容 database 包的占位导出
def load_lists_from_db():
    """兼容接口（文件版等同于 reload_lists_after_change）"""
    reload_lists_after_change()


def get_ip_dept_map() -> dict:
    """兼容接口（独立版无部门映射，返回空 dict）"""
    return {}


def lookup_employee(ip: str) -> dict:
    """兼容接口（独立版无员工信息）"""
    return {"ip": ip, "department": "Unknown", "name": "Unknown"}
