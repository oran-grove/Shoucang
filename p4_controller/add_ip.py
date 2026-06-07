# -*- coding: utf-8 -*-
"""
@module: add_ip.py
@description: IP黑白名单管理与P4流表注入
              黑白名单通过 database 模块统一管理（MySQL 为唯一数据源，常驻内存共享读取）
              禁止各模块私自操作数据库或自建黑白名单库。
"""

import sys
from pathlib import Path
from typing import Optional

# 确保项目根目录在 sys.path 中
_PROJECT_ROOT = Path(__file__).parent.parent.resolve()
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import paramiko  # type: ignore[import-untyped]

# 黑白名单统一通过 database 模块接口操作
from database import (
    is_blacklisted,
    is_whitelisted,
    add_to_db_blacklist,
    add_to_db_whitelist,
)

# ==========================================
# 远程虚拟机网络配置
# ==========================================
VM_IP = "192.168.56.101"        # VirtualBox 虚拟机网卡 IP
VM_PORT = 22                    # 虚拟机 SSH 端口
VM_USER = "p4"                  # 虚拟机用户名
VM_PASSWORD = "p4"              # 虚拟机密码
THRIFT_PORT = "9100"            # P4 交换机 Thrift 控制端口


# ==========================================
# SSH 连接与 P4 流表下发
# ==========================================
def _ssh_exec_p4_cmd(p4_cmd: str) -> str:
    """
    通过 SSH 连接虚拟机，执行 P4 simple_switch_CLI 命令。
    返回命令输出。异常由调用方处理。
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(VM_IP, port=VM_PORT, username=VM_USER, password=VM_PASSWORD, timeout=5)
        exec_cmd = f'echo "{p4_cmd}" | simple_switch_CLI --thrift-port {THRIFT_PORT}'
        stdin, stdout, stderr = ssh.exec_command(exec_cmd)
        output = stdout.read().decode('utf-8', errors='ignore')
        return output.strip()
    finally:
        ssh.close()


# ==========================================
# 黑名单下发
#   - 数据库写入: database.add_to_db_blacklist()
#   - P4 流表: SSH 下发 drop 规则
# ==========================================
def add_to_blacklist(ip: str, source: str, reason: Optional[str] = None) -> bool:
    """通过SSH向P4交换机下发黑名单阻断流表，同时写入数据库"""
    if source not in ["frontend", "controller"]:
        print(f"[错误] 未知的拉黑来源: {source}", flush=True)
        return False

    if is_whitelisted(ip):
        print(f"[跳过] IP {ip} 在白名单中，{source} 的拉黑请求已忽略", flush=True)
        return False

    if is_blacklisted(ip):
        return True

    print(f"[黑名单] 来源: {source} | 目标 IP: {ip} | 正在下发 P4 流表...", flush=True)

    # 第一步：写入数据库（database 模块负责刷新常驻内存）
    db_reason = reason if reason else f"由{source}触发"
    if not add_to_db_blacklist(ip, threat_level="高", reason=db_reason):
        print(f"   => [失败] 数据库黑名单写入失败，终止拉黑", flush=True)
        return False

    # 第二步：SSH 下发 P4 流表
    clean_ip = ip.split('/')[0].strip()
    p4_cmd = f'table_add MyIngress.blacklist_table drop {clean_ip} =>'
    try:
        output = _ssh_exec_p4_cmd(p4_cmd)
        print(f"   => [完成] P4 交换机响应: {output}", flush=True)
        return True
    except Exception as e:
        print(f"   => [失败] P4 流表下发异常: {e}", flush=True)
        return False


# ==========================================
# 白名单下发
#   - 数据库写入: database.add_to_db_whitelist()
#   - P4 流表: SSH 下发白名单规则
# ==========================================
def add_to_whitelist(ip: str, source: str, reason: Optional[str] = None) -> bool:
    """通过SSH向P4交换机下发白名单放行流表，同时写入数据库"""
    if source != "frontend":
        print(f"[拒绝] {source} 无权下发白名单，仅前端有此权限", flush=True)
        return False

    if is_whitelisted(ip):
        return True

    print(f"[白名单] 来源: {source} | 目标 IP: {ip} | 正在下发 P4 流表...", flush=True)

    # 第一步：写入数据库（database 模块负责刷新常驻内存）
    db_reason = reason if reason else f"由{source}手动加白"
    if not add_to_db_whitelist(ip, reason=db_reason):
        print(f"   => [失败] 数据库白名单写入失败，终止加白", flush=True)
        return False

    # 第二步：SSH 下发 P4 流表
    target_lpm = ip if '/' in ip else f"{ip}/32"
    p4_cmd = f'table_add MyIngress.whitelist_table set_whitelisted {target_lpm} =>'
    try:
        output = _ssh_exec_p4_cmd(p4_cmd)
        print(f"   => [完成] P4 交换机响应: {output}", flush=True)
        return True
    except Exception as e:
        print(f"   => [失败] P4 流表下发异常: {e}", flush=True)
        return False


# ==========================================
# IP 身份标签查询
# ==========================================
def get_ip_label(ip: str) -> str:
    """
    IP 身份查询接口。
    查询顺序：白名单 → 黑名单 → 内网/外网判定。
    """
    if is_whitelisted(ip):
        return "Whitelisted_VIP"
    if is_blacklisted(ip):
        return "Blacklisted_Ban"

    # 内网/保留地址 → Internal_Asset，其余 → External_User
    if ip.startswith(("10.", "192.168.", "172.", "127.")):
        return "Internal_Asset"
    return "External_User"
