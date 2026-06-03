# -*- coding: utf-8 -*-
"""
@module: add_ip.py
@description: 户籍资产与物理流表注入引擎 (跨系统远程 SSH 纯净版)
"""

import os
import re
import paramiko

# ==========================================
# ⚙️ 远程虚拟机网络拓扑配置 (与中央控制器完全对齐)
# ==========================================
VM_IP = "192.168.56.101"  # 💡 你的 VirtualBox 虚拟机网卡 IP
VM_PORT = 22  # 💡 虚拟机标准 SSH 端口
VM_USER = "p4"  # 💡 你的虚拟机用户名
VM_PASSWORD = "p4"  # 💡 你的虚拟机密码
THRIFT_PORT = "9100"  # 💡 P4 交换机监听的控制端口

BLACKLIST_FILE = "blacklist.txt"
WHITELIST_FILE = "whitelist.txt"


def load_list_from_file(filepath):
    """从本地文件加载 IP 集合到内存"""
    if not os.path.exists(filepath):
        return set()
    with open(filepath, 'r') as f:
        return set(line.strip() for line in f if line.strip())


def save_ip_to_file(filepath, ip):
    """将单个 IP 永久追加到本地文件"""
    with open(filepath, 'a') as f:
        f.write(ip + '\n')


# 内存高速缓存
CACHE_BLACKLIST = load_list_from_file(BLACKLIST_FILE)
CACHE_WHITELIST = load_list_from_file(WHITELIST_FILE)


# ==========================================
# 💀 黑名单下发模块 (双源调用 - 远程注入版)
# ==========================================
def add_to_blacklist(ip, source):
    """远程穿透至虚拟机，注入精确匹配阻断流表"""
    if source not in ["frontend", "controller"]:
        print(f"❌ [非法调用] 未知的拉黑来源: {source}", flush=True)
        return False

    if ip in CACHE_WHITELIST:
        print(f"⚠️ [行动取消] IP {ip} 拥有白名单免死金牌，{source} 拉黑请求被驳回！", flush=True)
        return False

    if ip in CACHE_BLACKLIST:
        return True

    print(f"💀 [封杀执行] 来源: {source} | 目标 IP: {ip} | 正在跨系统下发 P4 流表...", flush=True)
    save_ip_to_file(BLACKLIST_FILE, ip)
    CACHE_BLACKLIST.add(ip)

    # 🌟【远程注入核心】：开启 SSH 管道直连 VirtualBox
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(VM_IP, port=VM_PORT, username=VM_USER, password=VM_PASSWORD, timeout=5)

        # 💡 安全微雕：切除 /32，使用标准 drop，并在末尾加上 '=>' 防呆符！
        clean_ip = ip.split('/')[0].strip()
        p4_cmd = f'table_add MyIngress.blacklist_table drop {clean_ip} =>'
        exec_cmd = f'echo "{p4_cmd}" | simple_switch_CLI --thrift-port {THRIFT_PORT}'
        stdin, stdout, stderr = ssh.exec_command(exec_cmd)

        output = stdout.read().decode('utf-8', errors='ignore')
        print(f"   => 🔒 P4 物理网反馈: {output.strip()}", flush=True)
        return True
    except Exception as e:
        print(f"   => ❌ P4 物理拦截下发遭遇系统性失败: {e}", flush=True)
        return False
    finally:
        ssh.close()


# ==========================================
# 🛡️ 白名单下发模块 (单源调用 - 远程注入版)
# ==========================================
def add_to_whitelist(ip, source):
    """远程穿透至虚拟机，注入 LPM 匹配免检流表"""
    if source != "frontend":
        print(f"🚨 [越权拦截] 警告！{source} 试图下发白名单！只有前端拥有此权限。", flush=True)
        return False

    if ip in CACHE_WHITELIST:
        return True

    print(f"🛡️ [特权加白] 来源: {source} | 目标 IP: {ip} | 正在开通 P4 免检通道...", flush=True)
    save_ip_to_file(WHITELIST_FILE, ip)
    CACHE_WHITELIST.add(ip)

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(VM_IP, port=VM_PORT, username=VM_USER, password=VM_PASSWORD, timeout=5)

        # 💡 同样在末尾加上 '=>'，告诉硬件后面没有参数了！
        target_lpm = ip if '/' in ip else f"{ip}/32"
        p4_cmd = f'table_add MyIngress.whitelist_table set_whitelisted {target_lpm} =>'

        exec_cmd = f'echo "{p4_cmd}" | simple_switch_CLI --thrift-port {THRIFT_PORT}'
        stdin, stdout, stderr = ssh.exec_command(exec_cmd)

        output = stdout.read().decode('utf-8', errors='ignore')
        print(f"   => 🟢 P4 免检网反馈: {output.strip()}", flush=True)

        # 🌟【进阶联动】：如果此 IP 之前在黑名单里，加白时应联动让硬件释放它（此处可根据后续需要选配 table_delete）
        return True
    except Exception as e:
        print(f"   => ❌ P4 免检通道下发失败: {e}", flush=True)
        return False
    finally:
        ssh.close()


# ==========================================
# 🔎 资产画像及身份标签快速查询接口
# ==========================================
def get_ip_label(ip):
    """
    提供给数据打包器的 IP 身份查询接口
    """
    if ip in CACHE_WHITELIST:
        return "Whitelisted_VIP"
    elif ip in CACHE_BLACKLIST:
        return "Blacklisted_Ban"

    # 🌟【安全修复】：将原本返回的整型数字 5 修正为标准的资产标签字符串，防止主控系统因类型失配崩溃
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
        return "Internal_Asset"
    return "External_User"