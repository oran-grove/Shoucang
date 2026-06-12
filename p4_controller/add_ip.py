# -*- coding: utf-8 -*-
"""
@module: add_ip.py
@description: 户籍资产与物理流表注入引擎 (Thrift 直连 + 数据库统一管理版)
              黑白名单通过 database 模块统一管理（文件 / MySQL 为唯一数据源，常驻内存共享读取）
              禁止各模块私自操作数据库或自建黑白名单库。
"""

import logging
import sys
import socket
from pathlib import Path

# 确保项目根目录在 sys.path 中（兼容独立运行，必须先于 config 导入）
_PROJECT_ROOT = Path(__file__).parent.parent.resolve()
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# 🌟 Thrift 直连 BMv2 交换机（替代 SSH）
from thrift.transport import TSocket, TTransport
from thrift.protocol import TBinaryProtocol, TMultiplexedProtocol

# 黑白名单统一通过 database 模块接口操作
from database import (
    is_blacklisted,
    is_whitelisted,
    add_to_db_blacklist,
    add_to_db_whitelist,
)

logger = logging.getLogger(__name__)


# ==========================================
# 🔌 Thrift 直连辅助（替代 SSH + simple_switch_CLI）
# ==========================================
def _get_thrift_client():
    """创建与 BMv2 simple_switch 的 Thrift 连接"""
    from bm_runtime.standard import Standard
    transport = TTransport.TBufferedTransport(TSocket.TSocket('127.0.0.1', 9100))
    proto = TMultiplexedProtocol.TMultiplexedProtocol(
        TBinaryProtocol.TBinaryProtocol(transport), "standard")
    client = Standard.Client(proto)
    transport.open()
    return client, transport


def _ip_to_bytes(ip_str: str) -> bytes:
    """将点分十进制 IPv4 地址转为 4 字节大端二进制"""
    return socket.inet_aton(ip_str.strip())


# ==========================================
# 💀 黑名单下发模块 (双源调用 — Thrift 直连版)
#    - 数据库写入: database.add_to_db_blacklist()
#    - P4 物理流表: Thrift 注入 exact drop 规则
# ==========================================
def add_to_blacklist(ip: str, source: str, reason: str = "") -> bool:
    """通过 Thrift 直连交换机，注入精确匹配阻断流表"""
    from bm_runtime.standard.ttypes import (BmMatchParam, BmMatchParamExact,
                                             BmMatchParamType, BmAddEntryOptions)

    if source not in ["frontend", "controller"]:
        logger.error("非法调用！未知的拉黑来源: %s", source)
        return False

    if is_whitelisted(ip):
        logger.warning("行动取消！IP %s 拥有白名单免死金牌，%s 拉黑请求被驳回！", ip, source)
        return False

    if is_blacklisted(ip):
        return True

    logger.info("封杀执行！来源: %s | 目标 IP: %s | 正在通过 Thrift 下发 P4 流表...", source, ip)

    # 第一步：写入数据库（database 模块负责刷新常驻内存）
    if not add_to_db_blacklist(ip, threat_level="高", reason=reason or f"由{source}触发"):
        logger.error("数据库黑名单写入失败，终止拉黑")
        return False

    # 第二步：Thrift 注入 P4 物理流表（若交换机不可达，DB 写入已生效）
    clean_ip = ip.split('/')[0].strip()
    match_key = [BmMatchParam(
        type=BmMatchParamType.EXACT,
        exact=BmMatchParamExact(key=_ip_to_bytes(clean_ip))
    )]

    try:
        client, transport = _get_thrift_client()
        try:
            entry_handle = client.bm_mt_add_entry(
                0,                              # cxt_id
                'MyIngress.blacklist_table',    # table_name
                match_key,                      # match_key
                'MyIngress.drop',               # action_name (全限定名)
                [],                             # action_data
                BmAddEntryOptions()             # options
            )
            logger.info("P4 黑名单流表注入成功！entry_handle=%s", entry_handle)
        finally:
            transport.close()
    except Exception as e:
        logger.warning("P4 交换机不可达，流表未下发 (DB已生效): %s", e)
    return True


# ==========================================
# 🛡️ 白名单下发模块 (单源调用 — Thrift 直连版)
#    - 数据库写入: database.add_to_db_whitelist()
#    - P4 物理流表: Thrift 注入 LPM 免检规则
# ==========================================
def add_to_whitelist(ip: str, source: str, reason: str = "") -> bool:
    """通过 Thrift 直连交换机，注入 LPM 匹配免检流表"""
    from bm_runtime.standard.ttypes import (BmMatchParam, BmMatchParamLPM,
                                             BmMatchParamType, BmAddEntryOptions)

    if source != "frontend":
        logger.warning("越权拦截！%s 试图下发白名单！只有前端拥有此权限。", source)
        return False

    if is_whitelisted(ip):
        return True

    logger.info("特权加白！来源: %s | 目标 IP: %s | 正在通过 Thrift 下发 P4 免检通道...", source, ip)

    # 第一步：写入数据库（database 模块负责刷新常驻内存）
    if not add_to_db_whitelist(ip, reason=reason or f"由{source}手动加白"):
        logger.error("数据库白名单写入失败，终止加白")
        return False

    # 第二步：Thrift 注入 P4 物理流表（若交换机不可达，DB 写入已生效）
    if '/' in ip:
        addr, prefix = ip.split('/')
        prefix_len = int(prefix)
    else:
        addr = ip
        prefix_len = 32

    match_key = [BmMatchParam(
        type=BmMatchParamType.LPM,
        lpm=BmMatchParamLPM(key=_ip_to_bytes(addr), prefix_length=prefix_len)
    )]

    try:
        client, transport = _get_thrift_client()
        try:
            entry_handle = client.bm_mt_add_entry(
                0,                              # cxt_id
                'MyIngress.whitelist_table',    # table_name
                match_key,                      # match_key
                'MyIngress.set_whitelisted',    # action_name (全限定名)
                [],                             # action_data
                BmAddEntryOptions()             # options
            )
            logger.info("P4 免检通道开通成功！entry_handle=%s", entry_handle)
        finally:
            transport.close()
    except Exception as e:
        logger.warning("P4 交换机不可达，免检通道未下发 (DB已生效): %s", e)
    return True


# ==========================================
# 🔎 资产画像及身份标签快速查询接口
# ==========================================
def get_ip_label(ip: str) -> float:
    """
    提供给数据打包器的 IP 身份危险等级查询接口。
    返回 0.0~10.0 的危险分值，与 PORT_LABELS 的 0~10 分体系对齐。
    查询顺序：白名单 → 黑名单 → 内网/外网判定。
    """
    if is_whitelisted(ip):
        return 0.0   # 白名单免检，零风险
    if is_blacklisted(ip):
        from database import get_blacklist_threat_level
        level = get_blacklist_threat_level(ip)
        threat_score_map = {
            "高": 9.5,   # C2/APT/僵尸网络 → 一票否决
            "中": 8.5,   # 恶意软件/钓鱼/挖矿/DNS隧道 → 接近否决，需叠加
            "低": 7.5,   # 代理/VPN/扫描引擎 → 明显可疑，但力度较轻
        }
        return threat_score_map.get(level, 9.5)

    # 内网/保留地址 → 低风险，其余 → 中风险
    if ip.startswith(("10.", "192.168.", "172.", "127.")):
        return 3.0   # 内部资产
    return 6.0       # 外部通信（未知来源）
