# -*- coding: utf-8 -*-
"""
P4 虚拟机 — 全场景测试流量生成器
================================
在 P4 虚拟机中运行，通过 scapy 向 P4 交换机 (veth_h1) 发包，
覆盖黑白名单命中、多国家 IP、多部门员工、多端口威胁等级、
多熵值、多时段行为等维度，测试完整的 P4→控制器→多智能体链路。

双层黑/白名单架构:
  数据库层 (MySQL blacklist / whitelist 表):
    - 黑名单包含: 外部C2 IP + 内网被控IP (超集)
    - 白名单包含: CDN/DNS/云服务/内网基础设施
    - 消费者: data_bridge._get_ip_score() 对命中IP打分(0.0~9.5)

  P4 硬件层 (通过 add_ip.py 从数据库下发):
    - blacklist_table: 匹配 src_ip → drop (仅内网被控IP，约3条)
    - whitelist_table: 匹配 dst_ip → 绕过审计 (信任的公共/内网服务)

  流水线:
    内网 src → blacklist_table? → DROP (硬件阻断)
              ↓ 未命中
            whitelist_table? → 绕过audit (零开销放行)
              ↓ 未命中
            audit_table 评分 → 超阈值 → digest → 控制器
                                  ↓
                            data_bridge 处理 → IP评分 + 端口评分 + GeoIP
                                  ↓
                            traffic_log → LiveScanOrchestrator → LLM三层管线

用法:
    sudo python tests/p4_traffic_generator.py              # 全部场景
    sudo python tests/p4_traffic_generator.py --safe-only  # 仅安全场景
    sudo python tests/p4_traffic_generator.py --group 2    # 仅运行指定组
    sudo python tests/p4_traffic_generator.py --dry-run    # 仅打印不发包

设计原则:
    - 零项目依赖（仅需 scapy）
    - 场景按 P4 处理结果分组
    - 员工 IP 与 test_data.py 的 ip_dept_map 一致
"""

from scapy.all import *
import string
import time
import random
import os
import sys

# ============================================================
# 配置
# ============================================================
IFACE = "veth_h1"
PAUSE_SCENARIO = 0.5    # 场景间停顿(秒)
PAUSE_PACKET = 0.002    # 发包间隔(秒)
MAX_PAYLOAD = 1400      # 不超过 veth MTU 1500 - IP头20 - UDP头8 - 余量

# ============================================================
# 内网员工 IP — 与 test_data.py ip_dept_map 严格一致
# ============================================================
_FINANCE = {  # 财务部 (高风险部门)
    "张会计": "10.0.1.50", "李出纳": "10.0.1.51", "王财务": "10.0.1.52",
    "赵总监": "10.0.1.53", "钱审计": "10.0.1.54",
}
_RD = {  # 研发部
    "李工程师": "10.0.2.30", "陈程序员": "10.0.2.31", "刘架构师": "10.0.2.32",
    "周测试": "10.0.2.33", "黄运维": "10.0.2.34",
    "吴前端": "10.0.6.50", "郑后端": "10.0.6.51", "冯算法": "10.0.6.52",
    "测试A": "10.0.0.10", "测试B": "10.0.0.11", "测试C": "10.0.0.12",
}
_HR = {"王HR": "10.0.3.10", "孙招聘": "10.0.3.11", "吴薪酬": "10.0.3.12"}
_OPS = {"赵运维": "10.0.4.1", "钱网管": "10.0.4.2", "郑安全": "10.0.4.3"}
_MKT = {"陈市场": "10.0.5.20", "林品牌": "10.0.5.21", "杨推广": "10.0.5.22"}
_LEGAL = {"周法务": "10.0.7.10", "张合规": "10.0.7.11"}
_EXEC = {"罗CEO": "10.0.8.1", "许CTO": "10.0.8.2"}

# ============================================================
# 目标 IP 分类 — 与 test_data.py 的黑白名单一致
# ============================================================
# 白名单目标 IP（P4 whitelist_table 命中 dst_ip → 绕过审计）
_WL_DST = {
    "内网NAS": "10.0.0.100",
    "内网DNS": "10.0.0.200",
    "Cloudflare DNS": "1.1.1.1",
    "Google": "142.250.80.46",
    "GitHub": "140.82.112.4",
    "Office365": "13.107.42.14",
    "npm": "104.16.18.94",
    "NIST NTP": "129.6.15.28",
    "Google Workspace": "142.251.175.0",
}

# 黑名单目标 IP（P4 不处理 dst blacklist，但 data_bridge 会评分）
_BL_DST = {
    "CobaltStrike C2": ("45.33.32.156", 6666),
    "Metasploit": ("45.33.32.157", 4444),
    "APT28 C2": ("194.26.29.114", 443),
    "Sliver C2": ("185.130.104.231", 31337),
    "Mirai C2": ("193.27.228.54", 23),
    "WannaCry C2": ("192.0.2.55", 445),
    "DNS隧道出口": ("37.120.192.154", 53),
    "DNS隧道中转": ("144.76.136.12", 53),
    "SOCKS代理": ("51.38.115.200", 1080),
    "Monero矿池": ("51.15.56.68", 3333),
    "可疑VPS": ("198.51.100.77", 1337),
    "挖矿中转": ("185.165.171.84", 8080),
    "Tor出口1": ("23.129.64.210", 9001),
    "Tor出口2": ("185.220.101.34", 22),
}

# P4 黑名单内网 IP（作为 src_ip 时 P4 硬件直接丢弃）
_P4_BLACKLIST_SRC = {
    "横向移动跳板": "172.16.0.99",
    "内网可疑SMB": "192.168.100.88",
    "RDP横移探测": "10.255.255.1",
}

# 高危国家 IP（非黑名单，但 GeoIP 维度异常）
_HIGH_RISK_GEO = {
    "朝鲜IP": "175.45.176.0",
    "伊朗IP": "195.28.10.0",
    "俄罗斯IP": "194.26.29.114",  # 同时也在黑名单
}

# ============================================================
# 辅助函数
# ============================================================

def _random_payload(size: int, entropy: float) -> bytes:
    """生成指定大小和熵值的载荷。

    Args:
        size: 载荷字节数
        entropy: 0.0-1.0，熵值越高越接近随机
    """
    if entropy >= 0.85:
        return os.urandom(size)
    elif entropy >= 0.6:
        # 混合：70% 随机 + 30% 可打印
        rand_part = bytearray(os.urandom(int(size * 0.7)))
        text_part = ''.join(random.choices(string.ascii_letters + string.digits, k=size - len(rand_part))).encode()
        return bytes(rand_part) + text_part
    elif entropy >= 0.3:
        # 半结构化：类似 base64
        return b"".join(
            random.choice([b"DATA_", b"SYNC_", b"ACK_", b"REQ_", b"RESP_"])
            + os.urandom(8)
            for _ in range(max(1, size // 12))
        )[:size]
    else:
        # 低熵：重复模式
        pattern = b"NORMAL_TRAFFIC_FLOW_SEQUENCE_%04d_" % random.randint(0, 9999)
        return (pattern * (size // len(pattern) + 1))[:size]


def _burst(src_ip, dst_ip, sport, dport, proto="UDP", count=30,
           payload_size=512, entropy=0.5, delay=PAUSE_PACKET):
    """发送一组数据包，模拟一个网络流。

    Args:
        src_ip:  源 IP（内网员工IP，决定 P4 是否进入威胁管线）
        dst_ip:  目标 IP（白名单则绕过审计，黑名单则触发告警）
        sport:   源端口
        dport:   目标端口（触发端口威胁评分）
        proto:   "UDP" 或 "TCP"
        count:   发包数量
        payload_size: 每个包的载荷大小(字节)，自动截断到 MAX_PAYLOAD
        entropy: 载荷熵值 0.0-1.0
        delay:   包间延迟(秒)
    """
    # 载荷截断并等比增加包数，保持总流量不变
    if payload_size > MAX_PAYLOAD:
        ratio = payload_size / MAX_PAYLOAD
        payload_size = MAX_PAYLOAD
        count = int(count * ratio)
    for i in range(count):
        pkt = Ether() / IP(src=src_ip, dst=dst_ip) / \
              (UDP(sport=sport, dport=dport) if proto == "UDP"
               else TCP(sport=sport, dport=dport, flags="PA")) / \
              Raw(load=_random_payload(payload_size, entropy))
        sendp(pkt, iface=IFACE, verbose=False)
        time.sleep(delay)


def _section(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def _scenario(label: str, desc: str):
    print(f"\n  [{label}] {desc}")


# ============================================================
# Group 1: 黑名单 src_ip (内网被控主机) — 数据库黑名单 + P4 硬件阻断
# ============================================================
# 说明：项目有两层黑名单机制
#   L0 P4 硬件: blacklist_table 匹配 src_ip → drop（需通过 add_ip.py 下发）
#   L4 data_bridge: _get_ip_score() 对 src/dst 命中数据库黑名单的打高分
# 本组测试内网被控 IP 作 src → 若 P4 表已编程则硬件丢弃；
# 若未编程则 data_bridge 仍会对其打高危评分(7.5~9.5)
# ============================================================
def group1_p4_blacklist_drop():
    """内网黑名单 IP 作为 src — 测试双层阻断。

    数据库黑名单包含的内网 IP（横向移动跳板/可疑SMB/RDP横移），
    P4 层若已下发表项则硬件丢弃；data_bridge 层必定打高危评分。
    """
    _section("Group 1: 黑名单src_ip — 内网被控主机 (P4 drop + DB高危)")

    scenarios = [
        ("BL-DROP-01", "横向移动跳板机发包",
         _P4_BLACKLIST_SRC["横向移动跳板"], "10.0.0.2", 61234, 445, 50, 1024, 0.6),
        ("BL-DROP-02", "内网可疑SMB流量",
         _P4_BLACKLIST_SRC["内网可疑SMB"], "10.0.0.100", 61235, 445, 80, 4096, 0.5),
        ("BL-DROP-03", "RDP内网横移探测",
         _P4_BLACKLIST_SRC["RDP横移探测"], "10.0.0.2", 61236, 3389, 30, 512, 0.4),
    ]

    for label, desc, src, dst, sp, dp, n, sz, ent in scenarios:
        _scenario(label, desc)
        print(f"       {src}:{sp} → {dst}:{dp} | {n}包 × {sz}B | 熵={ent:.1f}")
        _burst(src, dst, sp, dp, count=n, payload_size=sz, entropy=ent)
        time.sleep(PAUSE_SCENARIO)


# ============================================================
# Group 2: 白名单 dst_ip — P4 绕过审计 + data_bridge 零分
# ============================================================
# P4 whitelist_table 匹配 dst_ip → 设置 is_whitelisted=1 → 跳过 audit_table
# data_bridge._get_ip_score() 对白名单 IP 返回 0.0（零风险）
# ============================================================
def group2_p4_whitelist_bypass():
    """白名单 dst_ip — P4 绕过审计 + data_bridge 零风险评分。

    P4 匹配 dst 到白名单后跳过 audit 寄存器评分；
    data_bridge 对白名单 IP 打分 0.0，多智能体应判定为 safe。
    """
    _section("Group 2: 白名单dst_ip — P4绕过审计 + DB零分")

    scenarios = [
        ("WL-S01", "研发访问GitHub", _RD["李工程师"], _WL_DST["GitHub"],
         52341, 443, 15, 1024, 0.5),
        ("WL-S02", "运维DNS查询", _OPS["钱网管"], _WL_DST["Cloudflare DNS"],
         30221, 53, 10, 64, 0.1),
        ("WL-S03", "市场部访问Google", _MKT["陈市场"], _WL_DST["Google"],
         45678, 443, 15, 512, 0.5),
        ("WL-S04", "测试主机访问NAS", _RD["测试A"], _WL_DST["内网NAS"],
         49152, 8080, 20, 2048, 0.2),
        ("WL-S05", "法务部Office365", _LEGAL["周法务"], _WL_DST["Office365"],
         53124, 443, 15, 512, 0.4),
        ("WL-S06", "研发npm下载", _RD["郑后端"], _WL_DST["npm"],
         60123, 443, 20, 2048, 0.5),
        ("WL-S07", "NTP时间同步", _OPS["郑安全"], _WL_DST["NIST NTP"],
         123, 123, 5, 48, 0.1),
        ("WL-S08", "CEO访问Google Workspace", _EXEC["许CTO"], _WL_DST["Google Workspace"],
         50123, 443, 15, 512, 0.4),
    ]

    for label, desc, src, dst, sp, dp, n, sz, ent in scenarios:
        _scenario(label, desc)
        print(f"       {src}:{sp} → {dst}:{dp} | {n}包 × {sz}B | 熵={ent:.1f}")
        _burst(src, dst, sp, dp, count=n, payload_size=sz, entropy=ent)
        time.sleep(PAUSE_SCENARIO)


# ============================================================
# Group 3: 数据库黑名单 dst_ip — P4正常通过 + data_bridge 高危评分
# ============================================================
# src 是正常内网IP（不在P4黑名单），dst 是数据库黑名单中的外部C2/恶意IP
# P4 正常审计 → data_bridge._get_ip_score(dst_ip) → 7.5~9.5分
# 多智能体 Layer1 应判定为 suspicious 或 dangerous
# ============================================================
def group3_suspicious():
    """数据库黑名单 dst_ip — P4 正常审计 + data_bridge 高危评分。

    src 为正常员工 IP，dst 命中数据库黑名单（SOCKS代理/可疑VPS/Tor出口/挖矿），
    data_bridge 对 dst_ip 打 7.5~9.5 威胁分 → 多智能体应判 suspicious。
    """
    _section("Group 3: 黑名单dst_ip — 可疑流量 (DB高危评分)")

    scenarios = [
        # (label, desc, src, dst, sp, dp, count, pkt_size, entropy)
        ("SP-S01", "张会计凌晨SOCKS代理大流量",
         _FINANCE["张会计"], _BL_DST["SOCKS代理"][0],
         55512, _BL_DST["SOCKS代理"][1], 150, 1400, 0.85),
        ("SP-S02", "王HR访问可疑VPS扫描端口",
         _HR["王HR"], _BL_DST["可疑VPS"][0],
         40123, _BL_DST["可疑VPS"][1], 100, 800, 0.75),
        ("SP-S03", "陈程序员UDP高熵到Ubuntu更新源(非标准端口)",
         _RD["陈程序员"], "91.189.91.38",
         50123, 9999, 80, 1000, 0.9),
        ("SP-S04", "郑安全大流量到Tor出口",
         _OPS["郑安全"], _BL_DST["Tor出口1"][0],
         49876, _BL_DST["Tor出口1"][1], 200, 1500, 0.88),
        ("SP-S05", "林品牌到挖矿中转节点",
         _MKT["林品牌"], _BL_DST["挖矿中转"][0],
         56123, _BL_DST["挖矿中转"][1], 120, 1024, 0.7),
    ]

    for label, desc, src, dst, sp, dp, n, sz, ent in scenarios:
        _scenario(label, desc)
        print(f"       {src}:{sp} → {dst}:{dp} | {n}包 × {sz}B | 熵={ent:.1f}")
        _burst(src, dst, sp, dp, count=n, payload_size=sz, entropy=ent)
        time.sleep(PAUSE_SCENARIO)


# ============================================================
# Group 4: 已知攻击模式 — 高威胁黑名单 dst + 特征端口 + 高熵
# ============================================================
# 本组覆盖 C2通信 / 反弹Shell / APT / DNS隧道 / 僵尸网络 / 挖矿
# dst_ip 命中数据库高威胁黑名单 + 端口为已知恶意端口(6666/4444/31337等)
# ============================================================
def group4_malicious():
    """已知攻击模式 — 高威胁 dst + 恶意端口 + 高熵。

    data_bridge IP评分 8.5~9.5 + 端口评分 9~10 → 总威胁分应超阻断阈值。
    多智能体 Layer1 应判 dangerous 直接告警。
    """
    _section("Group 4: 已知攻击模式 — 恶意流量 (预期 → malicious)")

    scenarios = [
        ("MAL-M01", "赵总监→Cobalt Strike C2 (6666)",
         _FINANCE["赵总监"], _BL_DST["CobaltStrike C2"][0],
         55555, _BL_DST["CobaltStrike C2"][1], 300, 1500, 0.95),
        ("MAL-M02", "测试B→Metasploit反弹Shell (4444)",
         _RD["测试B"], _BL_DST["Metasploit"][0],
         44444, _BL_DST["Metasploit"][1], 250, 1400, 0.92),
        ("MAL-M03", "罗CEO→APT28 C2 (俄罗斯IP)",
         _EXEC["罗CEO"], _BL_DST["APT28 C2"][0],
         60123, _BL_DST["APT28 C2"][1], 400, 1500, 0.96),
        ("MAL-M04", "王财务→DNS隐蔽信道 (53/UDP)",
         _FINANCE["王财务"], _BL_DST["DNS隧道出口"][0],
         34567, _BL_DST["DNS隧道出口"][1], 100, 512, 0.82),
        ("MAL-M05", "刘架构师→Sliver C2 (31337)",
         _RD["刘架构师"], _BL_DST["Sliver C2"][0],
         50001, _BL_DST["Sliver C2"][1], 280, 1400, 0.93),
        ("MAL-M06", "赵运维→WannaCry残留C2 (445)",
         _OPS["赵运维"], _BL_DST["WannaCry C2"][0],
         61234, _BL_DST["WannaCry C2"][1], 150, 4096, 0.55),
        ("MAL-M07", "杨推广→Mirai僵尸网络C2 (23)",
         _MKT["杨推广"], _BL_DST["Mirai C2"][0],
         60023, _BL_DST["Mirai C2"][1], 100, 256, 0.45),
        ("MAL-M08", "李出纳→Monero矿池 (3333)",
         _FINANCE["李出纳"], _BL_DST["Monero矿池"][0],
         53333, _BL_DST["Monero矿池"][1], 200, 800, 0.8),
        # 同一员工第二次异常 — 测试 L2 回溯关联
        ("MAL-M09", "张会计(同SP-S01)→DNS隧道中转",
         _FINANCE["张会计"], _BL_DST["DNS隧道中转"][0],
         56789, _BL_DST["DNS隧道中转"][1], 80, 600, 0.78),
    ]

    for label, desc, src, dst, sp, dp, n, sz, ent in scenarios:
        _scenario(label, desc)
        print(f"       {src}:{sp} → {dst}:{dp} | {n}包 × {sz}B | 熵={ent:.1f}")
        _burst(src, dst, sp, dp, count=n, payload_size=sz, entropy=ent)
        time.sleep(PAUSE_SCENARIO)


# ============================================================
# Group 5: 边界情况
# ============================================================
def group5_edge_cases():
    """边界测试：非典型特征组合。"""
    _section("Group 5: 边界情况 (Edge Cases)")

    scenarios = [
        ("EDGE-E01", "白名单GitHub但超大流量+高熵(80MB级)",
         _RD["周测试"], _WL_DST["GitHub"],
         49152, 443, 500, 1500, 0.95),
        ("EDGE-E02", "朝鲜IP低流量探测",
         _RD["测试C"], _HIGH_RISK_GEO["朝鲜IP"],
         49153, 80, 15, 64, 0.1),
        ("EDGE-E03", "伊朗IP中等流量TLS",
         _HR["孙招聘"], _HIGH_RISK_GEO["伊朗IP"],
         49154, 443, 60, 800, 0.8),
        ("EDGE-E04", "WannaCry C2极低流量心跳(5包)",
         _OPS["赵运维"], _BL_DST["WannaCry C2"][0],
         61234, _BL_DST["WannaCry C2"][1], 5, 100, 0.3),
        ("EDGE-E05", "Tor出口SSH隧道大流量",
         _RD["黄运维"], _BL_DST["Tor出口2"][0],
         60122, _BL_DST["Tor出口2"][1], 300, 1200, 0.9),
    ]

    for label, desc, src, dst, sp, dp, n, sz, ent in scenarios:
        _scenario(label, desc)
        print(f"       {src}:{sp} → {dst}:{dp} | {n}包 × {sz}B | 熵={ent:.1f}")
        _burst(src, dst, sp, dp, count=n, payload_size=sz, entropy=ent)
        time.sleep(PAUSE_SCENARIO)


# ============================================================
# Group 6: 多部门多行为 — 同部门不同员工对比
# ============================================================
def group6_cross_dept():
    """跨部门对比：财务部(高风险) vs 研发部(中等) vs 运维部(特权)。

    相同目标IP，不同部门的源IP → 测试部门维度的威胁差异
    """
    _section("Group 6: 跨部门行为对比")

    # 同一个可疑 VPS，三个部门访问
    target = _BL_DST["可疑VPS"]
    employees = [
        ("DEPT-01", "财务部钱审计→可疑VPS", _FINANCE["钱审计"]),
        ("DEPT-02", "研发部冯算法→可疑VPS", _RD["冯算法"]),
        ("DEPT-03", "运维部钱网管→可疑VPS", _OPS["钱网管"]),
    ]

    for label, desc, src in employees:
        _scenario(label, desc)
        print(f"       {src}:51234 → {target[0]}:{target[1]} | 80包 × 1024B | 熵=0.75")
        _burst(src, target[0], 51234, target[1], count=80, payload_size=1024, entropy=0.75)
        time.sleep(PAUSE_SCENARIO)

    # 财务部内部对比：正常 vs 异常
    _scenario("DEPT-04", "财务部张会计正常访问Google(对照组)")
    print(f"       {_FINANCE['张会计']}:52341 → {_WL_DST['Google']}:443 | 15包 × 512B | 熵=0.5")
    _burst(_FINANCE["张会计"], _WL_DST["Google"], 52341, 443, count=15, payload_size=512, entropy=0.5)
    time.sleep(PAUSE_SCENARIO)


# ============================================================
# 主入口
# ============================================================

GROUPS = {
    1: ("黑名单src_ip—内网被控主机", group1_p4_blacklist_drop),
    2: ("白名单dst_ip—正常业务放行", group2_p4_whitelist_bypass),
    3: ("黑名单dst_ip—可疑流量", group3_suspicious),
    4: ("已知攻击模式—恶意流量", group4_malicious),
    5: ("边界情况", group5_edge_cases),
    6: ("跨部门对比", group6_cross_dept),
}


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="P4全场景测试流量生成器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  sudo python tests/p4_traffic_generator.py                # 全部场景
  sudo python tests/p4_traffic_generator.py --group 3      # 仅可疑流量
  sudo python tests/p4_traffic_generator.py --group 1 4    # P4丢弃 + 恶意
  sudo python tests/p4_traffic_generator.py --safe-only    # 仅安全场景(Group1+2)
  sudo python tests/p4_traffic_generator.py --dry-run      # 仅打印不发包
        """,
    )
    parser.add_argument("--group", type=int, nargs="+", default=None,
                        help="指定运行的分组编号 (1-6)，不指定则全部运行")
    parser.add_argument("--safe-only", action="store_true",
                        help="仅运行安全场景 (Group 1+2)")
    parser.add_argument("--dry-run", action="store_true",
                        help="仅打印场景描述，不实际发包")
    args = parser.parse_args()

    if args.safe_only:
        selected = [1, 2]
    elif args.group:
        selected = sorted(set(args.group))
        invalid = [g for g in selected if g not in GROUPS]
        if invalid:
            print(f"❌ 无效分组: {invalid}，可选: {list(GROUPS.keys())}")
            sys.exit(1)
    else:
        selected = list(GROUPS.keys())

    print(f"{'='*60}")
    print(f"  P4 全场景测试流量生成器")
    print(f"  接口: {IFACE}")
    print(f"  场景组: {selected}")
    print(f"  模式: {'DRY-RUN (预览)' if args.dry_run else 'LIVE (发包)'}")
    print(f"{'='*60}")

    if args.dry_run:
        print("\n⚠ DRY-RUN 模式 — 仅打印场景，不实际发包\n")
        for gid in selected:
            name, _ = GROUPS[gid]
            print(f"  Group {gid}: {name}")
        return

    print("\n🔥 开始生成测试流量...\n")
    start_time = time.time()
    total_packets = 0

    try:
        for gid in selected:
            name, fn = GROUPS[gid]
            fn()
        total_time = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"  ✅ 全部完成! 耗时 {total_time:.0f} 秒")
        print(f"{'='*60}")
    except KeyboardInterrupt:
        print(f"\n\n⚠ 用户中断")


if __name__ == "__main__":
    main()
