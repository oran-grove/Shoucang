# -*- coding: utf-8 -*-
"""
数据库示例数据初始化
====================
直接运行以注入黑名单、白名单、员工IP映射到数据库。
重复执行不报错（幂等，使用 ON DUPLICATE KEY UPDATE）。

用法:
    python tests/test_data.py
"""

import sys
from pathlib import Path

# 确保项目根在 sys.path（本文件在 tests/ 子目录中）
_PROJECT_ROOT = Path(__file__).parent.parent.resolve()
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from database.connection import db_cursor


def _fix_enum(cursor):
    """修复blacklist表的threat_level ENUM编码（建表时可能因客户端编码导致损坏）"""
    try:
        cursor.execute("""
            ALTER TABLE blacklist
            MODIFY COLUMN threat_level ENUM('低','中','高')
            CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL
            COMMENT '威胁等级（低/中/高）'
        """)
    except Exception:
        pass


# ================================================================
# 黑名单：已知恶意IP (威胁情报聚合)
# ================================================================
BLACKLIST_ROWS = [
    # ── C2 服务器 ──
    ("45.33.32.156",     "高", "Cobalt Strike C2默认IP",               6666, "C2通信"),
    ("45.33.32.157",     "高", "Metasploit反弹Shell",                  4444, "后门"),
    ("103.56.17.98",     "高", "Empire C2框架监听",                    8080, "C2通信"),
    ("185.130.104.231",  "高", "Sliver C2控制器",                      31337, "C2通信"),
    ("194.26.29.114",    "高", "已知APT28 C2基础设施",                  443, "APT攻击"),
    ("5.252.177.23",     "高", "Hancitor木马C2",                       80, "木马"),
    ("185.220.101.34",   "高", "Tor出口节点-暗网流量中转",             22, "SSH隧道"),
    ("185.220.101.35",   "高", "Tor出口节点-暗网流量中转",             443, "Tor"),
    ("185.220.101.36",   "高", "Tor出口节点-暗网流量中转",             8443, "Tor"),
    ("23.129.64.210",    "中", "Tor出口节点",                          9001, "Tor"),
    ("199.249.230.89",   "中", "Tor出口节点",                          443, "Tor"),

    # ── 恶意软件分发 ──
    ("203.0.113.42",     "中", "恶意软件下载站(Emotet)",               8443, "恶意软件"),
    ("203.0.113.43",     "中", "恶意软件下载站(TrickBot)",             8080, "恶意软件"),
    ("198.51.100.77",    "中", "可疑境外VPS-多次内网扫描",              1337, "扫描"),
    ("198.51.100.88",    "中", "勒索软件C2通信节点",                    445, "勒索软件"),
    ("192.0.2.55",       "高", "WannaCry杀毒后残留C2",                 445, "勒索软件"),

    # ── 暴力破解 / 扫描 ──
    ("91.121.87.10",     "中", "境外可疑RDP爆破来源",                  3389, "暴力破解"),
    ("218.92.0.201",     "中", "SSH暴力破解源(国内)",                  22, "暴力破解"),
    ("58.218.199.147",   "中", "多端口扫描攻击源",                     22, "扫描"),
    ("185.156.73.54",    "中", "FTP暴力破解源",                        21, "暴力破解"),
    ("141.98.10.61",     "低", "互联网扫描引擎(Shodan)",               None, "扫描"),

    # ── 内网横向移动 ──
    ("172.16.0.99",      "高", "内网横向移动跳板机",                   None, "横向移动"),
    ("192.168.100.88",   "高", "可疑内网主机-异常SMB流量",             445, "横向移动"),
    ("10.255.255.1",     "中", "异常RDP内网横移探测",                 3389, "横向移动"),

    # ── 挖矿池 / Cryptojacking ──
    ("51.15.56.68",      "中", "Monero挖矿池(已知)",                  3333, "挖矿"),
    ("128.199.167.154",  "中", "Stratum矿池代理",                     4444, "挖矿"),
    ("185.165.171.84",   "中", "疑似挖矿中转节点",                    8080, "挖矿"),

    # ── 钓鱼 / 欺诈 ──
    ("104.21.85.39",     "中", "仿冒企业登录页",                       443, "钓鱼"),
    ("185.53.179.6",     "中", "凭证收集钓鱼站",                       80, "钓鱼"),

    # ── 僵尸网络 ──
    ("193.27.228.54",    "高", "Mirai僵尸网络控制器",                  23, "僵尸网络"),
    ("45.155.205.233",   "高", "Meris僵尸网络C2",                      443, "僵尸网络"),

    # ── DNS隧道 / 数据传输 ──
    ("144.76.136.12",    "中", "DNS隧道中转服务器",                    53, "DNS隧道"),
    ("37.120.192.154",   "中", "DNS隐蔽信道出口",                      53, "DNS隧道"),

    # ── 代理 / VPN出口 ──
    ("51.38.115.200",    "低", "公开SOCKS代理-可能被滥用",             1080, "代理"),
    ("185.199.240.55",   "低", "商业VPN出口-匿名化流量",               443, "VPN"),
]


# ================================================================
# 白名单：受信任的正常业务IP
# ================================================================
WHITELIST_ROWS = [
    # ── 内网基础设施 ──
    ("10.0.0.2",         "P4交换机管理接口",          None, "trust"),
    ("10.0.0.1",         "网关/路由器",               None, "trust"),
    ("10.0.0.100",       "内网文件服务器(NAS)",        8080, "trust"),
    ("10.0.0.200",       "内网DNS服务器",             53,   "trust"),
    ("10.0.0.250",       "内网日志服务器(ELK)",        9200, "trust"),
    ("10.0.0.254",       "内网监控服务器(Zabbix)",     10051, "trust"),
    ("192.168.1.1",      "核心路由器",                 None, "trust"),

    # ── 公共DNS ──
    ("8.8.8.8",          "Google Public DNS",          53,  "trust"),
    ("8.8.4.4",          "Google Public DNS (备用)",    53,  "trust"),
    ("1.1.1.1",          "Cloudflare DNS",             53,  "trust"),
    ("1.0.0.1",          "Cloudflare DNS (备用)",       53,  "trust"),
    ("9.9.9.9",          "Quad9 DNS",                  53,  "trust"),
    ("208.67.222.222",   "OpenDNS",                    53,  "trust"),
    ("208.67.220.220",   "OpenDNS (备用)",              53,  "trust"),

    # ── CDN / 静态资源 ──
    ("142.250.80.46",    "Google服务",                 443, "trust"),
    ("93.184.216.34",    "EdgeCast CDN",               80,  "trust"),
    ("151.101.1.140",    "Fastly CDN",                 443, "trust"),
    ("104.16.132.229",   "Cloudflare CDN",             443, "trust"),
    ("104.16.133.229",   "Cloudflare CDN",             443, "trust"),
    ("151.101.65.69",    "Fastly CDN(Reddit等)",       443, "trust"),

    # ── 云服务商 ──
    ("52.216.0.0",       "AWS S3(美东)",               443, "trust"),
    ("13.107.42.14",     "Microsoft Office 365",       443, "trust"),
    ("13.107.6.158",     "Microsoft Teams",            443, "trust"),
    ("142.251.175.0",    "Google Workspace",           443, "trust"),

    # ── 代码/包仓库 ──
    ("140.82.112.4",     "GitHub",                     443, "trust"),
    ("140.82.113.4",     "GitHub API",                 443, "trust"),
    ("151.101.0.223",    "PyPI(Python包)",             443, "trust"),
    ("104.16.18.94",     "npm registry",               443, "trust"),
    ("52.72.211.250",    "Docker Hub",                 443, "trust"),

    # ── 系统更新 ──
    ("91.189.91.38",     "Ubuntu更新源",               80,  "trust"),
    ("91.189.91.39",     "Ubuntu安全更新",             80,  "trust"),
    ("13.107.4.50",      "Windows Update",             443, "trust"),
    ("17.253.21.202",    "macOS更新(Apple)",           443, "trust"),

    # ── NTP时间同步 ──
    ("129.6.15.28",      "NIST NTP服务器",             123, "trust"),
    ("216.239.35.0",     "Google NTP",                 123, "trust"),
    ("162.159.200.123",  "Cloudflare NTP",             123, "trust"),

    # ── 常用SaaS ──
    ("34.196.254.28",    "Slack消息",                  443, "trust"),
    ("69.171.235.0",     "企业微信",                   443, "trust"),
    ("103.2.30.121",     "钉钉",                       443, "trust"),
    ("47.96.0.0",        "阿里云OSS",                  443, "trust"),
]


# ================================================================
# 员工IP映射
# ================================================================
IP_DEPT_ROWS = [
    ("EMP001", "10.0.1.50", "财务部", "张会计"),
    ("EMP002", "10.0.1.51", "财务部", "李出纳"),
    ("EMP003", "10.0.1.52", "财务部", "王财务"),
    ("EMP004", "10.0.1.53", "财务部", "赵总监"),
    ("EMP005", "10.0.1.54", "财务部", "钱审计"),
    ("EMP006", "10.0.2.30", "研发部", "李工程师"),
    ("EMP007", "10.0.2.31", "研发部", "陈程序员"),
    ("EMP008", "10.0.2.32", "研发部", "刘架构师"),
    ("EMP009", "10.0.2.33", "研发部", "周测试"),
    ("EMP010", "10.0.2.34", "研发部", "黄运维"),
    ("EMP011", "10.0.3.10", "人事部", "王HR"),
    ("EMP012", "10.0.3.11", "人事部", "孙招聘"),
    ("EMP013", "10.0.3.12", "人事部", "吴薪酬"),
    ("EMP014", "10.0.4.1",  "运维部", "赵运维"),
    ("EMP015", "10.0.4.2",  "运维部", "钱网管"),
    ("EMP016", "10.0.4.3",  "运维部", "郑安全"),
    ("EMP017", "10.0.5.20", "市场部", "陈市场"),
    ("EMP018", "10.0.5.21", "市场部", "林品牌"),
    ("EMP019", "10.0.5.22", "市场部", "杨推广"),
    ("EMP020", "10.0.6.50", "研发部", "吴前端"),
    ("EMP021", "10.0.6.51", "研发部", "郑后端"),
    ("EMP022", "10.0.6.52", "研发部", "冯算法"),
    ("EMP023", "10.0.7.10", "法务部", "周法务"),
    ("EMP024", "10.0.7.11", "法务部", "张合规"),
    ("EMP025", "10.0.8.1",  "管理层", "罗CEO"),
    ("EMP026", "10.0.8.2",  "管理层", "许CTO"),
    # P4测试虚拟机映射
    ("EMP027", "10.0.0.10", "研发部", "测试主机A"),
    ("EMP028", "10.0.0.11", "研发部", "测试主机B"),
    ("EMP029", "10.0.0.12", "研发部", "测试主机C"),
    ("EMP030", "10.0.0.13", "财务部", "测试主机D"),
]


def _batch_insert(table, columns, rows, update_cols):
    """通用批量插入"""
    inserted = 0
    with db_cursor() as (conn, cursor):
        conn.set_charset("utf8mb4")
        cols_str = ", ".join(columns)
        placeholders = ", ".join(["%s"] * len(columns))
        update_str = ", ".join(f"{c}=VALUES({c})" for c in update_cols)
        sql = f"INSERT INTO {table} ({cols_str}) VALUES ({placeholders}) ON DUPLICATE KEY UPDATE {update_str}"
        for row in rows:
            cursor.execute(sql, row)
            if cursor.rowcount > 0:
                inserted += 1
        conn.commit()
    return inserted


def seed_blacklist() -> int:
    with db_cursor() as (conn, cursor):
        _fix_enum(cursor)
        conn.commit()
    n = _batch_insert(
        "blacklist",
        ["ip_address", "threat_level", "reason", "port", "attack_type"],
        BLACKLIST_ROWS,
        ["threat_level", "reason", "port", "attack_type"],
    )
    print(f"[Seed] 黑名单: {n} 条")
    return n


def seed_whitelist() -> int:
    n = _batch_insert(
        "whitelist",
        ["ip_address", "reason", "port", "trust_level"],
        WHITELIST_ROWS,
        ["reason", "port", "trust_level"],
    )
    print(f"[Seed] 白名单: {n} 条")
    return n


def seed_ip_dept_map() -> int:
    n = _batch_insert(
        "ip_dept_map",
        ["number", "ip", "department", "name"],
        IP_DEPT_ROWS,
        ["department", "name"],
    )
    print(f"[Seed] 员工IP映射: {n} 条")
    return n


def seed_all() -> dict:
    print("[Seed] 注入示例数据...")
    result = {
        "blacklist": seed_blacklist(),
        "whitelist": seed_whitelist(),
        "ip_dept_map": seed_ip_dept_map(),
    }
    print(f"[Seed] 完成: 黑名单{result['blacklist']} 白名单{result['whitelist']} 员工{result['ip_dept_map']}")
    return result


if __name__ == "__main__":
    seed_all()
