# -*- coding: utf-8 -*-
import logging
import struct
import socket
from typing import cast

try:
    from .add_ip import get_ip_label      # 包模式
except ImportError:
    try:
        from add_ip import get_ip_label   # 独立模式
    except ImportError:
        def get_ip_label(ip):
            return 5.0  # 降级兜底：中等风险

logger = logging.getLogger(__name__)

# 🌟 共享内存写入器（替代 UDP）
# ==========================================
# ⚙️ 双缓冲冷/热池（两份轮换，生产者写一份、消费者读另一份）
# ==========================================
unanalyzed_table1 = {}  # 冷池 1
unanalyzed_table2 = {}  # 冷池 2
analyzed_table1 = {}    # 热池 1
analyzed_table2 = {}    # 热池 2

_write_buf = 1           # 生产者当前写入的缓冲号 (1 或 2)
_ready_buf = None        # 消费者可读的缓冲号 (1 或 2，None 表示未就绪)


def _cold():
    """返回当前写入目标冷池"""
    return unanalyzed_table1 if _write_buf == 1 else unanalyzed_table2


def _hot():
    """返回当前写入目标热池"""
    return analyzed_table1 if _write_buf == 1 else analyzed_table2


def swap_buffers():
    """生产者写完一轮后调用：标记刚写完的缓冲就绪，翻转到另一个"""
    global _write_buf, _ready_buf
    _ready_buf = _write_buf          # 刚写完的 → 就绪，消费者来读
    _write_buf = 3 - _write_buf      # 翻转到另一个缓冲


def clear_ready():
    """消费者处理完后调用：清空刚处理完的就绪池"""
    global _ready_buf
    if _ready_buf == 1:
        unanalyzed_table1.clear()
        analyzed_table1.clear()
    elif _ready_buf == 2:
        unanalyzed_table2.clear()
        analyzed_table2.clear()
    _ready_buf = None


def get_ready_pools():
    """消费者调用：返回 (就绪冷池, 就绪热池)，没数据返回 ({}, {})"""
    if _ready_buf == 1:
        return unanalyzed_table1, analyzed_table1
    elif _ready_buf == 2:
        return unanalyzed_table2, analyzed_table2
    return {}, {}

# ==========================================
# 🔥 端口威胁情报库（分值越高越危险，10 分封顶）
# ==========================================
PORT_LABELS = {
    # --- 10 分：高危 C2 / 远控木马 ---
    4444:  10,   # Metasploit / Cobalt Strike 默认监听
    3333:  10,   # 常见 C2 变种端口
    1337:  10,   # 各类后门 / rootkit
    31337: 10,   # Back Orifice / 后门标准端口
    6666:   9,   # IRC C2 常用
    6667:   9,   # IRC 默认
    6697:   9,   # IRC over SSL
    9999:   8,   # 常见反弹 shell / 木马

    # --- 9 分：DNS / 数据传输隧道 ---
    53:     9,   # DNS 隧道（高熵 DNS 直接拉满）

    # --- 7-8 分：数据外泄高危端口 ---
    22:     8,   # SSH 隧道 / SCP 数据传输
    21:     7,   # FTP 明文外传
    3389:   7,   # RDP 远程桌面数据泄露
    5900:   7,   # VNC 远程控制
    5901:   7,
    23:     6,   # Telnet 明文

    # --- 6 分：邮件外泄通道 ---
    25:     6,   # SMTP 邮件外发
    465:    6,   # SMTPS
    587:    6,   # SMTP Submission
    110:    5,   # POP3
    995:    5,   # POP3S
    143:    5,   # IMAP
    993:    5,   # IMAPS

    # --- 5 分：Windows 内网蔓延端口 ---
    135:    5,   # RPC
    139:    5,   # NetBIOS
    445:    5,   # SMB 永恒之蓝
    1433:   5,   # MSSQL
    3306:   5,   # MySQL
    1521:   5,   # Oracle
    5432:   5,   # PostgreSQL
    27017:  5,   # MongoDB
    6379:   5,   # Redis 未授权

    # --- 3-4 分：可疑 Web / 代理 ---
    8080:   4,   # 备用 HTTP / 代理
    8443:   4,   # 备用 HTTPS
    9090:   4,   # 常见管理面板
    1080:   4,   # SOCKS 代理
    3128:   4,   # Squid 代理
    8888:   3,   # 备用 HTTP

    # --- 1-2 分：正常业务端口（低风险，但高流量可升级） ---
    80:     2,   # HTTP
    443:    2,   # HTTPS
    123:    1,   # NTP
    161:    1,   # SNMP
    162:    1,   # SNMP Trap
    389:    1,   # LDAP
    636:    1,   # LDAPS
    514:    1,   # Syslog
}


def get_port_label(port):
    """返回端口对应的威胁分数（0~10），分数越高越危险"""
    # 1. 命中情报库，直接返回已知分数
    if port in PORT_LABELS:
        return PORT_LABELS[port]
    # 2. 动态端口（>49151），可能是反弹 shell / P2P，给中危分
    if port > 49151:
        return 5
    # 3. 注册端口但不在知名表里（1024-49151），给低危分
    if port > 1024:
        return 3
    # 4. 系统端口（0-1023）不在表里，极低风险
    return 1


# ==========================================
# 🛠️ P4 契约无损解包规范 (精炼对齐)
# ==========================================
# List 1 (34字节不变): 首包留痕契约
FMT_LIST1 = '>I 4s 4s B B H H 16s'

# 🌟【契约完美对齐】：对应 4个32位大I，3个16位大H，1个6字节全局时钟
FMT_LIST2 = '>IIIIHHH6s'  # 4+4+4+4 + 2+2+2 + 6 = 完美的 28 字节！


# ==========================================
# 📡 核心入口：P4 上报流路由分发总枢纽
# ==========================================
def process_p4_report(msg):
    payload = msg[32:]
    payload_len = len(payload)

    if payload_len <= 0:
        return []

    results = []
    pointer = 0

    # 滑动窗口解析：利用首字节标签动态解析粘包
    while pointer < payload_len:
        if payload_len - pointer < 28:
            break

        # 1. 读取当前块的前 4 字节（hash_index 所在位置）
        tag_bytes = payload[pointer: pointer + 4]
        # 大端解出无符号整数
        test_idx = struct.unpack('>I', tag_bytes)[0]

        # 2. 智能判定分流
        # 如果最高字节为 0xFF (即数值大于等于 0xFF000000)
        if test_idx >= 0xFF000000:
            # 检测到 28 字节高危报警包
            chunk = payload[pointer: pointer + 28]
            if len(chunk) == 28:
                vector = build_feature_vector(chunk)
                if vector:
                    results.append(vector)
            pointer += 28  # 步长精准向前滑动 28 字节
        else:
            # 检测到 34 字节冷池首包
            chunk = payload[pointer: pointer + 34]
            if len(chunk) == 34:
                init_first_packet(chunk)
            pointer += 34  # 步长精准向前滑动 34 字节

    return results
# ==========================================
# 🚀 内部打包与四维速率引擎更新逻辑
# ==========================================
def init_first_packet(chunk):
    """【冷池留痕】只抓取纯净的拓扑五元组"""
    hash_idx, src_raw, dst_raw, proto, _, sp, dp, _ = struct.unpack(FMT_LIST1, chunk)

    if hash_idx in _cold() or hash_idx in _hot():
        return True

    src_ip = socket.inet_ntoa(src_raw)
    dst_ip = socket.inet_ntoa(dst_raw)

    _cold()[hash_idx] = [src_ip, dst_ip, sp, dp, proto]
    return True


def build_feature_vector(chunk):
    """【特征熔炼】基于 28B 硬件无损契约，高保真还原 21 维态势感知矩阵"""
    logger.debug("开始解析 28B 高危报警包...")
    try:
        # P4 层 audit_digest_t 结构解包
        hash_idx, pkts, bytes_len, sum_e, max_e, min_e, reason, ts_raw = struct.unpack(FMT_LIST2, chunk)
    except Exception as e:
        logger.error("解包失败，请检查 FMT_LIST2 是否对齐: %s", e)
        return None

    # 从 6 字节的原始大端序列里平滑复活 48bit 硬件全局时钟
    current_ts = int.from_bytes(ts_raw, byteorder='big')
    hash_idx = hash_idx & 0x00FFFFFF
    # 1. 优先查热池
    if hash_idx in _hot():
        vector = _hot()[hash_idx]

    # 2. 查冷池（两表解耦，原位升级）
    elif hash_idx in _cold():
        base = _cold()[hash_idx]

        src_tag = get_ip_label(base[0])
        sp_tag = get_port_label(base[2])
        dp_tag = get_port_label(base[3])

        initial_ts = current_ts

        # 原位构建 21 维特征向量
        vector = [
            base[0], base[1], base[2], base[3], base[4],  # [0-4] 五元组
            src_tag, sp_tag, dp_tag,  # [5-7] 业务画像资产标签
            0, 0,  # [8-9] 历史总累计包、历史总累计字节
            initial_ts, current_ts,  # [10-11] 初始硬件时钟, 上次活跃硬件时钟
            0, 0, 0, 0,  # [12-15] 瞬时PPS, 全局PPS, 瞬时BPS, 全局BPS
            0.0, 0, 9999,  # [16-18] 历史均熵, 历史最高熵, 历史最低熵
            reason,  # [19] 硬件最底层的原始触发原由
            "Normal"  # [20] AI/模型预留的判决标签
        ]
    else:
        # 极端丢包容错兜底
        vector = ["Unknown"] * 8 + [0, 0, current_ts, current_ts, 0, 0, 0, 0, 0.0, 0, 9999, reason, "Normal"]

    # 3. 剥离状态，进行硬件级物理累加
    old_pkts = cast(int, vector[8])
    old_bytes = cast(int, vector[9])
    initial_ts = cast(int, vector[10])
    last_ts = cast(int, vector[11])

    new_pkts = old_pkts + pkts
    new_bytes = old_bytes + bytes_len  # bytes_len 来自硬件上报的真实数据

    # 4. 四维速率计算引擎 (含除零保护与精度保护)
    delta_instant = current_ts - last_ts if current_ts > last_ts else 0
    delta_global = current_ts - initial_ts if current_ts > initial_ts else 1

    # 💡 针对首包第一次报警（时间差为0）进行防冲高保护
    if delta_instant == 0:
        instant_pps = 0
        instant_bps = 0
    else:
        # 使用 round() 代替 int() 保留低频精度
        instant_pps = round((pkts / delta_instant) * 1000000)
        instant_bps = round((bytes_len / delta_instant) * 1000000)

    global_pps = round((new_pkts / delta_global) * 1000000)
    global_bps = round((new_bytes / delta_global) * 1000000)
    # 5. 21 维张量原位覆盖
    vector[8] = new_pkts
    vector[9] = new_bytes
    vector[11] = current_ts
    vector[12] = instant_pps
    vector[13] = global_pps
    vector[14] = instant_bps
    vector[15] = global_bps
    vector[16] = round(sum_e / pkts, 2) if pkts > 0 else 0
    vector[17] = max(vector[17], max_e)
    vector[18] = min(vector[18], min_e)
    vector[19] = reason

    # 挂载入热池
    if hash_idx not in _hot():
        _hot()[hash_idx] = vector
    logger.debug("解析成功，21维特征向量: %s", vector)
    return vector


def process_pulled_registers(vol_dump_str: bytes, ent_dump_str: bytes):
    """
    扫描当前写入缓冲的冷池，打包后翻转到就绪态，通知消费者来读。
    """
    cold = _cold()
    hot = _hot()
    unanalyzed_export = {}

    # 1. 扫描冷池（当前写入缓冲）
    for hash_idx, base in cold.items():
        offset = hash_idx * 8
        if offset + 8 > len(vol_dump_str) or offset + 8 > len(ent_dump_str):
            continue
        vol_chunk = vol_dump_str[offset:offset + 8]
        ent_chunk = ent_dump_str[offset:offset + 8]
        if vol_chunk == b'\x00\x00\x00\x00\x00\x00\x00\x00':
            continue
        raw_p4_binary = (vol_chunk + ent_chunk).hex()
        # 调试：打印每条非零记录的原始数据
        logger.debug("hash=%d offset=%d vol=%s ent=%s pkts=%d bytes=%d score=%d",
            hash_idx, offset,
            vol_chunk.hex(),
            ent_chunk.hex(),
            (int.from_bytes(vol_chunk, 'big') >> 48) & 0xFFFF,
            (int.from_bytes(vol_chunk, 'big') >> 24) & 0xFFFFFF,
            int.from_bytes(vol_chunk, 'big') & 0xFFFFFF)
        unanalyzed_export[hash_idx] = base + [raw_p4_binary]

    # 将拼装好的数据写回冷池（替换原始 5 元素条目为 6 元素条目）
    cold.clear()
    cold.update(unanalyzed_export)

    # 2. 复制热池
    analyzed_export = hot.copy()

    # 3. 翻转：标记当前缓冲就绪，清空并切换到另一个缓冲
    swap_buffers()
    cold_count = len(unanalyzed_export)
    hot_count = len(analyzed_export)
    logger.info(
        "定时器总线: 缓冲 %s 就绪！冷池 %d 条 / 热池 %d 条，已翻转到缓冲 %s",
        _ready_buf, cold_count, hot_count, _write_buf)

    # 通知 DataBridge 消费者有新数据就绪
    try:
        from data_gateway.data_bridge import notify_data_ready
        notify_data_ready()
    except ImportError:
        pass

    return unanalyzed_export, analyzed_export