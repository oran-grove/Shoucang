# -*- coding: utf-8 -*-
import struct
import socket
import json

try:
    from .add_ip import get_ip_label  # 包内导入
except ImportError:
    try:
        from add_ip import get_ip_label  # 独立运行
    except ImportError:
        def get_ip_label(ip: str) -> str:
            return "Unknown_Label"

TARGET_IP = "127.0.0.1"
TARGET_PORT = 9999
data_sender_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# ==========================================
# 全局双表内存存储
# ==========================================
unanalyzed_table = {}  # 未分析流：存放首包五元组 [src, dst, sp, dp, proto]
analyzed_table = {}    # 已分析流：存放 21 维特征张量，供分析器评估

PORT_LABELS = {}


def get_port_label(port):
    if port in PORT_LABELS:
        return 5
    if port > 49151:
        return 5
    return 5


# ==========================================
# P4 数据解包格式定义
# ==========================================
# 34 字节：首包五元组
FMT_LIST1 = '>I 4s 4s B B H H 16s'

# 28 字节：P4 audit_digest_t 结构对齐
# 4x32bit + 3x16bit + 6 字节硬件时钟
FMT_LIST2 = '>IIIIHHH6s'


# ==========================================
# P4 上报流路由分发
# ==========================================
def process_p4_report(msg):
    payload = msg[32:]
    payload_len = len(payload)

    if payload_len <= 0:
        return []

    results = []
    pointer = 0

    # 滑动窗口解析粘包数据，通过首字节标记区分 28B/34B 包
    while pointer < payload_len:
        if payload_len - pointer < 28:
            break

        # 读取前 4 字节（hash_index）判断包类型
        tag_bytes = payload[pointer: pointer + 4]
        test_idx = struct.unpack('>I', tag_bytes)[0]

        # 最高字节为 0xFF 标记 → 28 字节报警包
        if test_idx >= 0xFF000000:
            chunk = payload[pointer: pointer + 28]
            if len(chunk) == 28:
                vector = build_feature_vector(chunk)
                if vector:
                    results.append(vector)
            pointer += 28
        else:
            # 34 字节首包
            chunk = payload[pointer: pointer + 34]
            if len(chunk) == 34:
                init_first_packet(chunk)
            pointer += 34

    return results


# ==========================================
# 首包初始化与特征向量构建
# ==========================================
def init_first_packet(chunk):
    """记录首包五元组到未分析流表"""
    hash_idx, src_raw, dst_raw, proto, _, sp, dp, _ = struct.unpack(FMT_LIST1, chunk)

    if hash_idx in unanalyzed_table or hash_idx in analyzed_table:
        return True

    src_ip = socket.inet_ntoa(src_raw)
    dst_ip = socket.inet_ntoa(dst_raw)

    unanalyzed_table[hash_idx] = [src_ip, dst_ip, sp, dp, proto]
    return True


def build_feature_vector(chunk):
    """从 28 字节 P4 报警包构建 21 维特征向量"""
    try:
        hash_idx, pkts, bytes_len, sum_e, max_e, min_e, reason, ts_raw = struct.unpack(FMT_LIST2, chunk)
    except Exception as e:
        print(f"[错误] 解包失败: {e}")
        return None

    # 从 6 字节大端序列恢复 48bit 硬件时钟
    current_ts = int.from_bytes(ts_raw, byteorder='big')
    hash_idx = hash_idx & 0x00FFFFFF

    # 1. 优先查找已分析流表
    if hash_idx in analyzed_table:
        vector = analyzed_table[hash_idx]

    # 2. 从未分析流表升级
    elif hash_idx in unanalyzed_table:
        base = unanalyzed_table[hash_idx]

        src_tag = get_ip_label(base[0])
        sp_tag = get_port_label(base[2])
        dp_tag = get_port_label(base[3])

        initial_ts = current_ts

        # 构建 21 维特征向量
        vector = [
            base[0], base[1], base[2], base[3], base[4],  # [0-4] 五元组
            src_tag, sp_tag, dp_tag,                        # [5-7] 资产标签
            0, 0,                                           # [8-9] 累计包数, 累计字节
            initial_ts, current_ts,                         # [10-11] 初始时钟, 上次活跃时钟
            0, 0, 0, 0,                                     # [12-15] 瞬时/全局 PPS/BPS
            0.0, 0, 9999,                                   # [16-18] 均熵, 最高熵, 最低熵
            reason,                                          # [19] 触发原因
            "Normal"                                         # [20] 分析器判决标签
        ]
    else:
        # 防崩兜底
        vector = ["Unknown"] * 8 + [0, 0, current_ts, current_ts, 0, 0, 0, 0, 0.0, 0, 9999, reason, "Normal"]

    # 3. 累加统计
    old_pkts = int(vector[8])
    old_bytes = int(vector[9])
    initial_ts = int(vector[10])
    last_ts = int(vector[11])

    new_pkts = old_pkts + pkts
    new_bytes = old_bytes + bytes_len

    # 4. 四维速率计算
    delta_instant = current_ts - last_ts if current_ts > last_ts else 0
    delta_global = current_ts - initial_ts if current_ts > initial_ts else 1

    # 首包时间差为 0 时防止异常速率
    if delta_instant == 0:
        instant_pps = 0
        instant_bps = 0
    else:
        instant_pps = round((pkts / delta_instant) * 1000000)
        instant_bps = round((bytes_len / delta_instant) * 1000000)

    global_pps = round((new_pkts / delta_global) * 1000000)
    global_bps = round((new_bytes / delta_global) * 1000000)

    # 5. 更新特征向量
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

    # 放入已分析流表
    if hash_idx not in analyzed_table:
        analyzed_table[hash_idx] = vector

    return vector


def process_pulled_registers(vol_dump_str: bytes, ent_dump_str: bytes):
    """
    处理遥测拉取的全量寄存器数据。
    将 P4 寄存器原始二进制与内存流表合并，
    打包为 JSON 通过 UDP 发送给数据网关（端口 9999）。
    """
    unanalyzed_export = {}

    # 1. 扫描未分析流表
    for hash_idx, base in unanalyzed_table.items():
        offset = hash_idx * 8

        # 越界保护
        if offset + 8 > len(vol_dump_str) or offset + 8 > len(ent_dump_str):
            continue

        vol_chunk = vol_dump_str[offset:offset + 8]
        ent_chunk = ent_dump_str[offset:offset + 8]

        # 过滤空表项
        if vol_chunk == b'\x00\x00\x00\x00\x00\x00\x00\x00':
            continue

        raw_p4_binary = (vol_chunk + ent_chunk).hex()
        unanalyzed_export[hash_idx] = base + [raw_p4_binary]

    # 2. 复制已分析流表
    analyzed_export = analyzed_table.copy()

    # 3. 构建导出数据
    export_payload = {
        "unanalyzed_data": unanalyzed_export,
        "analyzed_data": analyzed_export
    }

    # 4. 序列化并发送
    export_str = json.dumps(export_payload)

    try:
        data_sender_sock.sendto(export_str.encode('utf-8'), (TARGET_IP, TARGET_PORT))
        print(
            f"[遥测] 流表快照已发送至端口 {TARGET_PORT} "
            f"(未分析 {len(unanalyzed_export)} 条, 已分析 {len(analyzed_export)} 条)",
            flush=True)
    except Exception as e:
        print(f"[遥测] 发送失败: {e}", flush=True)

    # 5. 清空内存，准备下一个周期
    unanalyzed_table.clear()
    analyzed_table.clear()

    return True
