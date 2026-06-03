# -*- coding: utf-8 -*-
import struct
import socket
import json

try:
    from add_ip import get_ip_label
except ImportError:
    def get_ip_label(ip):
        return "Unknown_Label"
TARGET_IP = "127.0.0.1"  # 本地进程或者对端服务器 IP
TARGET_PORT = 9999       # 对端进程专门用来接收流表数据的端口
data_sender_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# ==========================================
# ⚙️ 全局常驻双表内存大底座
# ==========================================
unanalyzed_table = {}  # 冷池：存放轻量级首包五元组数据 [src, dst, sp, dp, proto]
analyzed_table = {}  # 热池：长驻 21 维多模态特征张量，供后方判官高频评估

PORT_LABELS = {}


def get_port_label(port):
    if port in PORT_LABELS: return 5
    if port > 49151: return 5
    return 5


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

    # 🌟 绝杀：滑动滑窗，利用首字节染色标签动态解析粘包
    while pointer < payload_len:
        if payload_len - pointer < 28:
            break

        # 1. 偷看一眼当前块的前 4 字节（也就是 hash_index 所在的内存）
        tag_bytes = payload[pointer: pointer + 4]
        # 用大端解出无符号整数
        test_idx = struct.unpack('>I', tag_bytes)[0]

        # 2. 智能判定分流
        # 如果最高字节被染成了 0xFF (即数值大于等于 0xFF000000)
        if test_idx >= 0xFF000000:
            # 🚨 坐实了！这是 28 字节的高危报警包！
            chunk = payload[pointer: pointer + 28]
            if len(chunk) == 28:
                vector = build_feature_vector(chunk)
                if vector:
                    results.append(vector)
            pointer += 28  # 步长精准向前滑动 28 字节
        else:
            # 🟢 这绝对是 34 字节的冷池首包！
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

    if hash_idx in unanalyzed_table or hash_idx in analyzed_table:
        return True

    src_ip = socket.inet_ntoa(src_raw)
    dst_ip = socket.inet_ntoa(dst_raw)

    unanalyzed_table[hash_idx] = [src_ip, dst_ip, sp, dp, proto]
    return True


def build_feature_vector(chunk):
    """【特征熔炼】基于 28B 硬件无损契约，高保真还原 21 维态势感知矩阵"""
    print("开始解析")
    try:
        # 🌟【完美解包】：结构、顺序与 P4 层的 audit_digest_t 形成了绝对咬合
        hash_idx, pkts, bytes_len, sum_e, max_e, min_e, reason, ts_raw = struct.unpack(FMT_LIST2, chunk)
    except Exception as e:
        print(f"❌ [契约内爆] 解包失败，请检查 FMT_LIST2 是否对齐: {e}")
        return None, None, None

    # 从 6 字节的原始大端序列里平滑复活 48bit 硬件全局时钟
    current_ts = int.from_bytes(ts_raw, byteorder='big')
    hash_idx = hash_idx & 0x00FFFFFF
    # 1. 优先查热池
    if hash_idx in analyzed_table:
        vector = analyzed_table[hash_idx]

    # 2. 查冷池（两表解耦，原位升级）
    elif hash_idx in unanalyzed_table:
        base = unanalyzed_table[hash_idx]

        src_tag = get_ip_label(base[0])
        sp_tag = get_port_label(base[2])
        dp_tag = get_port_label(base[3])

        initial_ts = current_ts

        # 原位拼接 21 维满血空张量
        vector = [
            base[0], base[1], base[2], base[3], base[4],  # [0-4] 五元组
            src_tag, sp_tag, dp_tag,  # [5-7] 业务画像资产标签
            0, 0,  # [8-9] 历史总累计包、历史总累计字节
            initial_ts, current_ts,  # [10-11] 初始硬件时钟, 上次活跃硬件时钟
            0, 0, 0, 0,  # [12-15] 瞬时PPS, 全局PPS, 瞬时BPS, 全局BPS
            0.0, 0, 9999,  # [16-18] 历史均熵, 历史最高熵, 历史最低熵
            reason,  # [19] 硬件最底层的原始触发原由
            "Normal"  # [20] AI/模型判官预留的判决标签
        ]
    else:
        # 极端丢包防崩兜底
        vector = ["Unknown"] * 8 + [0, 0, current_ts, current_ts, 0, 0, 0, 0, 0.0, 0, 9999, reason, "Normal"]

    # 3. 剥离状态，进行硬件级物理累加
    old_pkts = vector[8]
    old_bytes = vector[9]
    initial_ts = vector[10]
    last_ts = vector[11]

    new_pkts = old_pkts + pkts
    new_bytes = old_bytes + bytes_len  # 🌟【修复核心】：现在的 bytes_len 是硬件亲自吐上来的真数据！

    # 4. 四维高性能速率引擎（附带完美的除零防护锁）
    # 4. 四维速率引擎重装上阵 (引入 round() 精度保护)
    delta_instant = current_ts - last_ts if current_ts > last_ts else 0
    delta_global = current_ts - initial_ts if current_ts > initial_ts else 1

    # 💡 针对首包第一次报警（时间差为0）进行防冲高保护
    if delta_instant == 0:
        instant_pps = 0
        instant_bps = 0
    else:
        # 🌟【修复核心】：用 round() 代替 int()，让 0.99 变成 1，不再丢失低频精度
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
    if hash_idx not in analyzed_table:
        analyzed_table[hash_idx] = vector
    print("解析成功")
    print(vector)
    return vector


def process_pulled_registers(vol_dump_str: bytes, ent_dump_str: bytes):
    """
    【数据零加工·全量流表跨进程跨端口中继器】
    格式完全不动，保留 P4 寄存器最原始的二进制十六进制特征，
    打包后原封不动、无损地喷射给指定的进程或网络端口。
    """
    unanalyzed_export = {}

    # 1. 扫描冷池
    for hash_idx, base in unanalyzed_table.items():
        offset = hash_idx * 8

        # 越界安全防护
        if offset + 8 > len(vol_dump_str) or offset + 8 > len(ent_dump_str):
            continue

        vol_chunk = vol_dump_str[offset:offset + 8]
        ent_chunk = ent_dump_str[offset:offset + 8]

        # 过滤没有产生任何流量包的幽灵表项
        if vol_chunk == b'\x00\x00\x00\x00\x00\x00\x00\x00':
            continue
        raw_p4_binary = (vol_chunk + ent_chunk).hex()
        # 听你的！直接保持最纯净的 P4 原始二进制 hex 字符串，留给后面的人去头疼解析
        unanalyzed_export[hash_idx] = base + [raw_p4_binary]

    # 2. 原封不动复制已经记录好 21 维高危特征的热池
    analyzed_export = analyzed_table.copy()

    # 3. 黄金合体：将两个表原汁原味地打进同一个大 Payload 容器
    export_payload = {
        "unanalyzed_data": unanalyzed_export,  # 冷池全网普通流
        "analyzed_data": analyzed_export  # 热池实时高危流
    }

    # 4. 序列化为标准的 JSON 传输媒介
    export_str = json.dumps(export_payload)

    # 5. 🌟【核心新增】：将全量流表跨进程原封不动打向指定端口
    try:
        # 将 JSON 编码为字节流，通过 UDP 套接字一枪轰给目标端口
        data_sender_sock.sendto(export_str.encode('utf-8'), (TARGET_IP, TARGET_PORT))
        print(
            f"🚀 [定时器总线] 已成功将全量双表快照（冷池 {len(unanalyzed_export)} 条，热池 {len(analyzed_export)} 条）原样投递至进程端口 {TARGET_PORT}！",
            flush=True)
    except Exception as e:
        print(f"❌ [定时器总线] 跨进程端口数据投递失败: {e}", flush=True)

    # 6. 暴力清理双表，清空内存，准备迎接下一个 100 秒新周期的轮询
    unanalyzed_table.clear()
    analyzed_table.clear()

    return True