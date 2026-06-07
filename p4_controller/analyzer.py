# -*- coding: utf-8 -*-
"""
@module: analyzer.py
@description: 流量分析器 — 基于多维特征的异常外发检测与评分。
"""

# ==========================================
# 安全控制阈值
# ==========================================
BLOCK_SCORE_THRESHOLD = 60  # 阻断阈值，需多维特征同时命中才会触发拉黑
BURST_RATIO_CRITICAL = 5.0  # 带宽突发比例阈值
ENTROPY_STABLE_LIMIT = 300  # 熵值稳定度上限
NORMAL_LOW_SPEED_BPS = 20480  # 低速流量基线（20KB/s）


def evaluate(vector):
    """
    多维特征综合评分。
    :param vector: 长度为 21 的一维特征数组
    :return: (is_malicious: bool, label: str)
    """
    if not vector or vector[0] == "Unknown":
        return False, "Clear_Traffic"

    threat_score = 0.0
    anomaly_reasons = []

    # ==========================================
    # 21 维特征提取
    # ==========================================
    src_ip = vector[0]
    dst_ip = vector[1]
    dst_port = vector[3]
    protocol = vector[4]

    try:
        src_danger_level = float(vector[5]) if vector[5] is not None else 0.0
    except ValueError:
        src_danger_level = 5.0

    try:
        dst_danger_level = float(vector[7]) if vector[7] is not None else 0.0
    except ValueError:
        dst_danger_level = 0.0

    accumulated_pkts = vector[8]
    accumulated_bytes = vector[9]
    initial_hw_ts = vector[10]
    last_hw_ts = vector[11]

    instant_pps = vector[12]
    global_pps = vector[13]
    instant_bps = vector[14]
    global_bps = vector[15]

    avg_entropy = vector[16]
    max_entropy = vector[17]
    min_entropy = vector[18]

    # ==========================================
    # 一票否决：极端危险目标
    # ==========================================
    if dst_danger_level >= 9.0:
        vector[20] = 100.0
        return True, f"Instant_Kill:__Connect_To_Critical_Danger_External_IP_({dst_ip})"

    if src_danger_level >= 9.0 and instant_pps > 10:
        if dst_danger_level > 3.0 or dst_port in [4444, 3333]:
            vector[20] = 100.0
            return True, f"Instant_Kill:__Core_Asset_Active_Exfiltration_Attempt"

    # ==========================================
    # 多维交叉评分
    # ==========================================

    # 1. 静态风险交叉
    static_cross_risk = (src_danger_level * dst_danger_level)
    if static_cross_risk > 75.0:
        threat_score += 40
        anomaly_reasons.append("Extreme_Static_Cross_Risk")
    elif static_cross_risk > 50.0:
        threat_score += 30
        anomaly_reasons.append("High_Static_Cross_Risk")
    elif static_cross_risk > 25.0:
        threat_score += 20
        anomaly_reasons.append("Suspicious_Static_Match")

    # 2. 带宽突增检测
    base_global_bps = global_bps if global_bps > 0 else 1
    if instant_bps > NORMAL_LOW_SPEED_BPS:
        bps_burst_ratio = instant_bps / base_global_bps

        if bps_burst_ratio > BURST_RATIO_CRITICAL:
            threat_score += 25
            anomaly_reasons.append("Critical_Bandwidth_Burst_Pump")
        elif bps_burst_ratio > 2.0:
            threat_score += 15
            anomaly_reasons.append("Minor_Bandwidth_Burst")

    # 3. 累计外发数据量
    if accumulated_bytes > 5242880:  # > 5MB
        threat_score += 25
        anomaly_reasons.append("High_Volume_Exfiltration")
    elif accumulated_bytes > 1048576:  # > 1MB
        threat_score += 10
        anomaly_reasons.append("Warning_Volume_Exfiltration")

    # 4. 载荷熵值分析
    entropy_gap = max_entropy - min_entropy
    flow_duration = last_hw_ts - initial_hw_ts

    if flow_duration > 5000000 and accumulated_pkts > 15 and entropy_gap < ENTROPY_STABLE_LIMIT:
        if avg_entropy > 2100:
            threat_score += 35
            anomaly_reasons.append("Persistent_Encrypted_Tunnel")
        elif avg_entropy < 300:
            threat_score += 25
            anomaly_reasons.append("Covert_C2_Beacon")

    # 5. 敏感端口高熵检测（DNS 隧道）
    if dst_port == 53 and avg_entropy > 2200:
        threat_score += 55
        anomaly_reasons.append("DNS_Tunnel_Suspicious")

    # ==========================================
    # 判定与特征写入
    # ==========================================
    final_score = min(threat_score, 100.0)
    vector[20] = final_score  # 将评分写入第 20 号槽位

    # 超过阈值，触发阻断
    if final_score >= BLOCK_SCORE_THRESHOLD:
        label = f"Insider_Blocked:_{','.join(anomaly_reasons)}"
        return True, label

    # 正常流量
    return False, "Normal_Outbound_Traffic"
