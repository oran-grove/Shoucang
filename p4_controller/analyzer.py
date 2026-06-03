# -*- coding: utf-8 -*-
"""
@module: analyzer.py (内鬼监视大脑 - 精准反误杀版)
@description: 针对纯外发拓扑，通过 60 分红线与多维动态交织，实现零误杀的前线精准阻断。
"""

# ==========================================
# ⚙️ 激进派安全控制阈值
# ==========================================
BLOCK_SCORE_THRESHOLD = 60  # 红线严卡 60 分，必须多维复合中毒才会触发物理拉黑
BURST_RATIO_CRITICAL = 5.0  # 突发脉冲敏感线
ENTROPY_STABLE_LIMIT = 300  # 熵值死板线
NORMAL_LOW_SPEED_BPS = 20480  # 降低保护线（20KB/s）


def evaluate(vector):
    """
    【多维特征全联动 - 零误杀打分引擎】
    :param vector: 严格长度为 21 的一维特征数组
    :return: (is_malicious: bool, label: str)
    """
    if not vector or vector[0] == "Unknown":
        return False, "Clear_Traffic"

    threat_score = 0.0
    anomaly_reasons = []

    # ==========================================
    # 🗂️ 21 维特征张量契约原位提取
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
    # ⚡ 核心进化：一票否决制 (针对极端危险情报)
    # ==========================================
    if dst_danger_level >= 9.0:
        vector[20] = 100.0
        return True, f"Instant_Kill:__Connect_To_Critical_Danger_External_IP_({dst_ip})"

    if src_danger_level >= 9.0 and instant_pps > 10:
        if dst_danger_level > 3.0 or dst_port in [4444, 3333]:
            vector[20] = 100.0
            return True, f"Instant_Kill:__Core_Asset_Active_Exfiltration_Attempt"

    # ==========================================
    # ⚖️ 特征动态研判流（多维交叉打分）
    # ==========================================

    # 1. 静态风险交叉相乘 (修正补齐了日志原因)
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

    # 2. 出海抽水带宽脉冲突变 (修正补齐了日志原因)
    base_global_bps = global_bps if global_bps > 0 else 1
    if instant_bps > NORMAL_LOW_SPEED_BPS:
        bps_burst_ratio = instant_bps / base_global_bps

        if bps_burst_ratio > BURST_RATIO_CRITICAL:
            threat_score += 25
            anomaly_reasons.append("Critical_Bandwidth_Burst_Pump")
        elif bps_burst_ratio > 2.0:
            threat_score += 15
            anomaly_reasons.append("Minor_Bandwidth_Burst")

    # 3. 累计外泄体积审计 (卡死 5MB 和 1MB)
    if accumulated_bytes > 5242880:  # > 5MB
        threat_score += 25
        anomaly_reasons.append("High_Volume_Exfiltration")
    elif accumulated_bytes > 1048576:  # > 1MB
        threat_score += 10
        anomaly_reasons.append("Warning_Volume_Exfiltration")

    # 4. 深度载荷死板度审计
    entropy_gap = max_entropy - min_entropy
    flow_duration = last_hw_ts - initial_hw_ts

    if flow_duration > 5000000 and accumulated_pkts > 15 and entropy_gap < ENTROPY_STABLE_LIMIT:
        if avg_entropy > 2100:
            threat_score += 35
            anomaly_reasons.append("Persistent_Encrypted_Tunnel")
        elif avg_entropy < 300:
            threat_score += 25
            anomaly_reasons.append("Covert_C2_Beacon")

    # 5. 敏感端口高熵数据走私 (DNS 隧道直接给 55 分)
    if dst_port == 53 and avg_entropy > 2200:
        threat_score += 55
        anomaly_reasons.append("DNS_Tunnel_走私嫌疑")

    # ==========================================
    # 🏁 判定裁决与特征反哺
    # ==========================================
    final_score = min(threat_score, 100.0)
    vector[20] = final_score  # 无损回哺给第 20 号槽位，大模型的最爱

    # 超过 60 分，前线铁证如山，直接物理阻断
    if final_score >= BLOCK_SCORE_THRESHOLD:
        label = f"Insider_Blocked:_{','.join(anomaly_reasons)}"
        return True, label

    # 纯净流量，完全无嫌疑
    return False, "Normal_Outbound_Traffic"