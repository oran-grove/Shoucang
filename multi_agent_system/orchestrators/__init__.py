# -*- coding: utf-8 -*-
"""
多智能体编排器包
================
- LiveScanOrchestrator: 逐条分析队列扫描
- row_to_flow_event(): 将 traffic_log 数据库行转为 FlowEvent（共享工具函数）
"""

from ..core.message import FlowEvent


def row_to_flow_event(row: dict) -> FlowEvent:
    """
    将 traffic_log 数据库行转换为 FlowEvent。

    供 LiveScanOrchestrator 使用，
    避免重复的 DB row → FlowEvent 转换逻辑。

    traffic_log 表字段:
        id, src_ip, dst_ip, src_port, dst_port, department,
        protocol, packet_time, traffic_size, is_blocked, entropy,
        src_tag, sp_tag, dp_tag, accumulated_pkts, accumulated_bytes,
        global_pps, global_bps, avg_entropy, country, employee, created_at, ...
    """
    src_ip = row.get("src_ip", "0.0.0.0")
    dst_ip = row.get("dst_ip", "0.0.0.0")
    src_port = row.get("src_port") or 0
    dst_port = row.get("dst_port") or 0
    protocol = row.get("protocol", "TCP")
    department = row.get("department", "")
    byte_count = row.get("traffic_size") or 0
    accumulated_pkts = row.get("accumulated_pkts") or 0
    accumulated_bytes = row.get("accumulated_bytes") or 0
    global_pps = row.get("global_pps") or 0
    global_bps = row.get("global_bps") or 0

    # build_row() 只写 avg_entropy，不写 entropy → 优先读 avg_entropy
    entropy_score = float(row.get("avg_entropy") or row.get("entropy") or 0.0)

    # 从端口推断应用层协议
    _app = "unknown"
    if dst_port == 53:      _app = "DNS"
    elif dst_port in (80, 8080): _app = "HTTP"
    elif dst_port in (443, 8443): _app = "TLS"
    elif dst_port == 22:    _app = "SSH"
    elif dst_port == 21:    _app = "FTP"
    elif dst_port == 23:    _app = "Telnet"
    elif dst_port == 25:    _app = "SMTP"
    elif dst_port == 3389:  _app = "RDP"
    elif dst_port == 3306:  _app = "MySQL"

    # 平均包长
    avg_pkt_size = round(accumulated_bytes / accumulated_pkts, 1) if accumulated_pkts > 0 else 0.0

    # 推断是否非工作时段
    pkt_time_str = str(row.get("packet_time", ""))
    work_hours_violation = False
    if pkt_time_str:
        try:
            from datetime import datetime
            dt = datetime.strptime(pkt_time_str[:19], "%Y-%m-%d %H:%M:%S")
            hour = dt.hour
            work_hours_violation = (hour < 6 or hour >= 22)
        except Exception:
            pass

    # 数据敏感性推断（仅从熵值）
    data_sensitivity = ""
    if entropy_score > 7.5:
        data_sensitivity = "疑似加密/混淆载荷"
    elif entropy_score > 5.0:
        data_sensitivity = "内部"
    elif entropy_score > 0:
        data_sensitivity = "公开"

    return FlowEvent(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        app_protocol=_app,
        department=department,
        pkt_count=accumulated_pkts,
        byte_count=byte_count,
        duration_seconds=0.0,  # traffic_log 无持续时间
        avg_pkt_size=avg_pkt_size,
        entropy_score=entropy_score,
        user_id=row.get("employee", ""),
        work_hours_violation=work_hours_violation,
        data_sensitivity=data_sensitivity,
        extra={
            "row_id": row.get("id"),
            "src_tag": row.get("src_tag"),
            "sp_tag": row.get("sp_tag"),
            "dp_tag": row.get("dp_tag"),
            "accumulated_pkts": accumulated_pkts,
            "accumulated_bytes": accumulated_bytes,
            "global_pps": global_pps,
            "global_bps": global_bps,
            "country": row.get("country", ""),
            "packet_time": pkt_time_str,
            "is_blocked": bool(row.get("is_blocked", 0)),
        },
    )


__all__ = ["row_to_flow_event"]
