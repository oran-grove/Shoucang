# -*- coding: utf-8 -*-
"""
多智能体编排器包
================
- LiveScanOrchestrator: 逐条分析队列扫描
- DeepAnalysisOrchestrator: 基线画像 / 时序异常 / 长周期深度分析
- row_to_flow_event(): 将 traffic_log 数据库行转为 FlowEvent（共享工具函数）
"""

from ..core.message import FlowEvent


def row_to_flow_event(row: dict) -> FlowEvent:
    """
    将 traffic_log 数据库行转换为 FlowEvent。

    供 LiveScanOrchestrator 和 DeepAnalysisOrchestrator 共用，
    避免重复的 DB row → FlowEvent 转换逻辑。

    traffic_log 表字段:
        id, src_ip, dst_ip, src_port, dst_port, department,
        protocol, packet_time, traffic_size, is_blocked, entropy,
        src_tag, sp_tag, dp_tag, accumulated_pkts, accumulated_bytes,
        global_pps, global_bps, avg_entropy, created_at, ...
    """
    return FlowEvent(
        src_ip=row.get("src_ip", "0.0.0.0"),
        dst_ip=row.get("dst_ip", "0.0.0.0"),
        src_port=row.get("src_port") or 0,
        dst_port=row.get("dst_port") or 0,
        protocol=row.get("protocol", "TCP"),
        department=row.get("department", ""),
        byte_count=row.get("traffic_size") or 0,
        entropy_score=float(row.get("entropy") or 0.0),
        extra={
            "row_id": row.get("id"),
            "src_tag": row.get("src_tag"),
            "sp_tag": row.get("sp_tag"),
            "dp_tag": row.get("dp_tag"),
            "accumulated_pkts": row.get("accumulated_pkts"),
            "accumulated_bytes": row.get("accumulated_bytes"),
            "global_pps": row.get("global_pps"),
            "global_bps": row.get("global_bps"),
            "avg_entropy": row.get("avg_entropy"),
            "packet_time": str(row.get("packet_time", "")),
            "is_blocked": bool(row.get("is_blocked", 0)),
        },
    )


__all__ = ["row_to_flow_event"]
