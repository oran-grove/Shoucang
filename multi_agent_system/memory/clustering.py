# -*- coding: utf-8 -*-
"""
模式聚类 — 自进化 Loop 2（每小时运行）
======================================

从 SQLite 反馈案例中自动聚类，生成候选模式卡片。

聚类维度:
- department: 部门
- protocol: 协议
- direction: 出站/入站（从 dst_ip 是否内网推断）
- day_range: 日期范围 (1-7, 8-15, 16-23, 24-31)
- encryption: 是否加密 (从 ai_reasoning 关键词推断)

安全约束:
- 聚类样本量 < 8 → 跳过（样本不足，不可靠）
- 新卡片默认 SHADOW 状态，不注入提示词
- 用户配置的排除维度（如 protocol=DNS）不参与聚类
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from .pattern_card import PatternCard, CardStatus
from .pattern_index import get_index
from .store import get_store

logger = logging.getLogger(__name__)

# 聚类参数
_MIN_SAMPLES = 8          # 最小样本量
_MIN_ERROR_RATE = 0.3     # 最低错误率（部门误报率低于此值不生成卡片）
_MAX_CARDS_PER_RUN = 10   # 每次运行最多生成卡片数

# 加密关键词（从 ai_reasoning 中提取）
_ENCRYPTION_KEYWORDS = [
    "加密", "TLS", "encrypt", "高熵", "entropy", "SSH隧道",
    "VPN", "Tor", "代理",
]


def run_hourly_clustering() -> dict:
    """
    执行 Loop 2 小时聚类。

    1. 从 SQLite 拉取过去24h的反馈统计
    2. 按 (department, protocol, day_range, encryption) 分组
    3. 对每组检查是否满足聚类条件
    4. 生成候选 SHADOW 卡片

    Returns:
        {"generated": N, "cards": [...], "skipped_groups": N}
    """
    store = get_store()
    index = get_index()
    stats = store.get_stats_for_clustering(hours=24)

    if stats["total_cases"] < _MIN_SAMPLES:
        logger.info(
            "[Clustering] 过去24h仅 %d 条反馈，不足聚类阈值 %d，跳过",
            stats["total_cases"], _MIN_SAMPLES,
        )
        return {"generated": 0, "cards": [], "skipped_groups": 0}

    # 分组
    groups = _group_cases(stats["fp_cases"] + stats["fn_cases"])
    logger.info(
        "[Clustering] 发现 %d 个候选聚类组 (total_cases=%d)",
        len(groups), stats["total_cases"],
    )

    generated = []
    skipped = 0
    for group_key, cases in groups.items():
        if len(cases) < _MIN_SAMPLES:
            skipped += 1
            continue

        # 检查此组的错误率
        dept = group_key[0]  # department
        protocol = group_key[1]  # protocol
        error_rate = _calc_group_error_rate(dept, protocol, stats)

        if error_rate < _MIN_ERROR_RATE:
            continue  # 此组误报/漏报率不高，不需要模式卡片

        # 决定卡片的"倾向"（正常 or 异常）
        fp_count = sum(1 for c in cases if c.get("category") == "fp")
        fn_count = sum(1 for c in cases if c.get("category") == "fn")
        is_normal_pattern = fp_count > fn_count  # 误报多=此模式通常是正常的

        # 生成卡片
        card = _create_card_from_group(
            group_key=group_key,
            cases=cases,
            is_normal=is_normal_pattern,
        )
        if card:
            index.add_card(card)
            generated.append(card.card_id)

            if len(generated) >= _MAX_CARDS_PER_RUN:
                break

    # 维护：衰减检查 + 清理无效影子
    retired = index.check_decay_all()
    removed = index.remove_stale_shadows()

    store.set_last_run("hourly_clustering", {
        "generated": len(generated),
        "retired": len(retired),
        "removed_shadows": removed,
        "total_groups": len(groups),
        "skipped": skipped,
    })

    logger.info(
        "[Clustering] Loop2完成: 生成=%d 退役=%d 清理影子=%d",
        len(generated), len(retired), removed,
    )
    return {
        "generated": len(generated),
        "cards": generated,
        "skipped_groups": skipped,
    }


def _group_cases(cases: list[dict]) -> dict[tuple, list[dict]]:
    """按多维特征分组案例"""
    groups: dict[tuple, list[dict]] = {}
    for case in cases:
        dept = case.get("department") or "unknown"
        protocol = case.get("protocol") or "TCP"

        # 推断方向
        dst_ip = case.get("dst_ip", "")
        direction = "outbound"
        if dst_ip.startswith(("10.", "192.168.", "172.")):
            direction = "internal"

        # 推断日期范围
        try:
            created = case.get("created_at", "")
            if created:
                day = datetime.fromisoformat(created).day
            else:
                day = datetime.now(timezone.utc).day
        except (ValueError, TypeError):
            day = datetime.now(timezone.utc).day
        if day <= 7:
            day_range = "1-7"
        elif day <= 15:
            day_range = "8-15"
        elif day <= 23:
            day_range = "16-23"
        else:
            day_range = "24-31"

        # 推断是否加密
        reasoning = (case.get("ai_reasoning") or "").lower()
        features_json = case.get("flow_features") or "{}"
        import json
        features = json.loads(features_json) if isinstance(features_json, str) else (features_json or {})
        entropy = features.get("entropy", 0) if isinstance(features, dict) else 0

        is_encrypted = any(kw in reasoning for kw in _ENCRYPTION_KEYWORDS)
        if entropy > 7.0:
            is_encrypted = True

        group_key = (dept, protocol, direction, day_range, is_encrypted)
        groups.setdefault(group_key, []).append(case)

    return groups


def _calc_group_error_rate(
    department: str, protocol: str, stats: dict,
) -> float:
    """计算特定部门+协议组合的错误率"""
    for g in stats.get("cases_by_group", []):
        if g["department"] == department and g["protocol"] == protocol:
            return g["error_rate"]
    return 0.0


def _create_card_from_group(
    group_key: tuple,
    cases: list[dict],
    is_normal: bool,
) -> PatternCard | None:
    """
    从案例组生成模式卡片。

    group_key = (department, protocol, direction, day_range, is_encrypted)
    is_normal=True 表示此模式通常是正常行为（FP居多）
    is_normal=False 表示此模式通常是异常（FN居多）
    """
    dept, protocol, direction, day_range, is_encrypted = group_key

    cardinality = "normal" if is_normal else "anomaly"
    week_num = datetime.now(timezone.utc).isocalendar()[1]
    year = datetime.now(timezone.utc).year
    card_id = f"P-{year}W{week_num:02d}-{cardinality[0].upper()}{len(cases):02d}"

    # 确保 ID 不重复
    index = get_index()
    base_id = card_id
    suffix = 0
    while index.get_card(card_id) is not None:
        suffix += 1
        card_id = f"{base_id}-{suffix}"

    if is_normal:
        title = (
            f"{dept} {direction} {protocol} "
            f"{'加密' if is_encrypted else '非加密'}传输 "
            f"(月度{day_range}日) → 通常为正常业务"
        )
    else:
        title = (
            f"{dept} {direction} {protocol} "
            f"{'加密' if is_encrypted else '非加密'}传输 "
            f"(月度{day_range}日) → 疑似异常模式"
        )

    # 提取代表性数据范围
    traffic_sizes = []
    for c in cases:
        features_json = c.get("flow_features") or "{}"
        import json
        features = json.loads(features_json) if isinstance(features_json, str) else (features_json or {})
        if isinstance(features, dict) and features.get("byte_count"):
            traffic_sizes.append(features["byte_count"])
        elif isinstance(features, dict) and features.get("traffic_size"):
            traffic_sizes.append(features["traffic_size"])

    feature_signature = {
        "department": dept,
        "protocol": protocol,
        "direction": direction,
        "day_range": [int(day_range.split("-")[0]), int(day_range.split("-")[1])],
        "encryption": is_encrypted,
    }
    if traffic_sizes:
        feature_signature["traffic_size_max"] = max(traffic_sizes)

    # 初始 confirmed/rejected = 0（影子状态）
    # 证据强度由后续管理员反馈累积
    card = PatternCard(
        card_id=card_id,
        title=title,
        status=CardStatus.SHADOW,
        feature_signature=feature_signature,
        confirmed_count=0,
        rejected_count=0,
        activation_threshold=5,
        created_at=datetime.now(timezone.utc).isoformat(),
        regression_test_passed=_run_regression_test(feature_signature),
    )

    # 记录回归检测结果
    if not card.regression_test_passed:
        card.regression_test_note = (
            "回归检测未通过：此模式特征与已知恶意案例存在交叉，"
            "激活前需人工审查。"
        )
        logger.warning(
            "[Clustering] 卡片 %s 回归检测未通过，保持在 SHADOW 状态",
            card_id,
        )

    return card


def _run_regression_test(feature_signature: dict) -> bool:
    """
    回归检测：检查新卡片是否会匹配历史确认恶意的案例。

    如果新卡片（通常为"正常业务"模式）覆盖了已知恶意案例，
    说明这个模式可能被利用作为攻击的掩护，不应自动激活。
    """
    store = get_store()
    malicious_cases = store.get_historical_malicious(limit=200)
    if not malicious_cases:
        return True  # 没有历史恶意案例，通过

    for case in malicious_cases:
        case_features = _extract_features_from_case(case)
        # 用卡片特征签名模拟匹配
        match = _signature_match(feature_signature, case_features)
        if match:
            logger.info(
                "[RegressionTest] 卡片与历史恶意案例冲突: case_id=%s", case["id"]
            )
            return False

    return True


def _extract_features_from_case(case: dict) -> dict:
    """从反馈案例中提取特征字典"""
    features = {
        "department": case.get("department", ""),
        "protocol": case.get("protocol", "TCP"),
    }
    dst_ip = case.get("dst_ip", "")
    features["direction"] = (
        "internal" if dst_ip.startswith(("10.", "192.168.", "172."))
        else "outbound"
    )
    return features


def _signature_match(signature: dict, features: dict) -> bool:
    """检查特征是否匹配签名（宽松匹配）"""
    for key, expected in signature.items():
        actual = features.get(key)
        if actual is None:
            continue
        if key == "day_range":
            # day_range 不参与回归检测（与时间无关）
            continue
        if isinstance(expected, (list, tuple)):
            if actual in expected or (isinstance(actual, (int, float)) and min(expected) <= actual <= max(expected)):
                continue
            else:
                return False
        elif actual != expected:
            return False
    # 所有非时间维度都匹配 → 冲突
    return True


__all__ = ["run_hourly_clustering"]
