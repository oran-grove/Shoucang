# -*- coding: utf-8 -*-
"""
模式卡片 — 自适应系统的 Tier 1 知识单元
========================================

每张 PatternCard 是一个可解释的半结构化知识片段，由管理员反馈
自动聚类生成，经过影子期验证后激活，通过 Ebbinghaus 遗忘曲线
自然衰减。激活的卡片在检测/研判时作为补充上下文注入提示词。

设计参考:
- A-MEM Zettelkasten 式交叉引用与动态链接
- SAGE Ebbinghaus 遗忘曲线记忆优先级
- PCT 安全回归防护门

安全约束:
- 新卡片必须通过影子模式 (SHADOW) → 回归检测 → 激活 (ACTIVE)
- 卡片只注入为上下文证据，不修改阈值、不覆盖 LLM 决策
- 退役 (RETIRED) 的卡片移入归档，原始案例 (Tier 0) 永不删除
"""

from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


class CardStatus(str, Enum):
    SHADOW = "shadow"     # 新生成，只记录匹配不注入提示词
    ACTIVE = "active"     # 通过验证，注入检测/研判提示词
    RETIRED = "retired"   # 衰减淘汰或手动退役，移入归档


@dataclass
class PatternCard:
    """
    单张模式卡片 — 半结构化知识单元。

    特征签名 (feature_signature) 定义了卡片匹配的条件维度，
    证据链 (confirmed_count / rejected_count) 来自管理员反馈，
    Ebbinghaus 衰减保证长期未强化的卡片自然淡化。

    Zettelkasten 链接: linked_cards 记录与此卡共享特征维度的其他卡片。
    """

    card_id: str                    # "P-2026W23-A07"
    title: str                      # 人类可读标题
    status: CardStatus = CardStatus.SHADOW

    # ---- 特征签名：定义此卡片的匹配条件 ----
    feature_signature: dict = field(default_factory=dict)
    # 示例: {"department": "财务部", "day_range": [25, 31],
    #        "direction": "outbound", "encryption": False, "traffic_size_max": 100}

    # ---- 证据链 (Wilson 下界避免小样本过拟合) ----
    confirmed_count: int = 0        # 管理员确认次数
    rejected_count: int = 0         # 管理员否定次数

    @property
    def evidence_strength(self) -> float:
        """Wilson 下界置信度 (http://www.evanmiller.org/how-not-to-sort-by-average-rating.html)"""
        n = self.confirmed_count + self.rejected_count
        if n == 0:
            return 0.0
        p = self.confirmed_count / n
        z = 1.96  # 95% 置信
        return (p + z*z/(2*n) - z*math.sqrt((p*(1-p) + z*z/(4*n))/n)) / (1 + z*z/n)

    # ---- Ebbinghaus 遗忘曲线 ----
    last_reinforced_at: str = ""    # ISO timestamp
    reinforcement_history: list = field(default_factory=list)
    # [(timestamp, "confirmed"|"rejected", admin_note), ...]

    @property
    def decay_score(self) -> float:
        """
        Ebbinghaus 衰减分数 (0-1)。
        衰减半衰期 14 天：14 天未强化则衰减到 0.5，28 天到 0.25。
        每次确认重置为 1.0 + 0.05 增量（上限 1.0）。
        """
        if not self.last_reinforced_at:
            return 1.0
        try:
            last = datetime.fromisoformat(self.last_reinforced_at)
            days_elapsed = (datetime.now(timezone.utc) - last).total_seconds() / 86400
        except (ValueError, TypeError):
            return 0.0
        half_life = 14.0
        return math.pow(0.5, days_elapsed / half_life)

    def reinforce(self, confirmed: bool, admin_note: str = "") -> None:
        """强化卡片（管理员反馈后调用）"""
        now = datetime.now(timezone.utc)
        if confirmed:
            self.confirmed_count += 1
        else:
            self.rejected_count += 1
        self.reinforcement_history.append({
            "timestamp": now.isoformat(),
            "action": "confirmed" if confirmed else "rejected",
            "note": admin_note[:200],
        })
        # 只保留最近 50 条记录
        if len(self.reinforcement_history) > 50:
            self.reinforcement_history = self.reinforcement_history[-50:]
        self.last_reinforced_at = now.isoformat()

    # ---- Zettelkasten 链接 ----
    linked_cards: list[str] = field(default_factory=list)
    link_reasons: dict[str, str] = field(default_factory=dict)
    # {"P-2025W50-C03": "同部门+同时段模式", "P-2026W01-B12": "同威胁类型"}

    # ---- 生命周期 ----
    activation_threshold: int = 5   # 需要多少次确认才能激活
    created_at: str = ""
    activated_at: str = ""
    retired_at: str = ""
    regression_test_passed: bool = False
    regression_test_note: str = ""

    def can_activate(self) -> bool:
        """检查是否满足激活条件"""
        return (
            self.status == CardStatus.SHADOW
            and self.confirmed_count >= self.activation_threshold
            and self.evidence_strength >= 0.75
            and self.regression_test_passed
        )

    def check_decay(self) -> bool:
        """
        检查是否需要退役。
        衰减分数 < 0.3 或 否定 > 确认 时触发。
        """
        if self.status != CardStatus.ACTIVE:
            return False
        return self.decay_score < 0.3 or self.rejected_count > self.confirmed_count

    # ---- 序列化 ----
    def to_dict(self) -> dict:
        return {
            "card_id": self.card_id,
            "title": self.title,
            "status": self.status.value,
            "feature_signature": self.feature_signature,
            "confirmed_count": self.confirmed_count,
            "rejected_count": self.rejected_count,
            "evidence_strength": round(self.evidence_strength, 4),
            "decay_score": round(self.decay_score, 4),
            "last_reinforced_at": self.last_reinforced_at,
            "reinforcement_history": self.reinforcement_history,
            "linked_cards": self.linked_cards,
            "link_reasons": self.link_reasons,
            "activation_threshold": self.activation_threshold,
            "created_at": self.created_at,
            "activated_at": self.activated_at,
            "retired_at": self.retired_at,
            "regression_test_passed": self.regression_test_passed,
            "regression_test_note": self.regression_test_note,
        }

    @classmethod
    def from_dict(cls, d: dict) -> PatternCard:
        return cls(
            card_id=d["card_id"],
            title=d["title"],
            status=CardStatus(d.get("status", "shadow")),
            feature_signature=d.get("feature_signature", {}),
            confirmed_count=d.get("confirmed_count", 0),
            rejected_count=d.get("rejected_count", 0),
            last_reinforced_at=d.get("last_reinforced_at", ""),
            reinforcement_history=d.get("reinforcement_history", []),
            linked_cards=d.get("linked_cards", []),
            link_reasons=d.get("link_reasons", {}),
            activation_threshold=d.get("activation_threshold", 5),
            created_at=d.get("created_at", ""),
            activated_at=d.get("activated_at", ""),
            retired_at=d.get("retired_at", ""),
            regression_test_passed=d.get("regression_test_passed", False),
            regression_test_note=d.get("regression_test_note", ""),
        )

    # ---- 匹配逻辑 ----
    def matches(self, flow_features: dict) -> float:
        """
        检查流特征是否匹配此卡片。
        返回匹配度 0.0-1.0（特征维度重合比例）。
        """
        if not self.feature_signature:
            return 0.0
        total = len(self.feature_signature)
        matched = 0
        for key, expected in self.feature_signature.items():
            actual = flow_features.get(key)
            if actual is None:
                continue
            if isinstance(expected, (list, tuple)):
                if actual in expected or (isinstance(actual, (int, float)) and min(expected) <= actual <= max(expected)):
                    matched += 1
            elif actual == expected:
                matched += 1
        return matched / total if total > 0 else 0.0

    def __repr__(self) -> str:
        return (
            f"<PatternCard({self.card_id}) [{self.status.value}] "
            f"title={self.title[:40]} evidence={self.evidence_strength:.0%} "
            f"decay={self.decay_score:.2f}>"
        )


# ============================================================
# 模式卡片的提示词格式化
# ============================================================

def format_cards_for_prompt(cards: list[PatternCard]) -> str:
    """
    将匹配到的激活卡片格式化为 LLM 提示词中的上下文注入。
    只注入 ACTIVE 状态的卡片。

    安全设计:
    - 明确指出"仅供参考"
    - 列出证据来源（确认次数）而非盲目宣称
    - 保留 LLM 独立判断的空间
    """
    active = [c for c in cards if c.status == CardStatus.ACTIVE]
    if not active:
        return ""

    # 按证据强度降序，只取前 5 条避免提示词过长
    active.sort(key=lambda c: c.evidence_strength, reverse=True)
    top = active[:5]

    lines = [
        "",
        "## 系统学习到的历史模式（仅供参考，不替代独立研判）",
        "",
    ]
    for i, card in enumerate(top, 1):
        direction_text = _describe_card_direction(card)
        lines.append(
            f"{i}. 模式 {card.card_id}: {card.title}"
        )
        lines.append(
            f"   证据强度: {card.evidence_strength:.0%} "
            f"(管理员累计确认 {card.confirmed_count} 例)"
        )
        if card.last_reinforced_at:
            try:
                last_dt = datetime.fromisoformat(card.last_reinforced_at)
                days_ago = (datetime.now(timezone.utc) - last_dt).days
                lines.append(f"   最近确认: {days_ago} 天前")
            except (ValueError, TypeError):
                pass
        lines.append(f"   结论: {direction_text}")
        lines.append("")

    lines.append("请综合以上已验证模式与当前案例的具体情况做出独立研判。")
    return "\n".join(lines)


def _describe_card_direction(card: PatternCard) -> str:
    """从卡片特征签名推断方向性描述"""
    direction = card.feature_signature.get("direction", "")
    encryption = card.feature_signature.get("encryption")
    evidence = card.evidence_strength

    if evidence >= 0.85:
        if direction == "outbound" and not encryption:
            return "此类流量历史上大概率是正常业务行为（如定期报表传输）"
        elif encryption:
            return "此类流量历史上高度疑似异常，建议重点关注"
    if evidence >= 0.70:
        if direction == "outbound":
            return "此类出站流量有较高概率为异常"
        return "此类流量有较高概率为正常"
    return "此类流量的历史模式尚不明确，建议谨慎判断"


__all__ = ["PatternCard", "CardStatus", "format_cards_for_prompt"]
