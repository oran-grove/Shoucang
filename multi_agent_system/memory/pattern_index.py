# -*- coding: utf-8 -*-
"""
模式卡片索引 — Tier 1 的内存快速检索层
=======================================

从 config/learning/patterns/ 目录加载所有模式卡片到内存，
按特征维度构建倒排索引，实现 O(1) 快速匹配。

索引结构:
- _cards: card_id → PatternCard 的完整映射
- _by_status: status → set[card_id] 分类索引
- _by_department: department → set[card_id] 部门索引
- _by_protocol: protocol → set[card_id] 协议索引

线程安全: RLOCK 保护写操作，读操作无锁 (Python GIL 保证 dict 读取安全)
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .pattern_card import (
    PatternCard, CardStatus, format_cards_for_prompt,
)
from .store import get_store

logger = logging.getLogger(__name__)

# 模式卡片存储根目录
_PATTERNS_ROOT = Path(__file__).parent / "data" / "patterns"


class PatternIndex:
    """
    模式卡片内存索引。

    从 JSON 文件加载所有卡片，构建多维倒排索引，
    支持按流特征快速查询匹配的激活卡片。

    用法:
        index = PatternIndex()
        index.load_all()

        # 检测/研判时查询匹配的模式
        matching = index.query({"department": "财务部", "protocol": "TCP",
                                "direction": "outbound"})
        context = index.format_context(matching)  # 注入提示词的文本

        # 聚类产生的新卡片
        index.add_card(new_card)

        # 管理员反馈后强化
        index.reinforce_card("P-2026W23-A07", confirmed=True)
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._cards: dict[str, PatternCard] = {}
        self._by_status: dict[CardStatus, set[str]] = {
            s: set() for s in CardStatus
        }
        self._by_department: dict[str, set[str]] = {}
        self._by_protocol: dict[str, set[str]] = {}
        self._loaded = False

    # ==================== 加载 ====================

    def load_all(self) -> int:
        """从磁盘加载所有模式卡片，返回加载数量"""
        with self._lock:
            count = 0
            for status_dir in ("active", "shadow", "retired"):
                dir_path = _PATTERNS_ROOT / status_dir
                if not dir_path.exists():
                    continue
                for file_path in sorted(dir_path.glob("*.json")):
                    try:
                        card = _load_card_from_file(file_path)
                        if card:
                            self._cards[card.card_id] = card
                            self._by_status[card.status].add(card.card_id)
                            self._index_card(card)
                            count += 1
                    except Exception as e:
                        logger.warning(
                            "[PatternIndex] 加载卡片失败 %s: %s", file_path.name, e
                        )
            self._loaded = True
            logger.info(
                "[PatternIndex] 已加载 %d 张模式卡片 (active=%d shadow=%d retired=%d)",
                count,
                len(self._by_status[CardStatus.ACTIVE]),
                len(self._by_status[CardStatus.SHADOW]),
                len(self._by_status[CardStatus.RETIRED]),
            )
            return count

    def _index_card(self, card: PatternCard) -> None:
        """将卡片加入倒排索引"""
        dept = card.feature_signature.get("department", "")
        if dept:
            self._by_department.setdefault(dept, set()).add(card.card_id)
        protocol = card.feature_signature.get("protocol", "")
        if protocol:
            self._by_protocol.setdefault(protocol, set()).add(card.card_id)

    def _unindex_card(self, card: PatternCard) -> None:
        """从倒排索引中移除卡片"""
        for dept_set in self._by_department.values():
            dept_set.discard(card.card_id)
        for proto_set in self._by_protocol.values():
            proto_set.discard(card.card_id)

    # ==================== 查询 ====================

    def query(
        self, flow_features: dict, min_match: float = 0.5, status: Optional[CardStatus] = None,
    ) -> list[PatternCard]:
        """
        查询匹配的活跃模式卡片。

        Args:
            flow_features: 从 FlowEvent 提取的特征字典
            min_match: 最低匹配度阈值 (0-1)
            status: 限定卡片状态，默认 None=全部

        Returns:
            按证据强度降序排列的匹配卡片列表
        """
        # 快速候选集：通过 department 和 protocol 缩小范围
        dept = flow_features.get("department", "")
        protocol = flow_features.get("protocol", "")
        candidate_ids: Optional[set[str]] = None

        if dept and dept in self._by_department:
            candidate_ids = set(self._by_department[dept])
        if protocol and protocol in self._by_protocol:
            proto_ids = self._by_protocol[protocol]
            candidate_ids = (
                candidate_ids & proto_ids if candidate_ids is not None
                else set(proto_ids)
            )

        if candidate_ids is None:
            # 无快速索引命中，全量匹配（卡片数量通常 < 500 张）
            candidates = list(self._cards.values())
        else:
            candidates = [self._cards[cid] for cid in candidate_ids if cid in self._cards]

        if status is not None:
            candidates = [c for c in candidates if c.status == status]

        scored = []
        for card in candidates:
            score = card.matches(flow_features)
            if score >= min_match:
                scored.append((score, card))
        scored.sort(key=lambda x: (x[1].evidence_strength, x[0]), reverse=True)
        return [card for _, card in scored]

    def get_active_cards(self) -> list[PatternCard]:
        """获取所有激活的卡片"""
        return [
            self._cards[cid] for cid in self._by_status[CardStatus.ACTIVE]
            if cid in self._cards
        ]

    def get_shadow_cards(self) -> list[PatternCard]:
        """获取所有影子卡片"""
        return [
            self._cards[cid] for cid in self._by_status[CardStatus.SHADOW]
            if cid in self._cards
        ]

    def get_card(self, card_id: str) -> Optional[PatternCard]:
        """按 ID 获取卡片"""
        return self._cards.get(card_id)

    # ==================== 写入 ====================

    def add_card(self, card: PatternCard) -> bool:
        """添加新卡片（写入 JSON 文件 + 内存索引）"""
        with self._lock:
            if card.card_id in self._cards:
                logger.warning("[PatternIndex] 卡片已存在: %s", card.card_id)
                return False
            self._cards[card.card_id] = card
            self._by_status[card.status].add(card.card_id)
            self._index_card(card)
            _save_card_to_file(card)
            get_store().log_pattern_event(
                card.card_id, "created",
                detail={"title": card.title, "status": card.status.value},
            )
            logger.info("[PatternIndex] 新卡片: %s [%s]", card.card_id, card.status.value)
            return True

    def activate_card(self, card_id: str) -> bool:
        """将影子卡片提升为激活状态"""
        with self._lock:
            card = self._cards.get(card_id)
            if not card or card.status != CardStatus.SHADOW:
                return False
            old_status = card.status
            card.status = CardStatus.ACTIVE
            card.activated_at = datetime.now(timezone.utc).isoformat()
            self._by_status[old_status].discard(card_id)
            self._by_status[CardStatus.ACTIVE].add(card_id)
            _save_card_to_file(card)
            get_store().log_pattern_event(
                card_id, "activated",
                detail={"evidence_strength": card.evidence_strength,
                        "confirmed_count": card.confirmed_count},
            )
            logger.info("[PatternIndex] 卡片激活: %s", card_id)
            return True

    def retire_card(self, card_id: str, reason: str = "") -> bool:
        """退役卡片"""
        with self._lock:
            card = self._cards.get(card_id)
            if not card or card.status == CardStatus.RETIRED:
                return False
            old_status = card.status
            card.status = CardStatus.RETIRED
            card.retired_at = datetime.now(timezone.utc).isoformat()
            self._by_status[old_status].discard(card_id)
            self._by_status[CardStatus.RETIRED].add(card_id)
            _save_card_to_file(card)
            get_store().log_pattern_event(
                card_id, "retired",
                detail={"reason": reason, "decay_score": card.decay_score},
            )
            logger.info("[PatternIndex] 卡片退役: %s (原因: %s)", card_id, reason)
            return True

    def reinforce_card(
        self, card_id: str, confirmed: bool, admin_note: str = "",
    ) -> bool:
        """
        强化卡片（管理员反馈后调用）。

        更新 Ebbinghaus 时间戳：
        - 确认 → 强化，衰减分数重置
        - 否定 → 记录，累计否定超过确认则触发退役
        """
        card = self._cards.get(card_id)
        if not card:
            return False

        snapshot = card.to_dict()
        card.reinforce(confirmed, admin_note)

        _save_card_to_file(card)
        get_store().log_pattern_event(
            card_id, "reinforced",
            detail={"confirmed": confirmed, "note": admin_note},
            snapshot=snapshot,
        )

        # 自动退役检查
        if card.check_decay():
            self.retire_card(card_id, reason="decay_or_rejected")

        return True

    # ==================== 格式化 ====================

    def format_context(self, flow_features: dict) -> str:
        """
        查询匹配的激活卡片并格式化为提示词上下文注入文本。
        这是检测/研判智能体调用的主要接口。
        """
        matching = self.query(flow_features, min_match=0.5, status=CardStatus.ACTIVE)
        if not matching:
            return ""
        return format_cards_for_prompt(matching)

    # ==================== 维护 ====================

    def check_decay_all(self) -> list[str]:
        """检查所有激活卡片是否衰减到阈值以下，返回应退役的卡片 ID 列表"""
        to_retire = []
        for cid in list(self._by_status[CardStatus.ACTIVE]):
            card = self._cards.get(cid)
            if card and card.check_decay():
                to_retire.append(cid)
        for cid in to_retire:
            self.retire_card(cid, reason="decay_auto")
        return to_retire

    def remove_stale_shadows(self, min_strength: float = 0.5) -> int:
        """清除证据不足的影子卡片（证据强度 < 阈值），返回清除数量"""
        removed = 0
        for cid in list(self._by_status[CardStatus.SHADOW]):
            card = self._cards.get(cid)
            if card and card.evidence_strength < min_strength and card.confirmed_count == 0:
                # 删除文件
                _delete_card_file(card.card_id, CardStatus.SHADOW)
                self._unindex_card(card)
                del self._cards[cid]
                self._by_status[CardStatus.SHADOW].discard(cid)
                removed += 1
        if removed:
            logger.info("[PatternIndex] 清除 %d 张无效影子卡片", removed)
        return removed

    # ==================== 统计 ====================

    @property
    def total_cards(self) -> int:
        return len(self._cards)

    @property
    def active_count(self) -> int:
        return len(self._by_status[CardStatus.ACTIVE])

    @property
    def shadow_count(self) -> int:
        return len(self._by_status[CardStatus.SHADOW])

    @property
    def retired_count(self) -> int:
        return len(self._by_status[CardStatus.RETIRED])

    def get_overview(self) -> dict:
        return {
            "total": self.total_cards,
            "active": self.active_count,
            "shadow": self.shadow_count,
            "retired": self.retired_count,
            "top_cards": [
                {
                    "card_id": c.card_id,
                    "title": c.title,
                    "evidence_strength": round(c.evidence_strength, 4),
                    "confirmed_count": c.confirmed_count,
                    "decay_score": round(c.decay_score, 4),
                }
                for c in sorted(
                    self.get_active_cards(),
                    key=lambda c: c.evidence_strength, reverse=True,
                )[:10]
            ],
        }


# ============================================================
# 文件读写辅助
# ============================================================

def _card_file_path(card_id: str, status: CardStatus) -> Path:
    """根据卡片 ID 和状态确定文件路径"""
    return _PATTERNS_ROOT / status.value / f"{card_id}.json"


def _save_card_to_file(card: PatternCard) -> None:
    """将卡片写入 JSON 文件"""
    dir_path = _PATTERNS_ROOT / card.status.value
    dir_path.mkdir(parents=True, exist_ok=True)
    file_path = dir_path / f"{card.card_id}.json"
    _atomic_write(file_path, json.dumps(card.to_dict(), ensure_ascii=False, indent=2))


def _load_card_from_file(file_path: Path) -> Optional[PatternCard]:
    """从 JSON 文件加载卡片"""
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
        return PatternCard.from_dict(data)
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        logger.warning("[PatternIndex] 文件损坏 %s: %s", file_path.name, e)
        return None


def _delete_card_file(card_id: str, status: CardStatus) -> None:
    """删除卡片文件"""
    file_path = _card_file_path(card_id, status)
    try:
        if file_path.exists():
            file_path.unlink()
    except OSError:
        pass


def _atomic_write(file_path: Path, content: str) -> None:
    """原子写入：先写临时文件再重命名"""
    tmp = file_path.with_suffix(".tmp")
    try:
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(file_path)
    except Exception:
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        raise


# ============================================================
# 模块级单例
# ============================================================

_index: Optional[PatternIndex] = None
_index_lock = threading.Lock()


def get_index() -> PatternIndex:
    """获取 PatternIndex 单例，首次调用时自动加载"""
    global _index
    if _index is None:
        with _index_lock:
            if _index is None:
                _index = PatternIndex()
                _index.load_all()
    return _index


__all__ = ["PatternIndex", "get_index"]
