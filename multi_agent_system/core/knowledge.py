"""
共享知识库模块
=============
管理黑白名单规则、威胁情报条目，提供线程安全的增删查改和自动过期清理。
"""

import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Optional

from .message import RuleEntry, RuleAction, TrafficVerdict, SeverityLevel


class KnowledgeBase:
    """
    线程安全的知识库，存储规则条目。
    - 黑名单：action=BLOCK, 高置信度
    - 白名单：action=ALLOW
    - 灰名单：action=MIRROR / THROTTLE
    """

    def __init__(self, max_rules: int = 100000, cleanup_interval_seconds: int = 300):
        self._lock = threading.RLock()
        self._rules: OrderedDict[str, RuleEntry] = OrderedDict()
        self._max_rules = max_rules
        self._cleanup_interval = cleanup_interval_seconds
        self._last_cleanup = time.monotonic()
        # 索引：按源IP快速查找
        self._src_ip_index: dict[str, set[str]] = {}

    def _maybe_cleanup(self) -> None:
        """定期清理过期规则"""
        now_mono = time.monotonic()
        if now_mono - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now_mono
        now = datetime.now(timezone.utc)
        expired_ids = [rid for rid, rule in self._rules.items() if rule.is_expired(now)]
        for rid in expired_ids:
            self._remove_rule(rid)

    def _remove_rule(self, rule_id: str) -> None:
        rule = self._rules.pop(rule_id, None)
        if rule and rule.src_ip:
            idx = self._src_ip_index.get(rule.src_ip, set())
            idx.discard(rule_id)
            if not idx:
                self._src_ip_index.pop(rule.src_ip, None)

    def add_rule(self, rule: RuleEntry) -> str:
        """添加规则，返回 rule_id"""
        with self._lock:
            self._maybe_cleanup()
            if len(self._rules) >= self._max_rules:
                # 删除最老的一条
                oldest = next(iter(self._rules))
                self._remove_rule(oldest)
            self._rules[rule.rule_id] = rule
            if rule.src_ip:
                self._src_ip_index.setdefault(rule.src_ip, set()).add(rule.rule_id)
            # 保持最近使用的顺序（OrderedDict 按插入顺序）
            self._rules.move_to_end(rule.rule_id)
            return rule.rule_id

    def get_rule(self, rule_id: str) -> Optional[RuleEntry]:
        with self._lock:
            self._maybe_cleanup()
            return self._rules.get(rule_id)

    def update_rule_hit(self, rule_id: str) -> None:
        with self._lock:
            rule = self._rules.get(rule_id)
            if rule:
                rule.hit_count += 1
                rule.last_hit_at = datetime.now(timezone.utc)
                self._rules.move_to_end(rule_id)

    def remove_rule(self, rule_id: str) -> bool:
        with self._lock:
            if rule_id in self._rules:
                self._remove_rule(rule_id)
                return True
            return False

    def query_by_src_ip(self, src_ip: str, action: Optional[RuleAction] = None) -> list[RuleEntry]:
        """按源IP查询规则"""
        with self._lock:
            self._maybe_cleanup()
            ids = self._src_ip_index.get(src_ip, set())
            results = [self._rules[rid] for rid in ids if rid in self._rules]
            if action:
                results = [r for r in results if r.action == action]
            return results

    def match(self, src_ip: str, dst_ip: str,
              src_port: int = 0, dst_port: int = 0,
              protocol: str = "") -> Optional[RuleEntry]:
        """
        精确匹配规则，返回最高优先级的匹配项。
        规则优先级：黑名单 > 灰名单 > 白名单。
        """
        with self._lock:
            self._maybe_cleanup()
            # 先查找源IP相关的所有规则
            candidates = list(self._rules.values())
            matched = []
            for rule in candidates:
                if rule.is_expired():
                    continue
                if rule.src_ip and rule.src_ip != src_ip:
                    continue
                if rule.dst_ip and rule.dst_ip != dst_ip:
                    continue
                if rule.src_port and rule.src_port != src_port:
                    continue
                if rule.dst_port and rule.dst_port != dst_port:
                    continue
                if rule.protocol and rule.protocol != protocol:
                    continue
                matched.append(rule)
            if not matched:
                return None
            # 按优先级排序：BLOCK > THROTTLE > MIRROR > ALLOW
            priority = {RuleAction.BLOCK: 0, RuleAction.THROTTLE: 1,
                        RuleAction.MIRROR: 2, RuleAction.ALLOW: 3}
            matched.sort(key=lambda r: priority.get(r.action, 5))
            return matched[0]

    def get_rules_by_action(self, action: RuleAction) -> list[RuleEntry]:
        """获取指定动作的所有非过期规则"""
        with self._lock:
            self._maybe_cleanup()
            return [r for r in self._rules.values() if r.action == action and not r.is_expired()]

    def get_top_hit_rules(self, n: int = 10) -> list[RuleEntry]:
        """获取命中次数最多的规则"""
        with self._lock:
            self._maybe_cleanup()
            sorted_rules = sorted(self._rules.values(), key=lambda r: r.hit_count, reverse=True)
            return sorted_rules[:n]

    def size(self) -> int:
        with self._lock:
            return len(self._rules)

    def clear_expired(self) -> int:
        """手动清除所有过期规则，返回清除数量"""
        with self._lock:
            now = datetime.now(timezone.utc)
            expired = [rid for rid, r in self._rules.items() if r.is_expired(now)]
            for rid in expired:
                self._remove_rule(rid)
            return len(expired)

    def to_sync_payload(self, max_rules: int = 100) -> list[dict]:
        """
        生成同步到 P4 交换机的规则列表。
        按置信度降序，只返回高置信度自动规则。
        """
        with self._lock:
            self._maybe_cleanup()
            # 只同步 BLOCK 和 ALLOW 规则
            rules = [r for r in self._rules.values()
                     if r.action in (RuleAction.BLOCK, RuleAction.ALLOW)
                     and r.confidence >= 0.7
                     and not r.is_expired()]
            rules.sort(key=lambda r: r.confidence, reverse=True)
            return [
                {
                    "rule_id": r.rule_id,
                    "src_ip": r.src_ip,
                    "dst_ip": r.dst_ip,
                    "src_port": r.src_port,
                    "dst_port": r.dst_port,
                    "protocol": r.protocol,
                    "action": r.action.value,
                    "confidence": r.confidence,
                }
                for r in rules[:max_rules]
            ]


__all__ = ["KnowledgeBase"]
