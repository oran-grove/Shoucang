# -*- coding: utf-8 -*-
"""
多智能体自适应记忆系统
======================

三层记忆架构 + 三环自适应流程。

快速使用:

    from multi_agent_system.memory import (
        MemoryStore,           # Tier 0: SQLite 反馈案例
        PatternCard,           # Tier 1: 模式卡片
        PatternIndex,          # Tier 1: 内存检索索引
        get_store,             # 单例获取
        get_index,             # 单例获取 (首次调用自动加载)
    )

    # 记录管理员反馈
    store = get_store()
    store.record_feedback(
        ai_verdict="malicious", ai_confidence=0.92,
        ai_reasoning="...", admin_action="block",
        ai_correct=True, admin_note="确认恶意",
        src_ip="10.0.1.15", department="财务部",
    )

    # 检测时注入模式上下文
    index = get_index()
    context = index.format_context(flow_features)
    # context 直接追加到 DetectionAgent / JudgmentAgent 的提示词中

    # 后台定时任务
    from multi_agent_system.memory.clustering import run_hourly_clustering
    from multi_agent_system.memory.weekly_extract import run_weekly_extraction

    # 每小时聚类
    await asyncio.to_thread(run_hourly_clustering)

    # 每周 LLM 模式提取（需要 LLM 后端）
    await run_weekly_extraction(llm_backend)

存储:
    multi_agent_system/memory/data/
      feedback.db          ← SQLite (Tier 0)
      patterns/            ← JSON 模式卡片 (Tier 1)
        active/   shadow/   retired/
      principles.json      ← 已审批的战略原则 (Tier 2)
      principles_candidate.json  ← 待审批候选
"""

from .pattern_card import (
    PatternCard,
    CardStatus,
    format_cards_for_prompt,
)

from .store import (
    MemoryStore,
    get_store,
)

from .pattern_index import (
    PatternIndex,
    get_index,
)

from .clustering import (
    run_hourly_clustering,
)

from .weekly_extract import (
    run_weekly_extraction,
    load_approved_principles,
    apply_principles_to_context,
)

__all__ = [
    # Tier 0 — SQLite 存储
    "MemoryStore",
    "get_store",

    # Tier 1 — 模式卡片
    "PatternCard",
    "CardStatus",
    "PatternIndex",
    "get_index",
    "format_cards_for_prompt",

    # 自适应循环
    "run_hourly_clustering",    # Loop 2
    "run_weekly_extraction",    # Loop 3

    # 战略原则
    "load_approved_principles",
    "apply_principles_to_context",
]
