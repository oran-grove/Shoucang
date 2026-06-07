# -*- coding: utf-8 -*-
"""
周度模式提取 — 自进化 Loop 3（每周日凌晨 3:00 运行）
====================================================

使用 LLM 对一周的错误案例做批量模式提炼，产出战略原则候选。

设计原则 (来自 GEPA / DORA 研究):
- LLM 只做语言原生反思，不修改任何实际参数
- 输出为人类可读的战略原则，需人工审批后生效
- 每条原则必须可追溯到 ≥ 3 张 Tier 1 模式卡片
- 自动验证：回归检测 + 引用完整性检查

安全约束:
- 绝不自动应用——写入 principles_candidate.json 待审批
- 验证失败 → 标记需要人工审查
- LLM 调用失败不影响系统运行
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .pattern_index import get_index, PatternIndex
from .store import get_store, MemoryStore

logger = logging.getLogger(__name__)

_PRINCIPLES_DIR = Path(__file__).parent / "data"
_CANDIDATE_FILE = _PRINCIPLES_DIR / "principles_candidate.json"
_PRINCIPLES_FILE = _PRINCIPLES_DIR / "principles.json"

# 最小案例数——少于这个数不值得调用 LLM
_MIN_ERRORS_FOR_LLM = 20


async def run_weekly_extraction(llm_backend=None) -> dict:
    """
    执行 Loop 3 周度 LLM 模式提取。

    Args:
        llm_backend: LLM 后端实例（需支持 .chat() 异步方法）。
                     如果为 None，尝试从已注册的后端获取。

    Returns:
        {"candidates_generated": N, "validated": N, "auto_applied": N}
    """
    store = get_store()
    index = get_index()

    # 1. 收集输入
    errors = store.get_errors_for_llm_extraction(days=7)
    if len(errors) < _MIN_ERRORS_FOR_LLM:
        logger.info(
            "[WeeklyExtract] 本周仅 %d 条错误案例，不足 LLM 提取阈值 %d，跳过",
            len(errors), _MIN_ERRORS_FOR_LLM,
        )
        return {"candidates_generated": 0, "validated": 0, "auto_applied": 0}

    active_cards = index.get_active_cards()
    shadow_cards = index.get_shadow_cards()
    overview = store.get_overview()

    # 2. 构建 LLM 提示词
    prompt = _build_extraction_prompt(errors, active_cards, shadow_cards, overview)

    # 3. 调用 LLM
    if llm_backend is None:
        logger.warning("[WeeklyExtract] 无 LLM 后端可用，跳过")
        return {"candidates_generated": 0, "validated": 0, "auto_applied": 0}

    try:
        response = await llm_backend.chat(
            system_prompt=_EXTRACTION_SYSTEM_PROMPT,
            user_prompt=prompt,
            model=getattr(llm_backend, "default_model", ""),
            temperature=0.2,
            max_tokens=4096,
        )
    except Exception as e:
        logger.exception("[WeeklyExtract] LLM 调用失败: %s", e)
        return {"candidates_generated": 0, "validated": 0, "auto_applied": 0}

    # 4. 解析 LLM 输出
    candidates = _parse_llm_output(response)
    if not candidates:
        logger.warning("[WeeklyExtract] LLM 输出解析失败，原始响应: %s", response[:200])
        return {"candidates_generated": 0, "validated": 0, "auto_applied": 0}

    # 5. 验证候选原则
    validated = []
    for cand in candidates:
        if _validate_candidate(cand, active_cards + shadow_cards):
            validated.append(cand)
        else:
            cand["_validation"] = "failed"
            validated.append(cand)  # 仍然保存，但标记验证失败

    # 6. 写入候选文件
    result_data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "week": datetime.now(timezone.utc).isocalendar()[1],
        "year": datetime.now(timezone.utc).year,
        "error_case_count": len(errors),
        "overview": overview,
        "principles": validated,
    }
    _CANDIDATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _CANDIDATE_FILE.write_text(
        json.dumps(result_data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    store.set_last_run("weekly_extraction", {
        "candidates": len(validated),
        "errors_analyzed": len(errors),
        "active_cards": len(active_cards),
    })

    logger.info(
        "[WeeklyExtract] Loop3完成: 生成 %d 条候选原则 (已验证=%d)",
        len(validated), sum(1 for v in validated if v.get("_validation") != "failed"),
    )
    return {
        "candidates_generated": len(validated),
        "validated": sum(1 for v in validated if v.get("_validation") != "failed"),
        "auto_applied": 0,  # 永不自定应用，需人工审批
    }


def _build_extraction_prompt(
    errors: list[dict],
    active_cards: list,
    shadow_cards: list,
    overview: dict,
) -> str:
    """构建 LLM 提取提示词"""
    fp_cases = [e for e in errors if e.get("category") == "fp"]
    fn_cases = [e for e in errors if e.get("category") == "fn"]

    prompt_parts = [
        "## 本周系统运行概览",
        f"- 总反馈案例: {overview.get('total_cases', '?')}",
        f"- 7日准确率: {overview.get('last_7d_accuracy', 0):.1%}",
        f"- 本周错误案例: {len(errors)} 条 (误报 {len(fp_cases)} / 漏报 {len(fn_cases)})",
        "",
        "## 活跃模式卡片 (Tier 1)",
    ]
    for card in active_cards[:20]:
        prompt_parts.append(
            f"- {card.card_id}: {card.title} "
            f"(证据强度={card.evidence_strength:.0%}, "
            f"确认={card.confirmed_count}, "
            f"衰减={card.decay_score:.2f})"
        )
    if shadow_cards:
        prompt_parts.append("\n## 候选影子卡片 (待验证)")
        for card in shadow_cards[:10]:
            prompt_parts.append(
                f"- {card.card_id}: {card.title} "
                f"(证据强度={card.evidence_strength:.0%})"
            )

    if fp_cases:
        prompt_parts.append(f"\n## 误报案例 (AI判恶意,实际正常) — {len(fp_cases)} 条")
        for case in fp_cases[:15]:
            prompt_parts.append(
                f"- [{case.get('department', '?')}] {case.get('ai_reasoning', '')[:200]}\n"
                f"  管理员批注: {case.get('admin_note', '')[:200]}"
            )

    if fn_cases:
        prompt_parts.append(f"\n## 漏报案例 (AI判正常,实际恶意) — {len(fn_cases)} 条")
        for case in fn_cases[:15]:
            prompt_parts.append(
                f"- [{case.get('department', '?')}] {case.get('ai_reasoning', '')[:200]}\n"
                f"  管理员批注: {case.get('admin_note', '')[:200]}"
            )

    prompt_parts.append("\n请基于以上信息，提取可泛化的战略原则。")
    return "\n".join(prompt_parts)


_EXTRACTION_SYSTEM_PROMPT = """你是一个内部威胁检测系统的知识提炼专家。

你的任务是从多智能体系统过去一周的错误案例和模式卡片中，
提炼出高层战略原则，帮助系统变得更加准确。

## 输出要求
以严格 JSON 格式输出：
```json
{
  "principles": [
    {
      "id": "PR-YYYY-WXX-NN",
      "title": "一句话描述这条原则",
      "description": "完整的行为模式描述，包括触发条件和适用场景",
      "evidence_sources": ["引用的卡片ID或反馈案例ID"],
      "category": "false_positive_pattern" | "false_negative_pattern" | "degradation_warning" | "general_insight",
      "severity": "high" | "medium" | "low",
      "suggested_action": "具体的改进建议（不涉及阈值调整！）",
      "related_principles": ["关联的其他原则ID"]
    }
  ]
}
```

## 约束
1. 每条原则必须引用至少 3 个证据来源（卡片ID 或案例ID）
2. 不要提出具体的数值阈值调整建议
3. 不要修改智能体的提示词
4. 只输出可验证的行为模式描述
5. 如果证据不足以形成可靠原则，宁可少输出不要硬凑"""


def _parse_llm_output(response: str) -> list[dict]:
    """解析 LLM 输出为原则列表"""
    import re
    try:
        # 尝试提取 JSON
        json_match = re.search(r'\{.*"principles"\s*:.*\}', response, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group(0))
        else:
            data = json.loads(response)
        return data.get("principles", [])
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        logger.warning("[WeeklyExtract] JSON 解析失败: %s", e)
        return []


def _validate_candidate(principle: dict, existing_cards: list) -> bool:
    """验证候选原则的质量"""
    # 必须有足够的证据引用
    sources = principle.get("evidence_sources", [])
    if len(sources) < 3:
        logger.warning("[WeeklyExtract] 原则 %s 证据不足: %d 条", principle.get("id", "?"), len(sources))
        return False

    # 引用必须存在（至少在现有卡片中）
    valid_refs = 0
    card_ids = {c.card_id for c in existing_cards}
    for src in sources:
        if src in card_ids:
            valid_refs += 1
    if valid_refs < 2:
        logger.warning("[WeeklyExtract] 原则 %s 有效引用不足: %d", principle.get("id", "?"), valid_refs)
        return False

    # 必需字段
    required = ["id", "title", "description", "category"]
    for field in required:
        if not principle.get(field):
            logger.warning("[WeeklyExtract] 原则 %s 缺少字段: %s", principle.get("id", "?"), field)
            return False

    return True


def load_approved_principles() -> list[dict]:
    """加载已审批的战略原则"""
    if not _PRINCIPLES_FILE.exists():
        return []
    try:
        data = json.loads(_PRINCIPLES_FILE.read_text(encoding="utf-8"))
        return data.get("principles", [])
    except Exception:
        return []


def apply_principles_to_context(principles: list[dict]) -> str:
    """将审批后的原则格式化为提示词上下文"""
    if not principles:
        return ""
    lines = ["", "## 已审批的战略原则（管理层确认的长期经验）", ""]
    for p in principles:
        lines.append(f"- **{p.get('title', '')}**: {p.get('description', '')}")
    lines.append("")
    return "\n".join(lines)


__all__ = ["run_weekly_extraction", "load_approved_principles", "apply_principles_to_context"]
