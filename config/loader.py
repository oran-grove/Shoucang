"""
配置加载器 — 纯内部辅助函数
===========================
仅供 config/store.py 使用。所有公开 API 通过 config/__init__.py 暴露。

内部函数:
  _deep_merge     — 深度合并两个字典
  _validate       — 校验配置字典中的可选值
  _compute_delta  — 计算 current 与 default 的差异
"""

import json
from copy import deepcopy
from typing import Any

from .shared_config import DEFAULT_CONFIG_PATH


# ============================================================
# 深度合并
# ============================================================

def _deep_merge(base: dict, override: dict) -> dict:
    """
    深度合并两个字典。
    override 中的值覆盖 base 中的值。
    嵌套 dict 递归合并，非 dict 值直接覆盖。
    以 _ 开头的 key（元数据/注释）仅保留 base 的，不参与覆盖。
    """
    result = deepcopy(base)
    for key, value in override.items():
        if key.startswith("_"):
            continue
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


# ============================================================
# 校验
# ============================================================

_VALID_BACKEND_NAMES = {"openai", "lmstudio", "deepseek"}


def _validate(config_dict: dict) -> list[str]:
    """
    校验配置字典中的可选值是否合法。
    返回警告列表（不会阻止加载，仅记录）。
    """
    warnings: list[str] = []

    # 校验 DeepSeek 专有参数
    deepseek = config_dict.get("backends", {}).get("deepseek", {})
    if deepseek:
        re_val = deepseek.get("reasoning_effort")
        if re_val is not None and re_val not in ("high", "max"):
            warnings.append(
                f"deepseek.reasoning_effort 值 '{re_val}' 无效，"
                f"可选值: 'high', 'max', null。已重置为 null。"
            )
            deepseek["reasoning_effort"] = None

        te = deepseek.get("thinking_enabled")
        if te is not None and not isinstance(te, bool):
            warnings.append(
                f"deepseek.thinking_enabled 值 '{te}' 无效，"
                f"可选值: true, false, null。已重置为 null。"
            )
            deepseek["thinking_enabled"] = None

    # 校验各智能体 backend 字段
    for agent_key in ("screening", "backtrack", "adjudication", "feedback"):
        agent = config_dict.get(agent_key, {})
        backend = agent.get("backend")
        if backend and backend not in _VALID_BACKEND_NAMES:
            warnings.append(
                f"{agent_key}.backend 值 '{backend}' 无效，"
                f"可选值: {', '.join(sorted(_VALID_BACKEND_NAMES))}。"
            )

    return warnings


# ============================================================
# 增量计算
# ============================================================

def _coerce_types(current: dict, default: dict) -> dict:
    """
    将 current 中与 default 语义相等但类型不同的值，
    强制转换为 default 中的类型。
    用于解决 WebUI 表单提交全部为字符串的问题。
    """
    result = {}
    for key, cur_val in current.items():
        if key.startswith("_"):
            result[key] = cur_val
            continue
        def_val = default.get(key)
        if def_val is None:
            result[key] = deepcopy(cur_val)
            continue
        if isinstance(cur_val, dict) and isinstance(def_val, dict):
            result[key] = _coerce_types(cur_val, def_val)
        elif isinstance(cur_val, list) and isinstance(def_val, list):
            result[key] = [
                _coerce_types_item(c, d) for c, d in
                zip(cur_val, def_val * max(len(cur_val), len(def_val)))
            ]
        else:
            result[key] = _coerce_item(cur_val, def_val)
    return result


def _coerce_item(cur_val: Any, def_val: Any) -> Any:
    """将 cur_val 转换为与 def_val 语义相等的同类型值。"""
    if isinstance(cur_val, type(def_val)):
        return cur_val
    # str → int / float / bool
    if isinstance(cur_val, str) and isinstance(def_val, (int, float, bool)):
        try:
            if isinstance(def_val, bool):
                return cur_val.lower() in ("true", "1", "yes")
            return type(def_val)(cur_val)
        except (ValueError, TypeError):
            return cur_val
    # int → float
    if isinstance(cur_val, int) and isinstance(def_val, float):
        return float(cur_val)
    return cur_val


def _coerce_types_item(cur_val: Any, def_val: Any) -> Any:
    """用于 list 元素内部的类型强制转换。"""
    if isinstance(cur_val, dict) and isinstance(def_val, dict):
        return _coerce_types(cur_val, def_val)
    return _coerce_item(cur_val, def_val)


def _compute_delta(default: dict, current: dict) -> dict:
    """
    递归比较 current 与 default，只返回与默认值不同的键。
    用于生成 config_user.json 的写入内容。
    """
    delta: dict = {}
    for key, value in current.items():
        if key.startswith("_"):
            continue
        if key not in default:
            delta[key] = deepcopy(value)
        elif isinstance(value, dict) and isinstance(default[key], dict):
            sub_delta = _compute_delta(default[key], value)
            if sub_delta:
                delta[key] = sub_delta
        elif value != default[key]:
            delta[key] = deepcopy(value)
    return delta
