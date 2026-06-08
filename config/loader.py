"""
统一配置管理器 — JSON 配置文件加载器
======================================

设计原则:
- 子模块（agents/backends/orchestrator）**绝不直接读取 JSON 文件**
- 配置读取和 OrchestratorConfig 构建全部由此模块完成
- 支持 默认配置 + 用户配置 双层合并
- 前端 PHP 和 Python 后端共用同一套 JSON 配置文件

用法:
    from config import load_config

    # 仅使用默认配置
    config = load_config()

    # 默认配置 + 用户覆盖
    config = load_config("config/config_user.json")

    # 传入 OrchestratorConfig 构建系统
    system = MultiAgentSystem(orchestrator_config=config)

    # 保存配置回 JSON（供前端编辑配置后保存）
    save_config(config, "config/config_saved.json")
"""

import json
from pathlib import Path
from copy import deepcopy
from typing import Any, Optional

from .schema import (
    BackendType,
    LLMBackendConfig,
    ScreeningAgentConfig,
    BacktrackAgentConfig,
    AdjudicationAgentConfig,
    FeedbackAgentConfig,
    OrchestratorConfig,
)

# ============================================================
# 默认配置文件路径（统一在 config/ 目录下）
# ============================================================

_DEFAULT_CONFIG_PATH = Path(__file__).parent / "config_default.json"


# ============================================================
# 可选值约束表（用于校验用户配置中的枚举类字段）
# ============================================================

_VALID_BACKEND_NAMES = {"openai", "lmstudio", "deepseek"}
_VALID_REASONING_EFFORT = {None, "high", "max"}
_VALID_THINKING_ENABLED = {None, True, False}


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
            continue  # 跳过元数据键
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def _validate_config(config_dict: dict) -> list[str]:
    """
    校验配置字典中的可选值是否合法。
    返回警告列表（不会阻止加载，仅记录）。
    """
    warnings = []

    # 校验 DeepSeek 专有参数
    deepseek = config_dict.get("backends", {}).get("deepseek", {})
    if deepseek:
        re = deepseek.get("reasoning_effort")
        if re is not None and re not in ("high", "max"):
            warnings.append(
                f"deepseek.reasoning_effort 值 '{re}' 无效，"
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
                f"请检查配置。"
            )

    return warnings


def _build_llm_config(backend_type: BackendType, d: dict) -> LLMBackendConfig:
    """从字典构建 LLMBackendConfig"""
    return LLMBackendConfig(
        backend_type=backend_type,
        model_name=d.get("model_name", ""),
        api_base=d.get("api_base", ""),
        api_key=d.get("api_key", ""),
        temperature=d.get("temperature", 0.3),
        max_tokens=d.get("max_tokens", 2048),
        timeout=d.get("timeout", 60.0),
        max_retries=d.get("max_retries", 3),
        auto_load=d.get("auto_load", True),
        load_config=d.get("load_config", {}) or {},
        thinking_enabled=d.get("thinking_enabled"),
        reasoning_effort=d.get("reasoning_effort"),
        include_reasoning=d.get("include_reasoning", False),
    )


def _build_screening_config(d: dict) -> ScreeningAgentConfig:
    return ScreeningAgentConfig(
        enabled=d.get("enabled", True),
        backend=BackendType(d.get("backend", "deepseek")),
        model_name=d.get("model_name", "deepseek-v4-flash"),
        system_prompt=d.get(
            "system_prompt",
            ScreeningAgentConfig.system_prompt,
        ),
        temperature=d.get("temperature", 0.3),
        max_tokens=d.get("max_tokens", 1024),
        max_context_tokens=d.get("max_context_tokens", 4096),
        confidence_threshold_dangerous=d.get("confidence_threshold_dangerous", 0.85),
        confidence_threshold_suspicious=d.get("confidence_threshold_suspicious", 0.50),
    )


def _build_backtrack_config(d: dict) -> BacktrackAgentConfig:
    return BacktrackAgentConfig(
        enabled=d.get("enabled", True),
        backend=BackendType(d.get("backend", "deepseek")),
        model_name=d.get("model_name", "deepseek-v4-flash"),
        system_prompt=d.get(
            "system_prompt",
            BacktrackAgentConfig.system_prompt,
        ),
        temperature=d.get("temperature", 0.3),
        max_tokens=d.get("max_tokens", 2048),
        lookback_windows=d.get("lookback_windows", [24, 168, 720, 2160]),
        relevance_threshold=d.get("relevance_threshold", 0.6),
        max_similar_records=d.get("max_similar_records", 20),
    )


def _build_adjudication_config(d: dict) -> AdjudicationAgentConfig:
    return AdjudicationAgentConfig(
        enabled=d.get("enabled", True),
        backend=BackendType(d.get("backend", "deepseek")),
        model_name=d.get("model_name", "deepseek-v4-flash"),
        system_prompt=d.get(
            "system_prompt",
            AdjudicationAgentConfig.system_prompt,
        ),
        temperature=d.get("temperature", 0.3),
        max_tokens=d.get("max_tokens", 2048),
    )


def _build_feedback_config(d: dict) -> FeedbackAgentConfig:
    return FeedbackAgentConfig(
        enabled=d.get("enabled", True),
        backend=BackendType(d.get("backend", "deepseek")),
        model_name=d.get("model_name", "deepseek-v4-flash"),
        system_prompt=d.get(
            "system_prompt",
            FeedbackAgentConfig.system_prompt,
        ),
        temperature=d.get("temperature", 0.2),
        max_tokens=d.get("max_tokens", 1024),
    )


def load_config(user_config_path: Optional[str] = None) -> OrchestratorConfig:
    """
    加载配置，返回 OrchestratorConfig。

    加载顺序：
    1. 加载 config/config_default.json（所有字段的默认值）
    2. 如果提供了 user_config_path 且文件存在，深合并覆盖

    Args:
        user_config_path: 用户配置文件路径。为 None 则仅使用默认配置。
                          用户文件只需包含要覆盖的字段，不必完整。

    Returns:
        OrchestratorConfig: 构建好的配置对象

    Raises:
        FileNotFoundError: config_default.json 不存在
        json.JSONDecodeError: JSON 格式错误
        ValueError: 配置校验失败（致命错误）

    Example:
        >>> config = load_config()  # 仅默认配置
        >>> config = load_config("config/config_user.json")  # 默认+用户覆盖
    """
    # 1. 加载默认配置
    if not _DEFAULT_CONFIG_PATH.exists():
        raise FileNotFoundError(
            f"默认配置文件不存在: {_DEFAULT_CONFIG_PATH}\n"
            f"请确保 config_default.json 在 config/ 目录下。"
        )
    with open(_DEFAULT_CONFIG_PATH, "r", encoding="utf-8") as f:
        default_dict = json.load(f)

    # 2. 加载并合并用户配置
    if user_config_path:
        user_path = Path(user_config_path)
        if user_path.exists():
            with open(user_path, "r", encoding="utf-8") as f:
                user_dict = json.load(f)
            merged = _deep_merge(default_dict, user_dict)
        else:
            print(f"[loader] 用户配置文件不存在: {user_config_path}，使用默认配置。")
            merged = default_dict
    else:
        merged = default_dict

    # 3. 校验可选值
    warnings = _validate_config(merged)
    for w in warnings:
        print(f"[loader] ⚠ {w}")

    # 4. 构建后端配置
    backends = merged.get("backends", {})
    for name in ("openai", "lmstudio", "deepseek"):
        if name not in backends:
            backends[name] = {}
    default_backends = {
        BackendType.OPENAI: _build_llm_config(BackendType.OPENAI, backends["openai"]),
        BackendType.LMSTUDIO: _build_llm_config(BackendType.LMSTUDIO, backends["lmstudio"]),
        BackendType.DEEPSEEK: _build_llm_config(BackendType.DEEPSEEK, backends["deepseek"]),
    }

    # 5. 构建 OrchestratorConfig
    return OrchestratorConfig(
        screening=_build_screening_config(merged.get("screening", {})),
        backtrack=_build_backtrack_config(merged.get("backtrack", {})),
        adjudication=_build_adjudication_config(merged.get("adjudication", {})),
        feedback=_build_feedback_config(merged.get("feedback", {})),
        default_backends=default_backends,
    )


def save_config(config: OrchestratorConfig, path: str) -> None:
    """
    将运行时配置序列化为 JSON 文件。

    Args:
        config: 运行中的 OrchestratorConfig 实例
        path: 保存路径
    """
    d = _config_to_dict(config)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=2)
    print(f"[loader] 配置已保存到: {path}")


def _config_to_dict(config: OrchestratorConfig) -> dict:
    """将 OrchestratorConfig 转换回字典（含所有字段，不含元数据注释）"""
    return {
        "backends": {
            "openai": {
                "model_name": config.default_backends[BackendType.OPENAI].model_name,
                "api_base": config.default_backends[BackendType.OPENAI].api_base,
                "api_key": config.default_backends[BackendType.OPENAI].api_key,
                "temperature": config.default_backends[BackendType.OPENAI].temperature,
                "max_tokens": config.default_backends[BackendType.OPENAI].max_tokens,
                "timeout": config.default_backends[BackendType.OPENAI].timeout,
                "max_retries": config.default_backends[BackendType.OPENAI].max_retries,
            },
            "lmstudio": {
                "model_name": config.default_backends[BackendType.LMSTUDIO].model_name,
                "api_base": config.default_backends[BackendType.LMSTUDIO].api_base,
                "api_key": config.default_backends[BackendType.LMSTUDIO].api_key,
                "temperature": config.default_backends[BackendType.LMSTUDIO].temperature,
                "max_tokens": config.default_backends[BackendType.LMSTUDIO].max_tokens,
                "timeout": config.default_backends[BackendType.LMSTUDIO].timeout,
                "max_retries": config.default_backends[BackendType.LMSTUDIO].max_retries,
                "auto_load": config.default_backends[BackendType.LMSTUDIO].auto_load,
                "load_config": config.default_backends[BackendType.LMSTUDIO].load_config,
            },
            "deepseek": {
                "model_name": config.default_backends[BackendType.DEEPSEEK].model_name,
                "api_base": config.default_backends[BackendType.DEEPSEEK].api_base,
                "api_key": config.default_backends[BackendType.DEEPSEEK].api_key,
                "temperature": config.default_backends[BackendType.DEEPSEEK].temperature,
                "max_tokens": config.default_backends[BackendType.DEEPSEEK].max_tokens,
                "timeout": config.default_backends[BackendType.DEEPSEEK].timeout,
                "max_retries": config.default_backends[BackendType.DEEPSEEK].max_retries,
                "thinking_enabled": config.default_backends[BackendType.DEEPSEEK].thinking_enabled,
                "reasoning_effort": config.default_backends[BackendType.DEEPSEEK].reasoning_effort,
                "include_reasoning": config.default_backends[BackendType.DEEPSEEK].include_reasoning,
            },
        },
        "screening": {
            "enabled": config.screening.enabled,
            "backend": config.screening.backend.value,
            "model_name": config.screening.model_name,
            "system_prompt": config.screening.system_prompt,
            "temperature": config.screening.temperature,
            "max_tokens": config.screening.max_tokens,
            "max_context_tokens": config.screening.max_context_tokens,
            "confidence_threshold_dangerous": config.screening.confidence_threshold_dangerous,
            "confidence_threshold_suspicious": config.screening.confidence_threshold_suspicious,
        },
        "backtrack": {
            "enabled": config.backtrack.enabled,
            "backend": config.backtrack.backend.value,
            "model_name": config.backtrack.model_name,
            "system_prompt": config.backtrack.system_prompt,
            "temperature": config.backtrack.temperature,
            "max_tokens": config.backtrack.max_tokens,
            "lookback_windows": config.backtrack.lookback_windows,
            "relevance_threshold": config.backtrack.relevance_threshold,
            "max_similar_records": config.backtrack.max_similar_records,
        },
        "adjudication": {
            "enabled": config.adjudication.enabled,
            "backend": config.adjudication.backend.value,
            "model_name": config.adjudication.model_name,
            "system_prompt": config.adjudication.system_prompt,
            "temperature": config.adjudication.temperature,
            "max_tokens": config.adjudication.max_tokens,
        },
        "feedback": {
            "enabled": config.feedback.enabled,
            "backend": config.feedback.backend.value,
            "model_name": config.feedback.model_name,
            "system_prompt": config.feedback.system_prompt,
            "temperature": config.feedback.temperature,
            "max_tokens": config.feedback.max_tokens,
        },
    }


# ============================================================
# 便捷函数：创建快速启动配置
# ============================================================


def quick_all_local(
    model_name: str = "qwen3.5-9b",
    api_base: str = "http://localhost:1234/v1",
) -> OrchestratorConfig:
    """快速创建"全部使用 LM Studio 本地模型"的配置。"""
    config = load_config()
    config.default_backends[BackendType.LMSTUDIO].model_name = model_name
    config.default_backends[BackendType.LMSTUDIO].api_base = api_base
    config.screening.backend = BackendType.LMSTUDIO
    config.screening.model_name = model_name
    config.backtrack.backend = BackendType.LMSTUDIO
    config.backtrack.model_name = model_name
    config.adjudication.backend = BackendType.LMSTUDIO
    config.adjudication.model_name = model_name
    config.feedback.backend = BackendType.LMSTUDIO
    config.feedback.model_name = model_name
    return config


def quick_all_deepseek(
    api_key: str,
    model_name: str = "deepseek-v4-flash",
    thinking_enabled: Optional[bool] = None,
    reasoning_effort: Optional[str] = None,
) -> OrchestratorConfig:
    """快速创建"全部使用 DeepSeek API"的配置。"""
    config = load_config()
    ds = config.default_backends[BackendType.DEEPSEEK]
    ds.api_key = api_key
    ds.model_name = model_name
    ds.thinking_enabled = thinking_enabled
    ds.reasoning_effort = reasoning_effort
    config.screening.backend = BackendType.DEEPSEEK
    config.screening.model_name = model_name
    config.backtrack.backend = BackendType.DEEPSEEK
    config.backtrack.model_name = model_name
    config.adjudication.backend = BackendType.DEEPSEEK
    config.adjudication.model_name = model_name
    config.feedback.backend = BackendType.DEEPSEEK
    config.feedback.model_name = model_name
    return config


# ============================================================
# 原始字典级读写（供不需要类型化 OrchestratorConfig 的模块使用）
# ============================================================

from .shared_config import USER_CONFIG_PATH


def load_config_dict() -> dict:
    """
    以原始字典形式返回合并后的配置（默认 + 用户覆盖）。
    """
    if not _DEFAULT_CONFIG_PATH.exists():
        return {}
    default = json.loads(_DEFAULT_CONFIG_PATH.read_text(encoding="utf-8"))
    if USER_CONFIG_PATH.exists():
        user = json.loads(USER_CONFIG_PATH.read_text(encoding="utf-8"))
        return _deep_merge(default, user)
    return default


def load_default_config_dict() -> dict:
    """返回纯默认配置字典（不含用户覆盖）。"""
    if not _DEFAULT_CONFIG_PATH.exists():
        return {}
    return json.loads(_DEFAULT_CONFIG_PATH.read_text(encoding="utf-8"))


def _compute_delta(default: dict, current: dict) -> dict:
    """
    递归比较 current 与 default，只返回与默认值不同的键。
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


def save_config_dict(config: dict) -> None:
    """
    将配置字典的增量部分写入 config_user.json。
    """
    default = json.loads(_DEFAULT_CONFIG_PATH.read_text(encoding="utf-8"))
    delta = _compute_delta(default, config)
    USER_CONFIG_PATH.write_text(
        json.dumps(delta, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "default":
        config = load_config()
        save_config(config, "config_user_template.json")
        print("已生成 config_user_template.json（可重命名为 config_user.json 后编辑）")
    else:
        user_path = sys.argv[1] if len(sys.argv) > 1 else None
        config = load_config(user_path)

        print("=" * 60)
        print("多智能体分析系统 — 配置加载成功")
        print("=" * 60)
        print(f"\n后端:")
        for bt in BackendType:
            be = config.default_backends[bt]
            print(f"  [{bt.value}] {be.model_name} @ {be.api_base}")
        print(f"\n智能体:")
        print(f"  L1-筛查: backend={config.screening.backend.value}, model={config.screening.model_name}")
        print(f"  L2-回溯: backend={config.backtrack.backend.value}, model={config.backtrack.model_name}")
        print(f"  L3-研判: backend={config.adjudication.backend.value}, model={config.adjudication.model_name}")
        print(f"  反馈:   backend={config.feedback.backend.value}, model={config.feedback.model_name}")

        ds = config.default_backends[BackendType.DEEPSEEK]
        if ds.api_key:
            print(f"\nDeepSeek V4:")
            print(f"  thinking_enabled: {ds.thinking_enabled}")
            print(f"  reasoning_effort: {ds.reasoning_effort}")
            print(f"  include_reasoning: {ds.include_reasoning}")
