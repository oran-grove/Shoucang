"""
多智能体分析系统 — 三层架构全真模拟测试
=======================================

在全真环境下测试多智能体模块的全部功能：
  - 三层分析管线（筛查 → 回溯 ⇄ 研判）
  - 管理员反馈 + 记忆系统自适应学习
  - LiveScanOrchestrator 逐条扫描调度
  - LM Studio 模型管理（可选，通过 --lmstudio 或自动检测启用）

运行方式：
    python -m multi_agent_system.example_usage                 # 全部测试
    python -m multi_agent_system.example_usage --lmstudio      # 含 LM Studio 管理测试
    python -m multi_agent_system.example_usage 1               # 仅运行指定模块
    python -m multi_agent_system.example_usage 1 2 3           # 运行多个模块

依赖：
    config_user.json 中配置有效的 DeepSeek API Key 即可运行核心测试。
    LM Studio 测试需要本地运行 LM Studio 服务 (http://localhost:1234)。
"""

import argparse
import asyncio
import logging
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

_PROJECT_ROOT = Path(__file__).parent.parent.resolve()
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from multi_agent_system import (
    MultiAgentSystem, Orchestrator, OrchestratorConfig,
    FlowEvent, ThreatVerdict, TrafficVerdict, SeverityLevel,
    BackendType,
    ScreeningAgent, BacktrackAgent, AdjudicationAgent, FeedbackAgent,
    AdminFeedback,
)
from multi_agent_system.orchestrators.live_scan_orchestrator import (
    LiveScanOrchestrator,
)
from multi_agent_system.orchestrators import row_to_flow_event
from config.loader import load_config

logging.basicConfig(
    level=logging.WARNING,  # 减少第三方库日志噪音
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("example")

SEP = "=" * 64
SUB = "-" * 48


def _h(title: str) -> None:
    print(f"\n{SEP}\n  {title}\n{SEP}")


def _sh(title: str) -> None:
    print(f"\n  {SUB}\n  {title}\n  {SUB}")


def _ok(msg: str) -> None:
    print(f"  [OK]  {msg}")


def _info(msg: str) -> None:
    print(f"        {msg}")


def _warn(msg: str) -> None:
    print(f"  [!!]  {msg}")


# ═══════════════════════════════════════════════════════════════
# 配置加载
# ═══════════════════════════════════════════════════════════════

def load_test_config() -> OrchestratorConfig:
    """加载测试配置，优先使用 config_user.json（含用户的 API Key）。"""
    user_path = _PROJECT_ROOT / "config" / "config_user.json"
    if user_path.exists():
        return load_config(str(user_path))
    return load_config()


def _check_backend_available(config: OrchestratorConfig, bt: BackendType) -> bool:
    """检查指定后端是否有可用的 API Key。"""
    be = config.default_backends.get(bt)
    if be is None:
        return False
    if bt in (BackendType.OPENAI, BackendType.DEEPSEEK):
        return bool(be.api_key and be.api_key.strip()
                    and "sk-your-" not in be.api_key
                    and "your-key" not in be.api_key)
    return True  # LMSTUDIO 不需要 API Key


# ═══════════════════════════════════════════════════════════════
# 示例数据
# ═══════════════════════════════════════════════════════════════

def build_sample_flows() -> list[FlowEvent]:
    """构造三层管线测试用流量。"""
    now = datetime.now(timezone.utc)
    return [
        FlowEvent(
            timestamp=now, src_ip="192.168.1.50", dst_ip="142.250.80.46",
            src_port=52341, dst_port=443,
            protocol="TCP", app_protocol="TLS",
            pkt_count=80, byte_count=45000, duration_seconds=12.0,
            avg_pkt_size=562, entropy_score=7.8,
            tls_sni="www.google.com",
            user_id="user_normal", department="研发部",
        ),
        FlowEvent(
            timestamp=now, src_ip="192.168.1.100", dst_ip="203.0.113.42",
            src_port=49152, dst_port=8443,
            protocol="TCP", app_protocol="TLS",
            pkt_count=5000, byte_count=8_000_000, duration_seconds=45.0,
            avg_pkt_size=1600, entropy_score=7.95,
            tls_sni="data-sync.unknown.example.com",
            user_id="user_suspicious", department="财务部",
            historical_frequency_zscore=3.2, historical_volume_zscore=4.1,
        ),
        FlowEvent(
            timestamp=now, src_ip="192.168.1.100", dst_ip="198.51.100.77",
            src_port=49153, dst_port=443,
            protocol="TCP", app_protocol="TLS",
            pkt_count=3000, byte_count=4_500_000, duration_seconds=32.0,
            avg_pkt_size=1500, entropy_score=7.90,
            user_id="user_suspicious", department="财务部",
            historical_frequency_zscore=2.8, historical_volume_zscore=3.5,
        ),
        FlowEvent(
            timestamp=now, src_ip="192.168.1.100", dst_ip="8.8.8.8",
            src_port=30221, dst_port=53,
            protocol="UDP", app_protocol="DNS",
            pkt_count=200, byte_count=120_000, duration_seconds=60.0,
            avg_pkt_size=600, entropy_score=6.5,
            dns_query="base64-encoded-payload.evil-dns.example.com",
            user_id="user_suspicious", department="财务部",
        ),
        FlowEvent(
            timestamp=now, src_ip="192.168.1.50", dst_ip="93.184.216.34",
            src_port=45678, dst_port=80,
            protocol="TCP", app_protocol="HTTP",
            pkt_count=30, byte_count=15000, duration_seconds=5.0,
            avg_pkt_size=500, entropy_score=5.2,
            user_id="user_normal", department="研发部",
        ),
    ]


# ═══════════════════════════════════════════════════════════════
# 测试 1: 三层分析管线（全真 API 调用）
# ═══════════════════════════════════════════════════════════════

async def test_pipeline(config: OrchestratorConfig):
    """全真测试 L1筛查 → L2回溯 ⇄ L3研判 三层管线。

    使用 config_user.json 中的 DeepSeek API Key 进行真实 LLM 分析。
    """
    _h("测试 1: 三层分析管线 (筛查 → 回溯 ⇄ 研判)")

    ds_ok = _check_backend_available(config, BackendType.DEEPSEEK)
    if not ds_ok:
        _warn("DeepSeek API Key 未配置或无效，跳过全真测试")
        _info("请在 config_user.json 的 backends.deepseek.api_key 中填入有效密钥")
        return

    _info(f"后端: DeepSeek/{config.default_backends[BackendType.DEEPSEEK].model_name}")
    _info(f"L1-筛查: {config.screening.backend.value}/{config.screening.model_name}")
    _info(f"L2-回溯: {config.backtrack.backend.value}/{config.backtrack.model_name}")
    _info(f"L3-研判: {config.adjudication.backend.value}/{config.adjudication.model_name}")

    system = MultiAgentSystem(config)
    await system.start()
    _ok("系统启动完成")

    flows = build_sample_flows()
    results: list[ThreatVerdict] = []

    for i, flow in enumerate(flows, 1):
        _sh(f"流量 #{i}: {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} [{flow.app_protocol}]")
        try:
            verdict = await system.analyze(flow)
            results.append(verdict)
            bt_depth = verdict.extra.get("backtrack_depth", 0) if verdict.extra else 0
            verdict_icon = {"malicious": "!!", "suspicious": " ?", "safe": "  ", "unknown": ".."}.get(
                verdict.verdict.value, "??")
            depth_info = f" (回溯{bt_depth}次)" if bt_depth > 0 else ""
            _ok(f"[{verdict_icon}] {verdict.verdict.value.upper()}{depth_info} | "
                f"严重度={verdict.severity.value} | 置信度={verdict.confidence:.0%}")
            _info(f"威胁类型: {verdict.threat_type}")
            _info(f"建议动作: {verdict.recommended_action}")
            if verdict.reasoning:
                _info(f"理由: {verdict.reasoning[:200]}")
        except Exception as e:
            _warn(f"分析失败: {e}")

    # 汇总
    verdicts = [r.verdict.value for r in results]
    _sh("管线汇总")
    _info(f"总分析: {len(results)} 条")
    _info(f"恶意: {verdicts.count('malicious')} | 可疑: {verdicts.count('suspicious')} | "
           f"安全: {verdicts.count('safe')} | 未知: {verdicts.count('unknown')}")

    stats = system.get_statistics()
    _info(f"已注册后端: {list(stats['backends'].keys())}")
    _info(f"反馈统计: {stats['feedback_stats']}")

    await system.stop()
    _ok("测试 1 完成")


# ═══════════════════════════════════════════════════════════════
# 测试 2: 管理员反馈闭环 + 记忆系统
# ═══════════════════════════════════════════════════════════════

async def test_feedback(config: OrchestratorConfig):
    """测试管理员反馈闭环 + 记忆系统自适应学习。"""
    _h("测试 2: 管理员反馈 + 记忆系统")

    from multi_agent_system.memory import get_store, get_index

    agent = FeedbackAgent()

    # 注入后端
    ds_cfg = config.default_backends.get(BackendType.DEEPSEEK)
    if ds_cfg and _check_backend_available(config, BackendType.DEEPSEEK):
        from multi_agent_system.backends import DeepSeekBackend
        agent.set_backend(DeepSeekBackend(
            api_base=ds_cfg.api_base, api_key=ds_cfg.api_key,
            timeout=ds_cfg.timeout, max_retries=ds_cfg.max_retries,
            default_model=ds_cfg.model_name,
        ))
        agent.model_name = ds_cfg.model_name

    # 记录判定
    verdict = ThreatVerdict(
        verdict=TrafficVerdict.MALICIOUS, severity=SeverityLevel.HIGH,
        confidence=0.88, threat_type="数据泄露",
        reasoning="高熵加密 + 非工作时段 + 大量出站到陌生境外IP",
        recommended_action="block",
    )
    agent.record_verdict(verdict)
    _ok(f"判定已记录 (id={verdict.verdict_id})")

    # 管理员确认恶意
    fb = AdminFeedback(
        verdict_id=verdict.verdict_id,
        feedback_type="confirm_malicious",
        admin_note="经排查确认为内部员工泄密行为，已移交安全部门",
        src_ip="192.168.1.100", dst_ip="203.0.113.42",
    )
    result = await agent.process(feedback=fb)
    _ok(f"确认恶意: {result.get('action')} — {result.get('reasoning', '')[:80]}")
    if result.get("llm_suggestion"):
        _info(f"LLM 增强分析: {str(result['llm_suggestion'])[:200]}")

    # 管理员标记误报
    fb2 = AdminFeedback(
        feedback_type="false_positive",
        admin_note="该 IP 为公司内部测试服务器，非恶意目标",
        src_ip="192.168.1.50",
    )
    result2 = await agent.process(feedback=fb2)
    _ok(f"标记误报: {result2.get('action')}")

    # 管理员标记漏报
    fb3 = AdminFeedback(
        feedback_type="false_negative",
        admin_note="该 C2 通信未被系统检测到，需补充检测模式",
        src_ip="10.99.0.13", dst_ip="45.33.32.156",
    )
    result3 = await agent.process(feedback=fb3)
    _ok(f"标记漏报: {result3.get('action')}")

    # 统计
    stats = agent.get_statistics()
    _info(f"总反馈: {stats['total_feedbacks']} | "
          f"近期类型: {stats['recent_feedback_types']}")

    # 记忆系统
    store = get_store()
    index = get_index()
    _ok(f"记忆系统就绪: store={type(store).__name__}, index={type(index).__name__}")

    _ok("测试 2 完成")


# ═══════════════════════════════════════════════════════════════
# 测试 3: 三层智能体独立验证
# ═══════════════════════════════════════════════════════════════

async def test_agents_standalone(config: OrchestratorConfig):
    """独立测试三个智能体的创建和基本功能。"""
    _h("测试 3: 三层智能体独立验证")

    ds_ok = _check_backend_available(config, BackendType.DEEPSEEK)
    if not ds_ok:
        _warn("DeepSeek API Key 未配置，仅验证构造不调用 LLM")
        await _test_agents_no_llm(config)
        return

    from multi_agent_system.backends import DeepSeekBackend
    ds_cfg = config.default_backends[BackendType.DEEPSEEK]

    backend = DeepSeekBackend(
        api_base=ds_cfg.api_base, api_key=ds_cfg.api_key,
        timeout=ds_cfg.timeout, max_retries=ds_cfg.max_retries,
        default_model=ds_cfg.model_name,
    )

    # 3a. 筛查智能体
    _sh("3a. L1-筛查智能体")
    screening = ScreeningAgent(
        name="TestScreening",
        system_prompt=config.screening.system_prompt,
        model_name=config.screening.model_name,
    )
    screening.set_backend(backend)
    _ok("筛查智能体创建成功")

    flow = FlowEvent(
        src_ip="192.168.1.100", dst_ip="45.33.32.156",
        src_port=49152, dst_port=443,
        protocol="TCP", app_protocol="TLS",
        byte_count=8_000_000, entropy_score=7.95,
        department="财务部",
    )
    try:
        result = await screening.process(flow)
        _ok(f"筛查结果: {result.verdict.value} (置信度={result.confidence:.0%})")
        _info(f"阈值校准: {screening.classify_threshold(result)}")
    except Exception as e:
        _warn(f"筛查失败: {e}")

    # 3b. 回溯智能体
    _sh("3b. L2-回溯智能体")
    backtrack = BacktrackAgent(
        name="TestBacktrack",
        system_prompt=config.backtrack.system_prompt,
        model_name=config.backtrack.model_name,
        relevance_threshold=config.backtrack.relevance_threshold,
    )
    backtrack.set_backend(backend)
    _ok("回溯智能体创建成功")

    similar_records = [
        {"id": 101, "src_ip": "192.168.1.100", "dst_ip": "45.33.32.156",
         "protocol": "TCP", "traffic_size": 5000000, "entropy": 7.8,
         "department": "财务部", "created_at": "2026-06-07 02:00:00"},
        {"id": 102, "src_ip": "192.168.1.100", "dst_ip": "8.8.8.8",
         "protocol": "UDP", "traffic_size": 500, "entropy": 6.0,
         "department": "财务部", "created_at": "2026-06-06 23:00:00"},
    ]
    matched: list = []
    try:
        bt_result = await backtrack.process(flow, similar_records)
        matched = bt_result.get("matched_records", [])
        _ok(f"回溯结果: {len(similar_records)}总 → {len(matched)}高关联")
    except Exception as e:
        _warn(f"回溯失败: {e}")

    # 3c. 研判智能体
    _sh("3c. L3-研判智能体")
    adjudication = AdjudicationAgent(
        name="TestAdjudication",
        system_prompt=config.adjudication.system_prompt,
        model_name=config.adjudication.model_name,
    )
    adjudication.set_backend(backend)
    _ok("研判智能体创建成功")

    try:
        adj_result = await adjudication.process(
            flow=flow,
            related_context=matched,
            backtrack_depth=1,
        )
        _ok(f"研判结果: {adj_result.verdict.value} | "
            f"严重度={adj_result.severity.value} | 置信度={adj_result.confidence:.0%}")
    except Exception as e:
        _warn(f"研判失败: {e}")

    _ok("测试 3 完成")


async def _test_agents_no_llm(config: OrchestratorConfig):
    """仅验证智能体构造（不调用 LLM）。"""
    screening = ScreeningAgent(
        system_prompt=config.screening.system_prompt,
        model_name=config.screening.model_name,
    )
    _ok(f"筛查智能体: {screening.name} (model={screening.model_name})")

    backtrack = BacktrackAgent(
        system_prompt=config.backtrack.system_prompt,
        model_name=config.backtrack.model_name,
    )
    _ok(f"回溯智能体: {backtrack.name} (model={backtrack.model_name}, "
        f"threshold={backtrack.relevance_threshold})")

    adjudication = AdjudicationAgent(
        system_prompt=config.adjudication.system_prompt,
        model_name=config.adjudication.model_name,
    )
    _ok(f"研判智能体: {adjudication.name} (model={adjudication.model_name})")

    _ok("三层智能体构造完成 (未调用 LLM)")


# ═══════════════════════════════════════════════════════════════
# 测试 4: LiveScanOrchestrator 调度验证
# ═══════════════════════════════════════════════════════════════

def test_live_scan(config: OrchestratorConfig):
    """验证 LiveScanOrchestrator 的 DB row 转换和调度配置。"""
    _h("测试 4: LiveScanOrchestrator 逐条扫描调度")

    db_row = {
        "id": 12345, "src_ip": "192.168.1.100", "dst_ip": "203.0.113.42",
        "src_port": 49152, "dst_port": 443, "protocol": "TCP",
        "department": "财务部", "traffic_size": 50000, "entropy": 7.5,
        "src_tag": "internal", "sp_tag": "suspicious", "dp_tag": "external",
        "accumulated_pkts": 1200, "accumulated_bytes": 800000,
        "global_pps": 350, "global_bps": 5000000, "avg_entropy": 6.8,
        "packet_time": "2026-06-01 14:30:00", "is_blocked": 0,
    }
    flow = row_to_flow_event(db_row)
    _ok(f"row_to_flow_event: {flow.src_ip}:{flow.src_port} -> "
        f"{flow.dst_ip}:{flow.dst_port} [{flow.protocol}]")
    _info(f"部门={flow.department}, 字节={flow.byte_count}, "
          f"熵={flow.entropy_score}, extra_keys={list(flow.extra.keys())}")

    _info(f"扫描配置: enabled={config.live_scan.enabled}, "
          f"interval={config.live_scan.scan_interval_seconds}s, "
          f"batch={config.live_scan.batch_size}, "
          f"concurrency={config.live_scan.max_concurrent_analyses}")

    _ok("测试 4 完成")


# ═══════════════════════════════════════════════════════════════
# 测试 5: 记忆系统完整功能
# ═══════════════════════════════════════════════════════════════

def test_memory():
    """测试三层记忆架构的读写操作。"""
    _h("测试 5: 记忆系统 (Tier 0 / Tier 1 / Tier 2)")

    from multi_agent_system.memory import (
        get_store, get_index,
        PatternCard, CardStatus, format_cards_for_prompt,
        load_approved_principles, apply_principles_to_context,
    )

    # Tier 0: 反馈案例写入
    store = get_store()
    store.record_feedback(
        ai_verdict="malicious", ai_confidence=0.92,
        ai_reasoning="高熵加密 + 非工作时段 + 大流量出站",
        ai_threat_type="数据泄露",
        admins_action="confirm_malicious", ai_correct=True,
        admin_note="经排查确认内部泄密",
        src_ip="192.168.1.100", dst_ip="203.0.113.42",
        src_port=49152, dst_port=8443,
        department="财务部", protocol="TCP",
        flow_features={"entropy": 7.95, "byte_count": 8_000_000},
    )
    _ok("Tier 0: 反馈案例写入 SQLite")

    # Tier 1: 模式卡片索引查询
    index = get_index()
    features = {"department": "财务部", "protocol": "TCP",
                "direction": "outbound", "encryption": True}
    matching = index.query(features, min_match=0.3)
    _ok(f"Tier 1: 模式卡片查询 -> {len(matching)} 个匹配")

    context = index.format_context(features)
    _info(f"Tier 1 上下文: {'无匹配' if not context else f'{len(context)} 字符'}")

    # 创建模式卡片
    card = PatternCard(
        card_id="test_card_001", title="测试: 财务部外传模式",
        feature_signature=features, status=CardStatus.ACTIVE,
    )
    formatted = format_cards_for_prompt([card])
    _ok(f"Tier 1: 卡片创建 + 格式化 ({len(formatted)} 字符)")

    # Tier 2: 战略原则
    principles = load_approved_principles()
    ctx = apply_principles_to_context(principles)
    _ok(f"Tier 2: 已审批原则 {len(principles)} 条"
        + (f" -> {len(ctx)} 字符上下文" if ctx else " (暂无)"))

    _ok("测试 5 完成")


# ═══════════════════════════════════════════════════════════════
# 测试 6: LM Studio 模型管理（可选）
# ═══════════════════════════════════════════════════════════════

def _detect_lmstudio(api_base: str = "http://localhost:1234/v1") -> bool:
    """检测 LM Studio 是否在本地运行。"""
    try:
        import urllib.request
        url = api_base.rstrip("/") + "/models"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 200
    except Exception:
        return False


def test_lmstudio(config: OrchestratorConfig):
    """LM Studio 模型管理功能测试。"""
    _h("测试 6: LM Studio 模型管理")

    lm_cfg = config.default_backends.get(BackendType.LMSTUDIO)
    if lm_cfg is None:
        _warn("LM Studio 后端未在配置中注册，跳过")
        return

    api_base = lm_cfg.api_base or "http://localhost:1234/v1"
    _info(f"API 地址: {api_base}")

    if not _detect_lmstudio(api_base):
        _warn(f"无法连接到 LM Studio ({api_base})，跳过测试")
        _info("请确认 LM Studio 已启动并启用本地 API 服务")
        return

    _ok("LM Studio 连接成功")

    from multi_agent_system.backends import LMStudioBackend
    from multi_agent_system.backends.base import LoadModelConfig

    backend = LMStudioBackend(
        api_base=api_base,
        api_key=lm_cfg.api_key or "lm-studio",
        timeout=lm_cfg.timeout or 30.0,
        max_retries=lm_cfg.max_retries or 2,
        default_model=lm_cfg.model_name or "",
        auto_load=lm_cfg.auto_load,
    )

    # 列出模型
    try:
        all_models = backend.list_models()
        _ok(f"可用模型: {len(all_models)} 个")
        for m in all_models[:5]:
            status_icon = "[loaded]" if m.status == "loaded" else "[ready] "
            _info(f"  {status_icon} {m.model_id} (type={m.type})")
        if len(all_models) > 5:
            _info(f"  ... 共 {len(all_models)} 个")
    except Exception as e:
        _warn(f"列出模型失败: {e}")
        all_models = []

    # 已加载模型
    try:
        loaded = backend.list_loaded_models()
        _ok(f"已加载模型: {len(loaded)} 个")
        for m in loaded:
            _info(f"  {m.model_id} | instance={m.instance_id} | "
                  f"load_time={m.load_time_seconds:.1f}s")
    except Exception as e:
        _warn(f"查询已加载模型失败: {e}")

    # 模型加载/卸载（仅在 safe 模式下演示）
    if all_models:
        target = all_models[0].model_id
        try:
            if not backend.is_model_loaded(target):
                _info(f"加载模型: {target} ...")
                result = backend.load_model(LoadModelConfig(model=target))
                _ok(f"加载完成: {result.model_id} ({result.load_time_seconds:.1f}s)")
            else:
                _info(f"模型已就绪: {target}")
        except Exception as e:
            _warn(f"模型加载演示跳过: {e}")

    _info(f"auto_load: {backend.auto_load}")

    _ok("测试 6 完成")


# ═══════════════════════════════════════════════════════════════
# 测试 7: 系统整体状态
# ═══════════════════════════════════════════════════════════════

def test_status(config: OrchestratorConfig):
    """打印系统配置摘要。"""
    _h("测试 7: 系统状态摘要")

    _info(f"DeepSeek: {'已配置' if _check_backend_available(config, BackendType.DEEPSEEK) else '未配置'}")
    _info(f"OpenAI:   {'已配置' if _check_backend_available(config, BackendType.OPENAI) else '未配置'}")
    _info(f"LMStudio: {'已注册' if BackendType.LMSTUDIO in config.default_backends else '未注册'}")

    _info(f"L1-筛查: {config.screening.backend.value}/{config.screening.model_name}")
    _info(f"L2-回溯: {config.backtrack.backend.value}/{config.backtrack.model_name}")
    _info(f"L3-研判: {config.adjudication.backend.value}/{config.adjudication.model_name}")
    _info(f"反馈:   {config.feedback.backend.value}/{config.feedback.model_name}")

    _info(f"回溯配置: 初始窗口={config.backtrack.initial_lookback_hours}h, "
          f"最大次数={config.backtrack.max_backtrack_count}, "
          f"扩展倍数={config.backtrack.lookback_multiplier}x")
    _info(f"实时扫描: {'启用' if config.live_scan.enabled else '禁用'} "
          f"(间隔={config.live_scan.scan_interval_seconds}s)")

    _ok("测试 7 完成")


# ═══════════════════════════════════════════════════════════════
# 主入口
# ═══════════════════════════════════════════════════════════════

def _parse_args():
    p = argparse.ArgumentParser(description="多智能体系统（三层架构）全真模拟测试")
    p.add_argument("modules", nargs="*", default=None,
                   help="指定测试编号 (1-7)，不指定则运行全部")
    p.add_argument("--lmstudio", action="store_true",
                   help="启用 LM Studio 模型管理测试")
    p.add_argument("--lmstudio-host", default="http://localhost:1234/v1",
                   help="LM Studio API 地址 (默认 http://localhost:1234/v1)")
    return p.parse_args()


async def main():
    args = _parse_args()
    config = load_test_config()

    # 如果指定了 lmstudio host，更新配置
    if args.lmstudio_host != "http://localhost:1234/v1":
        lm_cfg = config.default_backends.get(BackendType.LMSTUDIO)
        if lm_cfg:
            lm_cfg.api_base = args.lmstudio_host

    # 自动检测 LM Studio
    _lm_cfg = config.default_backends.get(BackendType.LMSTUDIO)
    _lm_base = _lm_cfg.api_base if _lm_cfg else "http://localhost:1234/v1"
    lmstudio_enabled = args.lmstudio or _detect_lmstudio(_lm_base)

    all_tests = [
        ("1", "三层分析管线", lambda: test_pipeline(config)),
        ("2", "管理员反馈 + 记忆系统", lambda: test_feedback(config)),
        ("3", "三层智能体独立验证", lambda: test_agents_standalone(config)),
        ("4", "LiveScanOrchestrator 调度", lambda: test_live_scan(config)),
        ("5", "记忆系统", lambda: test_memory()),
        ("6", "LM Studio 模型管理", lambda: test_lmstudio(config)),
        ("7", "系统状态摘要", lambda: test_status(config)),
    ]

    # 确定要运行的测试
    if args.modules:
        selected = []
        for m in args.modules:
            for tid, tname, _fn in all_tests:
                if tid == m:
                    selected.append((tid, tname, _fn))
                    break
            else:
                print(f"未知模块: {m}，可选: {[t[0] for t in all_tests]}")
        if not selected:
            return
    else:
        selected = all_tests

    # 如果 LM Studio 未启用，跳过测试 6
    if not lmstudio_enabled:
        selected = [t for t in selected if t[0] != "6"]
        if not args.modules or "6" in args.modules:
            _info("LM Studio 未检测到或未通过 --lmstudio 启用，测试 6 跳过")
            _info("使用 --lmstudio 参数强制启用")

    print(f"\n{'=' * 64}")
    print(f"  多智能体系统（三层架构）—— 全真模拟测试")
    print(f"{'=' * 64}")
    print(f"  时间: {datetime.now(timezone.utc).isoformat()}")
    print(f"  后端: DeepSeek {'已配置' if _check_backend_available(config, BackendType.DEEPSEEK) else '未配置'} | "
          f"LMStudio {'已启用' if lmstudio_enabled else '未启用'}")

    passed = 0
    failed = 0
    for tid, tname, fn in selected:
        try:
            result = fn()
            if asyncio.iscoroutine(result):
                await result
            passed += 1
        except Exception as e:
            failed += 1
            print(f"\n  [FAIL] 测试 {tid} ({tname}) 异常: {e}")
            import traceback
            traceback.print_exc()

    print(f"\n{'=' * 64}")
    print(f"  完成: {passed} 通过, {failed} 失败 (共 {passed + failed} 项)")
    print(f"{'=' * 64}")


if __name__ == "__main__":
    asyncio.run(main())
