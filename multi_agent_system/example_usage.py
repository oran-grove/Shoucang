"""
多智能体分析系统（慢脑）—— 全真模拟测试
========================================

在全真环境下测试多智能体模块的全部功能：
  - 实时分析管线（Detection -> Correlation -> Judgment -> Feedback）
  - 深度分析子模块（BaselineProfiling + TemporalAnomaly + DeepAnalysis）
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
    DetectionAgent, CorrelationAgent, JudgmentAgent, FeedbackAgent,
    AdminFeedback,
)
from multi_agent_system.agents.baseline_profiling_agent import (
    BaselineProfilingAgent, BehaviorBaseline,
)
from multi_agent_system.agents.temporal_anomaly_agent import TemporalAnomalyAgent
from multi_agent_system.orchestrators.deep_analysis_orchestrator import (
    DeepAnalysisOrchestrator,
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
    """构造实时管线测试用流量。"""
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


def build_historical_flows(entity_id: str = "user_zhangsan") -> list[FlowEvent]:
    """构造 90 天历史流量，模拟长周期低频率泄密模式。

    前 60 天：正常办公基线（工作日 09:00-18:00）
    后 30 天：混入隐蔽泄密（每 3 天凌晨 2 点传输 2-5MB，渐进递增）
    """
    now = datetime.now(timezone.utc)
    flows: list[FlowEvent] = []
    normal_ips = ["142.250.80.46", "93.184.216.34", "151.101.1.140"]
    exfil_ips = ["203.0.113.42", "198.51.100.77", "45.33.32.156"]

    for day_offset in range(90, 0, -1):
        day = now - timedelta(days=day_offset)
        if day.weekday() < 5:
            for hour in [9, 10, 11, 14, 15, 16, 17]:
                flows.append(FlowEvent(
                    timestamp=day.replace(hour=hour, minute=0, second=0),
                    src_ip="192.168.1.50", dst_ip=normal_ips[hour % 3],
                    src_port=50000 + hour, dst_port=443,
                    protocol="TCP", app_protocol="TLS",
                    pkt_count=60, byte_count=30000, duration_seconds=5.0,
                    avg_pkt_size=500, entropy_score=5.5,
                    user_id=entity_id, department="研发部",
                ))
        if day_offset <= 30:
            if day_offset % 3 == 0:
                size = 2_000_000 + (30 - day_offset) * 100_000
                flows.append(FlowEvent(
                    timestamp=day.replace(hour=2, minute=15, second=0),
                    src_ip="192.168.1.50", dst_ip=exfil_ips[day_offset % 3],
                    src_port=49152 + (day_offset % 10), dst_port=8443,
                    protocol="TCP", app_protocol="TLS",
                    pkt_count=int(size / 1400), byte_count=size,
                    duration_seconds=20.0, avg_pkt_size=1400, entropy_score=7.85,
                    user_id=entity_id, department="研发部",
                ))
            if day_offset % 2 == 0:
                flows.append(FlowEvent(
                    timestamp=day.replace(hour=23, minute=45, second=0),
                    src_ip="192.168.1.50", dst_ip="8.8.8.8",
                    src_port=30000 + (day_offset % 100), dst_port=53,
                    protocol="UDP", app_protocol="DNS",
                    pkt_count=3, byte_count=600, duration_seconds=1.0,
                    avg_pkt_size=200, entropy_score=6.1,
                    dns_query=f"data-{day_offset}.sync.exfil.example.com",
                    user_id=entity_id, department="研发部",
                ))
    return flows


# ═══════════════════════════════════════════════════════════════
# 测试 1: 实时分析管线（全真 API 调用）
# ═══════════════════════════════════════════════════════════════

async def test_pipeline(config: OrchestratorConfig):
    """全真测试 Detection -> Correlation -> Judgment 管线。

    使用 config_user.json 中的 DeepSeek API Key 进行真实 LLM 分析。
    """
    _h("测试 1: 实时分析管线 (Detection -> Correlation -> Judgment)")

    ds_ok = _check_backend_available(config, BackendType.DEEPSEEK)
    if not ds_ok:
        _warn("DeepSeek API Key 未配置或无效，跳过全真测试")
        _info("请在 config_user.json 的 backends.deepseek.api_key 中填入有效密钥")
        return

    _info(f"后端: DeepSeek/{config.default_backends[BackendType.DEEPSEEK].model_name}")

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
            verdict_icon = {"malicious": "!!", "suspicious": " ?", "safe": "  ", "unknown": ".."}.get(
                verdict.verdict.value, "??")
            _ok(f"[{verdict_icon}] {verdict.verdict.value.upper()} | "
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
    """测试管理员反馈闭环 + 记忆系统自适应学习。

    使用真实 LLM 增强分析反馈模式。
    """
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
# 测试 3: 深度分析子模块
# ═══════════════════════════════════════════════════════════════

async def test_deep_analysis(config: OrchestratorConfig):
    """测试深度分析：基线画像 + 时序异常检测 + 综合研判。

    基线画像使用纯统计方法（不依赖 LLM），可完全验证。
    时序异常先做统计预分析，如有可用后端则调用 LLM 进行模式解释。
    """
    _h("测试 3: 深度分析 (Baseline + Temporal + Judgment)")

    historical = build_historical_flows("user_zhangsan")
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    baseline_flows = [f for f in historical if f.timestamp < cutoff]
    recent_flows = [f for f in historical if f.timestamp >= cutoff]
    _info(f"历史数据: {len(historical)} 条 (基线窗口={len(baseline_flows)}, 近期={len(recent_flows)})")

    # -- 3a. 基线画像 --
    _sh("3a. 基线画像构建 (纯统计)")
    baseline_agent = BaselineProfilingAgent()
    baseline = baseline_agent.build_or_update_baseline(
        entity_id="user_zhangsan", entity_type="user",
        historical_flows=baseline_flows,
    )
    _ok(f"基线: entity={baseline.entity_id}, samples={baseline.sample_count}")
    _info(f"日均流量: {baseline.avg_flows_per_day:.1f} 次/天")
    _info(f"时均字节: {baseline.avg_bytes_per_hour / 1024:.1f} KB/h")
    _info(f"非工作时段占比: {baseline.off_hours_ratio:.1%}")
    _info(f"协议分布: {baseline.protocol_distribution}")

    # 基线偏离评估
    deviations = 0
    for flow in recent_flows[:20]:
        result = baseline_agent.evaluate_flow(flow, baseline)
        if result.verdict == TrafficVerdict.SUSPICIOUS:
            deviations += 1
    _ok(f"偏离评估: {deviations}/{min(20, len(recent_flows))} 条偏离基线")
    if deviations > 0:
        _info("凌晨泄密流量被基线偏离度正确捕获")

    # -- 3b. 时序异常 --
    _sh("3b. 时序异常检测")
    temporal_agent = TemporalAnomalyAgent()

    # 注入后端
    if _check_backend_available(config, BackendType.DEEPSEEK):
        ds_cfg = config.default_backends[BackendType.DEEPSEEK]
        from multi_agent_system.backends import DeepSeekBackend
        temporal_agent.set_backend(DeepSeekBackend(
            api_base=ds_cfg.api_base, api_key=ds_cfg.api_key,
            timeout=ds_cfg.timeout, max_retries=ds_cfg.max_retries,
            default_model=ds_cfg.model_name,
        ))
        temporal_agent.model_name = ds_cfg.model_name

    # 统计预分析（不依赖 LLM）
    slices = temporal_agent.slice_time_series(recent_flows, window_days=30)
    _info(f"时序切片: {len(slices)} 片 (每片 {temporal_agent.slice_size_hours}h)")
    active = [s for s in slices if s.total_bytes > 0]
    _info(f"活跃切片: {len(active)}/{len(slices)}")

    has_period, period_conf, period_desc = temporal_agent.detect_periodicity(slices)
    _ok(f"周期检测: {period_desc}")

    trend_dir, trend_conf, trend_desc = temporal_agent.detect_trend(slices)
    _ok(f"趋势检测: {trend_desc}")

    # LLM 全真分析
    if _check_backend_available(config, BackendType.DEEPSEEK):
        _info("调用 DeepSeek API 进行时序模式解释...")
        try:
            temporal_result = await temporal_agent.analyze(
                entity_id="user_zhangsan",
                historical_flows=recent_flows,
                window_days=30,
            )
            _ok(f"LLM 时序分析: verdict={temporal_result.verdict.value} | "
                f"confidence={temporal_result.confidence:.0%}")
            _info(f"威胁类型: {temporal_result.threat_type}")
            if temporal_result.reasoning:
                _info(f"推理: {temporal_result.reasoning[:250]}")
        except Exception as e:
            _warn(f"LLM 时序分析失败: {e}")

    # -- 3c. DeepAnalysisOrchestrator 组装 --
    _sh("3c. 综合研判编排")
    jcfg = config.judgment
    judgment_agent = JudgmentAgent(
        name="SlowJudgmentAgent",
        system_prompt=jcfg.system_prompt, model_name=jcfg.model_name,
        temperature=jcfg.temperature, max_tokens=jcfg.max_tokens,
    )
    if _check_backend_available(config, BackendType.DEEPSEEK):
        ds_cfg = config.default_backends[BackendType.DEEPSEEK]
        from multi_agent_system.backends import DeepSeekBackend
        judgment_agent.set_backend(DeepSeekBackend(
            api_base=ds_cfg.api_base, api_key=ds_cfg.api_key,
            timeout=ds_cfg.timeout, max_retries=ds_cfg.max_retries,
            default_model=ds_cfg.model_name,
        ))
        judgment_agent.model_name = ds_cfg.model_name

    da = DeepAnalysisOrchestrator(
        baseline_agent=baseline_agent, temporal_agent=temporal_agent,
        judgment_agent=judgment_agent,
        analysis_interval_hours=config.deep_analysis.analysis_interval_hours,
    )

    # 批量分析
    entity_flows = {"user_zhangsan": ("user", baseline_flows)}
    recent_map = {"user_zhangsan": recent_flows}
    alerts = await da.batch_analyze(entity_flows, recent_map)
    _ok(f"批量分析完成: {len(alerts)} 条告警")
    for i, alert in enumerate(alerts):
        _info(f"告警 #{i+1}: {alert.verdict.value}/{alert.severity.value} "
              f"({alert.confidence:.0%}) — {alert.threat_type}")

    stats = da.get_statistics()
    _info(f"基线跟踪: {stats['baselines_tracked']} 个实体 | "
          f"近期告警: {stats['total_recent_alerts']}")

    _ok("测试 3 完成")


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
    _info(f"回溯配置: lookback={config.retrospective_scan.lookback_days}d, "
          f"entities_per_cycle={config.retrospective_scan.entities_per_cycle}")

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
    """LM Studio 模型管理功能测试。

    需要本地运行 LM Studio (>=0.3.x) 并启用 API 服务。
    通过 --lmstudio 参数或自动检测启用。
    """
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

    # 自动加载开关
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

    _info(f"检测智能体: {config.detection.backend.value}/{config.detection.model_name}")
    _info(f"关联智能体: {config.correlation.backend.value}/{config.correlation.model_name}")
    _info(f"研判智能体: {config.judgment.backend.value}/{config.judgment.model_name}")
    _info(f"反馈智能体: {config.feedback.backend.value}/{config.feedback.model_name}")
    _info(f"深度分析周期: {config.deep_analysis.analysis_interval_hours}h")
    _info(f"实时扫描: {'启用' if config.live_scan.enabled else '禁用'} "
          f"(间隔={config.live_scan.scan_interval_seconds}s)")
    _info(f"回溯扫描: lookback={config.retrospective_scan.lookback_days}d")

    _ok("测试 7 完成")


# ═══════════════════════════════════════════════════════════════
# 主入口
# ═══════════════════════════════════════════════════════════════

def _parse_args():
    p = argparse.ArgumentParser(description="多智能体系统（慢脑）全真模拟测试")
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
        ("1", "实时分析管线", lambda: test_pipeline(config)),
        ("2", "管理员反馈 + 记忆系统", lambda: test_feedback(config)),
        ("3", "深度分析 (Baseline+Temporal+Judgment)", lambda: test_deep_analysis(config)),
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
    print(f"  多智能体系统（慢脑）—— 全真模拟测试")
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
