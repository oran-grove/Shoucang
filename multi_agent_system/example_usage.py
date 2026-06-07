"""
多智能体分析系统 — 主程序调用示例
======================================
演示 MultiAgentSystem 的完整使用流程，包括：
- 创建系统并配置后端
- 模拟流量事件分析
- 管理员反馈闭环
- 获取 P4 交换机规则
- 深度分析子模块（基线画像 + 时序异常）

运行前请确保：
1. LM Studio 已运行于 http://localhost:1234
   或 OpenAI API Key 已配置
2. pip install httpx
"""

import asyncio
import logging
import time
from datetime import datetime, timezone, timedelta

from multi_agent_system import (
    MultiAgentSystem,
    FlowEvent,
    ThreatVerdict,
    TrafficVerdict,
    SeverityLevel,
    BackendType,
    ModelInfo,
    LoadModelConfig,
)
from config.loader import load_config, save_config, quick_all_local, quick_all_deepseek

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


# ============================================================
# 示例数据构建 — 实时单流检测
# ============================================================

def build_sample_flows() -> list[FlowEvent]:
    """构造示例流量事件"""
    now = datetime.now(timezone.utc)
    return [
        # 1. 正常 HTTPS 浏览
        FlowEvent(
            timestamp=now,
            src_ip="192.168.1.50", dst_ip="142.250.80.46",
            src_port=52341, dst_port=443,
            protocol="TCP", app_protocol="TLS",
            pkt_count=80, byte_count=45000, duration_seconds=12.0,
            avg_pkt_size=562, entropy_score=7.8,
            tls_sni="www.google.com",
            ja4_fingerprint="t13d1516h2_8daaf6153d75",
        ),
        # 2. 疑似数据泄露：大量出站流量到陌生IP
        FlowEvent(
            timestamp=now,
            src_ip="192.168.1.100", dst_ip="203.0.113.42",
            src_port=49152, dst_port=8443,
            protocol="TCP", app_protocol="TLS",
            pkt_count=5000, byte_count=8_000_000, duration_seconds=45.0,
            avg_pkt_size=1600, entropy_score=7.95,
            tls_sni="data-sync.example.com",
            ja4_fingerprint="t13d1516h2_custom",
        ),
        # 3. 同一源 IP 的可疑连接（用于关联分析）
        FlowEvent(
            timestamp=now,
            src_ip="192.168.1.100", dst_ip="198.51.100.77",
            src_port=49153, dst_port=443,
            protocol="TCP", app_protocol="TLS",
            pkt_count=3000, byte_count=4_500_000, duration_seconds=32.0,
            avg_pkt_size=1500, entropy_score=7.90,
            tls_sni="api.suspicious-server.biz",
        ),
        # 4. DNS 隧道嫌疑
        FlowEvent(
            timestamp=now,
            src_ip="192.168.1.100", dst_ip="8.8.8.8",
            src_port=30221, dst_port=53,
            protocol="UDP", app_protocol="DNS",
            pkt_count=200, byte_count=120_000, duration_seconds=60.0,
            avg_pkt_size=600, entropy_score=6.5,
            dns_query="SLGVsbG9Xb3JsZAo.base64.evil-dns-tunnel.com",
        ),
        # 5. 正常 HTTP 访问
        FlowEvent(
            timestamp=now,
            src_ip="192.168.1.50", dst_ip="93.184.216.34",
            src_port=45678, dst_port=80,
            protocol="TCP", app_protocol="HTTP",
            pkt_count=30, byte_count=15000, duration_seconds=5.0,
            avg_pkt_size=500, entropy_score=5.2,
        ),
    ]


# ============================================================
# 示例数据构建 — 深度分析（长期历史日志）
# ============================================================

def build_historical_flows(entity_id: str = "user_zhangsan") -> list[FlowEvent]:
    """
    构造90天历史流量数据，模拟长周期低频率泄密模式。

    策略：
    - 前60天为正常行为基线（工作日朝九晚五模式）
    - 第61-90天混入隐蔽泄密模式：每3天凌晨2点传输2-5MB到境外IP
    - 同时在正常工作时间出现一些渐进递增的小量传输
    """
    now = datetime.now(timezone.utc)
    flows: list[FlowEvent] = []

    normal_dst_ips = ["142.250.80.46", "93.184.216.34", "151.101.1.140"]
    exfil_ips = ["203.0.113.42", "198.51.100.77", "45.33.32.156"]

    for day_offset in range(90, 0, -1):
        day = now - timedelta(days=day_offset)

        # ---------- 第一阶段：正常行为基线 (day_offset 90..31) ----------
        if day_offset > 30:
            # 工作日：08:00-18:00 正常办公流量
            if day.weekday() < 5:  # Mon-Fri
                for hour in [9, 10, 11, 14, 15, 16, 17]:
                    ts = day.replace(hour=hour, minute=0, second=0)
                    flows.append(FlowEvent(
                        timestamp=ts,
                        src_ip="192.168.1.50",
                        dst_ip=normal_dst_ips[hour % 3],
                        src_port=50000 + hour,
                        dst_port=443,
                        protocol="TCP",
                        app_protocol="TLS",
                        pkt_count=60,
                        byte_count=30000,
                        duration_seconds=5.0,
                        avg_pkt_size=500,
                        entropy_score=5.5,
                        user_id=entity_id,
                        department="研发部",
                    ))
            continue

        # ---------- 第二阶段：混入隐蔽泄密 (day_offset 30..1) ----------
        # 正常办公行为照常
        if day.weekday() < 5:
            for hour in [9, 10, 11, 14, 15, 16, 17]:
                ts = day.replace(hour=hour, minute=0, second=0)
                flows.append(FlowEvent(
                    timestamp=ts,
                    src_ip="192.168.1.50",
                    dst_ip=normal_dst_ips[hour % 3],
                    src_port=50000 + hour,
                    dst_port=443,
                    protocol="TCP",
                    app_protocol="TLS",
                    pkt_count=60,
                    byte_count=30000,
                    duration_seconds=5.0,
                    avg_pkt_size=500,
                    entropy_score=5.5,
                    user_id=entity_id,
                    department="研发部",
                ))

        # 每3天一次低频泄密（凌晨2点，2-5MB）
        if day_offset % 3 == 0:
            exfil_size = 2_000_000 + (30 - day_offset) * 100_000  # 渐进递增
            ts = day.replace(hour=2, minute=15, second=0)
            flows.append(FlowEvent(
                timestamp=ts,
                src_ip="192.168.1.50",
                dst_ip=exfil_ips[day_offset % 3],
                src_port=49152 + (day_offset % 10),
                dst_port=8443,
                protocol="TCP",
                app_protocol="TLS",
                pkt_count=int(exfil_size / 1400),
                byte_count=exfil_size,
                duration_seconds=20.0,
                avg_pkt_size=1400,
                entropy_score=7.85,
                user_id=entity_id,
                department="研发部",
            ))

        # 每天几次低频DNS查询到可疑域名
        if day_offset % 2 == 0:
            ts = day.replace(hour=23, minute=45, second=0)
            flows.append(FlowEvent(
                timestamp=ts,
                src_ip="192.168.1.50",
                dst_ip="8.8.8.8",
                src_port=30000 + (day_offset % 100),
                dst_port=53,
                protocol="UDP",
                app_protocol="DNS",
                pkt_count=3,
                byte_count=600,
                duration_seconds=1.0,
                avg_pkt_size=200,
                entropy_score=6.1,
                dns_query=f"data-{day_offset}.sync.exfil.example.com",
                user_id=entity_id,
                department="研发部",
            ))

    return flows


# ============================================================
# 多智能体系统演示 — LM Studio 模型管理
# ============================================================

async def lmstudio_management_example():
    """
    演示 LM Studio 模型管理功能（智能加载、列表、卸载等）。

    运行前提：
        LM Studio 已在本地运行并启用 API (http://localhost:1234)。
        新版本 LM Studio (>=0.3.x) 支持管理 API 端口 1234。

    推荐用法：
        通过 load_config("config_user.json") 加载配置，
        无需在代码中手动 add_lmstudio_backend()。
    """
    print("=" * 60)
    print("LM Studio 模型管理功能演示")
    print("=" * 60)

    # ---- 推荐：从 JSON 配置文件加载 ----
    config = load_config("config_user.json")
    # 确保后端配置指向本地 LM Studio
    lm_cfg = config.default_backends[BackendType.LMSTUDIO]
    lm_cfg.api_base = "http://localhost:1234/v1"
    lm_cfg.model_name = "qwen3.5-9b"
    lm_cfg.auto_load = True
    lm_cfg.load_config = {
        "context_length": 16384,
        "flash_attention": True,
        "eval_batch_size": 512,
    }

    system = MultiAgentSystem(config)
    await system.start()

    try:
        # ---- 1. 列出所有可用模型 ----
        print("\n📋 列出 LM Studio 中所有可用模型:")
        all_models = system.list_lm_models()
        if all_models:
            for m in all_models:
                status_icon = "✅" if m.status == "loaded" else "⏳"
                ctx_info = f"上下文长度: {m.context_length}" if m.context_length else ""
                print(f"  {status_icon} {m.model_id} ({m.type}) {ctx_info}")
        else:
            print("  (未发现模型 — 请确认 LM Studio 正在运行)")

        # ---- 2. 查看已加载模型 ----
        print("\n🔍 当前已加载模型:")
        loaded = system.get_lm_loaded_models()
        if loaded:
            for m in loaded:
                print(f"  ✅ instance_id={m.instance_id} | {m.model_id} | 加载耗时: {m.load_time_seconds:.1f}s")
        else:
            print("  (无已加载模型)")

        # ---- 3. 加载指定模型 ----
        print("\n🚀 尝试加载模型 'qwen3.5-9b' (已加载则跳过):")
        # 先检查是否已在 LM Studio 中手动加载
        if system.is_lm_model_loaded("qwen3.5-9b"):
            print("  ✅ 模型已就绪，无需加载")
        else:
            # 通过管理 API 加载
            print("  ⏳ 模型未加载，正在通过 POST /api/v1/models/load 加载...")
            try:
                result = system.load_lm_model(
                    model="qwen3.5-9b",
                    context_length=16384,
                    flash_attention=True,
                    echo_load_config=True,
                )
                print(f"  ✅ 加载成功！耗时 {result.load_time_seconds:.1f}s")
                print(f"     instance_id={result.instance_id}")
                if result.context_length:
                    print(f"     context_length={result.context_length}")
            except Exception as e:
                print(f"  ⚠ 加载失败: {e}")
                print(f"     提示：如果模型已在 LM Studio GUI 中加载，请忽略此错误")

        # ---- 4. 获取后端运行信息 ----
        print("\n📊 LM Studio 后端状态:")
        info = system.get_lm_backend_info()
        for k, v in info.items():
            if k == "loaded_models":
                print(f"  {k}: {len(v)} 个已加载")
            else:
                print(f"  {k}: {v}")

        # ---- 5. 刷新模型列表缓存 ----
        print("\n🔄 刷新已加载模型缓存:")
        updated = system.refresh_lm_models()
        print(f"  当前已加载: {[m.model_id for m in updated]}")

        # ---- 6. 自动加载开关 ----
        print("\n⚙️ 模型自动加载控制:")
        print(f"  当前状态: {'🟢 已启用' if system.get_lm_backend_info().get('auto_load') else '🔴 已禁用'}")
        print("  可通过 system.set_lm_auto_load(False) 禁用自动加载，")
        print("  禁用后需手动调用 system.load_lm_model() 加载模型。")

    except Exception as e:
        print(f"\n❌ 错误: {e}")

    finally:
        await system.stop()

    print("\n✅ LM Studio 管理演示完成\n")


# ============================================================
# 多智能体系统演示 — DeepSeek 后端
# ============================================================

async def deepseek_example():
    """
    演示 DeepSeek API 后端用法。

    运行前提：
        设置环境变量 DEEPSEEK_API_KEY 或在代码中直接替换。

    API 密钥、模型名、超时等参数均从 config_user.json 读取，
    无需在代码中硬编码。
    """
    import os

    config = load_config("config_user.json")
    ds_cfg = config.default_backends[BackendType.DEEPSEEK]

    print("=" * 60)
    print("DeepSeek API 后端演示")
    print("=" * 60)

    system = MultiAgentSystem()

    # 添加 DeepSeek 后端（参数全部来自配置文件）
    system.add_deepseek_backend(
        api_key=ds_cfg.api_key,
        api_base=ds_cfg.api_base,
        model_name=ds_cfg.model_name,
        timeout=ds_cfg.timeout,
        max_retries=ds_cfg.max_retries,
    )

    # 设置所有智能体使用 DeepSeek
    system.set_detection_backend(BackendType.DEEPSEEK)
    system.set_correlation_backend(BackendType.DEEPSEEK)
    system.set_judgment_backend(BackendType.DEEPSEEK)
    system.set_feedback_backend(BackendType.DEEPSEEK)

    print(f"后端配置完成，模型: {ds_cfg.model_name}")
    print(f"API 地址: {ds_cfg.api_base}")
    print()

    # 可选：演示推理模型
    api_key_set = ds_cfg.api_key and ds_cfg.api_key not in ("sk-your-deepseek-key", "")
    if api_key_set:
        print("💡 提示：如需使用推理模型 (deepseek-v4-pro)，")
        print("   调用 add_deepseek_backend() 并设置 model_name='deepseek-v4-pro'")
        print("   V4 推理模型支持 thinking_enabled=True/False 控制思考模式")
        print("   以及 reasoning_effort 参数: 'high' 或 'max'")
        print("   可通过 include_reasoning=True 查看模型思考过程")
    else:
        print("⚠ 未设置有效的 DEEPSEEK_API_KEY，跳过实际调用。")
        print("  请在 config_user.json 中配置，或设置环境变量 DEEPSEEK_API_KEY 后重试。")

    print("\n✅ DeepSeek 后端演示完成\n")


# ============================================================
# 多智能体系统演示 — 异步分析流程
# ============================================================

async def async_example():
    """异步使用示例"""
    print("=" * 60)
    print("多智能体分析系统 — 异步示例")
    print("=" * 60)

    # 1. 创建系统 — 使用 DeepSeek API 配置
    config = load_config("config_user.json")
    system = MultiAgentSystem(config)

    # 2. 所有智能体使用默认的 DeepSeek API（由 config_user.json 配置）

    # 4. 启动系统
    await system.start()
    print(f"系统已启动 — 统计: {system.get_statistics()}")

    # 5. 分析流量
    flows = build_sample_flows()
    for i, flow in enumerate(flows, 1):
        print(f"\n{'─' * 40}")
        print(f"分析流量 #{i}: {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} [{flow.app_protocol}]")
        print(f"  SNI: {flow.tls_sni or 'N/A'}  |  DNS: {flow.dns_query or 'N/A'}")

        try:
            verdict = await system.analyze(flow)
            print(f"  判定: {verdict.verdict.value.upper()} | "
                  f"严重度: {verdict.severity.value} | "
                  f"置信度: {verdict.confidence:.2%}")
            print(f"  威胁类型: {verdict.threat_type}")
            print(f"  建议动作: {verdict.recommended_action}")
            if verdict.reasoning:
                print(f"  理由: {verdict.reasoning[:200]}")
        except Exception as e:
            print(f"  ⚠ 分析失败: {e}")

    # 6. 模拟管理员反馈
    print(f"\n{'─' * 40}")
    print("管理员反馈: 标记误报")
    fb_result = await system.feedback(
        feedback_type="false_positive",
        src_ip="192.168.1.100",
        admin_note="这是内部测试服务器的流量，不是恶意行为",
    )
    print(f"  反馈结果: {fb_result}")

    print(f"\n管理员反馈: 确认恶意")
    fb_result = await system.feedback(
        feedback_type="confirm_malicious",
        src_ip="10.99.0.13",
        admin_note="确认此前标记的可疑IP为已知APT组织C2",
    )
    print(f"  反馈结果: {fb_result}")

    # 7. 获取 P4 同步规则
    print(f"\n{'─' * 40}")
    print("P4 交换机规则同步列表:")
    rules = system.get_p4_rules(max_rules=20)
    for rule in rules:
        print(f"  规则 {rule['rule_id']}: {rule['src_ip'] or '*'} -> {rule['dst_ip'] or '*'} "
              f"| 动作: {rule['action']} | 置信度: {rule['confidence']:.2f}")
    if not rules:
        print("  (暂无高置信度规则)")

    # 8. 统计
    print(f"\n{'─' * 40}")
    print("系统统计:")
    stats = system.get_statistics()
    for k, v in stats.items():
        print(f"  {k}: {v}")

    # 9. 停止系统
    await system.stop()
    print("\n系统已停止")


# ============================================================
# 多智能体系统演示 — 同步流程
# ============================================================

async def _sync_example_impl():
    """同步示例的内部异步实现（可在任意上下文中被调用）"""
    config = load_config("config_user.json")
    system = MultiAgentSystem(config)
    try:
        await system.start()
        flow = FlowEvent(
            src_ip="192.168.1.200",
            dst_ip="45.33.32.156",
            src_port=55555,
            dst_port=4444,
            protocol="TCP",
            app_protocol="unknown",
            byte_count=10_000_000,
            entropy_score=7.95,
        )
        try:
            verdict = await system.analyze(flow)
            print(f"判定: {verdict.verdict.value} | 建议: {verdict.recommended_action}")
        except Exception as e:
            print(f"分析失败: {e}")
        p4_rules = system.get_p4_rules()
        print(f"P4 规则数: {len(p4_rules)}")
    finally:
        await system.stop()


def sync_example():
    """同步使用示例（用于非异步环境）"""
    import asyncio

    print("=" * 60)
    print("多智能体分析系统 — 同步示例")
    print("=" * 60)

    # 检测是否在已有事件循环中运行
    try:
        loop = asyncio.get_running_loop()
        if loop.is_running():
            print("⚠ 已在异步事件循环中运行，直接 await 内部实现...")
            # 在已有循环中返回协程，由外层调用者 await
            return _sync_example_impl()
    except RuntimeError:
        pass  # 无运行中的事件循环，可以安全使用 asyncio.run

    asyncio.run(_sync_example_impl())


# ============================================================
# 深度分析演示 — 基线画像 + 时序异常检测（配置来自 config_user.json）
# ============================================================

async def deep_analysis_example():
    """
    演示深度分析子模块的完整工作流程：
    1. BaselineProfilingAgent — 构建/更新用户行为基线
    2. TemporalAnomalyAgent — 检测90天窗口内的时序异常
    3. DeepAnalysisOrchestrator — 协调分析流程并生成告警

    演示目的：
        - 展示基线画像智能体如何从历史日志中提取正常行为模式
        - 展示时序异常智能体如何发现"每3天凌晨2点低频泄密"
        - 展示深度分析编排器如何将基线偏离和时序异常合并研判

    所有智能体的提示词、模型名、后端参数均从 config_user.json 读取，
    代码中不再硬编码任何配置。
    """
    from multi_agent_system.agents.baseline_profiling_agent import BaselineProfilingAgent
    from multi_agent_system.agents.temporal_anomaly_agent import TemporalAnomalyAgent
    from multi_agent_system.agents.judgment_agent import JudgmentAgent
    from multi_agent_system.orchestrators.deep_analysis_orchestrator import DeepAnalysisOrchestrator
    from multi_agent_system.backends import (
        LMStudioBackend,
        OpenAIBackend,
        DeepSeekBackend,
    )

    print("=" * 60)
    print("深度分析子模块 — 基线画像 + 时序异常检测演示")
    print("=" * 60)

    # ============================================================
    # 步骤 1: 构造历史数据
    # ============================================================
    print("\n📊 步骤 1: 生成90天模拟历史日志...")
    print("   模式设计:")
    print("   - 第1-60天: 正常办公行为基线（工作日09:00-18:00）")
    print("   - 第61-90天: 混入隐蔽泄密（每3天凌晨2点传输2-5MB到境外）")
    print("   - 同时存在低频DNS隧道查询")

    historical_flows = build_historical_flows("user_zhangsan")
    print(f"   生成日志数: {len(historical_flows)} 条")

    # 按时间窗口划分：前60天=基线，后30天=待分析
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=30)
    baseline_flows = [f for f in historical_flows if f.timestamp < cutoff_date]
    recent_flows = [f for f in historical_flows if f.timestamp >= cutoff_date]
    print(f"   基线窗口 (前60天): {len(baseline_flows)} 条")
    print(f"   分析窗口 (后30天): {len(recent_flows)} 条")

    # ============================================================
    # 步骤 2: 从 config_user.json 加载配置，创建智能体实例
    # ============================================================
    print("\n🔧 步骤 2: 从配置文件加载深度分析子模块智能体配置...")
    _deep_cfg = load_config("config_user.json")

    # 基线画像智能体 — 配置来自 deep_analysis.baseline_profiling
    _bcfg = _deep_cfg.deep_analysis.baseline_profiling
    baseline_agent = BaselineProfilingAgent(
        name="BaselineProfilingAgent",
        system_prompt=_bcfg.system_prompt,
        model_name=_bcfg.model_name,
        temperature=_bcfg.temperature,
        max_tokens=_bcfg.max_tokens,
    )
    # 时序异常智能体 — 配置来自 deep_analysis.temporal_anomaly
    _tcfg = _deep_cfg.deep_analysis.temporal_anomaly
    temporal_agent = TemporalAnomalyAgent(
        name="TemporalAnomalyAgent",
        system_prompt=_tcfg.system_prompt,
        model_name=_tcfg.model_name,
        temperature=_tcfg.temperature,
        max_tokens=_tcfg.max_tokens,
    )
    # 研判智能体 — 配置来自 judgment（与多智能体系统共用提示词）
    _jcfg = _deep_cfg.judgment
    judgment_agent = JudgmentAgent(
        name="SlowJudgmentAgent",
        system_prompt=_jcfg.system_prompt,
        model_name=_jcfg.model_name,
        temperature=_jcfg.temperature,
        max_tokens=_jcfg.max_tokens,
    )
    print(f"   基线画像: backend={_bcfg.backend.value}, model={_bcfg.model_name}")
    print(f"   时序异常: backend={_tcfg.backend.value}, model={_tcfg.model_name}")
    print(f"   综合研判: backend={_jcfg.backend.value}, model={_jcfg.model_name}")

    # 注入后端 — 全部从 config.default_backends 读取
    print("   尝试连接后端...")
    backend_available = True
    try:
        _lm_cfg = _deep_cfg.default_backends[BackendType.LMSTUDIO]
        _ds_cfg = _deep_cfg.default_backends[BackendType.DEEPSEEK]
        _oa_cfg = _deep_cfg.default_backends[BackendType.OPENAI]

        # 基线智能体用 LM Studio
        lm_backend = LMStudioBackend(
            api_base=_lm_cfg.api_base,
            api_key=_lm_cfg.api_key,
            timeout=_lm_cfg.timeout,
            max_retries=_lm_cfg.max_retries,
            default_model=_lm_cfg.model_name,
            auto_load=_lm_cfg.auto_load,
            default_load_config=LoadModelConfig(
                context_length=_lm_cfg.load_config.get("context_length"),
                eval_batch_size=_lm_cfg.load_config.get("eval_batch_size"),
                flash_attention=_lm_cfg.load_config.get("flash_attention"),
                num_experts=_lm_cfg.load_config.get("num_experts"),
                offload_kv_cache_to_gpu=_lm_cfg.load_config.get("offload_kv_cache_to_gpu"),
                echo_load_config=_lm_cfg.load_config.get("echo_load_config", False),
            ),
        )
        baseline_agent.set_backend(lm_backend)
        baseline_agent.model_name = _lm_cfg.model_name
        print(f"   ✅ LM Studio 后端已连接 (基线画像, model={_lm_cfg.model_name})")

        def _create_backend(bt: BackendType):
            """根据配置中的后端类型创建对应后端实例"""
            if bt == BackendType.DEEPSEEK:
                return DeepSeekBackend(
                    api_base=_ds_cfg.api_base,
                    api_key=_ds_cfg.api_key,
                    timeout=_ds_cfg.timeout,
                    max_retries=_ds_cfg.max_retries,
                    default_model=_ds_cfg.model_name,
                )
            elif bt == BackendType.OPENAI:
                return OpenAIBackend(
                    api_base=_oa_cfg.api_base,
                    api_key=_oa_cfg.api_key,
                    timeout=_oa_cfg.timeout,
                    max_retries=_oa_cfg.max_retries,
                    default_model=_oa_cfg.model_name,
                )
            else:
                return lm_backend

        # 时序智能体后端
        _tbe = _create_backend(_tcfg.backend)
        if _tbe is lm_backend and _tcfg.backend != BackendType.LMSTUDIO:
            temporal_agent.model_name = _lm_cfg.model_name  # 降级时修正模型名
        temporal_agent.set_backend(_tbe)
        print(f"   ✅ 时序分析后端已连接 ({_tcfg.backend.value})")

        # 研判智能体后端
        _jbe = _create_backend(_jcfg.backend)
        if _jbe is lm_backend and _jcfg.backend != BackendType.LMSTUDIO:
            judgment_agent.model_name = _lm_cfg.model_name
        judgment_agent.set_backend(_jbe)
        print(f"   ✅ 综合研判后端已连接 ({_jcfg.backend.value})")
    except Exception as e:
        print(f"   ⚠ 后端连接失败: {e}")
        print("   ℹ️ 将使用模拟数据演示分析流程...")
        backend_available = False

    # 创建深度分析编排器
    deep_analysis = DeepAnalysisOrchestrator(
        baseline_agent=baseline_agent,
        temporal_agent=temporal_agent,
        judgment_agent=judgment_agent,
        analysis_interval_hours=_deep_cfg.deep_analysis.analysis_interval_hours,
    )
    print("   ✅ DeepAnalysisOrchestrator 初始化完成")

    # ============================================================
    # 步骤 3: 执行基线画像（纯统计，不需要 LLM）
    # ============================================================
    print("\n📈 步骤 3: 构建用户行为基线...")
    baseline = None
    try:
        baseline = deep_analysis.baseline_agent.build_or_update_baseline(
            entity_id="user_zhangsan",
            entity_type="user",
            historical_flows=baseline_flows,
        )
        print(f"   基线构建完成:")
        print(f"   - 实体: {baseline.entity_id} ({baseline.entity_type})")
        print(f"   - 样本数: {baseline.sample_count}")
        print(f"   - 日均流量: {baseline.avg_flows_per_day * (baseline.avg_bytes_per_flow or 1):.0f} 次/天")
        print(f"   - 每小时平均字节: {baseline.avg_bytes_per_hour / 1024:.1f} KB/h")
        print(f"   - 协议分布: {baseline.protocol_distribution}")
        print(f"   - 非工作时段占比: {baseline.off_hours_ratio:.1%}")
    except Exception as e:
        print(f"   ⚠ 基线构建出错: {e}")

    # ============================================================
    # 步骤 4: 时序异常检测（统计预分析，LLM 解释）
    # ============================================================
    print("\n🔍 步骤 4: 时序异常检测...")
    print("   分析窗口: 后30天")
    print("   检测目标: 周期性低频传输 / 渐进递增 / 信标心跳 / 非工作时段活动")
    try:
        temporal_result = await deep_analysis.temporal_agent.analyze(
            entity_id="user_zhangsan",
            historical_flows=recent_flows,
            window_days=30,
        )
        print(f"   时序分析结果:")
        print(f"   - 判定: {temporal_result.verdict.value}")
        print(f"   - 置信度: {temporal_result.confidence:.2%}")
        print(f"   - 威胁类型: {temporal_result.threat_type}")
        if temporal_result.reasoning:
            print(f"   - 推理: {temporal_result.reasoning[:300]}")
    except Exception as e:
        print(f"   ⚠ 时序分析出错 (可能无LLM后端): {e}")
        print("   ℹ️ 预期检测到的模式:")
        print("     ✓ 周期性低频传输: 每3天凌晨2点出现大流量")
        print("     ✓ 渐进递增: 每3天的传输量从2MB递增到5MB")
        print("     ✓ 非工作时段活动: 02:00-02:20 的高熵出站连接")
        print("     ✓ 目标轮换: 3个境外IP周期轮换")

    # ============================================================
    # 步骤 5: 基线偏离评估
    # ============================================================
    print("\n📉 步骤 5: 基线偏离评估...")
    try:
        deviation_count = 0
        for flow in recent_flows[:50]:  # 采样分析
            dev_result = deep_analysis.baseline_agent.evaluate_flow(flow, baseline)
            if dev_result.verdict == TrafficVerdict.SUSPICIOUS:
                deviation_count += 1
        print(f"   偏离事件数 (采样50条): {deviation_count}")
        print(f"   偏离率: {deviation_count / 50 * 100:.1f}%")
        if deviation_count > 0:
            print("   ⚠ 存在基线偏离 — 正常办公时间外的异常流量模式")

        # 基线变化分析
        shift_result = await deep_analysis.baseline_agent.analyze_baseline_shift(
            "user_zhangsan", recent_flows[:100]
        )
        print(f"   基线偏移判定: {shift_result.verdict.value}")
        print(f"   偏移置信度: {shift_result.confidence:.2%}")
    except Exception as e:
        print(f"   ⚠ 偏离评估出错: {e}")

    # ============================================================
    # 步骤 6: 深度分析编排器批量分析
    # ============================================================
    print("\n🧠 步骤 6: DeepAnalysisOrchestrator 综合研判...")
    print("   协调基线+时序结果 → 综合判定")
    try:
        entity_flows = {"user_zhangsan": ("user", baseline_flows)}
        recent_map = {"user_zhangsan": recent_flows}
        alerts = await deep_analysis.batch_analyze(entity_flows, recent_map)
        print(f"   生成告警数: {len(alerts)}")
        for i, alert in enumerate(alerts):
            print(f"\n   --- 告警 #{i+1} ---")
            print(f"   判定: {alert.verdict.value} | 严重度: {alert.severity.value}")
            print(f"   置信度: {alert.confidence:.2%}")
            print(f"   威胁类型: {alert.threat_type}")
            if alert.reasoning:
                print(f"   理由: {alert.reasoning[:250]}")

        # 获取高严重度告警
        high_alerts = deep_analysis.get_recent_alerts(severity_min=SeverityLevel.MEDIUM)
        print(f"\n   📊 中高危告警数: {len(high_alerts)}")

        # 获取统计
        stats = deep_analysis.get_statistics()
        print(f"\n   📊 深度分析子模块统计:")
        for k, v in stats.items():
            print(f"      {k}: {v}")

    except Exception as e:
        print(f"   ⚠ 综合研判出错 (可能无LLM后端): {e}")
        print("   ℹ️ 预期输出示例 (实际运行时需要LLM后端):")
        print("     --- 告警 #1 ---")
        print("     判定: malicious | 严重度: high")
        print("     置信度: 92.00%")
        print("     威胁类型: 长周期低频数据泄密")
        print("     理由: 综合基线偏离和时序异常检测，用户 zhangsan")
        print("           在30天内出现10次非工作时段(凌晨2点)的异常外传，")
        print("           传输量从2MB递进到5MB，形成低慢外传模式，")
        print("           已触发三层时序模式匹配：周期性低频+渐进递增+目标轮换")

    print("\n✅ 深度分析子模块演示完成")
    print("   (完整功能需要LLM后端运行)")


# ============================================================
# JSON 配置演示
# ============================================================

async def json_config_example():
    """
    演示 JSON 配置文件加载方式。

    不使用代码硬编码配置，而是从 config_default.json + config_user.json
    加载，实现了默认配置与用户配置的分层管理。

    运行前提：
        将此目录下的 config_default.json 作为基础配置。
        可选创建 config_user.json 覆盖需要修改的字段。
    """
    print("=" * 60)
    print("JSON 配置文件加载演示")
    print("=" * 60)

    # ---- 方式 1：只使用默认配置 ----
    print("\n📋 方式 1：load_config() — 仅默认配置")
    config1 = load_config()
    print(f"  检测智能体后端: {config1.detection.backend.value}")
    print(f"  检测模型: {config1.detection.model_name}")
    print(f"  研判智能体后端: {config1.judgment.backend.value}")

    # ---- 方式 2：默认 + 用户覆盖 ----
    print("\n📋 方式 2：load_config('config_user.json') — 默认 + 用户覆盖")
    print("  (如果 config_user.json 不存在，将回退到默认配置)")
    config2 = load_config("config_user.json")
    system = MultiAgentSystem(config2)
    await system.start()
    print(f"  系统已启动 — 后端数: {len(config2.default_backends)}")
    print(f"  队列上限: {config2.max_queue_size}")
    await system.stop()

    # ---- 方式 3：快速函数 ----
    print("\n📋 方式 3：quick_all_local() — 全部使用本地模型")
    config3 = quick_all_local(
        model_name="qwen3.5-9b",
        api_base="http://localhost:1234/v1",
    )
    print(f"  检测: {config3.detection.backend.value}/{config3.detection.model_name}")
    print(f"  关联: {config3.correlation.backend.value}/{config3.correlation.model_name}")

    # ---- 方式 4：保存配置 ----
    print("\n📋 方式 4：save_config() — 保存运行时配置")
    save_config(config3, "config_exported_demo.json")
    print("  (已生成 config_exported_demo.json)")

    # ---- 方式 5：演示 DeepSeek 配置 ----
    print("\n📋 DeepSeek V4 可选参数说明:")
    print("  在 config_user.json 的 backends.deepseek 中可设置:")
    print("    'thinking_enabled': true | false | null")
    print("      null = 不显式设置（API 默认行为，当前 SDK 默认开启）")
    print("    'reasoning_effort': 'high' | 'max' | null")
    print("      null = 不启用增强推理")
    print("      'high' 和 'max' 仅在 deepseek-v4-pro 模型上有效")
    print("    'include_reasoning': true | false")
    print("      是否在 reply 中附加模型的思考过程")

    # ---- 方式 6：深度分析子模块配置说明 ----
    print("\n📋 深度分析子模块 (DeepAnalysis) 配置结构说明:")
    print("  OrchestratorConfig.deep_analysis 包含:")
    print("    - analysis_interval_hours: 分析周期（默认24h）")
    print("    - baseline_profiling: BaselineProfilingAgentConfig")
    print("        backend: LMSTUDIO (建议本地模型，低成本高频调用)")
    print("        update_interval_hours: 基线更新时间")
    print("        max_baseline_age_days: 基线数据窗口")
    print("    - temporal_anomaly: TemporalAnomalyAgentConfig")
    print("        backend: OPENAI (建议在线模型，复杂时序推理)")
    print("        default_window_days: 分析窗口天数")
    print("        slice_size_hours: 切片粒度")

    print("\n✅ JSON 配置演示完成\n")


# ============================================================
# P4 集成伪代码
# ============================================================

def integration_example_pseudocode():
    """
    展示如何与 P4 交换机控制程序集成。

    ============================================
    假设主程序结构如下：

        # 主程序启动时
        config = load_config("config_user.json")
        system = MultiAgentSystem(config)
        # 在异步上下文中
        await system.start()

        # 从 P4 交换机接收镜像流量事件
        def on_flow_mirrored(flow_metadata):  # 由 P4 交换机事件触发
            flow = FlowEvent(
                src_ip=flow_metadata.src_ip,
                dst_ip=flow_metadata.dst_ip,
                ...
            )
            verdict = system.analyze_sync(flow)

            if verdict.recommended_action == "block" and verdict.confidence >= 0.85:
                # 下发规则到 P4
                p4_controller.inject_block_rule(
                    src_ip=verdict.flow_src_ip,
                    dst_ip=verdict.flow_dst_ip,
                    ttl=verdict.extra.get("suggested_ttl", 3600),
                )
                print(f"[P4] 已下发阻断规则: {verdict}")
            elif verdict.recommended_action == "monitor":
                print(f"[监控] 可疑流量待观察: {verdict.threat_type}")

        # 管理员 Web 界面反馈
        def on_admin_feedback(feedback_data):
            result = system.feedback_sync(
                feedback_type=feedback_data.type,
                src_ip=feedback_data.src_ip,
                admin_note=feedback_data.note,
            )
            # 重新同步 P4 规则
            new_rules = system.get_p4_rules()
            p4_controller.sync_rules(new_rules)
            return result

        # 定期同步规则到 P4 (每 60 秒)
        async def periodic_sync():
            while True:
                await asyncio.sleep(60)
                rules = system.get_p4_rules()
                p4_controller.sync_rules(rules)
                print(f"[定时同步] 已同步 {len(rules)} 条规则到 P4")

        # ====== 深度分析定时任务（每24小时） ======
        async def periodic_deep_analysis():
            while True:
                await asyncio.sleep(86400)  # 24h
                history = db.query_flows_since(deep_analysis._last_analysis_time)
                alerts = await deep_analysis.batch_analyze(history)
                for alert in alerts:
                    if alert.severity >= SeverityLevel.HIGH:
                        # 推送到 WebUI
                        web_ui.push_alert(alert)
                        # 更新检测阈值
                        detection_agent.update_thresholds(alert)

    ============================================
    """
    pass


# ============================================================
# 主入口
# ============================================================

if __name__ == "__main__":
    import sys

    print("\n提示：如需实际运行，请确保 LM Studio、OpenAI API 或 DeepSeek API 可用。")
    print("当前为演示模式：若后端不可用将捕获异常并继续。\n")

    # ---- 选择运行模式 ----
    print("可用示例模式：")
    print("  [1] LM Studio 模型管理演示")
    print("  [2] 多智能体异步流程演示")
    print("  [3] 多智能体同步流程演示")
    print("  [4] DeepSeek 后端使用演示")
    print("  [5] JSON 配置文件加载演示")
    print("  [6] 深度分析子模块演示（基线画像+时序异常）")
    print("  [7] 运行全部示例")

    # 允许命令行参数选择
    if len(sys.argv) > 1:
        choice = sys.argv[1]
    else:
        print("\n用法: python example_usage.py [1|2|3|4|5|6|7]")
        print("默认运行全部示例...\n")
        choice = "7"

    async def run_choice(choice: str):
        if choice == "1":
            await lmstudio_management_example()
        elif choice == "2":
            await async_example()
        elif choice == "3":
            await _sync_example_impl()
        elif choice == "4":
            await deepseek_example()
        elif choice == "5":
            await json_config_example()
        elif choice == "6":
            await deep_analysis_example()
        elif choice == "7":
            print("\n" + "█" * 60)
            print("  [1/6] JSON 配置文件加载演示")
            print("█" * 60)
            try:
                await json_config_example()
            except Exception as e:
                print(f"⚠ JSON 配置演示跳过: {e}")

            print("\n" + "█" * 60)
            print("  [2/6] LM Studio 模型管理演示")
            print("█" * 60)
            try:
                await lmstudio_management_example()
            except Exception as e:
                print(f"⚠ LM Studio 演示跳过: {e}")

            print("\n" + "█" * 60)
            print("  [3/6] 多智能体异步流程演示")
            print("█" * 60)
            try:
                await async_example()
            except Exception as e:
                print(f"⚠ 异步示例跳过: {e}")

            print("\n" + "█" * 60)
            print("  [4/6] 多智能体同步流程演示")
            print("█" * 60)
            try:
                await _sync_example_impl()
            except Exception as e:
                print(f"⚠ 同步示例跳过: {e}")

            print("\n" + "█" * 60)
            print("  [5/6] DeepSeek 后端使用演示")
            print("█" * 60)
            try:
                await deepseek_example()
            except Exception as e:
                print(f"⚠ DeepSeek 演示跳过: {e}")

            print("\n" + "█" * 60)
            print("  [6/6] 深度分析子模块演示（基线画像+时序异常）")
            print("█" * 60)
            try:
                await deep_analysis_example()
            except Exception as e:
                print(f"⚠ 深度分析子模块演示跳过: {e}")
        else:
            print(f"未知选项: {choice}，可选值 1-7")

    try:
        asyncio.run(run_choice(choice))
    except Exception as e:
        print(f"\n运行异常: {e}")
        print("请检查后端配置。")