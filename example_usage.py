"""
多智能体反泄密系统 — 主程序调用示例
======================================
演示 MultiAgentSystem 的完整使用流程，包括：
- 创建系统并配置后端
- 模拟流量事件分析
- 管理员反馈闭环
- 获取 P4 交换机规则

运行前请确保：
1. LM Studio 已运行于 http://localhost:1234
   或 OpenAI API Key 已配置
2. pip install httpx
"""

import asyncio
import logging
import time
from datetime import datetime, timezone

from multi_agent_system import (
    MultiAgentSystem,
    FlowEvent,
    ThreatVerdict,
    TrafficVerdict,
    BackendType,
)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


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


async def async_example():
    """异步使用示例"""
    print("=" * 60)
    print("多智能体反泄密系统 — 异步示例")
    print("=" * 60)

    # 1. 创建系统
    system = MultiAgentSystem()

    # 2. 配置后端
    #    LM Studio 本地 AI（用于快速检测和反馈）
    system.add_lmstudio_backend(
        api_base="http://localhost:1234/v1",
        model_name="qwen2.5-7b-instruct",
    )
    #    OpenAI API（用于关联分析和综合研判）
    # system.add_openai_backend(
    #     api_key="sk-your-key",
    #     api_base="https://api.openai.com/v1",
    #     model_name="gpt-4o-mini",
    # )

    # 3. 设置各智能体使用的后端（默认已合理设置，可按需调整）
    # system.set_detection_backend(BackendType.LMSTUDIO)    # 默认
    # system.set_correlation_backend(BackendType.LMSTUDIO)  # 无在线API时全用本地
    # system.set_judgment_backend(BackendType.LMSTUDIO)

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


def sync_example():
    """同步使用示例（用于非异步环境）"""
    print("=" * 60)
    print("多智能体反泄密系统 — 同步示例")
    print("=" * 60)

    system = MultiAgentSystem()
    system.add_lmstudio_backend("http://localhost:1234/v1")  # 无 LM Studio 时会报错

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
        verdict = system.analyze_sync(flow)
        print(f"判定: {verdict.verdict.value} | 建议: {verdict.recommended_action}")
    except Exception as e:
        print(f"分析失败: {e}")

    p4_rules = system.get_p4_rules()
    print(f"P4 规则数: {len(p4_rules)}")


# ======== 主程序集成伪代码 ========
def integration_example_pseudocode():
    """
    展示如何与 P4 交换机控制程序集成。

    ============================================
    假设主程序结构如下：

        # 主程序启动时
        system = MultiAgentSystem()
        system.add_lmstudio_backend("http://localhost:1234/v1")
        system.add_openai_backend("sk-xxx")
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

    ============================================
    """
    pass


if __name__ == "__main__":
    # 运行异步示例
    print("\n提示：如需实际运行，请确保 LM Studio 或 OpenAI API 可用。")
    print("当前为演示模式：若后端不可用将捕获异常并继续。\n")

    try:
        asyncio.run(async_example())
    except Exception as e:
        print(f"\n异步示例运行异常: {e}")
        print("请检查后端配置。")
