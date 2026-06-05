# -*- coding: utf-8 -*-
"""
================================================================================
  P4异构多智能体反泄密平台 — 系统主入口
================================================================================
  启动并协调以下四大系统层保持正常运行：

  Layer 1 — P4 硬件层 (p4_controller)
    - Flask REST API (端口 5000)：接收前端黑白名单控制指令
    - pynng 子线程：监听 P4 交换机上报的实时行为特征
    - 定时器线程：每 100 秒 SSH 拉取 P4 寄存器、清扫重置

  Layer 2 — 快脑智能体层 (multi_agent_system)
    - 多智能体编排器：检测/关联/研判/反馈全流程
    - LiveScanOrchestrator：逐条评判队列扫描（从DB拉取逐一分析）
    - 本地 LLM (LM Studio) 或云端 API (OpenAI / DeepSeek) 后端

  Layer 3 — 慢脑智能体层 (multi_agent_system slow_brain)
    - 基线画像智能体：构建用户行为基线
    - 时序异常智能体：检测长周期/低频/碎片化泄密
    - 慢脑编排器：协调深度分析与策略反哺

  Layer 4 — 统一管理面 (数据标注 + 数据库)
    - ColdTableProcessor：UDP 9999 接收冷热表，GeoIP 丰富，MySQL 入库
    - 后台攒批写入线程：queue.Queue -> MySQL 零拷贝

  跨层联动：
    - 策略反哺：慢脑 -> 快脑阈值更新 / P4 流表下发
    - 告警推送：各层 -> WebUI 前端大屏

  使用方式：
      python main.py                        # 全量启动
      python main.py --no-slow-brain        # 禁用慢脑层
      python main.py --no-live-scan         # 禁用逐条评判扫描
      python main.py --no-llm               # 禁用 LLM 智能体（仅 P4 + 数据标注）
      python main.py --dry-run              # 仅打印启动信息，不实际运行

  依赖安装：
      pip install -r requirements.txt

  MySQL 初始化：
      登录 MySQL 后执行: source database/create_database.sql
================================================================================
"""

import argparse
import asyncio
import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path

from multi_agent_system import MultiAgentSystem
# LiveScanOrchestrator 在 start_fast_brain() 中延迟导入，
# 避免 dry-run / --no-llm 场景引入不必要的数据库依赖

# ============================================================
# 日志配置
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_logger = logging.getLogger("PlatformMain")

# ============================================================
# 颜色终端输出（跨平台 Windows 支持）
# ============================================================
try:
    import ctypes

    _kernel32 = ctypes.windll.kernel32
    _kernel32.SetConsoleMode(_kernel32.GetStdHandle(-11), 7)
except Exception:
    pass

_COLOR_RESET = "\033[0m"
_COLOR_GREEN = "\033[92m"
_COLOR_YELLOW = "\033[93m"
_COLOR_RED = "\033[91m"
_COLOR_CYAN = "\033[96m"
_COLOR_BOLD = "\033[1m"


def _green(s: str) -> str:
    return f"{_COLOR_GREEN}{s}{_COLOR_RESET}"


def _yellow(s: str) -> str:
    return f"{_COLOR_YELLOW}{s}{_COLOR_RESET}"


def _red(s: str) -> str:
    return f"{_COLOR_RED}{s}{_COLOR_RESET}"


def _cyan(s: str) -> str:
    return f"{_COLOR_CYAN}{s}{_COLOR_RESET}"


def _bold(s: str) -> str:
    return f"{_COLOR_BOLD}{s}{_COLOR_RESET}"


# ============================================================
# 全局组件引用（用于优雅关闭）
# ============================================================
_global_state = {
    "cold_processor": None,
    "cold_thread": None,
    "multi_agent_system": None,
    "slow_brain": None,
    "slow_brain_task": None,
    "db_stop_event": None,
    "p4_controller_ready": threading.Event(),
    "shutdown_requested": threading.Event(),
    "live_scanner": None,
}


# ============================================================
# 启动打印横幅
# ============================================================
def print_banner():
    """打印系统启动横幅（纯 ASCII，兼容所有终端）"""
    banner = r"""
+============================================================================+
|          P4 异构多智能体反泄密平台 -- 系统启动中...                          |
|                                                                            |
|  Layer 1  P4 硬件层        -> pynng 探针 + Flask API(:5000) + 100s 遥测    |
|  Layer 2  快脑智能体层      -> 多智能体编排 + 逐条评判队列扫描              |
|  Layer 3  慢脑智能体层      -> 基线画像 + 时序异常 + 长周期深度分析            |
|  Layer 4  统一管理面        -> ColdTableProcessor UDP:9999 + MySQL 攒批写入  |
|  跨层联动  策略反哺          -> 慢脑生成策略 -> 快脑阈值更新 / P4 流表下发     |
+============================================================================+
"""
    print(banner)


# ============================================================
# Layer 1: P4 硬件层启动
# ============================================================
def start_p4_controller() -> threading.Thread:
    """
    启动 P4 控制器 Flask 服务线程。
    control.py 内部会：
      - 启动 100 秒定时器 (SSH 拉取 P4 寄存器 + 清零)
      - 启动 pynng 子线程 (监听 P4 硬件探针报文)
      - 启动 Flask app.run() 阻塞主线程
    因此我们将其放入独立线程运行。

    注意：定时器通过 _patch_control_timer() 补绑 telemetry_job 回调后启动。
    """
    _logger.info(_cyan("[Layer 1] 启动 P4 硬件控制器..."))

    def _run_flask():
        try:
            from p4_controller.control import (
                app,
                p4_listener_thread,
            )

            # 1. 启动 P4 pynng 监听子线程
            threading.Thread(
                target=p4_listener_thread, daemon=True, name="P4-Probe-Bus"
            ).start()

            # 2. 通知主线程 P4 控制器已就绪
            _global_state["p4_controller_ready"].set()

            # 3. Flask 阻塞运行
            app.run(host="0.0.0.0", port=5000, use_reloader=False, debug=False)
        except Exception as e:
            _logger.error(_red(f"[Layer 1] P4 控制器启动失败: {e}"))
            import traceback
            traceback.print_exc()

    flask_thread = threading.Thread(
        target=_run_flask, daemon=True, name="P4-Flask-Main"
    )
    flask_thread.start()

    # 等待 Flask 就绪（最多 10 秒）
    if not _global_state["p4_controller_ready"].wait(timeout=10):
        _logger.warning(
            _yellow("[Layer 1] P4 控制器就绪超时，但后端线程仍在尝试启动...")
        )

    _logger.info(_green("[Layer 1] P4 硬件控制器已启动 [OK]"))
    return flask_thread


def _patch_control_timer():
    """
    修复 control.py 中 start_timer_thread 的回调未绑定问题。
    原代码在 if __name__ == '__main__' 中绑定 telemetry_job，
    但作为模块导入时不会执行。这里手动补绑。
    """
    try:
        from p4_controller.control import start_timer_thread, telemetry_job

        start_timer_thread(100, telemetry_job)
        _logger.info("[Layer 1] 100 秒遥测定时器已绑定 telemetry_job")
    except Exception as e:
        _logger.warning(_yellow(f"[Layer 1] 定时器补绑失败 (可能已绑定): {e}"))


# ============================================================
# Layer 2: 快脑智能体层启动
# ============================================================
async def start_fast_brain(
    enable_llm: bool = True,
    enable_live_scan: bool = True,
) -> bool:
    """
    启动多智能体编排器（快脑层）+ 逐条评判队列扫描器。

    Args:
        enable_llm: 是否启用 LLM 智能体
        enable_live_scan: 是否启用逐条评判扫描（独立于 enable_llm）

    Returns:
        bool: 快脑编排器是否成功启动
    """
    if not enable_llm:
        _logger.info(_yellow("[Layer 2] 快脑智能体层已跳过 (--no-llm)"))
        return False

    _logger.info(_cyan("[Layer 2] 启动快脑智能体层..."))
    try:
        from config.loader import load_config

        # 加载配置（默认 + 用户覆盖）
        config_path = Path(__file__).parent / "config" / "config_user.json"
        if config_path.exists():
            config = load_config(str(config_path))
        else:
            _logger.warning(
                _yellow("[Layer 2] config_user.json 不存在，使用默认配置")
            )
            config = load_config()

        system = MultiAgentSystem(orchestrator_config=config)
        await system.start()

        _global_state["multi_agent_system"] = system
        _logger.info(_green("[Layer 2] 快脑智能体层已启动 [OK]"))
        _logger.info(
            f"[Layer 2]   检测: {config.detection.backend.value}/{config.detection.model_name}"
        )
        _logger.info(
            f"[Layer 2]   关联: {config.correlation.backend.value}/{config.correlation.model_name}"
        )
        _logger.info(
            f"[Layer 2]   研判: {config.judgment.backend.value}/{config.judgment.model_name}"
        )

        # ---- 启动 LiveScanOrchestrator（逐条评判队列扫描） ----
        if enable_live_scan:
            from multi_agent_system.orchestrators.live_scan_orchestrator import (
                LiveScanOrchestrator,
            )
            live_scanner = LiveScanOrchestrator(
                orchestrator=system._orchestrator,
                config=config.live_scan,
            )
            _global_state["live_scanner"] = live_scanner

            if config.live_scan.enabled:
                await live_scanner.start()
                _logger.info(
                    _green(
                        "[Layer 2]   逐条评判扫描已启动 "
                        f"(起始ID={live_scanner._last_processed_id}, "
                        f"间隔={config.live_scan.scan_interval_seconds}s)"
                    )
                )
            else:
                _logger.info(
                    _yellow(
                        "[Layer 2]   逐条评判扫描已就绪但未启动 "
                        "(配置 enabled=false)"
                    )
                )
        else:
            _logger.info(
                _yellow("[Layer 2]   逐条评判扫描已禁用 (--no-live-scan)")
            )

        return True

    except Exception as e:
        _logger.error(_red(f"[Layer 2] 快脑智能体层启动失败: {e}"))
        import traceback
        traceback.print_exc()
        return False


async def stop_fast_brain():
    """优雅关闭快脑智能体层（先停逐条扫描，再停编排器）"""
    # 1. 先停止 LiveScanOrchestrator
    live_scanner = _global_state.get("live_scanner")
    if live_scanner is not None:
        try:
            await live_scanner.stop()
            _logger.info(_green("[Layer 2] 逐条评判扫描已停止"))
        except Exception as e:
            _logger.warning(_yellow(f"[Layer 2] 停止逐条扫描时出错: {e}"))

    # 2. 再停止快脑编排器
    system = _global_state.get("multi_agent_system")
    if system is not None:
        try:
            await system.stop()
            _logger.info(_green("[Layer 2] 快脑智能体层已停止"))
        except Exception as e:
            _logger.warning(_yellow(f"[Layer 2] 快脑停止时出错: {e}"))


# ============================================================
# Layer 3: 慢脑智能体层启动
# ============================================================
async def start_slow_brain(enable_llm: bool = True) -> bool:
    """
    启动慢脑智能体层（基线画像 + 时序异常 + 深度分析编排器）。
    如果 enable_llm=False 则跳过。
    慢脑层持续在后台运行（每 analysis_interval_hours 执行一次分析）。
    """
    if not enable_llm:
        _logger.info(_yellow("[Layer 3] 慢脑智能体层已跳过"))
        return False

    _logger.info(_cyan("[Layer 3] 启动慢脑智能体层..."))
    try:
        from multi_agent_system.agents.baseline_profiling_agent import (
            BaselineProfilingAgent,
        )
        from multi_agent_system.agents.temporal_anomaly_agent import (
            TemporalAnomalyAgent,
        )
        from multi_agent_system.agents.judgment_agent import JudgmentAgent
        from multi_agent_system.orchestrators.slow_brain_orchestrator import (
            SlowBrainOrchestrator,
        )
        from multi_agent_system.backends import (
            LMStudioBackend,
            OpenAIBackend,
            DeepSeekBackend,
        )
        from config.loader import load_config
        from multi_agent_system.config import BackendType

        _slow_cfg = load_config(
            str(Path(__file__).parent / "config" / "config_user.json")
            if (Path(__file__).parent / "config" / "config_user.json").exists()
            else None
        )

        # 构建各智能体
        _bcfg = _slow_cfg.slow_brain.baseline_profiling
        baseline_agent = BaselineProfilingAgent(
            name="BaselineProfilingAgent",
            system_prompt=_bcfg.system_prompt,
            model_name=_bcfg.model_name,
            temperature=_bcfg.temperature,
            max_tokens=_bcfg.max_tokens,
        )

        _tcfg = _slow_cfg.slow_brain.temporal_anomaly
        temporal_agent = TemporalAnomalyAgent(
            name="TemporalAnomalyAgent",
            system_prompt=_tcfg.system_prompt,
            model_name=_tcfg.model_name,
            temperature=_tcfg.temperature,
            max_tokens=_tcfg.max_tokens,
        )

        _jcfg = _slow_cfg.judgment
        judgment_agent = JudgmentAgent(
            name="SlowJudgmentAgent",
            system_prompt=_jcfg.system_prompt,
            model_name=_jcfg.model_name,
            temperature=_jcfg.temperature,
            max_tokens=_jcfg.max_tokens,
        )

        # 注入后端（尝试使用配置中指定的后端）
        try:
            _bt = _bcfg.backend
            _lm_cfg = _slow_cfg.default_backends[BackendType.LMSTUDIO]
            lm_backend = LMStudioBackend(
                api_base=_lm_cfg.api_base,
                api_key=_lm_cfg.api_key,
                timeout=_lm_cfg.timeout,
                max_retries=_lm_cfg.max_retries,
                default_model=_lm_cfg.model_name,
                auto_load=_lm_cfg.auto_load,
            )
            baseline_agent.set_backend(lm_backend)
            baseline_agent.model_name = _lm_cfg.model_name
            _logger.info(f"[Layer 3]   基线画像后端: LMStudio/{_lm_cfg.model_name}")

            temporal_agent.set_backend(lm_backend)
            temporal_agent.model_name = _lm_cfg.model_name
            judgment_agent.set_backend(lm_backend)
            judgment_agent.model_name = _lm_cfg.model_name
        except Exception as e:
            _logger.warning(_yellow(f"[Layer 3]   后端连接失败 (将降级运行): {e}"))

        # 创建慢脑编排器
        slow_brain = SlowBrainOrchestrator(
            baseline_agent=baseline_agent,
            temporal_agent=temporal_agent,
            judgment_agent=judgment_agent,
            analysis_interval_hours=_slow_cfg.slow_brain.analysis_interval_hours,
        )

        _global_state["slow_brain"] = slow_brain
        _logger.info(_green("[Layer 3] 慢脑智能体层已就绪 [OK]"))
        _logger.info(
            f"[Layer 3]   分析周期: {_slow_cfg.slow_brain.analysis_interval_hours}h"
        )
        return True

    except Exception as e:
        _logger.error(_red(f"[Layer 3] 慢脑智能体层启动失败: {e}"))
        import traceback
        traceback.print_exc()
        return False


async def slow_brain_background_loop():
    """
    慢脑层后台循环：每 analysis_interval_hours 小时执行一次深度分析。
    分析结果通过策略反哺到快脑层和 P4 层。
    """
    slow_brain = _global_state.get("slow_brain")
    if slow_brain is None:
        return

    interval_seconds = slow_brain.analysis_interval_hours * 3600
    _logger.info(
        _cyan(f"[Layer 3] 慢脑后台上报循环已启动 (间隔 {interval_seconds}s)")
    )

    # 首次延迟 60s，给系统留出预热时间
    await asyncio.sleep(60)

    while not _global_state["shutdown_requested"].is_set():
        try:
            _logger.info(_cyan("[Layer 3] 慢脑开始执行长周期深度分析..."))
            stats = slow_brain.get_statistics() if slow_brain else {}
            _logger.info(f"[Layer 3] 慢脑层当前统计: {stats}")

            alerts = slow_brain.get_recent_alerts(severity_min=3) if slow_brain else []
            if alerts:
                _logger.info(
                    _yellow(f"[Layer 3] 发现 {len(alerts)} 条高严重度告警，待反哺...")
                )

        except Exception as e:
            _logger.error(_red(f"[Layer 3] 慢脑分析循环异常: {e}"))

        try:
            await asyncio.wait_for(
                _global_state["shutdown_requested"].wait(), timeout=interval_seconds
            )
        except asyncio.TimeoutError:
            continue


# ============================================================
# Layer 4: 数据标注与数据库写入启动
# ============================================================
def start_data_labeling() -> bool:
    """
    启动冷表处理器：
      - UDP :9999 监听冷热表数据
      - GeoIP 丰富 + 员工信息查询
      - queue.Queue -> MySQL 攒批写入（零拷贝）
    """
    _logger.info(_cyan("[Layer 4] 启动数据标注与持久化层..."))
    try:
        from data_labeling.cold_table_processor import ColdTableProcessor

        processor = ColdTableProcessor()
        _global_state["cold_processor"] = processor

        # 后台线程运行 UDP 监听循环
        thread = threading.Thread(
            target=processor.run, daemon=True, name="ColdTable-UDP"
        )
        thread.start()
        _global_state["cold_thread"] = thread

        _logger.info(
            _green(
                "[Layer 4] 冷表处理器已启动 [OK] (UDP :9999, 零拷贝队列 -> MySQL)"
            )
        )
        return True

    except Exception as e:
        _logger.error(_red(f"[Layer 4] 数据标注层启动失败: {e}"))
        import traceback
        traceback.print_exc()
        return False


def stop_data_labeling():
    """优雅关闭数据标注层"""
    processor = _global_state.get("cold_processor")
    if processor is not None:
        try:
            processor.running = False
            _logger.info("[Layer 4] 冷表处理器已请求停止")
        except Exception as e:
            _logger.warning(_yellow(f"[Layer 4] 停止冷表处理器时出错: {e}"))

    db_stop = _global_state.get("db_stop_event")
    if db_stop is not None:
        try:
            from database.writer import stop_db_writer

            stop_db_writer(db_stop)
            _logger.info("[Layer 4] 数据库写入线程已请求停止")
        except Exception as e:
            _logger.warning(_yellow(f"[Layer 4] 停止 DB 写入器时出错: {e}"))


# ============================================================
# GeoIP 数据库自动更新
# ============================================================
def _start_geoip_auto_update_thread(args: argparse.Namespace):
    """
    根据命令行参数和配置文件，启动 GeoIP 数据库定期自动更新线程。
    - 若 --geoip-update-interval 0 或配置文件 enabled=false → 禁用自动更新
    - 否则按指定间隔（默认 168h = 7d）定时下载最新 GeoLite2-City.mmdb
    """
    # 确定更新间隔
    interval_hours = args.geoip_update_interval
    if interval_hours is None:
        # 从配置文件读取
        try:
            import json
            user_cfg_path = Path(__file__).parent / "config" / "config_user.json"
            if user_cfg_path.exists():
                with open(user_cfg_path, "r", encoding="utf-8") as f:
                    user_cfg = json.load(f)
                geoip_cfg = user_cfg.get("geoip", {})
                if not geoip_cfg.get("enabled", True):
                    _logger.info("[GeoIP] 配置文件中已禁用自动更新")
                    return
                interval_hours = geoip_cfg.get("update_interval_hours", 168)
            else:
                interval_hours = 168
        except Exception:
            interval_hours = 168  # 默认 7 天

    if interval_hours <= 0:
        _logger.info("[GeoIP] 自动更新已禁用 (interval=0)")
        return

    interval_seconds = interval_hours * 3600

    def _geoip_updater():
        _logger.info(
            _cyan(f"[GeoIP] 自动更新线程已启动 (间隔 {interval_hours}h)")
        )
        # 等待系统启动完成再触发首次更新
        _global_state["shutdown_requested"].wait(timeout=60)

        while not _global_state["shutdown_requested"].is_set():
            try:
                _logger.info(_cyan("[GeoIP] 开始定期更新 GeoIP 数据库..."))
                from data_labeling.cold_table_processor import update_geoip_db
                success = update_geoip_db()
                if success:
                    _logger.info(_green("[GeoIP] 自动更新完成"))
                else:
                    _logger.warning(_yellow("[GeoIP] 自动更新失败，将在下一周期重试"))
            except Exception as e:
                _logger.error(_red(f"[GeoIP] 更新异常: {e}"))

            # 等待下一个周期或收到关闭信号
            _global_state["shutdown_requested"].wait(timeout=interval_seconds)

    t = threading.Thread(target=_geoip_updater, daemon=True, name="GeoIP-Updater")
    t.start()


# ============================================================
# 系统健康检查
# ============================================================
def health_check_loop():
    """
    后台健康检查线程：每 30 秒打印一次系统状态。
    维护全局状态字典供 WebUI / 监控调用。
    """
    _logger.info("[HealthCheck] 健康检查线程已启动 (每 30s)")
    while not _global_state["shutdown_requested"].is_set():
        status = {
            "p4_controller": _global_state["p4_controller_ready"].is_set(),
            "fast_brain": _global_state.get("multi_agent_system") is not None,
            "live_scanner": _global_state.get("live_scanner") is not None,
            "slow_brain": _global_state.get("slow_brain") is not None,
            "data_labeling": _global_state.get("cold_processor") is not None,
            "uptime": time.time() - _global_state.get("start_time", time.time()),
        }

        def _ok(v: bool) -> str:
            return "OK" if v else "--"

        _logger.info(
            f"[HealthCheck] 系统状态: "
            f"P4={_ok(status['p4_controller'])} "
            f"快脑={_ok(status['fast_brain'])} "
            f"逐条扫描={_ok(status['live_scanner'])} "
            f"慢脑={_ok(status['slow_brain'])} "
            f"数据标注={_ok(status['data_labeling'])} "
            f"| 运行 {status['uptime']:.0f}s"
        )
        _global_state["shutdown_requested"].wait(timeout=30)


# ============================================================
# 信号处理（优雅关闭）
# ============================================================
def _setup_signal_handlers(loop: asyncio.AbstractEventLoop):
    """注册 SIGINT / SIGTERM 回调"""

    def _shutdown():
        _logger.info(_yellow("\n[!] 收到终止信号，开始优雅关闭..."))
        _global_state["shutdown_requested"].set()

    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda s, f: _shutdown())
    except Exception:
        pass


# ============================================================
# 主入口
# ============================================================
async def async_main(args: argparse.Namespace):
    """异步主逻辑"""
    _global_state["start_time"] = time.time()
    print_banner()

    # ---- 启动顺序 ----

    # 1. Layer 4: 数据标注层（独立，最先启动）
    if not args.no_cold_table:
        start_data_labeling()
    else:
        _logger.info(_yellow("[Layer 4] 冷表处理器已跳过 (--no-cold-table)"))

    # 2. Layer 1: P4 硬件控制层
    if not args.no_p4:
        flask_thread = start_p4_controller()
        _patch_control_timer()
    else:
        _logger.info(_yellow("[Layer 1] P4 控制器已跳过 (--no-p4)"))

    # 3. Layer 2: 快脑智能体层（含逐条评判扫描）
    fast_brain_ready = await start_fast_brain(
        enable_llm=not args.no_llm,
        enable_live_scan=not args.no_live_scan,
    )

    # 4. Layer 3: 慢脑智能体层
    slow_brain_ready = await start_slow_brain(
        enable_llm=not args.no_llm and not args.no_slow_brain
    )

    # 5. 启动健康检查线程
    health_thread = threading.Thread(
        target=health_check_loop, daemon=True, name="HealthCheck"
    )
    health_thread.start()

    # 5.5 GeoIP 自动更新定时线程
    _start_geoip_auto_update_thread(args)

    # 6. 启动慢脑后台循环（如果就绪）
    slow_brain_task = None
    if slow_brain_ready:
        slow_brain_task = asyncio.create_task(slow_brain_background_loop())
        _global_state["slow_brain_task"] = slow_brain_task

    # ---- 打印最终启动报告 ----
    def _status(b: bool) -> str:
        return "已启动 [OK]" if b else "已跳过 [--]"

    # 逐条扫描状态
    live_scanner = _global_state.get("live_scanner")
    live_scan_running = (
        live_scanner is not None
        and live_scanner._running
    )

    print()
    print("=" * 76)
    print("*** 系统启动完成！***".center(76))
    print("=" * 76)
    print(
        f"  P4 控制器        {_status(not args.no_p4) : <40}"
    )
    print(
        f"  快脑智能体       {_status(fast_brain_ready) : <40}"
    )
    print(
        f"  逐条评判扫描     {_status(live_scan_running) : <40}"
    )
    print(
        f"  慢脑智能体       {_status(slow_brain_ready) : <40}"
    )
    print(
        f"  冷表处理器       {_status(not args.no_cold_table) : <40}"
    )
    print("  健康检查         [OK] 每 30s")
    print()
    print("  API 端点:")
    print("    P4 控制面 (Flask)    -> http://0.0.0.0:5000")
    print("    冷表处理器 (UDP)      -> 0.0.0.0:9999")
    print()
    print("  按 Ctrl+C 优雅关闭系统")
    print("=" * 76)
    print()

    # ---- 主循环：等待关闭信号 ----
    try:
        while not _global_state["shutdown_requested"].is_set():
            await asyncio.sleep(1)

    except KeyboardInterrupt:
        _logger.info(_yellow("\n收到 Ctrl+C，开始优雅关闭..."))
    finally:
        _global_state["shutdown_requested"].set()

    # ---- 优雅关闭流程 ----
    _logger.info(_yellow("=" * 60))
    _logger.info(_yellow("正在执行优雅关闭流程..."))

    # 1. 取消慢脑后台任务
    if slow_brain_task is not None:
        slow_brain_task.cancel()
        try:
            await slow_brain_task
        except asyncio.CancelledError:
            pass
        _logger.info(_green("[Layer 3] 慢脑后台上报循环已停止"))

    # 2. 停止快脑智能体层（含逐条扫描）
    await stop_fast_brain()

    # 3. 停止数据标注层
    stop_data_labeling()

    # 4. 等待各线程自然退出
    _logger.info("等待后台线程退出...")
    await asyncio.sleep(2)

    _logger.info(_green("系统已完全关闭。再见！"))
    print()
    print("=" * 76)
    print("  系统已安全关闭 [OK]".center(76))
    print("=" * 76)
    print()


def main():
    """主函数：解析参数，构建异步上下文，启动系统"""
    parser = argparse.ArgumentParser(
        description="P4 异构多智能体反泄密平台 — 系统启动器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python main.py                          # 全量启动 (所有4层 + 逐条扫描)
  python main.py --no-llm                 # 跳过 LLM 智能体 (仅 P4 + 数据标注)
  python main.py --no-slow-brain          # 跳过慢脑层
  python main.py --no-live-scan           # 跳过逐条评判队列扫描
  python main.py --no-p4                  # 跳过 P4 控制器 (仅智能体 + 数据标注)
  python main.py --no-cold-table          # 跳过冷表处理器
  python main.py --no-p4 --no-cold-table  # 仅启动智能体层
  python main.py --dry-run                # 仅打印启动信息，不实际运行
        """,
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="禁用 LLM 智能体层 (快脑 + 慢脑)",
    )
    parser.add_argument(
        "--no-slow-brain",
        action="store_true",
        help="仅禁用慢脑智能体层",
    )
    parser.add_argument(
        "--no-live-scan",
        action="store_true",
        help="禁用逐条评判队列扫描（LiveScanOrchestrator）",
    )
    parser.add_argument(
        "--no-p4",
        action="store_true",
        help="禁用 P4 硬件控制器",
    )
    parser.add_argument(
        "--no-cold-table",
        action="store_true",
        help="禁用冷表处理器 (UDP :9999 + MySQL 写入)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="仅打印配置摘要，不实际启动",
    )
    parser.add_argument(
        "--update-geoip-now",
        action="store_true",
        help="启动时立即更新 GeoIP 数据库（GeoLite2-City.mmdb）",
    )
    parser.add_argument(
        "--geoip-update-interval",
        type=int,
        default=None,
        metavar="HOURS",
        help="GeoIP 数据库自动更新间隔（小时），设为 0 禁用自动更新。"
             "默认读取 config/config_user.json 中的 geoip.update_interval_hours",
    )
    args = parser.parse_args()

    # ---- GeoIP 自动更新引导 ----
    if args.update_geoip_now:
        _logger.info(_cyan("手动触发 GeoIP 数据库更新..."))
        from data_labeling.cold_table_processor import update_geoip_db
        success = update_geoip_db()
        if success:
            _logger.info(_green("GeoIP 数据库更新完成。"))
        else:
            _logger.warning(_yellow("GeoIP 数据库更新失败，将继续使用现有数据库。"))
        print()

    # dry-run 模式
    if args.dry_run:
        print_banner()
        _logger.info(_yellow("DRY-RUN 模式 — 仅显示启动信息，不实际运行。"))
        print("\n将启动的组件:")

        print(f"  P4 控制器:        {'[OK]' if not args.no_p4 else '[--] (--no-p4)'}")
        print(f"  快脑智能体:       {'[OK]' if not args.no_llm else '[--] (--no-llm)'}")
        print(
            f"  逐条评判扫描:     {'[OK]' if not args.no_llm and not args.no_live_scan else '[--]'}"
        )
        print(
            f"  慢脑智能体:       {'[OK]' if not args.no_llm and not args.no_slow_brain else '[--]'}"
        )
        print(
            f"  冷表处理器:       {'[OK]' if not args.no_cold_table else '[--] (--no-cold-table)'}"
        )
        print("\n实际启动请移除 --dry-run 参数。")
        return

    # 处理 --no-llm 同时影响快脑和慢脑的语义
    if args.no_llm:
        args.no_slow_brain = True

    # 创建事件循环并运行
    try:
        asyncio.run(async_main(args))
    except KeyboardInterrupt:
        _logger.info("收到中断信号，退出。")
    except Exception as e:
        _logger.error(_red(f"系统启动失败: {e}"))
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()