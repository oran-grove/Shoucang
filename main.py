# -*- coding: utf-8 -*-
"""
================================================================================
  守藏 — 基于P4的异构多智能体反泄密平台  系统主入口
================================================================================
  启动并协调以下系统层：

  Layer 1 — P4 硬件层 (p4_controller)
    - Flask 守护进程 (端口 5000)：P4 控制面
    - pynng 子线程：监听 P4 交换机上报的实时行为特征
    - 定时器线程：每 100 秒通过 Thrift 拉取 P4 寄存器并重置

  Layer 2 — 多智能体系统 — 基于 LLM 的异步分析与研判
    - 多智能体编排器：检测/关联/研判/反馈全流程
    - LiveScanOrchestrator：逐条分析队列扫描（从DB拉取逐一分析）
    - DeepAnalysisOrchestrator：基线画像 / 时序异常 / 长周期深度分析
    - 本地 LLM (LM Studio) 或云端 API (OpenAI / DeepSeek) 后端

  Layer 3 — 数据网关 (data_gateway)
    - DataBridge：UDP 9999 接收流量数据，GeoIP 丰富，MySQL 入库
    - 后台攒批写入线程：queue.Queue -> MySQL

  统一后端 (FastAPI)
    - REST API 服务 (替代所有 PHP)
    - 前端静态文件托管
    - 前后端分离架构

  使用方式：
       python main.py                        # 全量启动
       python main.py --no-slow-brain        # 跳过深度分析子模块
       python main.py --no-live-scan         # 禁用逐条分析扫描
       python main.py --no-llm               # 禁用多智能体系统（仅 P4 + 数据网关 + 前端）
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
    "data_bridge": None,
    "bridge_thread": None,
    "multi_agent_system": None,
    "deep_analysis": None,
    "deep_analysis_task": None,
    "db_stop_event": None,
    "p4_controller_ready": threading.Event(),
    "shutdown_requested": threading.Event(),
    "live_scanner": None,
    "backend_server": None,
    "backend_thread": None,
    "backend_port": 8080,
}


# ============================================================
# 启动打印横幅
# ============================================================
def print_banner():
    """打印系统启动横幅"""
    banner = r"""
+============================================================================+
|              守藏 — 基于P4的异构多智能体反泄密平台  启动中...                       |
|                                                                            |
|  Layer 1  P4 硬件层        -> pynng 监听 + Flask(:5000) + 遥测              |
|  Layer 2  多智能体系统       -> 检测/关联/研判/反馈管线 + 基线画像 + 时序异常   |
|  Layer 3  数据网关          -> DataBridge UDP:9999 + MySQL 攒批写入          |
|  WebUI    前端可视化         -> FastAPI(:8080) 仪表盘 / REST API / 静态资源   |
|  跨层联动                   -> 深度分析生成策略 -> P4 流表下发 / 检测阈值更新   |
+============================================================================+
"""
    print(banner)


# ============================================================
# WebUI: FastAPI 统一后端
# ============================================================
def start_backend(port: int = 8080) -> threading.Thread:
    """
    启动 FastAPI 统一后端服务器：
      - REST API 端点（配置、员工、黑白名单、告警等）
      - 前端静态文件托管

    Args:
        port: 监听端口，默认 8080

    Returns:
        threading.Thread: 后端服务线程
    """
    _logger.info(_cyan("[WebUI] 启动 FastAPI 统一后端服务器..."))

    _global_state["backend_port"] = port

    def _run_backend():
        try:
            from backend.api_server import start_in_thread as _backend_start_in_thread

            _backend_start_in_thread(host="0.0.0.0", port=port)
            _logger.info(
                _green(
                    f"[WebUI] FastAPI 后端服务已启动 [OK] -> http://0.0.0.0:{port}"
                )
            )
        except OSError as e:
            if hasattr(e, "errno") and e.errno == 10048:  # Address already in use
                _logger.warning(
                    _yellow(
                        f"[WebUI] 端口 {port} 已被占用，"
                        f"使用 --frontend-port 指定其他端口"
                    )
                )
            else:
                _logger.error(_red(f"[WebUI] 后端服务启动失败: {e}"))
        except Exception as e:
            _logger.error(_red(f"[WebUI] 后端服务启动失败: {e}"))
            import traceback
            traceback.print_exc()

    thread = threading.Thread(
        target=_run_backend, daemon=True, name="FastAPI-Backend"
    )
    thread.start()
    _global_state["backend_thread"] = thread
    return thread


def stop_backend():
    """优雅关闭 FastAPI 后端服务器"""
    server = _global_state.get("backend_server")
    if server is not None:
        try:
            server.should_exit = True
            _logger.info(_green("[WebUI] FastAPI 后端服务已停止"))
        except Exception as e:
            _logger.warning(_yellow(f"[WebUI] 停止后端时出错: {e}"))


# ============================================================
# Layer 1: P4 硬件层启动
# ============================================================
def start_p4_controller() -> threading.Thread:
    """
    启动 P4 控制器 Flask 服务线程。
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
    """
    try:
        from p4_controller.control import start_timer_thread, telemetry_job

        start_timer_thread(100, telemetry_job)
        _logger.info("[Layer 1] 100 秒遥测定时器已绑定 telemetry_job")
    except Exception as e:
        _logger.warning(_yellow(f"[Layer 1] 定时器补绑失败 (可能已绑定): {e}"))


# ============================================================
# Layer 2: 多智能体系统（慢脑）启动
# ============================================================
async def start_multi_agent_system(
    enable_llm: bool = True,
    enable_live_scan: bool = True,
) -> bool:
    """
    启动多智能体编排器 + 逐条分析队列扫描器。
    """
    if not enable_llm:
        _logger.info(_yellow("[Layer 2] 多智能体系统已跳过 (--no-llm)"))
        return False

    _logger.info(_cyan("[Layer 2] 启动多智能体系统..."))
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
        _logger.info(_green("[Layer 2] 多智能体系统已启动 [OK]"))
        _logger.info(
            f"[Layer 2]   检测: {config.detection.backend.value}/{config.detection.model_name}"
        )
        _logger.info(
            f"[Layer 2]   关联: {config.correlation.backend.value}/{config.correlation.model_name}"
        )
        _logger.info(
            f"[Layer 2]   研判: {config.judgment.backend.value}/{config.judgment.model_name}"
        )

        # ---- 启动 LiveScanOrchestrator（逐条分析队列扫描） ----
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
                        "[Layer 2]   逐条分析扫描已启动 "
                        f"(起始ID={live_scanner._last_processed_id}, "
                        f"间隔={config.live_scan.scan_interval_seconds}s)"
                    )
                )
            else:
                _logger.info(
                    _yellow(
                        "[Layer 2]   逐条分析扫描已就绪但未启动 "
                        "(配置 enabled=false)"
                    )
                )
        else:
            _logger.info(
                _yellow("[Layer 2]   逐条分析扫描已禁用 (--no-live-scan)")
            )

        return True

    except Exception as e:
        _logger.error(_red(f"[Layer 2] 多智能体系统启动失败: {e}"))
        import traceback
        traceback.print_exc()
        return False


async def stop_multi_agent_system():
    """优雅关闭多智能体系统"""
    live_scanner = _global_state.get("live_scanner")
    if live_scanner is not None:
        try:
            await live_scanner.stop()
            _logger.info(_green("[Layer 2] 逐条分析扫描已停止"))
        except Exception as e:
            _logger.warning(_yellow(f"[Layer 2] 停止逐条扫描时出错: {e}"))

    system = _global_state.get("multi_agent_system")
    if system is not None:
        try:
            await system.stop()
            _logger.info(_green("[Layer 2] 多智能体系统已停止"))
        except Exception as e:
            _logger.warning(_yellow(f"[Layer 2] 多智能体停止时出错: {e}"))


# ============================================================
# 深度分析子模块：基线画像 + 时序异常检测
# ============================================================
async def start_deep_analysis(enable_llm: bool = True) -> bool:
    """启动深度分析子模块（基线画像 + 时序异常）"""
    if not enable_llm:
        _logger.info(_yellow("[Layer 3] 深度分析子模块已跳过"))
        return False

    _logger.info(_cyan("[Layer 3] 启动深度分析子模块..."))
    try:
        from multi_agent_system.agents.baseline_profiling_agent import (
            BaselineProfilingAgent,
        )
        from multi_agent_system.agents.temporal_anomaly_agent import (
            TemporalAnomalyAgent,
        )
        from multi_agent_system.agents.judgment_agent import JudgmentAgent
        from multi_agent_system.orchestrators.deep_analysis_orchestrator import (
            DeepAnalysisOrchestrator,
        )
        from multi_agent_system.backends import (
            LMStudioBackend,
            OpenAIBackend,
            DeepSeekBackend,
        )
        from config.loader import load_config
        from multi_agent_system.config import BackendType

        _deep_cfg = load_config(
            str(Path(__file__).parent / "config" / "config_user.json")
            if (Path(__file__).parent / "config" / "config_user.json").exists()
            else None
        )

        # 构建各智能体
        _bcfg = _deep_cfg.deep_analysis.baseline_profiling
        baseline_agent = BaselineProfilingAgent(
            name="BaselineProfilingAgent",
            system_prompt=_bcfg.system_prompt,
            model_name=_bcfg.model_name,
            temperature=_bcfg.temperature,
            max_tokens=_bcfg.max_tokens,
        )

        _tcfg = _deep_cfg.deep_analysis.temporal_anomaly
        temporal_agent = TemporalAnomalyAgent(
            name="TemporalAnomalyAgent",
            system_prompt=_tcfg.system_prompt,
            model_name=_tcfg.model_name,
            temperature=_tcfg.temperature,
            max_tokens=_tcfg.max_tokens,
        )

        _jcfg = _deep_cfg.judgment
        judgment_agent = JudgmentAgent(
            name="SlowJudgmentAgent",
            system_prompt=_jcfg.system_prompt,
            model_name=_jcfg.model_name,
            temperature=_jcfg.temperature,
            max_tokens=_jcfg.max_tokens,
        )

        # 注入后端（根据配置动态选择：deepseek / openai / lmstudio）
        _BACKEND_CLASS_MAP = {
            BackendType.DEEPSEEK: DeepSeekBackend,
            BackendType.OPENAI: OpenAIBackend,
            BackendType.LMSTUDIO: LMStudioBackend,
        }

        def _build_backend(backend_type: BackendType):
            """根据 BackendType 构建对应的后端实例"""
            _be_cfg = _deep_cfg.default_backends[backend_type]
            _cls = _BACKEND_CLASS_MAP[backend_type]
            _kwargs = dict(
                api_base=_be_cfg.api_base,
                api_key=_be_cfg.api_key,
                timeout=_be_cfg.timeout,
                max_retries=_be_cfg.max_retries,
                default_model=_be_cfg.model_name,
            )
            if backend_type == BackendType.LMSTUDIO:
                _kwargs["auto_load"] = _be_cfg.auto_load
            if backend_type == BackendType.DEEPSEEK:
                if _be_cfg.thinking_enabled is not None:
                    _kwargs["default_thinking_enabled"] = _be_cfg.thinking_enabled
                if _be_cfg.reasoning_effort is not None:
                    _kwargs["default_reasoning_effort"] = _be_cfg.reasoning_effort
                _kwargs["include_reasoning"] = _be_cfg.include_reasoning
            return _cls(**_kwargs)

        try:
            _bt = _bcfg.backend
            if _bt not in _BACKEND_CLASS_MAP:
                raise ValueError(f"不支持的后端类型: {_bt}")

            slow_backend = _build_backend(_bt)
            baseline_agent.set_backend(slow_backend)
            baseline_agent.model_name = _bcfg.model_name
            _logger.info(
                f"[Layer 3]   基线画像后端: {_bt.value}/{_bcfg.model_name}"
            )

            _tt = _tcfg.backend
            _temporal_backend = (
                slow_backend if _tt == _bt else _build_backend(_tt)
            )
            temporal_agent.set_backend(_temporal_backend)
            temporal_agent.model_name = _tcfg.model_name
            _logger.info(
                f"[Layer 3]   时序异常后端: {_tt.value}/{_tcfg.model_name}"
            )

            _jt = _jcfg.backend
            _judgment_backend = (
                slow_backend if _jt == _bt else _build_backend(_jt)
            )
            judgment_agent.set_backend(_judgment_backend)
            judgment_agent.model_name = _jcfg.model_name
            _logger.info(
                f"[Layer 3]   研判后端: {_jt.value}/{_jcfg.model_name}"
            )
        except Exception as e:
            _logger.warning(_yellow(f"[Layer 3]   后端连接失败 (将降级运行): {e}"))

        # 创建深度分析编排器
        deep_analysis = DeepAnalysisOrchestrator(
            baseline_agent=baseline_agent,
            temporal_agent=temporal_agent,
            judgment_agent=judgment_agent,
            analysis_interval_hours=_deep_cfg.deep_analysis.analysis_interval_hours,
        )

        _global_state["deep_analysis"] = deep_analysis
        _logger.info(_green("[Layer 3] 深度分析子模块已就绪 [OK]"))
        _logger.info(
            f"[Layer 3]   分析周期: {_deep_cfg.deep_analysis.analysis_interval_hours}h"
        )
        return True

    except Exception as e:
        _logger.error(_red(f"[Layer 3] 深度分析子模块启动失败: {e}"))
        import traceback
        traceback.print_exc()
        return False


async def deep_analysis_background_loop():
    """
    深度分析后台循环：每 analysis_interval_hours 小时执行一次深度分析。
    分析结果通过策略反馈到 P4 层和检测阈值。
    """
    deep_analysis = _global_state.get("deep_analysis")
    if deep_analysis is None:
        return

    interval_seconds = deep_analysis.analysis_interval_hours * 3600
    _logger.info(
        _cyan(f"[Layer 3] 深度分析后台上报循环已启动 (间隔 {interval_seconds}s)")
    )

    # 首次延迟 60s，给系统留出预热时间
    await asyncio.sleep(60)

    while not _global_state["shutdown_requested"].is_set():
        try:
            _logger.info(_cyan("[Layer 3] 开始执行长周期深度分析..."))
            stats = deep_analysis.get_statistics() if deep_analysis else {}
            _logger.info(f"[Layer 3] 深度分析当前统计: {stats}")

            alerts = deep_analysis.get_recent_alerts(severity_min=3) if deep_analysis else []
            if alerts:
                _logger.info(
                    _yellow(f"[Layer 3] 发现 {len(alerts)} 条高严重度告警，待反哺...")
                )

        except Exception as e:
            _logger.error(_red(f"[Layer 3] 深度分析循环异常: {e}"))

        try:
            await asyncio.wait_for(
                _global_state["shutdown_requested"].wait(), timeout=interval_seconds
            )
        except asyncio.TimeoutError:
            continue


# ============================================================
# 自适应后台循环 (Loop 2 小时聚类 + Loop 3 周度 LLM 提取)
# ============================================================
async def _evolution_background_loop():
    """
    自适应系统后台循环:
    - Loop 2: 每小时运行模式聚类 (零 LLM 成本)
    - Loop 3: 每周日 3:00 运行 LLM 模式提取
    """
    from multi_agent_system.memory.clustering import run_hourly_clustering
    from multi_agent_system.memory.weekly_extract import run_weekly_extraction
    from datetime import datetime as _dt
    import time as _time

    _logger.info(_cyan("[Evolution] 自适应系统后台任务就绪"))

    # 首次延迟 120s，给系统启动留时间
    await asyncio.sleep(120)

    last_hourly = None
    last_weekly_check = None

    while not _global_state["shutdown_requested"].is_set():
        try:
            now = _time.time()

            # Loop 2: 每小时聚类
            if last_hourly is None or (now - last_hourly) >= 3600:
                _logger.info(_cyan("[Evolution:Loop2] 执行小时聚类..."))
                result = await asyncio.to_thread(run_hourly_clustering)
                _logger.info(
                    "[Evolution:Loop2] 完成: 新卡片=%d 退役=%d",
                    result.get("generated", 0),
                    result.get("skipped_groups", 0),
                )
                last_hourly = now

            # Loop 3: 每周日 3:00
            if last_weekly_check is None or (now - last_weekly_check) >= 3600:
                dt = _dt.now()
                if dt.weekday() == 6 and dt.hour == 3:
                    _logger.info(_cyan("[Evolution:Loop3] 执行周度 LLM 模式提取..."))
                    try:
                        from config.loader import load_config
                        from multi_agent_system.config import BackendType
                        cfg = load_config()
                        ds_cfg = cfg.default_backends.get(BackendType.DEEPSEEK)
                        if ds_cfg and ds_cfg.api_key:
                            from multi_agent_system.backends.deepseek_backend import DeepSeekBackend
                            llm = DeepSeekBackend(
                                api_base=ds_cfg.api_base,
                                api_key=ds_cfg.api_key,
                                timeout=ds_cfg.timeout,
                                max_retries=ds_cfg.max_retries,
                                default_model=ds_cfg.model_name,
                            )
                            result3 = await run_weekly_extraction(llm)
                            _logger.info(
                                "[Evolution:Loop3] 完成: 候选原则=%d",
                                result3.get("candidates_generated", 0),
                            )
                        else:
                            _logger.info("[Evolution:Loop3] DeepSeek API Key 未配置, 跳过")
                    except Exception as e:
                        _logger.warning(f"[Evolution:Loop3] 执行失败: {e}")
                    last_weekly_check = now

        except Exception as e:
            _logger.error(_red(f"[Evolution] 后台循环异常: {e}"))

        try:
            await asyncio.wait_for(
                _global_state["shutdown_requested"].wait(), timeout=60,
            )
        except asyncio.TimeoutError:
            continue

    _logger.info(_green("[Evolution] 自适应后台任务已停止"))


# ============================================================
# Layer 3: 数据网关启动
# ============================================================
def start_data_gateway() -> bool:
    """启动数据网关"""
    _logger.info(_cyan("[Layer 3] 启动数据网关..."))
    try:
        from data_gateway.data_bridge import DataBridge

        bridge = DataBridge()
        _global_state["data_bridge"] = bridge

        # 后台线程运行 UDP 监听循环
        thread = threading.Thread(
            target=bridge.run, daemon=True, name="DataBridge-UDP"
        )
        thread.start()
        _global_state["bridge_thread"] = thread

        _logger.info(
            _green(
                "[Layer 3] 数据网关已启动 [OK] (UDP :9999, 零拷贝队列 -> MySQL)"
            )
        )
        return True

    except Exception as e:
        _logger.error(_red(f"[Layer 3] 数据网关启动失败: {e}"))
        import traceback
        traceback.print_exc()
        return False


def stop_data_gateway():
    """优雅关闭数据网关"""
    bridge = _global_state.get("data_bridge")
    if bridge is not None:
        try:
            bridge.running = False
            _logger.info("[Layer 3] 数据网关已请求停止")
        except Exception as e:
            _logger.warning(_yellow(f"[Layer 3] 停止数据网关时出错: {e}"))

    db_stop = _global_state.get("db_stop_event")
    if db_stop is not None:
        try:
            from database.writer import stop_db_writer

            stop_db_writer(db_stop)
            _logger.info("[Layer 3] 数据库写入线程已请求停止")
        except Exception as e:
            _logger.warning(_yellow(f"[Layer 3] 停止 DB 写入器时出错: {e}"))


# ============================================================
# GeoIP 数据库自动更新
# ============================================================
def _start_geoip_auto_update_thread(args: argparse.Namespace):
    """启动 GeoIP 数据库定期自动更新线程"""
    interval_hours = args.geoip_update_interval
    if interval_hours is None:
        # 从配置文件读取（通过统一 config 加载器）
        try:
            from config.loader import load_config_dict
            user_cfg = load_config_dict()
            geoip_cfg = user_cfg.get("geoip", {})
            if not geoip_cfg.get("enabled", True):
                _logger.info("[GeoIP] 配置文件中已禁用自动更新")
                return
            interval_hours = geoip_cfg.get("update_interval_hours", 168)
        except Exception:
            interval_hours = 168

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
                from data_gateway.data_bridge import update_geoip_db
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
    """后台健康检查线程"""
    _logger.info("[HealthCheck] 健康检查线程已启动 (每 30s)")
    while not _global_state["shutdown_requested"].is_set():
        status = {
            "p4_controller": _global_state["p4_controller_ready"].is_set(),
            "multi_agent": _global_state.get("multi_agent_system") is not None,
            "live_scanner": _global_state.get("live_scanner") is not None,
            "deep_analysis": _global_state.get("deep_analysis") is not None,
            "data_gateway": _global_state.get("data_bridge") is not None,
            "backend": _global_state.get("backend_thread") is not None,
            "uptime": time.time() - _global_state.get("start_time", time.time()),
        }

        def _ok(v: bool) -> str:
            return "OK" if v else "--"

        _logger.info(
            f"[HealthCheck] 系统状态: "
            f"P4={_ok(status['p4_controller'])} "
            f"多智能体={_ok(status['multi_agent'])} "
            f"逐条扫描={_ok(status['live_scanner'])} "
            f"深度分析={_ok(status['deep_analysis'])} "
            f"数据网关={_ok(status['data_gateway'])} "
            f"前端={_ok(status['backend'])} "
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
    _global_state["backend_port"] = args.frontend_port
    print_banner()

    # ---- 初始化：从 MySQL 加载黑白名单/IP映射到常驻内存 ----
    try:
        from database import load_lists_from_db
        load_lists_from_db()
        _logger.info(_green("[数据库] 黑白名单 + IP-部门映射已加载到常驻内存"))
    except Exception as e:
        _logger.warning(_yellow(f"[数据库] 黑白名单初始化失败 (非致命): {e}"))

    # ---- 启动顺序 ----

    # 1. FastAPI 统一后端（最先启动，前端 + REST API）
    if not args.no_frontend:
        start_backend(port=args.frontend_port)
    else:
        _logger.info(_yellow("[WebUI] 后端服务器已跳过 (--no-frontend)"))

    # 2. 数据网关
    if not args.no_data_gateway:
        start_data_gateway()
    else:
        _logger.info(_yellow("[Layer 3] 数据网关已跳过 (--no-data-gateway)"))

    # 3. Layer 1: P4 硬件控制层
    if not args.no_p4:
        flask_thread = start_p4_controller()
        _patch_control_timer()
    else:
        _logger.info(_yellow("[Layer 1] P4 控制器已跳过 (--no-p4)"))

    # 4. 多智能体系统（慢脑）
    multi_agent_ready = await start_multi_agent_system(
        enable_llm=not args.no_llm,
        enable_live_scan=not args.no_live_scan,
    )

    # 5. 深度分析子模块（基线画像 + 时序异常）
    deep_analysis_ready = await start_deep_analysis(
        enable_llm=not args.no_llm and not args.no_slow_brain
    )

    # 6. 启动健康检查线程
    health_thread = threading.Thread(
        target=health_check_loop, daemon=True, name="HealthCheck"
    )
    health_thread.start()

    # 7. GeoIP 自动更新定时线程
    _start_geoip_auto_update_thread(args)

    # 8. 启动慢脑后台循环
    deep_analysis_task = None
    if deep_analysis_ready:
        deep_analysis_task = asyncio.create_task(deep_analysis_background_loop())
        _global_state["deep_analysis_task"] = deep_analysis_task

    # 9. 启动自适应定时任务 (Loop 2: 小时聚类, Loop 3: 周度LLM提取)
    evolution_task = asyncio.create_task(_evolution_background_loop())

    # ---- 打印最终启动报告 ----
    def _status(b: bool) -> str:
        return _green("已启动 [OK]") if b else _yellow("已跳过 [--]")

    # 逐条扫描状态
    live_scanner = _global_state.get("live_scanner")
    live_scan_running = (
        live_scanner is not None
        and live_scanner._running
    )

    print()
    print("=" * 76)
    print(_bold("*** 系统启动完成！ ***".center(76)))
    print("=" * 76)
    print(
        f"  前端可视化       {_status(not args.no_frontend) : <40}"
    )
    print(
        f"  P4 控制器        {_status(not args.no_p4) : <40}"
    )
    print(
        f"  多智能体系统     {_status(multi_agent_ready) : <40}"
    )
    print(
        f"  逐条分析扫描     {_status(live_scan_running) : <40}"
    )
    print(
        f"  深度分析子模块   {_status(deep_analysis_ready) : <40}"
    )
    print(
        f"  数据网关         {_status(not args.no_data_gateway) : <40}"
    )
    print("  健康检查         [OK] 每 30s")
    print()
    print("  服务端点:")
    if not args.no_frontend:
        print(f"    前端可视化 (FastAPI) -> http://0.0.0.0:{args.frontend_port}")
    print("    P4 控制面 (Flask)   -> http://0.0.0.0:5000")
    print("    数据网关 (UDP)         -> 0.0.0.0:9999")
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
    if deep_analysis_task is not None:
        deep_analysis_task.cancel()
        try:
            await deep_analysis_task
        except asyncio.CancelledError:
            pass
        _logger.info(_green("[Layer 3] 深度分析后台上报循环已停止"))

    # 1.5 停止自适应后台任务
    evolution_task.cancel()
    try:
        await evolution_task
    except asyncio.CancelledError:
        pass

    # 2. 停止多智能体系统
    await stop_multi_agent_system()

    # 3. 停止数据网关
    stop_data_gateway()

    # 4. 停止前端服务器
    stop_backend()

    # 5. 等待各线程自然退出
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
    # ---- 强制 stdout 使用 UTF-8 ----
    if sys.stdout.encoding != "utf-8":
        try:
            sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:
            pass
    if sys.stderr.encoding != "utf-8":
        try:
            sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        description="守藏 — 基于P4的异构多智能体反泄密平台 系统启动器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python main.py                          # 全量启动 (所有4层 + 逐条扫描 + 前端)
  python main.py --no-llm                 # 跳过 LLM 智能体 (仅 P4 + 数据网关 + 前端)
  python main.py --no-slow-brain          # 跳过深度分析子模块（基线画像+时序异常）
  python main.py --no-live-scan           # 跳过逐条分析队列扫描
  python main.py --no-p4                  # 跳过 P4 控制器
  python main.py --no-data-gateway        # 跳过数据网关
  python main.py --no-frontend            # 跳过前端服务器
  python main.py --frontend-port 3000     # 前端使用端口 3000
  python main.py --no-p4 --no-data-gateway  # 仅启动智能体系统
  python main.py --dry-run                # 仅打印启动信息，不实际运行
        """,
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="禁用 LLM 智能体系统（多智能体系统 + 深度分析子模块）",
    )
    parser.add_argument(
        "--no-slow-brain",
        action="store_true",
        help="仅禁用深度分析子模块（基线画像+时序异常）",
    )
    parser.add_argument(
        "--no-live-scan",
        action="store_true",
        help="禁用逐条分析队列扫描（LiveScanOrchestrator）",
    )
    parser.add_argument(
        "--no-p4",
        action="store_true",
        help="禁用 P4 硬件控制器",
    )
    parser.add_argument(
        "--no-data-gateway",
        action="store_true",
        help="禁用数据网关 (UDP :9999 + MySQL 写入)",
    )
    parser.add_argument(
        "--no-frontend",
        action="store_true",
        help="禁用前端 Web 可视化服务器",
    )
    parser.add_argument(
        "--frontend-port",
        type=int,
        default=8080,
        metavar="PORT",
        help="前端 Web 服务器端口 (默认 8080)",
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
        from data_gateway.data_bridge import update_geoip_db
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

        print(f"  前端可视化:       {'[OK]' if not args.no_frontend else '[--] (--no-frontend)'}")
        if not args.no_frontend:
            print(f"    端口:           {args.frontend_port}")
            print(f"    后端:           FastAPI (REST API + 静态文件)")
        print(f"  P4 控制器:        {'[OK]' if not args.no_p4 else '[--] (--no-p4)'}")
        print(f"  多智能体系统:     {'[OK]' if not args.no_llm else '[--] (--no-llm)'}")
        print(
            f"  逐条分析扫描:     {'[OK]' if not args.no_llm and not args.no_live_scan else '[--]'}"
        )
        print(
            f"  深度分析子模块:   {'[OK]' if not args.no_llm and not args.no_slow_brain else '[--]'}"
        )
        print(
            f"  数据网关:           {'[OK]' if not args.no_data_gateway else '[--] (--no-data-gateway)'}"
        )
        print("\n实际启动请移除 --dry-run 参数。")
        return

    # 处理 --no-llm 同时禁用整个多智能体系统和深度分析子模块的语义
    if args.no_llm:
        args.no_slow_brain = True

    # ---- 安装 uvicorn 提示 ----
    try:
        import uvicorn  # noqa: F401
    except ImportError:
        _logger.error(_red("缺少 uvicorn 依赖。请运行: pip install uvicorn"))
        sys.exit(1)

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