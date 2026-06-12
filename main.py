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

  Layer 2 — 多智能体系统 — 基于 LLM 的三层智能体架构
    - Layer 1 筛查: 多线程逐条分析，危险→前端, 安全→丢弃, 可疑→L2
    - Layer 2 回溯: DB查询相似记录，LLM过滤关联度
    - Layer 3 研判: 结合回溯数据最终判定，可疑→循环回溯
    - LiveScanOrchestrator：逐条分析队列扫描（从DB拉取逐一分析）
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
    "db_stop_event": None,
    "p4_controller_ready": threading.Event(),
    "shutdown_requested": threading.Event(),
    "live_scanner": None,
    "verdict_write_queue": None,
    "verdict_stop_event": None,
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
|  Layer 2  多智能体系统       -> L1筛查 → L2回溯 ⇄ L3研判 三层管线             |
|  Layer 3  数据网关          -> DataBridge UDP:9999 + MySQL 攒批写入          |
|  WebUI    前端可视化         -> FastAPI(:8080) 仪表盘 / REST API / 静态资源   |
|  跨层联动                   -> 研判结果生成策略 -> P4 流表下发 / 检测阈值更新   |
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
# Layer 2: 多智能体系统（三层架构）启动
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

        # 写入全局活跃配置单例
        from config.active import set_active_config
        set_active_config(config)

        system = MultiAgentSystem(orchestrator_config=config)
        await system.start()

        _global_state["multi_agent_system"] = system
        _logger.info(_green("[Layer 2] 多智能体系统已启动 [OK]"))
        _logger.info(
            f"[Layer 2]   L1-筛查: {config.screening.backend.value}/{config.screening.model_name}"
        )
        _logger.info(
            f"[Layer 2]   L2-回溯: {config.backtrack.backend.value}/{config.backtrack.model_name}"
        )
        _logger.info(
            f"[Layer 2]   L3-研判: {config.adjudication.backend.value}/{config.adjudication.model_name}"
        )

        # ---- 注入告警回调：研判结果 → 前端告警缓冲区 ----
        def _alert_callback(verdict, flow):
            """将研判产生的高危/可疑判定推送到前端告警缓冲"""
            try:
                from backend.api_server import push_alert

                src_ip = flow.src_ip if flow else ""
                lookback_hours = (
                    verdict.extra.get("lookback_window_hours", 0)
                    if verdict.extra else 0
                )
                label_parts = [
                    f"[L3-研判] {verdict.threat_type}",
                    f"({verdict.verdict.value}, 置信度:{verdict.confidence:.0%}",
                ]
                if lookback_hours > 0:
                    if lookback_hours < 1:
                        win_label = f"{int(lookback_hours * 60)}m"
                    elif lookback_hours < 24:
                        win_label = f"{lookback_hours:.0f}h"
                    elif lookback_hours % 24 == 0:
                        win_label = f"{int(lookback_hours // 24)}d"
                    else:
                        d = int(lookback_hours // 24)
                        h = int(lookback_hours % 24)
                        win_label = f"{d}d{h}h"
                    label_parts[-1] += f", 回溯窗口{win_label}"
                label_parts[-1] += ")"

                push_alert(
                    ip=src_ip,
                    label=" ".join(label_parts),
                    details={
                        "verdict": verdict.verdict.value,
                        "severity": verdict.severity.value,
                        "confidence": verdict.confidence,
                        "reasoning": verdict.reasoning[:300],
                        "threat_type": verdict.threat_type,
                        "src_ip": src_ip,
                        "dst_ip": flow.dst_ip if flow else "",
                        "recommended_action": verdict.recommended_action,
                        "lookback_window_hours": lookback_hours,
                    },
                )
                _logger.debug(
                    "[Layer 2] 告警已推送前端: %s → %s",
                    src_ip, verdict.threat_type,
                )
            except Exception as e:
                _logger.warning(_yellow(f"[Layer 2] 告警推送前端失败: {e}"))

        system._orchestrator.alert_callback = _alert_callback
        _logger.info(_green("[Layer 2]   告警回调已注入 (研判 → 前端)"))

        # ---- 启动 LiveScanOrchestrator（逐条分析队列扫描） ----
        if enable_live_scan:
            from multi_agent_system.orchestrators.live_scan_orchestrator import (
                LiveScanOrchestrator,
            )
            live_scanner = LiveScanOrchestrator(
                orchestrator=system._orchestrator,
                config=config.live_scan,
                verdict_queue=_global_state.get("verdict_write_queue"),
            )
            _global_state["live_scanner"] = live_scanner

            if config.live_scan.enabled:
                await live_scanner.start()
                _logger.info(
                    _green(
                        "[Layer 2]   逐条分析扫描已启动 "
                        f"(起始ID={live_scanner._last_processed_id}, "
                        f"空闲探询={config.live_scan.idle_poll_interval_seconds}s, "
                        f"并发={config.live_scan.max_concurrent_analyses})"
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
        # 从全局活跃配置读取
        try:
            from config.active import get_active_config
            geoip_cfg = get_active_config().geoip
            if not geoip_cfg.enabled:
                _logger.info("[GeoIP] 配置文件中已禁用自动更新")
                return
            interval_hours = geoip_cfg.update_interval_hours
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

    # ---- 启动判定结果批量写入器 ----
    from database.writer import start_verdict_writer, stop_verdict_writer as _stop_vw
    _vq, _ve = start_verdict_writer()
    _global_state["verdict_write_queue"] = _vq
    _global_state["verdict_stop_event"] = _ve
    _logger.info(_green("[数据库] 判定批量写入器已启动 [OK]"))

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

    # 4. 多智能体系统（三层架构）
    multi_agent_ready = await start_multi_agent_system(
        enable_llm=not args.no_llm,
        enable_live_scan=not args.no_live_scan,
    )

    # 5. 启动健康检查线程
    health_thread = threading.Thread(
        target=health_check_loop, daemon=True, name="HealthCheck"
    )
    health_thread.start()

    # 6. GeoIP 自动更新定时线程
    _start_geoip_auto_update_thread(args)

    # 7. 启动自适应定时任务 (Loop 2: 小时聚类, Loop 3: 周度LLM提取)
    from multi_agent_system.memory.evolution import run_evolution_loop
    evolution_task = asyncio.create_task(
        run_evolution_loop(_global_state["shutdown_requested"])
    )

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

    # 1. 停止自适应后台任务
    evolution_task.cancel()
    try:
        await evolution_task
    except asyncio.CancelledError:
        pass

    # 2. 停止多智能体系统
    await stop_multi_agent_system()

    # 2.5 停止判定批量写入器（在多智能体之后、数据网关之前）
    _ve = _global_state.get("verdict_stop_event")
    if _ve is not None:
        from database.writer import stop_verdict_writer as _stop_vw
        _stop_vw(_ve)
        _logger.info(_green("[数据库] 判定批量写入器已停止"))

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
  python main.py                        # 全量启动 (所有层 + 逐条扫描 + 前端)
  python main.py --no-llm               # 跳过 LLM 智能体 (仅 P4 + 数据网关 + 前端)
  python main.py --no-live-scan         # 跳过逐条分析队列扫描
  python main.py --no-p4                # 跳过 P4 控制器
  python main.py --no-data-gateway      # 跳过数据网关
  python main.py --no-frontend          # 跳过前端服务器
  python main.py --frontend-port 3000   # 前端使用端口 3000
  python main.py --dry-run              # 仅打印启动信息，不实际运行
        """,
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="禁用 LLM 智能体系统（多智能体系统）",
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
            f"  数据网关:         {'[OK]' if not args.no_data_gateway else '[--] (--no-data-gateway)'}"
        )
        print("\n实际启动请移除 --dry-run 参数。")
        return

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
