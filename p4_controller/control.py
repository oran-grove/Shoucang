# -*- coding: utf-8 -*-
"""
@module: controller.py
@description: P4 SDN控制器 — P4交换机连接、流量监听、遥测与寄存器管理。
"""

import logging
import traceback
import sys
import struct
import threading
import pynng
import requests
from flask import Flask

# Thrift 直连 BMv2 交换机
from thrift.transport import TSocket, TTransport
from thrift.protocol import TBinaryProtocol, TMultiplexedProtocol

# 日志
_logger = logging.getLogger("P4Controller")

# 核心业务模块
# 兼容两种执行模式：包内导入 (python -m p4_controller.control) / 独立运行
try:
    from . import data_packer
    from . import analyzer
    from . import add_ip
    from .timer import start_timer_thread
except ImportError:
    import data_packer         # type: ignore[no-redef]
    import analyzer            # type: ignore[no-redef]
    import add_ip              # type: ignore[no-redef]
    from timer import start_timer_thread  # type: ignore[no-redef]

app = Flask(__name__)

# ==========================================
# 全局配置
# ==========================================
P4_SWITCH_IPC = 'tcp://192.168.56.101:10001'
FRONTEND_ALERT_API = 'http://127.0.0.1:8080/api/alert'  # 前端实时告警接口

# 保护 data_packer 字典的并发安全锁
table_lock = threading.Lock()


# ==========================================
# 告警上报
# ==========================================
def report_alert_to_frontend(ip_addr, label):
    """向 WebUI 推送高危告警"""
    _logger.warning("检测到异常外发 IP: %s | 标签: %s", ip_addr, label)
    try:
        payload = {"ip": ip_addr, "label": label}
        requests.post(FRONTEND_ALERT_API, json=payload, timeout=2)
    except Exception:
        _logger.debug("通知前端失败 (WebUI 服务可能未启动)")


# ==========================================
# P4 流量监听
# ==========================================

def p4_listener_thread():
    """
    P4 交换机流量监听线程。
    - 连接到 P4 交换机 pynng 发布端
    - 接收实时行为特征报文 -> data_packer -> analyzer
    - 连接不可达时降级运行（记录警告，不崩溃）
    """
    _logger.info("P4 pynng 监听器启动中...")

    try:
        _logger.info("正在连接 P4 交换机 %s ...", P4_SWITCH_IPC)
        with pynng.Sub0(dial=P4_SWITCH_IPC, recv_timeout=2000) as sub:
            sub.subscribe(b'')
            _logger.info("P4 交换机连接成功，开始监听...")

            while True:
                try:
                    msg = sub.recv()
                    try:
                        with table_lock:
                            high_risk_flows = data_packer.process_p4_report(msg)
                        if not high_risk_flows:
                            continue

                        for vector in high_risk_flows:
                            is_malicious, label = analyzer.evaluate(vector)
                            _logger.debug(
                                "流量分析完成: is_malicious=%s, label=%s",
                                is_malicious, label,
                            )
                            if is_malicious:
                                src_ip = vector[0]
                                add_ip.add_to_blacklist(src_ip, source="controller")
                                report_alert_to_frontend(src_ip, label)

                    except Exception as proc_err:
                        _logger.error(
                            "数据处理异常: %s\n%s",
                            proc_err,
                            traceback.format_exc(),
                        )
                        continue

                except pynng.Timeout:
                    continue

    except pynng.exceptions.ConnectionRefused:
        _logger.warning(
            "P4 交换机 %s 连接被拒绝 — P4 硬件层降级运行 "
            "(不影响其他功能，待交换机上线后重启)",
            P4_SWITCH_IPC,
        )
    except Exception as global_err:
        _logger.error(
            "P4 监听线程异常终止: %s\n%s",
            global_err,
            traceback.format_exc(),
        )


# ==========================================
# 遥测：定时拉取 P4 寄存器并重置
# ==========================================
def telemetry_job():
    """通过 Thrift 直连 BMv2 交换机，拉取全量寄存器数据并重置"""
    try:
        from bm_runtime.standard import Standard
    except ImportError:
        _logger.error("缺少 bm_runtime 模块，请从 VM 拷贝 BMv2 Thrift 绑定到项目目录")
        return

    _logger.info("遥测定时器触发，Thrift 直连拉取寄存器...")

    transport = TTransport.TBufferedTransport(TSocket.TSocket('127.0.0.1', 9100))
    # BMv2 simple_switch 使用 TMultiplexedProtocol，服务名固定为 "standard"
    proto = TMultiplexedProtocol.TMultiplexedProtocol(
        TBinaryProtocol.TBinaryProtocol(transport), "standard")
    client = Standard.Client(proto)

    try:
        transport.open()

        # bm_register_read_all 返回 list[int]（每个 int 是 64 位寄存器值），
        # 需转换为 bytes（每 8 字节大端打包）供 process_pulled_registers 使用
        vol_list = client.bm_register_read_all(0, 'MyIngress.reg_volume_score')
        ent_list = client.bm_register_read_all(0, 'MyIngress.reg_entropy_stat')
        vol_data = b''.join(struct.pack('>Q', v) for v in vol_list)
        ent_data = b''.join(struct.pack('>Q', v) for v in ent_list)
        _logger.info("寄存器拉取成功 Vol: %dB, Ent: %dB", len(vol_data), len(ent_data))

        with table_lock:
            data_packer.process_pulled_registers(vol_data, ent_data)

        # 重置寄存器，准备下一个周期
        client.bm_register_reset(0, 'MyIngress.reg_volume_score')
        client.bm_register_reset(0, 'MyIngress.reg_entropy_stat')
        _logger.info("寄存器重置完成")

    except Exception as e:
        _logger.error("Thrift 直连失败（端口转发已配置？VM 已启动？）: %s", e)
    finally:
        transport.close()


# ==========================================
# 启动时清空交换机状态
# ==========================================
def reset_switch_on_startup():
    """启动时清空交换机寄存器，确保从干净状态开始"""
    try:
        from bm_runtime.standard import Standard
    except ImportError:
        print("[启动] 缺少 bm_runtime，跳过寄存器清空", flush=True)
        return

    print("[启动] 正在清空交换机寄存器...", flush=True)
    transport = TTransport.TBufferedTransport(TSocket.TSocket('127.0.0.1', 9100))
    proto = TMultiplexedProtocol.TMultiplexedProtocol(
        TBinaryProtocol.TBinaryProtocol(transport), "standard")
    client = Standard.Client(proto)

    try:
        transport.open()
        client.bm_register_reset(0, 'MyIngress.reg_volume_score')
        client.bm_register_reset(0, 'MyIngress.reg_entropy_stat')
        print("[启动] 交换机寄存器已清空", flush=True)
    except Exception as e:
        print(f"[启动] 清空失败（交换机是否已启动？）: {e}", flush=True)
    finally:
        transport.close()


# ==========================================
# 启动入口
# ==========================================
if __name__ == '__main__':
    print("=" * 60)
    print("P4 控制器启动中...")
    print("=" * 60)

    # 0. 启动时清空交换机寄存器
    reset_switch_on_startup()

    # 1. 启动遥测定时器（100 秒周期）
    start_timer_thread(100, telemetry_job)

    # 2. 启动 P4 流量监听线程
    threading.Thread(target=p4_listener_thread, daemon=True, name="P4-Listener").start()

    # 3. 启动 Flask（P4 控制面守护进程，黑名单下发已迁移至 FastAPI :8080）
    app.run(host='0.0.0.0', port=5000, use_reloader=False)
