# -*- coding: utf-8 -*-
"""
@module: controller.py
@description: SDN 态势感知中央调度枢纽 (完美对齐接口版)
"""

import logging
import traceback
import sys
import struct
import threading
import pynng
import requests
from flask import Flask

# 🌟 剧情线 3：Thrift 直连 BMv2 交换机（替代 SSH）
from thrift.transport import TSocket, TTransport
from thrift.protocol import TBinaryProtocol, TMultiplexedProtocol

# ── 日志 ──────────────────────────────────────────────
_logger = logging.getLogger("P4Controller")

# 🔌 引入你的三大核心业务模块
# 兼容两种执行模式：包内导入 (python -m p4_controller.control) / 独立运行
try:
    from . import data_packer  # 打包底座
    from . import analyzer     # 判官大脑
    from . import add_ip       # 完美对齐：户籍资产模块
    from .timer import start_timer_thread  # 独立计时器
except ImportError:
    import data_packer         # type: ignore[no-redef]
    import analyzer            # type: ignore[no-redef]
    import add_ip              # type: ignore[no-redef]
    from timer import start_timer_thread  # type: ignore[no-redef]

app = Flask(__name__)

# ==========================================
# ⚙️ 全局配置与多线程数据锁
# ==========================================
P4_SWITCH_IPC = 'tcp://192.168.56.101:10001'
FRONTEND_ALERT_API = 'http://127.0.0.1:8080/api/alert'  # 前端大屏实时告警接口

# 【核心防线】：保护 data_packer 字典的并发安全锁
table_lock = threading.Lock()


# ==========================================
# 🛠️ 本地网络执行组件
# ==========================================
def report_alert_to_frontend(ip_addr, label):
    """【执行器】直接向前端大屏推送高危内鬼告警"""
    _logger.warning("🚨 发现高危外发！内鬼IP: %s | 触发标签: %s", ip_addr, label)
    try:
        payload = {"ip": ip_addr, "label": label}
        requests.post(FRONTEND_ALERT_API, json=payload, timeout=2)
    except Exception:
        _logger.debug("通知前端大屏失败 (大屏服务可能未启动)")


# ==========================================
# 🎬 剧情线 2：P4 探针接收 -> 打包 -> 判官 -> 拉黑 & 本地前端上报
# ==========================================

def p4_listener_thread():
    """
    P4 硬件探针监听线程。
    - 连接到 P4 交换机 pynng 发布端
    - 接收实时行为特征报文 -> data_packer -> analyzer
    - 连接不可达时降级运行（记录警告，不崩溃）
    """
    _logger.info("剧情线 2：P4 pynng 接收总线已就位...")

    try:
        # 尝试连接，若不可达则降级等待
        _logger.info("正在连接 P4 交换机 %s ...", P4_SWITCH_IPC)
        with pynng.Sub0(dial=P4_SWITCH_IPC, recv_timeout=2000) as sub:
            sub.subscribe(b'')
            _logger.info("P4 硬件管道连接成功！开始监听...")

            while True:
                try:
                    msg = sub.recv()
                    # 护住内部的数据处理
                    try:
                        with table_lock:
                            high_risk_flows = data_packer.process_p4_report(msg)
                        if not high_risk_flows:
                            continue

                        for vector in high_risk_flows:
                            is_malicious, label = analyzer.evaluate(vector)
                            _logger.debug(
                                "判官已收到哈希槽位的21维特征！"
                                "is_malicious=%s, label=%s",
                                is_malicious, label,
                            )
                            if is_malicious:
                                src_ip = vector[0]
                                add_ip.add_to_blacklist(src_ip, source="controller")
                                report_alert_to_frontend(src_ip, label)

                    except Exception as proc_err:
                        _logger.error(
                            "数据解析层异常: %s\n%s",
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
# 🎬 剧情线 3：定时器触发 -> 本地拉取 -> 硬件寄存器重置
# ==========================================
def telemetry_job():
    """100秒时间到！通过本地 Thrift 直连 BMv2 交换机（无需 SSH、无需文本解析）"""
    # 动态导入从 VM 拷贝过来的 BMv2 Thrift stubs
    try:
        from bm_runtime.standard import Standard
    except ImportError:
        _logger.error("缺少 bm_runtime 模块！请从 VM 拷贝 BMv2 Thrift 绑定到项目目录")
        return

    _logger.info("剧情线 3：达到 100 秒节拍，Thrift 直连拉取寄存器...")

    transport = TTransport.TBufferedTransport(TSocket.TSocket('127.0.0.1', 9100))
    # BMv2 simple_switch 使用 TMultiplexedProtocol，服务名固定为 "standard"
    proto = TMultiplexedProtocol.TMultiplexedProtocol(
        TBinaryProtocol.TBinaryProtocol(transport), "standard")
    client = Standard.Client(proto)

    try:
        transport.open()

        # 🚀 bm_register_read_all 返回 list[int]（每个 int 是 64 位寄存器值），
        #    需转换为 bytes（每 8 字节大端打包）才能喂给 process_pulled_registers
        vol_list = client.bm_register_read_all(0, 'MyIngress.reg_volume_score')
        ent_list = client.bm_register_read_all(0, 'MyIngress.reg_entropy_stat')
        vol_data = b''.join(struct.pack('>Q', v) for v in vol_list)
        ent_data = b''.join(struct.pack('>Q', v) for v in ent_list)
        _logger.info("全量寄存器拉取成功！Vol: %dB, Ent: %dB", len(vol_data), len(ent_data))

        # 安全上锁，扔给清洗中继器
        with table_lock:
            data_packer.process_pulled_registers(vol_data, ent_data)

        # 阅后即焚：重置寄存器，备战下一个 100 秒周期
        client.bm_register_reset(0, 'MyIngress.reg_volume_score')
        client.bm_register_reset(0, 'MyIngress.reg_entropy_stat')
        _logger.info("剧情线 3：寄存器重置成功，环境已清空。")

    except Exception as e:
        _logger.error("剧情线 3 Thrift 直连失败（端口转发配了吗？VM 开机了吗？）: %s", e)
    finally:
        transport.close()
# ==========================================
# 🧹 开机自启动：清空交换机哈希表
# ==========================================
def reset_switch_on_startup():
    """控制器启动时自动清空交换机双寄存器，确保从干净状态开始巡逻"""
    try:
        from bm_runtime.standard import Standard
    except ImportError:
        print("⚠️ [开机自检] 缺少 bm_runtime，跳过寄存器清空", flush=True)
        return

    print("🧹 [开机自检] 正在清空交换机哈希表（双寄存器全量归零）...", flush=True)
    transport = TTransport.TBufferedTransport(TSocket.TSocket('127.0.0.1', 9100))
    proto = TMultiplexedProtocol.TMultiplexedProtocol(
        TBinaryProtocol.TBinaryProtocol(transport), "standard")
    client = Standard.Client(proto)

    try:
        transport.open()
        client.bm_register_reset(0, 'MyIngress.reg_volume_score')
        client.bm_register_reset(0, 'MyIngress.reg_entropy_stat')
        print("✅ [开机自检] 交换机哈希表已归零，内存环境纯净。", flush=True)
    except Exception as e:
        print(f"❌ [开机自检] 清空失败（交换机是否已启动？）: {e}", flush=True)
    finally:
        transport.close()


# ==========================================
# 🚀 引擎点火启动
# ==========================================
if __name__ == '__main__':
    print("=" * 60)
    print("🚀 [态势感知大脑] 中央调度总线控制器正在初始化...")
    print("=" * 60)

    # 0. 开机自检：清空交换机哈希表，从零开始
    reset_switch_on_startup()

    # 1. 启动独立定时器（传入 100 秒和本地清扫回调）
    start_timer_thread(100, telemetry_job)

    # 2. 异步启动 P4 硬件探针报文监听子线程
    threading.Thread(target=p4_listener_thread, daemon=True, name="P4-Probe-Bus").start()

    # 3. 启动 Flask（P4 控制面守护进程，黑名单下发已迁移至 FastAPI :8080）
    app.run(host='0.0.0.0', port=5000, use_reloader=False)