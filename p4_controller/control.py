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
from flask import Flask, request, jsonify

# Thrift 直连 BMv2 交换机（替代 SSH）
from thrift.transport import TSocket, TTransport
from thrift.protocol import TBinaryProtocol, TMultiplexedProtocol

# 🔌 双模式导入：支持包内调用 (main.py) 和独立运行
try:
    from . import data_packer   # 包模式: p4_controller.data_packer
    from . import analyzer
    from . import add_ip
    from .timer import start_timer_thread
except ImportError:
    import data_packer          # 独立模式
    import analyzer
    import add_ip
    from timer import start_timer_thread  # pyright: ignore

app = Flask(__name__)

# ==========================================
# ⚙️ 全局配置与多线程数据锁
# ==========================================
P4_SWITCH_IPC = 'tcp://192.168.56.102:10001'
FRONTEND_ALERT_API = 'http://127.0.0.1:8080/api/alert'  # 前端大屏实时告警接口

# 【核心防线】：保护 data_packer 字典的并发安全锁
table_lock = threading.Lock()

# 📝 日志：统一使用模块 logger，由 main.py 的 logging.basicConfig 统一管理
logger = logging.getLogger(__name__)
telemetry_logger = logging.getLogger(__name__ + ".telemetry")


# ==========================================
# 🛠️ 本地网络执行组件
# ==========================================
def report_alert_to_frontend(ip_addr, label):
    """直接向前端大屏推送高危内部威胁告警"""
    logger.warning("发现高危外发：IP: %s | 触发标签: %s", ip_addr, label)
    try:
        payload = {"ip": ip_addr, "label": label}
        requests.post(FRONTEND_ALERT_API, json=payload, timeout=2)
    except Exception as e:
        logger.error("通知前端大屏失败 (大屏服务可能未启动): %s", e)


# ==========================================
# 前端 API 接口：黑白名单控制 (对齐 add_ip 接口)
# ==========================================
@app.route('/api/blacklist', methods=['POST'])
def handle_frontend_blacklist():
    data = request.json
    target_ip = data.get('ip')
    action = data.get('action')

    if not target_ip:
        return jsonify({"status": "error", "msg": "缺少 IP 参数"}), 400

    if action == 'block':
        # 完美对齐：传入 ip 和 source="frontend" 满足权限校验
        add_ip.add_to_blacklist(target_ip, source="frontend")
        return jsonify({"status": "success", "msg": f"已成功物理拉黑 {target_ip}"})

    elif action == 'whitelist':
        # 完美对齐：传入 ip 和 source="frontend" 满足特权校验
        add_ip.add_to_whitelist(target_ip, source="frontend")
        return jsonify({"status": "success", "msg": f"已成功加白/解封 {target_ip}"})

    return jsonify({"status": "error", "msg": "未知控制动作"}), 400


# ==========================================
# P4 探针接收 -> 打包 -> 分析评估 -> 拉黑 & 本地前端上报
# ==========================================
def p4_listener_thread():
    """P4 探针监听线程：接收交换机上报的实时数据"""
    logger.info("P4 pynng 接收总线已就位...")

    try:
        with pynng.Sub0(dial=P4_SWITCH_IPC, recv_timeout=2000) as sub:
            sub.subscribe(b'')
            logger.info("P4 硬件管道连接成功，开始监听...")

            while True:
                try:
                    msg = sub.recv()
                    logger.debug("收到 P4 上报原始报文，长度: %d 字节", len(msg))
                    try:
                        with table_lock:
                            high_risk_flows = data_packer.process_p4_report(msg)
                        if not high_risk_flows:
                            logger.debug("首包建立成功")
                            continue

                        for vector in high_risk_flows:
                            is_malicious, label = analyzer.evaluate(vector)
                            logger.debug("安全分析评估完成: is_malicious=%s, label=%s", is_malicious, label)
                            if is_malicious:
                                src_ip = vector[0]
                                add_ip.add_to_blacklist(src_ip, source="controller")
                                report_alert_to_frontend(src_ip, label)

                    except Exception as proc_err:
                        logger.error("数据解析层错误: %s", proc_err, exc_info=True)
                        with open("crash.txt", "a", encoding="utf-8") as f:
                            f.write(f"数据解析层错误: {proc_err}\n")
                            traceback.print_exc(file=f)
                        continue

                except pynng.Timeout:
                    continue

    except Exception as global_err:
        # 线程崩溃时，将错误详情写入当前目录下的 crash.txt
        logger.critical("后台监听线程遭遇致命错误！已将错误详情写入本地 crash.txt 文件！", exc_info=True)
        with open("crash.txt", "w", encoding="utf-8") as f:
            f.write(f"警告！监听线程彻底崩溃！全局错误原因: {global_err}\n")
            f.write("====== 以下为导致线程崩溃的 Traceback ======\n")
            traceback.print_exc(file=f)
# ==========================================
# 定时器触发 -> 本地拉取 -> 硬件寄存器重置
# ==========================================
def telemetry_job():
    """通过本地 Thrift 直连 BMv2 交换机拉取寄存器数据（无需 SSH、无需文本解析）"""
    # 动态导入从 VM 拷贝过来的 BMv2 Thrift stubs
    try:
        from bm_runtime.standard import Standard
    except ImportError:
        telemetry_logger.error("缺少 bm_runtime 模块！请从 VM 拷贝 BMv2 Thrift 绑定到项目目录")
        return

    telemetry_logger.info("定时器触发，Thrift 直连拉取寄存器...")

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
        telemetry_logger.info(f"全量寄存器拉取成功！Vol: {len(vol_data)}B, Ent: {len(ent_data)}B")

        # 安全上锁，交由数据处理模块
        with table_lock:
            data_packer.process_pulled_registers(vol_data, ent_data)

        # 重置寄存器，准备下一个采集周期
        client.bm_register_reset(0, 'MyIngress.reg_volume_score')
        client.bm_register_reset(0, 'MyIngress.reg_entropy_stat')
        telemetry_logger.info("寄存器重置成功，环境已清空。")

    except Exception as e:
        telemetry_logger.error(f"Thrift 直连失败（端口转发配了吗？VM 开机了吗？）: {e}")
    finally:
        transport.close()
# ==========================================
# 🧹 开机自启动：清空交换机哈希表 + 清空 P4 流表黑白名单
# ==========================================
def reset_switch_on_startup():
    """控制器启动时自动清空交换机双寄存器及黑白名单流表，确保从干净状态开始运行"""
    try:
        from bm_runtime.standard import Standard
    except ImportError:
        logger.warning("缺少 bm_runtime，跳过寄存器清空")
        return

    logger.info("正在清空交换机状态（寄存器 + 黑白名单流表）...")
    transport = TTransport.TBufferedTransport(TSocket.TSocket('127.0.0.1', 9100))
    proto = TMultiplexedProtocol.TMultiplexedProtocol(
        TBinaryProtocol.TBinaryProtocol(transport), "standard")
    client = Standard.Client(proto)

    try:
        transport.open()
        # 1. 清空哈希寄存器
        client.bm_register_reset(0, 'MyIngress.reg_volume_score')
        client.bm_register_reset(0, 'MyIngress.reg_entropy_stat')
        logger.info("交换机哈希表已归零。")

        # 2. 清空 P4 流表黑白名单
        client.bm_mt_clear_entries(0, 'MyIngress.blacklist_table', False)
        logger.info("P4 黑名单流表已清空。")
        client.bm_mt_clear_entries(0, 'MyIngress.whitelist_table', False)
        logger.info("P4 白名单流表已清空。")
    except Exception as e:
        logger.error("清空交换机状态失败（交换机是否已启动？）: %s", e)
    finally:
        transport.close()


# ==========================================
# 🚀 引擎点火启动
# ==========================================
if __name__ == '__main__':
    logger.info("=" * 60)
    logger.info("SDN 态势感知中央调度控制器正在初始化...")
    logger.info("=" * 60)

    # 0. 开机自检：清空交换机哈希表，从零开始
    reset_switch_on_startup()

    # 1. 启动独立定时器（传入 100 秒和本地清扫回调）
    start_timer_thread(100, telemetry_job)

    # 2. 异步启动 P4 硬件探针报文监听子线程
    threading.Thread(target=p4_listener_thread, daemon=True, name="P4-Probe-Bus").start()

    # 3. 启动 Flask 接收前端黑白名单控制（阻断运行）
    app.run(host='0.0.0.0', port=5000, use_reloader=False)