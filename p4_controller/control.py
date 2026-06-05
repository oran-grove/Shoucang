# -*- coding: utf-8 -*-
"""
@module: controller.py
@description: SDN 态势感知中央调度枢纽 (完美对齐接口版)
"""

import logging
import traceback
import sys
import threading
import pynng
import requests
import subprocess  # 剧情线 3 需要用它来亲自动手重置硬件
from flask import Flask, request, jsonify
import re
import struct

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
# 🎬 剧情线 1：前端上帝之手 (API -> 对齐 add_ip 接口)
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
    """100秒时间到！利用 Paramiko SSH 真正穿透到 VirtualBox 虚拟机拉取流表并重置"""
    import paramiko  # 🌟 引入远程连线模块
    _logger.info("剧情线 3：达到 100 秒节拍，开始通过 SSH 连入 VirtualBox 榨取全网环境表...")

    # ============================================================
    # ⚙️ 【关键配置】：请根据你的 VirtualBox 虚拟机的网络情况填写
    # ============================================================
    VM_IP = "192.168.56.101"  # 💡 填写你虚拟机的真实 IP（就是你上面 P4_SWITCH_IPC 里的那个 IP）
    VM_PORT = 22  # 💡 虚拟机标准 SSH 端口
    VM_USER = "p4"  # 💡 你的虚拟机用户名
    VM_PASSWORD = "p4"  # 💡 你的虚拟机密码

    # 初始化 SSH 超级特工
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # 1. 跨越时空物理破门
        ssh.connect(VM_IP, port=VM_PORT, username=VM_USER, password=VM_PASSWORD, timeout=5)

        # 2. 隔空喊话：在虚拟机内部利用管道将读取指令喂给它本地的 simple_switch_CLI
        pull_cmd = 'echo -e "register_read MyIngress.reg_volume_score\nregister_read MyIngress.reg_entropy_stat" | simple_switch_CLI --thrift-port 9100'
        stdin, stdout, stderr = ssh.exec_command(pull_cmd)
        cli_output = stdout.read().decode('utf-8', errors='ignore')

        # 3. 战术解析：将文本无损熔炼为 8 字节二进制串
        vol_list = []
        ent_list = []

        for line in cli_output.splitlines():
            if "reg_volume_score=" in line:
                vol_list = [int(x) for x in re.findall(r'\d+', line.split('=')[1])]
            elif "reg_entropy_stat=" in line:
                ent_list = [int(x) for x in re.findall(r'\d+', line.split('=')[1])]

        # 防御性全零阵兜底
        if not vol_list: vol_list = [0] * 1048576
        if not ent_list: ent_list = [0] * 1048576

        vol_str = b"".join(struct.pack('>Q', val) for val in vol_list)
        ent_str = b"".join(struct.pack('>Q', val) for val in ent_list)

        _logger.info(
            "SSH 成功跨系统剥离原始数据！Volume 表 %d 字节, Entropy 表 %d 字节",
            len(vol_str), len(ent_str),
        )

        # 4. 跨进程解耦分发：安全上锁，扔给清洗中继器
        with table_lock:
            data_packer.process_pulled_registers(vol_str, ent_str)

        # 5. 阅后即焚：发送重置指令给虚拟机内的交换机，备战下一个周期
        reset_cmd = 'echo -e "register_reset MyIngress.reg_volume_score\nregister_reset MyIngress.reg_entropy_stat" | simple_switch_CLI --thrift-port 9100'
        ssh.exec_command(reset_cmd)

        _logger.info("剧情线 3：虚拟机内部物理寄存器重置成功，环境已清空。")

    except Exception as e:
        _logger.warning("剧情线 3 定时任务远程 SSH 执行失败: %s", e)
    finally:
        ssh.close()


# ==========================================
# 🚀 启动 (供 main.py 作为模块导入时调用)
# ==========================================
if __name__ == '__main__':
    # 【独立运行模式】：在父级目录用 python -m p4_controller.control 启动
    _logger.info("=== P4 中央控制器 (独立模式) ===")

    # 启动 P4 监听
    threading.Thread(target=p4_listener_thread, daemon=True, name="P4-Probe-Bus").start()

    # 启动 100 秒定时器
    start_timer_thread(100, telemetry_job)

    # Flask REST API
    app.run(host="0.0.0.0", port=5000, use_reloader=False, debug=False)