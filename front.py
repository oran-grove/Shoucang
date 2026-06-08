# -*- coding: utf-8 -*-
"""
@module: frontend_mock.py
@description: 态势感知大屏伪前端系统 (完美合流 8080 端口)
"""

import logging
from flask import Flask, request, jsonify, render_template_string
import requests

logger = logging.getLogger(__name__)

app = Flask(__name__)

# ==========================================
# ⚙️ 配置：指向你 5000 端口的中央控制器
# ==========================================
CONTROLLER_API = "http://127.0.0.1:5000/api/blacklist"

# 全局内存冷水池：存储从中央控制器接收到的高危内鬼流
realtime_alerts = []


# ==========================================
# 📺 剧情线 A：接收中央控制器的 5000 端口疯狂弹射
# ==========================================
@app.route('/api/alert', methods=['POST'])
def receive_alert_from_controller():
    """【核心契约】接收 Ingress 判官打完标签后的实时上报"""
    data = request.json
    ip = data.get('ip', 'Unknown')
    label = data.get('label', 'Normal')

    # 压入前端告警队列，打上序号
    alert_entry = {
        "id": len(realtime_alerts) + 1,
        "ip": ip,
        "label": label
    }
    realtime_alerts.insert(0, alert_entry)  # 最新告警永远置顶

    logger.info("成功捕获内鬼特征！IP: %s | 威胁类型: %s", ip, label)
    return jsonify({"status": "success", "msg": "大屏已同步接收"}), 200


# ==========================================
# 📊 剧情线 B：供前端网页轮询读取数据的 API
# ==========================================
@app.route('/api/get_alerts', methods=['GET'])
def get_alerts():
    return jsonify(realtime_alerts)


# ==========================================
# 🔌 剧情线 C：前端上帝之手代理（规避浏览器 CORS 跨域拦截）
# ==========================================
@app.route('/api/proxy_control', methods=['POST'])
def proxy_control():
    """将大屏下发的封锁/白名单指令无损转发给 5000 端口控制器"""
    data = request.json
    try:
        res = requests.post(CONTROLLER_API, json=data, timeout=3)
        return jsonify(res.json()), res.status_code
    except Exception as e:
        return jsonify({"status": "error", "msg": f"无法触达中央控制器: {e}"}), 500


# ==========================================
# 🎨 剧情线 D：高科技科技感大屏幕 Web UI
# ==========================================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>SDN 态势感知核心防御大屏</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-gray-100 min-h-screen font-mono p-8">

    <div class="border-b border-cyan-500 pb-4 mb-8 flex justify-between items-center">
        <div>
            <h1 class="text-3xl font-bold text-cyan-400 tracking-wider">⚡ SDN 态势感知网络防御指挥中心</h1>
            <p class="text-sm text-gray-400 mt-1">系统状态：<span class="text-green-400 animate-pulse">● 正在高频巡逻 P4 硬件交换机</span></p>
        </div>
        <div class="text-right text-sm text-cyan-500">
            PORT: 8080 (FRONTEND)
        </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div class="bg-gray-800 border border-gray-700 rounded-lg p-6 h-fit shadow-xl">
            <h2 class="text-xl font-bold text-cyan-400 mb-6 flex items-center">🛠️ 控制面特权下发引擎</h2>

            <div class="space-y-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-2">目标恶意内鬼 IP</label>
                    <input type="text" id="target_ip" placeholder="例如: 10.0.0.1" 
                           class="w-full bg-gray-900 border border-gray-600 rounded px-4 py-2 text-cyan-300 focus:outline-none focus:border-cyan-400">
                </div>

                <div class="flex gap-4 pt-2">
                    <button onclick="sendControl('block')" 
                            class="flex-1 bg-red-600 hover:bg-red-700 text-white font-bold py-2 rounded transition shadow-md shadow-red-900/30">
                        ⚡ 物理拉黑
                    </button>
                    <button onclick="sendControl('whitelist')" 
                            class="flex-1 bg-emerald-600 hover:bg-emerald-700 text-white font-bold py-2 rounded transition shadow-md shadow-emerald-900/30">
                        🛡️ 特权加白
                    </button>
                </div>
            </div>

            <div id="feedback" class="mt-6 p-3 rounded bg-gray-900 text-xs text-gray-400 min-h-[40px] border border-gray-700 flex items-center">
                🤖 机制就绪，等待下发指令...
            </div>
        </div>

        <div class="lg:col-span-2 bg-gray-800 border border-gray-700 rounded-lg p-6 shadow-xl flex flex-col h-[600px]">
            <h2 class="text-xl font-bold text-red-400 mb-4 flex justify-between items-center">
                <span>🚨 P4 探针实时威胁弹射大屏</span>
                <span class="text-xs text-gray-500 bg-gray-900 px-2 py-1 rounded">每秒自动刷新</span>
            </h2>

            <div class="grid grid-cols-3 bg-gray-900 p-3 rounded-t text-sm font-bold text-gray-400 border-b border-gray-700">
                <div>告警序号</div>
                <div>拦截/告警 IP</div>
                <div class="text-right">判官裁决标签</div>
            </div>

            <div id="alert_container" class="flex-1 overflow-y-auto space-y-2 py-2 pr-1">
                <div class="text-center text-gray-500 py-12 text-sm">📡 暂无高危流触网，网络环境纯净...</div>
            </div>
        </div>
    </div>

    <script>
        // 1. 上递封锁与放行
        function sendControl(action) {
            const ip = document.getElementById('target_ip').value.trim();
            const feedback = document.getElementById('feedback');
            if(!ip) {
                feedback.innerHTML = "❌ 错误：下发失败，IP 不能为空！";
                feedback.className = "mt-6 p-3 rounded bg-red-950/40 text-xs text-red-400 border border-red-900";
                return;
            }

            feedback.innerHTML = "⏳ 正在同步写入 P4 物理流表...";
            feedback.className = "mt-6 p-3 rounded bg-gray-900 text-xs text-yellow-400 border border-gray-700";

            fetch('/api/proxy_control', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip, action: action })
            })
            .then(res => res.json())
            .then(data => {
                if(data.status === 'success') {
                    feedback.innerHTML = `✅ 控制器响应: ${data.msg}`;
                    feedback.className = "mt-6 p-3 rounded bg-emerald-950/40 text-xs text-emerald-400 border border-emerald-900";
                } else {
                    feedback.innerHTML = `❌ 控制器拒绝: ${data.msg || '未知错误'}`;
                    feedback.className = "mt-6 p-3 rounded bg-red-950/40 text-xs text-red-400 border border-red-900";
                }
            })
            .catch(err => {
                feedback.innerHTML = `❌ 骨干通信失败: ${err}`;
                feedback.className = "mt-6 p-3 rounded bg-red-950/40 text-xs text-red-400 border border-red-900";
            });
        }

        // 2. 高频定时拉取情报
        function fetchAlerts() {
            fetch('/api/get_alerts')
            .then(res => res.json())
            .then(data => {
                const container = document.getElementById('alert_container');
                if (data.length === 0) {
                    container.innerHTML = '<div class="text-center text-gray-500 py-12 text-sm">📡 暂无高危流触网，网络环境纯净...</div>';
                    return;
                }

                container.innerHTML = data.map(item => `
                    <div class="grid grid-cols-3 bg-gray-900/60 hover:bg-gray-900 p-3 rounded text-sm transition border border-gray-800 animate-fadeIn">
                        <div class="text-gray-500">#${item.id}</div>
                        <div class="font-bold text-yellow-400">${item.ip}</div>
                        <div class="text-right font-bold text-red-500 bg-red-950/30 px-2 rounded w-fit ml-auto border border-red-900/40 text-xs py-0.5">${item.label}</div>
                    </div>
                `).join('');
            });
        }

        // 每 1000 毫秒高速同步一次大屏
        setInterval(fetchAlerts, 1000);
        fetchAlerts();
    </script>
</body>
</html>
"""


@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )
    logger.info("=" * 60)
    logger.info("态势感知伪前端核心告警展示大屏服务正在点火...")
    logger.info("已经建立与控制器的 5000 端口代理链路！")
    logger.info("请在浏览器直接访问: http://127.0.0.1:8080")
    logger.info("=" * 60)
    app.run(host='0.0.0.0', port=8080, debug=False)