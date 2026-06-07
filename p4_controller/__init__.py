"""
p4_controller — P4 硬件层 (Layer 1)
- control.py:   P4 SDN控制器 (Flask 守护进程 + pynng 监听 + 遥测)
- data_packer.py: 数据包处理 (hash 槽位维护，21 维特征构建)
- analyzer.py:    流量分析器 (规则匹配与评分)
- add_ip.py:      IP管理与P4流表注入 (黑白名单 + SSH 远程下发)
- timer.py:       定时器 (100s 周期触发 P4 寄存器采集与重置)
"""
