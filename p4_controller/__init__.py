"""
p4_controller — P4 硬件层 (Layer 1)
- control.py:   SDN 态势感知中央调度枢纽 (Flask API + pynng 探针 + 100s 遥测)
- data_packer.py: 数据包打包底座 (维护 hash 槽位，21 维特征构建)
- analyzer.py:    反泄密判官大脑 (规则匹配 + 评分)
- add_ip.py:      户籍资产与 P4 物理流表注入 (黑白名单 + SSH 远程注入)
- timer.py:       独立计时器 (100s 周期触发 P4 寄存器清扫)
"""