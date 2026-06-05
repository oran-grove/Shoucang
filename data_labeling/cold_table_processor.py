# -*- coding: utf-8 -*-
"""
冷表处理器：从 UDP 9999 接收原代码发送的冷/热表 JSON，
遍历冷表解析第六位 P4 寄存器原始数据，与热表合并后写入数据库。
内置零拷贝写入：queue.Queue → DB背景攒批线程，无JSON序列化，无内存拷贝。
独立于原代码运行，不修改任何原有文件。

合并规则（冷表 hash_idx 在热表中存在）：
  - 五元组、资产标签：保持不变（取自热表）
  - 历史总累计包   = 热表[8]  + 冷表.pkts
  - 历史总累计字节 = 热表[9]  + 冷表.bytes
  - 全局PPS        = 更新后总包 // 100
  - 全局BPS        = 更新后总字节 // 100
  - 历史均熵       = (热表均熵 * 热表总包 + 冷表均熵 * 冷表总包) / 更新后总包
  - 历史最高熵     = max(热表[17], 冷表.max_e)
  - 历史最低熵     = min(热表[18], 冷表.min_e)
  - 删除：初始时钟[10]、上次时钟[11]、瞬时PPS[12]、瞬时BPS[14]、reason[19]、Normal[20]

不在热表中：
  - 五元组取自冷表，资产标签默认 5，其余取冷表解析值
"""

import socket
import json
import threading
from typing import Any

# ============================================================
# 0. 可配置参数
# ============================================================
UDP_LISTEN_IP = "127.0.0.1"
UDP_LISTEN_PORT = 9999

# GeoIP 数据库路径（MaxMind GeoLite2-City.mmdb）
# 优先使用 shared_config 中的常量，如果未设置则回退到本地硬编码默认值
try:
    from config.shared_config import GEOIP_DB_PATH, GEOIP_DOWNLOAD_URL
except ImportError:
    from pathlib import Path as _Path
    GEOIP_DB_PATH = str(_Path(__file__).parent / "GeoLite2-City.mmdb")
    GEOIP_DOWNLOAD_URL = "https://cdn.jsdelivr.net/npm/geolite2-city/GeoLite2-City.mmdb.gz"

# 下载临时文件名
GEOIP_GZ_TEMP = GEOIP_DB_PATH + ".gz"


# ============================================================
# 1. P4 寄存器原始数据解析（冷表第六位）
# ============================================================
def parse_raw_p4_hex(hex_str: str) -> dict:
    """
    vol_chunk 8B + ent_chunk 8B = 32 hex chars，大端 64 位:
      vol: {pkts[63:48], bytes[47:24], score[23:0]}
      ent: {max_e[63:52], min_e[51:40], sum_e[39:0]}
    """
    if len(hex_str) < 32:
        return {"pkts": 0, "bytes": 0, "score": 0,
                "max_e": 0, "min_e": 0, "sum_e": 0, "avg_entropy": 0.0}

    vol_val = int(hex_str[0:16], 16)
    ent_val = int(hex_str[16:32], 16)

    pkts = (vol_val >> 48) & 0xFFFF
    bytes_len = (vol_val >> 24) & 0xFFFFFF

    max_e = (ent_val >> 52) & 0xFFF
    min_e = (ent_val >> 40) & 0xFFF
    sum_e = ent_val & 0xFFFFFFFFFF

    avg_entropy = round(sum_e / pkts, 2) if pkts > 0 else 0.0

    return {
        "pkts": pkts,
        "bytes": bytes_len,
        "max_e": max_e,
        "min_e": min_e,
        "sum_e": sum_e,
        "avg_entropy": avg_entropy,
    }


# ============================================================
# 2. GeoIP 国家查询
# ============================================================
_geoip_reader: Any = None


def _init_geoip():
    global _geoip_reader
    if _geoip_reader is not None:
        return
    try:
        import maxminddb
        _geoip_reader = maxminddb.open_database(GEOIP_DB_PATH)
        print(f"🌍 GeoIP 数据库已加载: {GEOIP_DB_PATH}")
    except ImportError:
        print("⚠️ maxminddb 未安装，请执行: pip install maxminddb")
    except FileNotFoundError:
        print(f"⚠️ GeoIP 数据库文件未找到: {GEOIP_DB_PATH}")
    except Exception as e:
        print(f"⚠️ GeoIP 初始化失败: {e}")


def lookup_country(ip: str) -> str:
    """根据 IP 返回国家名称，失败返回空字符串。"""
    if _geoip_reader is None:
        _init_geoip()
    if _geoip_reader is None:
        return ""
    try:
        # 跳过内网/保留地址
        if ip.startswith(("10.", "192.168.", "172.", "127.")):
            return "Intranet"
        data = _geoip_reader.get(ip)
        if data is None:
            return ""
        # maxminddb 返回 Record（dict-like），类型检查忽略即可
        return data.get("country", {}).get("names", {}).get("en", "")  # type: ignore[union-attr,return-value]
    except Exception:
        return ""



def _close_geoip():
    """关闭当前 GeoIP reader 以释放文件句柄。"""
    global _geoip_reader
    if _geoip_reader is not None:
        try:
            _geoip_reader.close()
        except Exception:
            pass
        _geoip_reader = None


def update_geoip_db():
    """
    从 jsDelivr CDN 下载最新 GeoLite2-City.mmdb.gz，
    解压后替换本地数据库文件，并重新加载 reader。
    """
    import gzip
    import shutil
    from urllib.request import urlopen

    print(f"⬇️ 正在下载 GeoIP 数据库: {GEOIP_DOWNLOAD_URL}")
    try:
        resp = urlopen(GEOIP_DOWNLOAD_URL, timeout=120)
        with open(GEOIP_GZ_TEMP, "wb") as f:
            shutil.copyfileobj(resp, f)
        resp.close()
    except Exception as e:
        print(f"❌ 下载失败: {e}")
        return False

    print("📦 正在解压...")
    try:
        with gzip.open(GEOIP_GZ_TEMP, "rb") as f_in, \
             open(GEOIP_DB_PATH, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
        print(f"✅ GeoIP 数据库已更新: {GEOIP_DB_PATH}")
    except Exception as e:
        print(f"❌ 解压失败: {e}")
        return False
    finally:
        try:
            import os as _os
            _os.remove(GEOIP_GZ_TEMP)
        except Exception:
            pass

    # 替换 reader
    _close_geoip()
    _init_geoip()
    return True


# ============================================================
# 3. 员工信息查询（源 IP → 员工名 + 部门，通过 API 服务器获取）
# ============================================================
API_SERVER_URL = "http://127.0.0.1:5000"

_employee_cache: dict = {}  # ip → (name, department)


def fetch_ip_dept_map() -> dict:
    """
    从 API 服务器 /api/ip_map 拉取全量 IP→员工映射。
    Returns: {ip: (name, department), ...}
    """
    global _employee_cache
    from urllib.request import urlopen

    try:
        resp = urlopen(f"{API_SERVER_URL}/api/ip_map", timeout=10)
        raw = resp.read().decode("utf-8")
        resp.close()
        payload = json.loads(raw)
    except Exception as e:
        print(f"⚠️ 获取 IP 部门映射失败: {e}")
        return _employee_cache

    if payload.get("code") != "0":
        print(f"⚠️ API 返回异常: {payload.get('msg', '')}")
        return _employee_cache

    new_cache = {}
    for item in payload.get("data", []):
        ip = item.get("ip", "")
        name = item.get("name", "")
        dept = item.get("department", "")
        if ip:
            new_cache[ip] = (name, dept)

    _employee_cache = new_cache
    print(f"🔗 已从 API 加载 {len(_employee_cache)} 条 IP→员工映射")
    return _employee_cache


def lookup_employee(src_ip: str) -> tuple:
    """
    查询源 IP 对应的员工姓名和部门（从缓存中查找）。
    Returns: (employee_name: str, department: str)
    """
    return _employee_cache.get(src_ip, ("", ""))


# ============================================================
# 4. 核心：遍历冷表，与热表合并（增加 GeoIP + 员工信息丰富）
# ============================================================
def build_row(hash_key, src_ip, dst_ip, sp, dp, proto,
              src_tag, sp_tag, dp_tag,
              accumulated_pkts, accumulated_bytes,
              global_pps, global_bps,
              avg_entropy, max_entropy, min_entropy,
              country="", employee="", department="") -> dict:
    """构建统一的结果行"""
    return {
        "hash_idx": hash_key,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": sp,
        "dst_port": dp,
        "protocol": proto,
        "src_tag": src_tag,
        "sp_tag": sp_tag,
        "dp_tag": dp_tag,
        "accumulated_pkts": accumulated_pkts,
        "accumulated_bytes": accumulated_bytes,
        "global_pps": global_pps,
        "global_bps": global_bps,
        "avg_entropy": avg_entropy,
        "max_entropy": max_entropy,
        "min_entropy": min_entropy,
        "country": country,
        "employee": employee,
        "department": department,
    }


def process_tables(unanalyzed_data: dict, analyzed_data: dict) -> dict:
    """
    遍历冷表，解析第六位原数据，与热表合并后返回新结果表。
    冷表和热表均只读，不做任何修改。
    """
    result_table = {}

    for hash_key, cold_entry in unanalyzed_data.items():
        hash_key_str = str(hash_key)

        if len(cold_entry) < 6:
            continue
        raw_hex = cold_entry[5]
        cold = parse_raw_p4_hex(raw_hex)

        if cold["pkts"] == 0 and cold["bytes"] == 0:
            continue

        hot = analyzed_data.get(hash_key_str)

        if hot is not None:
            # ============================================
            # 情况 A：热表中存在 —— 冷热合并
            # ============================================
            new_pkts = hot[8] + cold["pkts"]
            new_bytes = hot[9] + cold["bytes"]

            if new_pkts > 0:
                new_avg_entropy = round(
                    (hot[16] * hot[8] + cold["avg_entropy"] * cold["pkts"]) / new_pkts, 2
                )
            else:
                new_avg_entropy = 0.0

            src_ip = hot[0]
            dst_ip = hot[1]

            result_table[hash_key_str] = build_row(
                hash_key,
                src_ip, dst_ip, hot[2], hot[3], hot[4],
                hot[5], hot[6], hot[7],
                new_pkts, new_bytes,
                new_pkts // 100, new_bytes // 100,
                new_avg_entropy,
                max(hot[17], cold["max_e"]),
                min(hot[18], cold["min_e"]),
            )

        else:
            # ============================================
            # 情况 B：热表中不存在 —— 纯冷表数据
            # ============================================
            src_ip, dst_ip, sp, dp, proto = cold_entry[0:5]

            result_table[hash_key_str] = build_row(
                hash_key,
                src_ip, dst_ip, sp, dp, proto,
                5, 5, 5,
                cold["pkts"], cold["bytes"],
                cold["pkts"] // 100, cold["bytes"] // 100,
                cold["avg_entropy"],
                cold["max_e"],
                cold["min_e"],
            )

    # ============================================
    # 丰富阶段：GeoIP + 员工信息
    # ============================================
    for row in result_table.values():
        row["country"] = lookup_country(row["dst_ip"])
        employee, department = lookup_employee(row["src_ip"])
        row["employee"] = employee
        row["department"] = department

    return result_table


# ============================================================
# 5. 数据库写入（零拷贝：queue.Queue + 后台攒批线程）
# ============================================================
# 旧版的共享内存方案（SHM_NAME/MAX_PACKETS/PACKET_SIZE/HEADER_SIZE）
# 已被移除，改为进程内 queue.Queue 直传 dict。
# 数据流: ColdTableProcessor → queue.Queue → DB写入线程 → MySQL
# dict 直接引用传递，无 JSON 序列化，无内存拷贝。
# 详见 database/writer.py

from database.writer import start_db_writer, stop_db_writer


# ============================================================
# 6. UDP 接收与主循环
# ============================================================
class ColdTableProcessor:
    """监听 UDP 端口，接收冷/热表，合并后写入数据库（零拷贝 queue.Queue）。"""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(5.0)
        self.running = True
        self.lock = threading.Lock()
        self._last_employee_refresh = 0

        # 启动后台数据库写入线程（零拷贝 queue.Queue）
        self.write_queue, self.stop_event = start_db_writer()

    def handle_payload(self, data: bytes):
        try:
            payload = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError as e:
            print(f"❌ JSON 解析失败: {e}")
            return

        unanalyzed = payload.get("unanalyzed_data", {})
        analyzed = payload.get("analyzed_data", {})

        print(f"📥 冷表 {len(unanalyzed)} 条, 热表 {len(analyzed)} 条")

        with self.lock:
            result = process_tables(unanalyzed, analyzed)
            if result:
                # dict 直接入队，零拷贝（引用传递，无 JSON 序列化）
                for row in result.values():
                    self.write_queue.put(row)
                print(f"   📤 已入队 {len(result)} 条 (queue.Queue → DB攒批写入)")

            enriched = sum(1 for r in result.values() if r.get("country") or r.get("employee"))
            print(f"📊 输出 {len(result)} 条记录 (含 GeoIP/员工信息: {enriched} 条)")

    def run(self):
        try:
            self.sock.bind((UDP_LISTEN_IP, UDP_LISTEN_PORT))
        except OSError as e:
            print(f"❌ 绑定 UDP {UDP_LISTEN_IP}:{UDP_LISTEN_PORT} 失败: {e}")
            return

        # 预加载 GeoIP
        _init_geoip()
        # 预加载员工信息
        fetch_ip_dept_map()

        print(f"🚀 监听 UDP {UDP_LISTEN_IP}:{UDP_LISTEN_PORT}")
        print(f"   写入方式: queue.Queue → DB攒批写入（零拷贝，无JSON序列化）")
        print(f"   员工库: {API_SERVER_URL}/api/ip_map")

        import time
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
                print(f"📡 收到来自 {addr}，{len(data)} 字节")
                self.handle_payload(data)
            except socket.timeout:
                # 每 10 分钟刷新员工缓存
                now = time.time()
                if now - self._last_employee_refresh > 600:
                    fetch_ip_dept_map()
                    self._last_employee_refresh = now
                continue
            except Exception as e:
                print(f"⚠️ 异常: {e}")

        self.sock.close()
        stop_db_writer(self.stop_event)
        print("🛑 已停止")


if __name__ == "__main__":
    processor = ColdTableProcessor()
    try:
        processor.run()
    except KeyboardInterrupt:
        processor.running = False
        print("\n🛑 收到中断信号，退出...")
