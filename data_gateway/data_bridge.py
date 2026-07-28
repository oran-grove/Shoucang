# -*- coding: utf-8 -*-
"""
流量数据处理器：从 UDP 9999 接收流量数据 JSON，
遍历未分析流解析第六位 P4 寄存器原始数据，与已分析流合并后写入数据库。
内置零拷贝写入：queue.Queue → DB背景攒批线程，无JSON序列化，无内存拷贝。
独立于原代码运行，不修改任何原有文件。

合并规则（未分析流 hash_idx 在已分析流中存在）：
  - 五元组、资产标签：保持不变（取自已分析流）
  - 历史总累计包   = 已分析流[8]  + 未分析流.pkts
  - 历史总累计字节 = 已分析流[9]  + 未分析流.bytes
  - 全局PPS        = 更新后总包 // 100
  - 全局BPS        = 更新后总字节 // 100
  - 历史均熵       = (已分析流均熵 * 已分析流总包 + 未分析流均熵 * 未分析流总包) / 更新后总包
  - 历史最高熵     = max(已分析流[17], 未分析流.max_e)
  - 历史最低熵     = min(已分析流[18], 未分析流.min_e)
  - 删除：初始时钟[10]、上次时钟[11]、瞬时PPS[12]、瞬时BPS[14]、reason[19]、Normal[20]

不在已分析流中：
  - 五元组取自未分析流，资产标签默认 5，其余取未分析流解析值
"""

import logging
import threading
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

# ============================================================
# 0. 双缓冲通知机制（data_packer → data_bridge）
# ============================================================
_data_ready_event = threading.Event()


def notify_data_ready():
    """由 data_packer.process_pulled_registers() 调用，通知有新数据就绪"""
    _data_ready_event.set()

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
# 1. IP 威胁评分（复用 database 模块的黑白名单缓存）
# ============================================================
def _get_ip_score(ip: str) -> float:
    """返回 IP 威胁分数 0.0~10.0，查询顺序：白名单 → 黑名单(按等级) → 内网/外网"""
    if is_whitelisted(ip):
        return 0.0
    if is_blacklisted(ip):
        from database import get_blacklist_threat_level
        level = get_blacklist_threat_level(ip)
        return {"高": 9.5, "中": 8.5, "低": 7.5}.get(level, 9.5)
    if ip.startswith(("10.", "192.168.", "172.", "127.")):
        return 3.0
    return 6.0


# ============================================================
# 2. 端口威胁评分（常驻字典，无需查库）
# ============================================================
_PORT_LABELS = {
    4444: 10, 3333: 10, 1337: 10, 31337: 10,
    6666:  9, 6667:  9, 6697:  9, 9999:  8,
    53:    9,   # DNS 隧道
    22:    8, 21: 7, 3389: 7, 5900: 7, 5901: 7, 23: 6,
    25:    6, 465: 6, 587: 6,
    110:   5, 995: 5, 143: 5, 993: 5,
    135:   5, 139: 5, 445: 5, 1433: 5, 3306: 5,
    1521:  5, 5432: 5, 27017: 5, 6379: 5,
    8080:  4, 8443: 4, 9090: 4, 1080: 4, 3128: 4, 8888: 3,
    80:    2, 443: 2,
    123:   1, 161: 1, 162: 1, 389: 1, 636: 1, 514: 1,
}


def _get_port_score(port: int) -> int:
    """返回端口威胁分数 0~10"""
    if port in _PORT_LABELS:
        return _PORT_LABELS[port]
    if port > 49151:
        return 5
    if port > 1024:
        return 3
    return 1


# ============================================================
# 3. P4 寄存器原始数据解析
# ============================================================

# MySQL traffic_log.avg_entropy 列类型为 DECIMAL(10,4)，最大 999999.9999
_MAX_AVG_ENTROPY = 999999.9999


def _clamp_entropy(value: float) -> float:
    """将 avg_entropy 钳位到 MySQL DECIMAL(10,4) 安全范围。

    P4 寄存器累加值在 hash 碰撞或长时间运行后可能溢出，
    导致 sum_e/pkts 计算出天文数字，超出列类型范围。
    """
    if value > _MAX_AVG_ENTROPY or value < 0:
        return 0.0
    return value


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
    avg_entropy = _clamp_entropy(avg_entropy)

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
        logger.info("GeoIP 数据库已加载: %s", GEOIP_DB_PATH)
    except ImportError:
        logger.warning("maxminddb 未安装，请执行: pip install maxminddb")
    except FileNotFoundError:
        logger.warning("GeoIP 数据库文件未找到: %s", GEOIP_DB_PATH)
    except Exception as e:
        logger.warning("GeoIP 初始化失败: %s", e)


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

    logger.info("正在下载 GeoIP 数据库: %s", GEOIP_DOWNLOAD_URL)
    try:
        resp = urlopen(GEOIP_DOWNLOAD_URL, timeout=120)
        with open(GEOIP_GZ_TEMP, "wb") as f:
            shutil.copyfileobj(resp, f)
        resp.close()
    except Exception as e:
        logger.error("GeoIP 下载失败: %s", e)
        return False

    # 先释放当前 GeoIP reader 的文件句柄（Windows 上 mmdb 文件被 mmap 锁定）
    _close_geoip()

    logger.info("正在解压 GeoIP 数据库...")
    new_path = GEOIP_DB_PATH + ".new"
    try:
        # 将下载内容读入内存
        with open(GEOIP_GZ_TEMP, "rb") as f:
            raw = f.read()

        # 检测是否为 gzip 格式（magic: 0x1f 0x8b）
        # urllib 可能已透明解压 Content-Encoding，导致存下来的是裸 mmdb
        if raw[:2] == b'\x1f\x8b':
            logger.info("检测到 gzip 格式，正在解压...")
            raw = gzip.decompress(raw)
        else:
            logger.info("数据已解压，直接写入...")

        # 先写入临时文件，再 os.replace 原子替换，避免 Windows mmap 残留锁
        with open(new_path, "wb") as f_out:
            f_out.write(raw)
        import os as _os
        try:
            _os.replace(new_path, GEOIP_DB_PATH)
        except PermissionError:
            _os.remove(GEOIP_DB_PATH)
            _os.rename(new_path, GEOIP_DB_PATH)
        logger.info("GeoIP 数据库已更新: %s", GEOIP_DB_PATH)
    except Exception as e:
        logger.error("GeoIP 解压失败: %s", e)
        # 清理失败的临时文件
        try:
            import os as _os2
            _os2.remove(new_path)
        except Exception:
            pass
        return False
    finally:
        # 重新加载 reader
        _init_geoip()
        try:
            import os as _os3
            _os3.remove(GEOIP_GZ_TEMP)
        except Exception:
            pass
    return True


# ============================================================
# 3. 员工信息查询（源 IP → 员工名 + 部门）
#    统一通过 database 模块获取（MySQL ip_dept_map 表）
#    不再直接调用 Flask API，彻底解耦各模块间依赖
# ============================================================
from database import lookup_employee, get_ip_dept_map, load_lists_from_db, is_blacklisted, is_whitelisted


def refresh_employee_cache() -> dict:
    """
    刷新 IP-部门映射：从 database 模块重新加载 MySQL ip_dept_map 表。
    所有模块统一使用 database 模块提供的接口，不私自操作数据库。
    返回最新的 {ip: (name, department), ...} 字典。
    """
    load_lists_from_db()
    return get_ip_dept_map()


# ============================================================
# 4. 核心：遍历未分析流，与已分析流合并（增加 GeoIP + 员工信息丰富）
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
        "avg_entropy": _clamp_entropy(avg_entropy),
        "max_entropy": max_entropy,
        "min_entropy": min_entropy,
        "country": country,
        "employee": employee,
        "department": department,
        "packet_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def process_tables(unanalyzed_data: dict, analyzed_data: dict) -> dict:
    """
    遍历未分析流，解析第六位原数据，与已分析流合并后返回新结果表。
    未分析流和已分析流均只读，不做任何修改。
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

        hot = analyzed_data.get(hash_key)

        if hot is not None:
            # ============================================
            # 情况 A：已分析流中存在 —— 流合并
            # ============================================
            new_pkts = hot[8] + cold["pkts"]
            new_bytes = hot[9] + cold["bytes"]

            if new_pkts > 0:
                new_avg_entropy = round(
                    (hot[16] * hot[8] + cold["avg_entropy"] * cold["pkts"]) / new_pkts, 2
                )
            else:
                new_avg_entropy = 0.0
            # 防止热表累积脏值导致合并后溢出 DECIMAL(10,4)
            new_avg_entropy = _clamp_entropy(new_avg_entropy)

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
            # 情况 B：已分析流中不存在 —— 纯未分析流数据
            # ============================================
            src_ip, dst_ip, sp, dp, proto = cold_entry[0:5]

            result_table[hash_key_str] = build_row(
                hash_key,
                src_ip, dst_ip, sp, dp, proto,
                _get_ip_score(src_ip), _get_port_score(sp), _get_port_score(dp),
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
# 数据流: DataBridge → queue.Queue → DB写入线程 → MySQL
# dict 直接引用传递，无 JSON 序列化，无内存拷贝。
# 详见 database/writer.py

from database.writer import start_db_writer, stop_db_writer


# ============================================================
# 6. UDP 接收与主循环
# ============================================================
class DataBridge:
    """UDP 数据桥：接收流量数据，解码合并，GeoIP+员工富化，零拷贝入 DB。"""

    def __init__(self):
        self.running = True
        self.lock = threading.Lock()
        self._last_employee_refresh = 0

        # 启动后台数据库写入线程（零拷贝 queue.Queue）
        self.write_queue, self.stop_event = start_db_writer()

    def _print_rows(self, result: dict):
        """入库前记录每行数据的关键字段，方便调试"""
        for key, row in result.items():
            logger.debug(
                "[hash=%s] %s:%s -> %s:%s proto=%s pkts=%s bytes=%s "
                "entropy(avg/max/min)=%s/%s/%s country=%s employee=%s dept=%s",
                key,
                row.get('src_ip'), row.get('src_port'),
                row.get('dst_ip'), row.get('dst_port'),
                row.get('protocol'),
                row.get('accumulated_pkts'), row.get('accumulated_bytes'),
                row.get('avg_entropy'), row.get('max_entropy'), row.get('min_entropy'),
                row.get('country'), row.get('employee'), row.get('department'),
            )

    def run(self):
        # 预加载 GeoIP
        _init_geoip()
        # 预加载员工信息（通过 database 模块从 MySQL ip_dept_map 表加载）
        refresh_employee_cache()

        logger.info("[数据桥] 双缓冲模式已就绪（从 data_packer 内存直接读取，无UDP/无JSON序列化）")
        logger.info("  写入方式: queue.Queue → DB攒批写入（零拷贝）")
        logger.info("  员工库: MySQL ip_dept_map (通过 database 模块)")

        import time
        while self.running:
            try:
                # 等待 data_packer 通知新数据就绪
                _data_ready_event.wait(timeout=10.0)

                if not _data_ready_event.is_set():
                    # 超时：刷新员工缓存
                    now = time.time()
                    if now - self._last_employee_refresh > 600:
                        refresh_employee_cache()
                        self._last_employee_refresh = now
                    continue

                _data_ready_event.clear()

                # 从双缓冲读取就绪数据
                try:
                    from p4_controller.data_packer import get_ready_pools, clear_ready
                except ImportError:
                    import importlib
                    dp = importlib.import_module("p4_controller.data_packer")
                    get_ready_pools = dp.get_ready_pools
                    clear_ready = dp.clear_ready

                unanalyzed, analyzed = get_ready_pools()
                if not unanalyzed and not analyzed:
                    continue

                logger.info("[数据桥] 未分析流 %d 条, 已分析流 %d 条", len(unanalyzed), len(analyzed))

                with self.lock:
                    result = process_tables(unanalyzed, analyzed)
                    if result:
                        # 入库前记录
                        self._print_rows(result)
                        # dict 直接入队，零拷贝（引用传递，无 JSON 序列化）
                        for row in result.values():
                            self.write_queue.put(row)
                        logger.info("  已入队 %d 条 (queue.Queue → DB攒批写入)", len(result))

                    enriched = sum(1 for r in result.values() if r.get("country") or r.get("employee"))
                    logger.info("输出 %d 条记录 (含 GeoIP/员工信息: %d 条)", len(result), enriched)

                # 清空就绪缓冲，释放给 data_packer 下一轮写入
                clear_ready()

                # 刷新员工缓存
                now = time.time()
                if now - self._last_employee_refresh > 600:
                    refresh_employee_cache()
                    self._last_employee_refresh = now

            except Exception as e:
                logger.warning("数据桥运行时异常: %s", e)

        stop_db_writer(self.stop_event)
        logger.info("数据桥已停止")


if __name__ == "__main__":
    bridge = DataBridge()
    try:
        bridge.run()
    except KeyboardInterrupt:
        bridge.running = False
        logger.info("收到中断信号，退出...")
