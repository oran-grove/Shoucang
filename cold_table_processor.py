# -*- coding: utf-8 -*-
"""
冷表处理器：从共享内存双缓冲读取原代码发送的冷/热表，
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

import logging
import threading
from typing import Any

logger = logging.getLogger(__name__)

# ============================================================
# 0. 可配置参数
# ============================================================

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

    logger.info("正在解压 GeoIP 数据库...")
    try:
        with gzip.open(GEOIP_GZ_TEMP, "rb") as f_in, \
             open(GEOIP_DB_PATH, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
        logger.info("GeoIP 数据库已更新: %s", GEOIP_DB_PATH)
    except Exception as e:
        logger.error("GeoIP 解压失败: %s", e)
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
# 3. 员工信息查询（源 IP → 员工名 + 部门）
#    统一通过 database 模块获取（MySQL ip_dept_map 表）
#    不再直接调用 Flask API，彻底解耦各模块间依赖
# ============================================================
from database import lookup_employee, get_ip_dept_map, reload_lists_after_change


def refresh_employee_cache() -> dict:
    """
    刷新 IP-部门映射：从 database 模块重新加载 MySQL ip_dept_map 表。
    所有模块统一使用 database 模块提供的接口，不私自操作数据库。
    返回最新的 {ip: (name, department), ...} 字典。
    """
    reload_lists_after_change()
    return get_ip_dept_map()


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
# 数据流: 共享内存 → ColdTableProcessor → queue.Queue → DB写入线程 → MySQL
# dict 直接引用传递，无 JSON 序列化，无内存拷贝。
# 详见 database/writer.py

from database.writer import start_db_writer, stop_db_writer


# ============================================================
# 6. 共享内存接收与主循环（替代 UDP）
# ============================================================
class ColdTableProcessor:
    """通过共享内存双缓冲接收冷/热表，合并后写入数据库（零拷贝 queue.Queue）。"""

    def __init__(self):
        self.running = True
        self.lock = threading.Lock()
        self._last_employee_refresh = 0

        # 启动后台数据库写入线程（零拷贝 queue.Queue）
        self.write_queue, self.stop_event = start_db_writer()

    def handle_payload(self, unanalyzed: dict, analyzed: dict):
        cold_count = len(unanalyzed)
        hot_count = len(analyzed)
        logger.info("收到冷表 %d 条, 热表 %d 条", cold_count, hot_count)

        with self.lock:
            result = process_tables(unanalyzed, analyzed)
            if result:
                for row in result.values():
                    self.write_queue.put(row)
                logger.info("已入队 %d 条 (queue.Queue → DB攒批写入)", len(result))

            enriched = sum(1 for r in result.values() if r.get("country") or r.get("employee"))
            logger.info("输出 %d 条记录 (含 GeoIP/员工信息: %d 条)", len(result), enriched)

    def run(self):
        # 预加载 GeoIP
        _init_geoip()
        # 预加载员工信息（通过 database 模块从 MySQL ip_dept_map 表加载）
        refresh_employee_cache()

        # 🌟 打开共享内存消费者
        from shared_pools import SharedPoolConsumer
        consumer = SharedPoolConsumer()

        logger.info("共享内存双缓冲消费者已就绪")
        logger.info("  读取方式: 共享内存轮询（零网络开销）")
        logger.info("  写入方式: queue.Queue → DB攒批写入（零拷贝，无JSON序列化）")
        logger.info("  员工库: MySQL ip_dept_map (通过 database 模块)")

        import time
        while self.running:
            try:
                # 阻塞等待直到生产者写入新数据（超时 105 秒 > 100 秒周期）
                unanalyzed, analyzed = consumer.get(timeout=105.0)

                if unanalyzed or analyzed:
                    self.handle_payload(unanalyzed, analyzed)

                # 每 10 分钟刷新员工缓存
                now = time.time()
                if now - self._last_employee_refresh > 600:
                    refresh_employee_cache()
                    self._last_employee_refresh = now

            except Exception as e:
                logger.warning("冷表处理异常: %s", e)
                time.sleep(1)

        consumer.close()
        stop_db_writer(self.stop_event)
        logger.info("冷表处理器已停止")


if __name__ == "__main__":
    processor = ColdTableProcessor()
    try:
        processor.run()
    except KeyboardInterrupt:
        processor.running = False
        logger.info("收到中断信号，退出...")
