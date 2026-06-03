"""
消费者 - 最简版
从共享内存读取数据包并存入数据库
共享内存不存在时直接打印，不等待
"""

import json
import pymysql
from datetime import datetime
from multiprocessing import shared_memory

# ==================== 数据库配置 ====================
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '2005jjayyayyAX',  # ← 改成你的MySQL密码
    'database': 'insider_threat_db',
    'charset': 'utf8mb4'
}

# ==================== 共享内存配置 ====================
SHM_NAME = "packet_queue"
MAX_PACKETS = 1000
PACKET_SIZE = 4096
HEADER_SIZE = 12


# ==================== 存储函数 ====================
def store_packet(packet):
    """存入数据库 - 按写入方字段接收"""
    conn = pymysql.connect(**DB_CONFIG)
    cursor = conn.cursor()
    try:
        # 获取表所有字段
        cursor.execute("DESCRIBE traffic_log")
        table_fields = [row[0] for row in cursor.fetchall()]

        # 取 packet 中所有在表中存在的字段
        write_fields = [f for f in packet.keys() if f in table_fields]

        if not write_fields:
            print(f"   ⚠️ 没有匹配的字段，跳过")
            return

        # 构建 INSERT 语句
        placeholders = ', '.join(['%s'] * len(write_fields))
        fields_str = ', '.join(write_fields)
        sql = f"INSERT INTO traffic_log ({fields_str}) VALUES ({placeholders})"

        # 获取对应的值
        values = [packet.get(field) for field in write_fields]

        cursor.execute(sql, values)
        conn.commit()
        print(f"   ✅ 已入库: {packet.get('src_ip')} -> {packet.get('dst_ip')}")
    except Exception as e:
        print(f"   ❌ 入库失败: {e}")
    finally:
        conn.close()


# ==================== 读取共享内存 ====================
def read_from_shared_memory():
    """读取共享内存中的数据"""
    # 连接共享内存
    try:
        shm = shared_memory.SharedMemory(name=SHM_NAME, create=False)
        print(f"✅ 已连接到共享内存: {SHM_NAME}")
    except FileNotFoundError:
        print(f"❌ 共享内存 {SHM_NAME} 不存在")
        print("   请确保同学1已经启动生产者程序")
        return None
    except Exception as e:
        print(f"❌ 连接失败: {e}")
        return None

    # 获取数据包数量
    try:
        count = int.from_bytes(shm.buf[8:12], byteorder='little')
        print(f"📊 待处理数据包数量: {count}")

        if count == 0:
            print("没有待处理的数据包")
            shm.close()
            return []

        # 读取所有数据包
        packets = []
        for _ in range(count):
            read_pos = int.from_bytes(shm.buf[4:8], byteorder='little')
            offset = HEADER_SIZE + read_pos * PACKET_SIZE

            data_len = int.from_bytes(shm.buf[offset:offset+4], byteorder='little')
            data = bytes(shm.buf[offset+4:offset+4+data_len])

            # 更新读指针
            new_read_pos = (read_pos + 1) % MAX_PACKETS
            shm.buf[4:8] = new_read_pos.to_bytes(4, byteorder='little')

            packets.append(json.loads(data.decode('utf-8')))

        # 更新count为0
        shm.buf[8:12] = (0).to_bytes(4, byteorder='little')

        shm.close()
        return packets

    except Exception as e:
        print(f"❌ 读取失败: {e}")
        shm.close()
        return []


# ==================== 主程序 ====================
if __name__ == "__main__":
    print("=" * 50)
    print("消费者启动")
    print("=" * 50)

    # 读取共享内存
    packets = read_from_shared_memory()

    if packets is None:
        print("程序退出")
    elif len(packets) == 0:
        print("没有数据，程序退出")
    else:
        print(f"\n📥 共读取 {len(packets)} 个数据包")
        print("开始入库...\n")
        for packet in packets:
            store_packet(packet)
        print(f"\n✅ 完成，共入库 {len(packets)} 条")