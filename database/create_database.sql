-- ============================================
-- 守藏 - 数据库创建脚本
-- ============================================

-- 1. 创建数据库
DROP DATABASE IF EXISTS insider_threat_db;
CREATE DATABASE insider_threat_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 2. 使用数据库
USE insider_threat_db;

-- ============================================
-- 3. 创建黑名单表 (blacklist)
-- ============================================
CREATE TABLE blacklist (
    id INT AUTO_INCREMENT PRIMARY KEY COMMENT '主键id自增',
    ip_address VARCHAR(45) NOT NULL UNIQUE COMMENT '可疑ip地址',
    threat_level ENUM('低','中','高') NOT NULL COMMENT '威胁等级（低/中/高）',
    reason VARCHAR(100) NOT NULL COMMENT '拉黑原因',
    port INT DEFAULT NULL COMMENT '端口号',
    attack_type VARCHAR(50) DEFAULT NULL COMMENT '攻击类型'
) COMMENT='黑名单表';

-- ============================================
-- 4. 创建 IP-部门映射表 (ip_dept_map)
-- ============================================
CREATE TABLE ip_dept_map (
    id INT AUTO_INCREMENT PRIMARY KEY COMMENT '自增主键',
    number VARCHAR(50) NOT NULL UNIQUE COMMENT '工号',
    ip VARCHAR(45) NOT NULL UNIQUE COMMENT 'ip地址',
    department VARCHAR(100) NOT NULL COMMENT '所属部门',
    name VARCHAR(50) NOT NULL COMMENT '姓名',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间'
) COMMENT='IP部门映射表';

-- ============================================
-- 5. 创建流量日志表 (traffic_log)
-- ============================================
CREATE TABLE traffic_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '自增id',
    src_ip VARCHAR(45) NOT NULL COMMENT '源ip',
    dst_ip VARCHAR(45) NOT NULL COMMENT '目标ip',
    department VARCHAR(50) DEFAULT NULL COMMENT '部门',
    protocol VARCHAR(20) DEFAULT NULL COMMENT '协议',
    packet_time DATETIME NOT NULL COMMENT '包时间',
    traffic_size INT DEFAULT NULL COMMENT '流量大小（已废弃—请使用 accumulated_bytes）',
    is_blocked TINYINT DEFAULT 0 COMMENT '是否拦截',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    entropy DECIMAL(5,4) DEFAULT NULL COMMENT '熵值',
    src_port INT DEFAULT NULL COMMENT '源端口号',
    dst_port INT DEFAULT NULL COMMENT '目标端口',
    src_tag INT DEFAULT NULL COMMENT '源标签',
    sp_tag INT DEFAULT NULL COMMENT 'sp标签',
    dp_tag INT DEFAULT NULL COMMENT 'DP标签',
    accumulated_pkts BIGINT DEFAULT NULL COMMENT '累计包数',
    accumulated_bytes BIGINT DEFAULT NULL COMMENT '累计字节数',
    global_pps BIGINT DEFAULT NULL COMMENT '全局包速率',
    global_bps BIGINT DEFAULT NULL COMMENT '全局比特速率',
    avg_entropy DECIMAL(10,4) DEFAULT NULL COMMENT '平均熵值',
    max_entropy DECIMAL(10,4) DEFAULT NULL COMMENT '最大熵值',
    min_entropy DECIMAL(10,4) DEFAULT NULL COMMENT '最小熵值',
    country VARCHAR(50) DEFAULT NULL COMMENT '国家',
    employee VARCHAR(50) DEFAULT NULL COMMENT '员工',
    hash_idx VARCHAR(100) DEFAULT NULL COMMENT '哈希索引',
    ai_analyzed TINYINT DEFAULT 0 COMMENT 'AI是否已分析(0未分析/1已分析)',
    ai_verdict TINYINT DEFAULT NULL COMMENT 'AI判定(0安全/1可疑/2危险)',
    ai_reasoning TEXT DEFAULT NULL COMMENT 'AI分析理由',

    INDEX idx_src_ip (src_ip),
    INDEX idx_dst_ip (dst_ip),
    INDEX idx_packet_time (packet_time)
) COMMENT='流量日志表';

-- ============================================
-- 6. 创建白名单表 (whitelist)
-- ============================================
CREATE TABLE whitelist (
    id INT AUTO_INCREMENT PRIMARY KEY COMMENT '主键id自增',
    ip_address VARCHAR(45) NOT NULL UNIQUE COMMENT '信任ip地址',
    reason VARCHAR(100) DEFAULT NULL COMMENT '加白原因',
    port INT DEFAULT NULL COMMENT '端口号',
    trust_level VARCHAR(20) DEFAULT NULL COMMENT '信任等级'
) COMMENT='白名单表';