<?php
/**
 * 统一配置读取代理
 * 从项目根目录 config/ 读取 JSON 配置文件并返回
 * 替代前端直接 read config_user.json
 */
header('Content-Type: application/json; charset=utf-8');

$configFile = __DIR__ . '/../../config/config_user.json';

if (!file_exists($configFile)) {
    http_response_code(404);
    echo json_encode(['error' => '配置文件不存在'], JSON_UNESCAPED_UNICODE);
    exit;
}

readfile($configFile);