<?php
header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['code' => 405, 'msg' => '仅支持 POST 请求'], JSON_UNESCAPED_UNICODE);
    exit;
}

$defaultFile = __DIR__ . '/../../config/config_default.json';
$userFile = __DIR__ . '/../../config/config_user.json';

if (!file_exists($defaultFile)) {
    echo json_encode(['code' => 500, 'msg' => '默认配置文件不存在'], JSON_UNESCAPED_UNICODE);
    exit;
}

$result = copy($defaultFile, $userFile);

if ($result) {
    echo json_encode(['code' => 0, 'msg' => '已恢复默认配置'], JSON_UNESCAPED_UNICODE);
} else {
    echo json_encode(['code' => 500, 'msg' => '恢复失败，请检查文件权限'], JSON_UNESCAPED_UNICODE);
}
