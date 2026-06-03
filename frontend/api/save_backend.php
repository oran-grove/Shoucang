<?php
header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['code' => 405, 'msg' => '仅支持 POST 请求'], JSON_UNESCAPED_UNICODE);
    exit;
}

$configFile = __DIR__ . '/../../config/config_user.json';

if (!file_exists($configFile)) {
    echo json_encode(['code' => 500, 'msg' => '配置文件不存在'], JSON_UNESCAPED_UNICODE);
    exit;
}

$backend = $_POST['backend'] ?? 'deepseek';
$config = json_decode(file_get_contents($configFile), true);

if (!isset($config['backends'][$backend])) {
    echo json_encode(['code' => 500, 'msg' => '后端配置不存在'], JSON_UNESCAPED_UNICODE);
    exit;
}

// 顶层字符串字段
$strFields = ['api_key', 'model_name', 'api_base'];
foreach ($strFields as $field) {
    if (isset($_POST[$field])) {
        $config['backends'][$backend][$field] = strval($_POST[$field]);
    }
}

// 布尔字段
if (isset($_POST['auto_load'])) {
    $config['backends'][$backend]['auto_load'] = filter_var($_POST['auto_load'], FILTER_VALIDATE_BOOLEAN);
}

// load_config 嵌套字段
if (isset($_POST['context_length'])) {
    $config['backends'][$backend]['load_config']['context_length'] = intval($_POST['context_length']);
}
if (isset($_POST['flash_attention'])) {
    $config['backends'][$backend]['load_config']['flash_attention'] = filter_var($_POST['flash_attention'], FILTER_VALIDATE_BOOLEAN);
}

$json = json_encode($config, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
$result = file_put_contents($configFile, $json);

if ($result !== false) {
    echo json_encode(['code' => 0, 'msg' => '保存成功'], JSON_UNESCAPED_UNICODE);
} else {
    echo json_encode(['code' => 500, 'msg' => '保存失败，请检查文件权限'], JSON_UNESCAPED_UNICODE);
}
