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

$config = json_decode(file_get_contents($configFile), true);

$sections = ['detection', 'correlation', 'judgment', 'feedback'];

foreach ($sections as $section) {
    if (isset($_POST[$section]) && is_array($_POST[$section])) {
        foreach ($_POST[$section] as $key => $value) {
            if (isset($config[$section][$key])) {
                $originalType = gettype($config[$section][$key]);
                switch ($originalType) {
                    case 'integer':
                        $config[$section][$key] = intval($value);
                        break;
                    case 'double':
                        $config[$section][$key] = floatval($value);
                        break;
                    case 'boolean':
                        $config[$section][$key] = filter_var($value, FILTER_VALIDATE_BOOLEAN);
                        break;
                    default:
                        $config[$section][$key] = strval($value);
                        break;
                }
            }
        }
    }
}

$json = json_encode($config, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
$result = file_put_contents($configFile, $json);

if ($result !== false) {
    echo json_encode(['code' => 0, 'msg' => '保存成功'], JSON_UNESCAPED_UNICODE);
} else {
    echo json_encode(['code' => 500, 'msg' => '保存失败，请检查文件权限'], JSON_UNESCAPED_UNICODE);
}
