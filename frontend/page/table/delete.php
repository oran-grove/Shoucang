<?php
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Allow: POST, OPTIONS');
    echo '405 Method Not Allowed';
    exit;
}

header('Content-Type: application/json');

$input = file_get_contents('php://input');
$toDelete = json_decode($input, true);

if (!$toDelete || !is_array($toDelete)) {
    echo json_encode(['code' => 1, 'msg' => '无效的数据', 'debug_input' => $input]);
    exit;
}

$jsonFile = __DIR__ . '/../../api/table.json';

if (!file_exists($jsonFile)) {
    echo json_encode(['code' => 1, 'msg' => '数据文件不存在', 'path' => $jsonFile]);
    exit;
}

$content = file_get_contents($jsonFile);
$wrapper = json_decode($content, true);

if (!$wrapper || !isset($wrapper['data'])) {
    echo json_encode(['code' => 1, 'msg' => '数据格式错误']);
    exit;
}

// 提取待删除的 number 集合
$deleteNumbers = array_column($toDelete, 'number');

if (empty($deleteNumbers)) {
    echo json_encode(['code' => 1, 'msg' => '未找到 number 字段', 'received' => $toDelete]);
    exit;
}

// 过滤掉匹配的记录
$before = count($wrapper['data']);
$wrapper['data'] = array_values(array_filter($wrapper['data'], function ($item) use ($deleteNumbers) {
    return !in_array($item['number'], $deleteNumbers);
}));
$after = count($wrapper['data']);
$deleted = $before - $after;

$wrapper['count'] = $after;
$bytes = file_put_contents($jsonFile, json_encode($wrapper, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));

if ($bytes === false) {
    echo json_encode(['code' => 1, 'msg' => '写入文件失败', 'path' => $jsonFile]);
    exit;
}

// 通知 Python 端同步删除
$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => 'http://127.0.0.1:5000/api/delete',
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => $input,
    CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 5,
]);
curl_exec($ch);
curl_close($ch);

echo json_encode([
    'code' => 0,
    'msg' => '删除成功',
    'count' => $after,
    'deleted' => $deleted,
    'delete_numbers' => $deleteNumbers
]);
