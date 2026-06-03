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
$payload = json_decode($input, true);

if (!$payload || !isset($payload['original']) || !isset($payload['updated'])) {
    echo json_encode(['code' => 1, 'msg' => '无效的数据', 'input' => $input]);
    exit;
}

$originalNumber = $payload['original']['number'];
$updated = $payload['updated'];

$jsonFile = __DIR__ . '/../../api/table.json';

if (!file_exists($jsonFile)) {
    echo json_encode(['code' => 1, 'msg' => '数据文件不存在']);
    exit;
}

$content = file_get_contents($jsonFile);
$wrapper = json_decode($content, true);

if (!$wrapper || !isset($wrapper['data'])) {
    echo json_encode(['code' => 1, 'msg' => '数据格式错误']);
    exit;
}

$found = false;
foreach ($wrapper['data'] as &$item) {
    if ($item['number'] === $originalNumber) {
        $item = $updated; // 覆盖整条记录
        $found = true;
        break;
    }
}
unset($item);

if (!$found) {
    echo json_encode(['code' => 1, 'msg' => '未找到原始记录', 'original_number' => $originalNumber]);
    exit;
}

file_put_contents($jsonFile, json_encode($wrapper, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));

// 通知 Python 端同步更新
$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => 'http://127.0.0.1:5000/api/update',
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => $input,
    CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 5,
]);
curl_exec($ch);
curl_close($ch);

echo json_encode(['code' => 0, 'msg' => '更新成功']);
