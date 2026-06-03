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
$data = json_decode($input, true);

if (!$data) {
    echo json_encode(['code' => 1, 'msg' => '无效的数据']);
    exit;
}

// 1. 写入 table.json
$jsonFile = __DIR__ . '/../../api/table.json';
$apiDir = dirname($jsonFile);
if (!is_dir($apiDir)) {
    mkdir($apiDir, 0777, true);
}
$wrapper = ['code' => 0, 'count' => 0, 'data' => []];
if (file_exists($jsonFile)) {
    $content = file_get_contents($jsonFile);
    $existing = json_decode($content, true);
    if ($existing && isset($existing['data'])) {
        $wrapper = $existing;
    }
}
$wrapper['data'][] = $data;
$wrapper['count'] = count($wrapper['data']);
file_put_contents($jsonFile, json_encode($wrapper, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => 'http://localhost:5000/api/save',
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => $input,
    CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 5,
]);
$response = curl_exec($ch);
$curlError = curl_error($ch);
curl_close($ch);

echo json_encode([
    'code' => 0,
    'msg' => '保存成功',
    'forward_result' => $response ?: $curlError
]);
