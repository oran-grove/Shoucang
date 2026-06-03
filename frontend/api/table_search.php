<?php
header('Content-Type: application/json');

$jsonFile = __DIR__ . '/table.json';

// 每次调用时从 localhost:5000/api/ip_map 更新数据
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'http://127.0.0.1:5000/api/ip_map');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 10);
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Accept: application/json']);
$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($response !== false && $httpCode === 200) {
    $apiResult = json_decode($response, true);
    if (json_last_error() === JSON_ERROR_NONE && isset($apiResult['data']) && is_array($apiResult['data'])) {
        // 过滤掉 created_at 字段，保留 id, number, ip, department, name
        $cleanData = [];
        $skipFields = ['created_at'];
        foreach ($apiResult['data'] as $item) {
            $row = [];
            foreach ($item as $k => $v) {
                if (!in_array($k, $skipFields)) {
                    $row[$k] = $v;
                }
            }
            $cleanData[] = $row;
        }
        $wrapper = [
            'code' => 0,
            'count' => count($cleanData),
            'data'  => $cleanData
        ];
        file_put_contents($jsonFile, json_encode($wrapper, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }
}

if (!file_exists($jsonFile)) {
    echo json_encode(['code' => 1, 'msg' => '数据文件不存在']);
    exit;
}

$content = file_get_contents($jsonFile);
$wrapper = json_decode($content, true);

if (!$wrapper || !isset($wrapper['data'])) {
    echo json_encode(['code' => 0, 'count' => 0, 'data' => []]);
    exit;
}

$data = $wrapper['data'];

// 获取所有非空的搜索参数（排除 layui 分页参数）
$layuiKeys = ['page', 'limit', 'searchParams'];
$filters = [];
foreach ($_GET as $key => $val) {
    $val = trim($val);
    if ($val !== '' && !in_array($key, $layuiKeys)) {
        $filters[$key] = $val;
    }
}

// AND 逻辑：所有非空过滤条件必须同时匹配
if (!empty($filters)) {
    $data = array_values(array_filter($data, function ($item) use ($filters) {
        foreach ($filters as $field => $value) {
            if (!isset($item[$field]) || (string)$item[$field] !== $value) {
                return false;
            }
        }
        return true;
    }));
}

echo json_encode([
    'code' => 0,
    'count' => count($data),
    'data' => $data
]);
