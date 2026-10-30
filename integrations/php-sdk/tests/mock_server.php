<?php
/**
 * 门面 mock 服务端（php -S 路由脚本），只用于冒烟测试。
 * 独立于 SDK 重新实现验签（按服务端：从原始 query 串解析再规范化），
 * 校验 nonce 防重放、写请求 Idempotency-Key；状态存 MOCK_STATE 指向的 JSON 文件。
 * 特殊：external_service_id 以 "flaky" 开头的第一次 suspend 返回 503，测试重试。
 */
const MOCK_KEY = 'cbb_AAAAAAAAAAAAAAAAAAAAAA';
const MOCK_SECRET = 'cbs_mock-secret-for-smoke-tests-only';

$stateFile = getenv('MOCK_STATE') ?: sys_get_temp_dir() . '/cdnca-mock-state.json';
$fp = fopen($stateFile, 'c+');
flock($fp, LOCK_EX);
$state = json_decode(stream_get_contents($fp), true) ?: ['nonces' => [], 'services' => [], 'idem' => [], 'calls' => []];

function done($status, $payload)
{
    global $fp, $state;
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($state));
    flock($fp, LOCK_UN);
    http_response_code($status);
    header('Content-Type: application/json');
    header('X-Request-ID: mock-' . substr(md5(uniqid('', true)), 0, 8));
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
function fail($status, $code, $message)
{
    done($status, ['error' => ['code' => $code, 'message' => $message, 'request_id' => 'req-' . $code]]);
}
function header_value($name)
{
    $key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
    return isset($_SERVER[$key]) ? $_SERVER[$key] : null;
}

// ---- 验签（Go url.ParseQuery 语义：+ 和 %20 都是空格）
$method = $_SERVER['REQUEST_METHOD'];
$uri = $_SERVER['REQUEST_URI'];
$path = parse_url($uri, PHP_URL_PATH);
$raw = (string)parse_url($uri, PHP_URL_QUERY);
$pairs = [];
foreach ($raw === '' ? [] : explode('&', $raw) as $part) {
    $kv = explode('=', $part, 2);
    $pairs[] = [urldecode($kv[0]), urldecode(isset($kv[1]) ? $kv[1] : '')];
}
usort($pairs, function ($a, $b) { return strcmp($a[0], $b[0]) ?: strcmp($a[1], $b[1]); });
$canonical = implode('&', array_map(function ($p) { return rawurlencode($p[0]) . '=' . rawurlencode($p[1]); }, $pairs));
$body = file_get_contents('php://input');
$ts = header_value('X-Cdnca-Timestamp');
$nonce = header_value('X-Cdnca-Nonce');
$sts = implode("\n", [$method, $path, $canonical, $ts, $nonce, hash('sha256', $body)]);
if (header_value('X-Cdnca-Bridge-Key') !== MOCK_KEY || abs(time() - (int)$ts) > 300
    || !preg_match('/^[A-Za-z0-9_-]{16,64}$/', (string)$nonce)
    || !hash_equals(hash_hmac('sha256', $sts, MOCK_SECRET), (string)header_value('X-Cdnca-Signature'))) {
    fail(401, 'unauthorized', 'Unauthorized');
}
if (isset($state['nonces'][$nonce])) {
    fail(401, 'unauthorized', 'Unauthorized');
}
$state['nonces'][$nonce] = time();
$idem = header_value('Idempotency-Key');
if ($method === 'POST' && !preg_match('/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/', (string)$idem)) {
    fail(400, 'bridge_validation_error', 'Idempotency-Key required');
}
$input = $body === '' ? [] : json_decode($body, true);
$state['calls'][] = ['method' => $method, 'path' => $path, 'idem' => $idem];

$prefix = '/v1/billing-bridge';
if (strpos($path, $prefix) !== 0) {
    fail(404, 'not_found', 'Not Found');
}
$route = substr($path, strlen($prefix));

if ($method === 'GET' && $route === '/ping') {
    done(200, ['data' => ['owner_kind' => 'platform', 'owner_scope_id' => 'scope-1', 'module_enabled' => true, 'server_time' => gmdate('c')]]);
}
if ($method === 'GET' && $route === '/products') {
    done(200, ['data' => [['id' => 'prod-basic', 'revision' => 3, 'name' => '基础版', 'periods' => [['period' => 'month', 'price_minor' => 9900], ['period' => 'year', 'price_minor' => 99000]], 'site_limit' => 10, 'node_limit' => 0]]]);
}
if ($method === 'GET' && $route === '/usage') {
    parse_str($raw, $q);
    $rows = [];
    foreach (explode(',', (string)$q['ids']) as $id) {
        if (isset($state['services'][$id])) {
            $rows[] = ['external_service_id' => $id, 'period_start' => '2026-10-01T00:00:00Z', 'period_end' => '2026-11-01T00:00:00Z',
                'traffic_bytes' => 5368709120, 'peak_bandwidth_bps' => 1000000, 'bandwidth_95th_bps' => 800000, 'finalized_through' => gmdate('c')];
        }
    }
    done(200, ['data' => $rows]);
}
if ($method === 'POST' && $route === '/services') {
    $sid = $input['external_service_id'];
    if (isset($state['services'][$sid])) {
        $svc = $state['services'][$sid];
        if ($svc['product']['id'] !== $input['product_id']) {
            fail(409, 'bridge_service_conflict', 'service exists with different parameters');
        }
        $svc['created'] = false;
        done(200, ['data' => $svc]);
    }
    if ($input['product_id'] !== 'prod-basic') {
        fail(404, 'bridge_product_not_found', 'product not found');
    }
    $svc = ['external_system' => 'whmcs', 'external_service_id' => $sid, 'external_client_id' => $input['external_client_id'],
        'status' => 'active', 'product' => ['id' => 'prod-basic', 'revision' => 3, 'name' => '基础版'], 'period' => $input['period'],
        'starts_at' => gmdate('c'), 'ends_at' => gmdate('c', time() + 30 * 86400), 'suspended_at' => null,
        'user' => ['id' => 'user-' . $input['external_client_id'], 'username' => 'whmcs_' . $input['external_client_id'], 'email' => $input['client']['email']],
        'console_url' => 'https://cdn.example.com'];
    $state['services'][$sid] = $svc;
    $svc['created'] = true;
    done(201, ['data' => $svc]);
}
if (preg_match('#^/services/(whmcs|zjmf|zjmf_cbap)/([^/]+)(?:/([a-z]+))?$#', $route, $m)) {
    $sid = rawurldecode($m[2]);
    $action = isset($m[3]) ? $m[3] : '';
    if (!isset($state['services'][$sid])) {
        fail(404, 'bridge_service_not_found', 'service not found');
    }
    $svc = &$state['services'][$sid];
    if ($action === 'suspend' && strpos($sid, 'flaky') === 0 && empty($state['flaked'][$sid])) {
        $state['flaked'][$sid] = $idem;
        fail(503, 'unavailable', 'Service Unavailable');
    }
    if ($method === 'GET' && $action === '') {
        done(200, ['data' => $svc + ['created' => false]]);
    }
    if ($method === 'POST' && $svc['status'] === 'terminated' && $action !== 'terminate') {
        fail(409, 'bridge_service_terminated', 'service terminated');
    }
    switch ($method === 'POST' ? $action : '') {
        case 'suspend':
            $svc['status'] = 'suspended';
            $svc['suspended_at'] = gmdate('c');
            done(200, ['data' => $svc + ['created' => false]]);
        case 'unsuspend':
            $svc['status'] = 'active';
            $svc['suspended_at'] = null;
            done(200, ['data' => $svc + ['created' => false]]);
        case 'renew':
            $svc['ends_at'] = gmdate('c', strtotime($svc['ends_at']) + 30 * 86400);
            done(200, ['data' => $svc + ['created' => false]]);
        case 'change':
            $svc['product']['id'] = $input['product_id'];
            done(200, ['data' => $svc + ['created' => false]]);
        case 'terminate':
            $svc['status'] = 'terminated';
            done(200, ['data' => $svc + ['created' => false]]);
        case 'sso':
            if ($svc['status'] !== 'active') {
                fail(409, 'bridge_validation_error', 'service not active');
            }
            done(200, ['data' => ['url' => 'https://cdn.example.com/sso/bridge?ticket=t' . bin2hex(random_bytes(8)), 'expires_at' => gmdate('c', time() + 60)]]);
    }
}
fail(404, 'not_found', 'Not Found');
