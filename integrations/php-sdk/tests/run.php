<?php
/**
 * 纯 PHP 断言测试（不依赖 phpunit）：php integrations/php-sdk/tests/run.php
 * 1. 签名向量：tests/vectors.json 由 Go 实现（credential.go）生成，PHP 必须逐字节一致。
 * 2. 幂等键、nonce、错误解析、参数校验。
 */
require __DIR__ . '/../src/CdncaBridgeClient.php';

$failures = 0;
$count = 0;
function check($name, $cond, $detail = '')
{
    global $failures, $count;
    $count++;
    if ($cond) {
        echo "ok   $name\n";
    } else {
        $failures++;
        echo "FAIL $name" . ($detail !== '' ? "\n     $detail" : '') . "\n";
    }
}

// ---- 1. 签名向量
$doc = json_decode(file_get_contents(__DIR__ . '/vectors.json'), true);
check('vectors.json 可解析且有 3 组', is_array($doc) && count($doc['vectors']) === 3);
foreach ($doc['vectors'] as $v) {
    $cq = CdncaBridgeClient::canonicalQuery($v['query_pairs']);
    check($v['name'] . ' canonical_query', $cq === $v['canonical_query'], "php=$cq\n     go =" . $v['canonical_query']);
    // 服务端从原始 query 串解析：PHP 规范化串再被 Go 解析后结果不变（发送串=规范串）
    $sts = CdncaBridgeClient::stringToSign($v['method'], $v['path'], $cq, $v['timestamp'], $v['nonce'], $v['body']);
    check($v['name'] . ' string_to_sign', $sts === $v['string_to_sign'], json_encode($sts));
    $sig = CdncaBridgeClient::sign($v['secret'], $sts);
    check($v['name'] . ' signature', $sig === $v['signature'], "php=$sig go=" . $v['signature']);
}
// 关联数组形式（多值）与成对形式结果一致
check('canonicalQuery 关联数组多值', CdncaBridgeClient::canonicalQuery(['z' => ['b', 'a c'], 'a' => '1']) === 'a=1&z=a%20c&z=b');
check('canonicalQuery 空', CdncaBridgeClient::canonicalQuery([]) === '');

// ---- 2. nonce / 幂等键
$n = CdncaBridgeClient::newNonce();
check('nonce 匹配服务端格式', (bool)preg_match('/^[A-Za-z0-9_-]{16,64}$/', $n), $n);
check('nonce 每次不同', $n !== CdncaBridgeClient::newNonce());
check('幂等键常规', CdncaBridgeClient::idempotencyKey('whmcs', '1001', 'create', '2026-10-27') === 'whmcs:1001:create:2026-10-27');
$hashed = CdncaBridgeClient::idempotencyKey('whmcs', '10 01', 'create', str_repeat('x', 200));
check('幂等键非法字符退化为哈希且合规', (bool)preg_match(CdncaBridgeClient::IDEMPOTENCY_PATTERN, $hashed) && strpos($hashed, 'whmcs:h') === 0, $hashed);
check('幂等键哈希稳定', $hashed === CdncaBridgeClient::idempotencyKey('whmcs', '10 01', 'create', str_repeat('x', 200)));

// ---- 3. 参数校验（不发请求）
$client = new CdncaBridgeClient('http://127.0.0.1:1', 'cbb_test', 'cbs_test', ['retries' => 0]);
function expectCode($name, $code, callable $fn)
{
    try {
        $fn();
        check($name, false, '未抛异常');
    } catch (CdncaBridgeException $e) {
        check($name, $e->getErrorCode() === $code, $e->getErrorCode() . ': ' . $e->getMessage());
    }
}
expectCode('非法 external_system', 'client_invalid_argument', function () use ($client) { $client->getService('foo', '1'); });
expectCode('外部 ID 含空格', 'client_invalid_argument', function () use ($client) { $client->getService('whmcs', 'a b'); });
expectCode('写请求缺幂等键', 'client_invalid_argument', function () use ($client) { $client->request('POST', '/services', [], []); });
expectCode('无效基址', 'client_invalid_argument', function () { new CdncaBridgeClient('ftp://x', 'k', 's'); });
expectCode('连接失败 → network_error', 'network_error', function () use ($client) { $client->ping(); });

// ---- 4. 响应解析（私有方法经反射）
$parse = new ReflectionMethod('CdncaBridgeClient', 'parse');
$parse->setAccessible(true);
check('解析成功 data', $parse->invoke(null, 200, '{"data":{"a":1}}', '') === ['a' => 1]);
try {
    $parse->invoke(null, 409, '{"error":{"code":"bridge_service_conflict","message":"conflict","request_id":"req-1"}}', 'hdr');
    check('解析错误', false);
} catch (CdncaBridgeException $e) {
    check('解析错误 code/status/request_id', $e->getErrorCode() === 'bridge_service_conflict' && $e->getHttpStatus() === 409
        && $e->getRequestId() === 'req-1' && $e->getMessage() === 'conflict');
}
try {
    $parse->invoke(null, 502, '<html>bad gateway</html>', 'hdr-9');
    check('解析非 JSON', false);
} catch (CdncaBridgeException $e) {
    check('解析非 JSON → invalid_response 带头部 request_id', $e->getErrorCode() === 'invalid_response' && $e->getRequestId() === 'hdr-9');
}

echo "\n$count 项，失败 $failures 项\n";
exit($failures === 0 ? 0 : 1);
