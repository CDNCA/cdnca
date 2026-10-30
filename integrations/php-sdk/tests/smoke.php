<?php
/**
 * 冒烟：起 mock 服务端（php -S），用 SDK 和 WHMCS 模块各走一遍
 * create → suspend → sso（含幂等重复 create、5xx 重试、错误码）。
 *   php integrations/php-sdk/tests/smoke.php
 */
require __DIR__ . '/../src/CdncaBridgeClient.php';

$port = getenv('MOCK_PORT') ?: '18765';
$state = tempnam(sys_get_temp_dir(), 'cdnca-mock');
file_put_contents($state, '');
$cmd = sprintf('MOCK_STATE=%s exec %s -S 127.0.0.1:%s %s > /dev/null 2>&1',
    escapeshellarg($state), escapeshellarg(PHP_BINARY), $port, escapeshellarg(__DIR__ . '/mock_server.php'));
$proc = proc_open($cmd, [], $pipes);
register_shutdown_function(function () use ($proc, $state) {
    proc_terminate($proc);
    @unlink($state);
});
for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', (int)$port); $i++) {
    usleep(100000);
}

$failures = 0;
$count = 0;
function check($name, $cond, $detail = '')
{
    global $failures, $count;
    $count++;
    echo ($cond ? 'ok   ' : 'FAIL ') . $name . (!$cond && $detail !== '' ? "\n     $detail" : '') . "\n";
    if (!$cond) {
        $failures++;
    }
}

$base = "http://127.0.0.1:$port";
$key = 'cbb_AAAAAAAAAAAAAAAAAAAAAA';
$secret = 'cbs_mock-secret-for-smoke-tests-only';

// ---------------------------------------------------------------- SDK
$c = new CdncaBridgeClient($base, $key, $secret, ['retry_delay_ms' => 10]);
check('SDK ping', $c->ping()['module_enabled'] === true);
check('SDK products', $c->listProducts()[0]['id'] === 'prod-basic');
$payload = ['external_system' => 'whmcs', 'external_service_id' => '9001', 'external_client_id' => '7',
    'client' => ['email' => 'a@example.com', 'display_name' => '张 三'], 'product_id' => 'prod-basic', 'period' => 'month'];
$s = $c->createService($payload, 'whmcs:9001:create:v1');
check('SDK create 新建', $s['created'] === true && $s['status'] === 'active');
$s = $c->createService($payload, 'whmcs:9001:create:v1');
check('SDK create 重复 → created:false', $s['created'] === false);
try {
    $c->createService(['product_id' => 'other'] + $payload, 'whmcs:9001:create:v2');
    check('SDK create 冲突', false);
} catch (CdncaBridgeException $e) {
    check('SDK create 冲突 → 409 bridge_service_conflict', $e->getErrorCode() === 'bridge_service_conflict' && $e->getHttpStatus() === 409);
}
check('SDK suspend', $c->suspendService('whmcs', '9001', '欠费', 'whmcs:9001:suspend:1')['status'] === 'suspended');
check('SDK unsuspend', $c->unsuspendService('whmcs', '9001', 'whmcs:9001:unsuspend:1')['status'] === 'active');
$sso = $c->createSso('whmcs', '9001', '', 'whmcs:9001:sso:1');
check('SDK sso url', strpos($sso['url'], '/sso/bridge?ticket=') !== false);
$usage = $c->getUsage('whmcs', ['9001', 'missing']);
check('SDK usage（含中文无关 query 签名）', count($usage) === 1 && $usage[0]['traffic_bytes'] === 5368709120);
try {
    $c->getService('whmcs', 'nope');
    check('SDK 404', false);
} catch (CdncaBridgeException $e) {
    check('SDK 404 → bridge_service_not_found + request_id', $e->getErrorCode() === 'bridge_service_not_found' && $e->getRequestId() !== '');
}
$bad = new CdncaBridgeClient($base, $key, 'cbs_wrong', ['retries' => 0]);
try {
    $bad->ping();
    check('SDK 错密钥', false);
} catch (CdncaBridgeException $e) {
    check('SDK 错密钥 → 401 不重试', $e->getHttpStatus() === 401);
}
// 5xx 重试：同一幂等键
$c->createService(['external_service_id' => 'flaky1'] + $payload, 'whmcs:flaky1:create:v1');
$s = $c->suspendService('whmcs', 'flaky1', '', 'whmcs:flaky1:suspend:1');
$calls = json_decode(file_get_contents($state), true)['calls'];
$suspendCalls = array_values(array_filter($calls, function ($x) { return substr($x['path'], -strlen('/flaky1/suspend')) === '/flaky1/suspend'; }));
check('SDK 503 后重试成功', $s['status'] === 'suspended' && count($suspendCalls) === 2);
check('SDK 重试沿用同一 Idempotency-Key', $suspendCalls[0]['idem'] === 'whmcs:flaky1:suspend:1' && $suspendCalls[1]['idem'] === 'whmcs:flaky1:suspend:1');
$last = json_encode($c->getLastExchange());
check('lastExchange 不含 secret 与签名', strpos($last, $secret) === false && strpos($last, 'X-Cdnca-Signature: ***') !== false);

// ---------------------------------------------------------------- WHMCS 模块
define('WHMCS', true);
$GLOBALS['module_log'] = [];
function logModuleCall($module, $action, $request, $response, $processed = '', $replace = [])
{
    $GLOBALS['module_log'][] = json_encode([$module, $action, $request, $response, $processed, $replace], JSON_UNESCAPED_UNICODE);
}
require __DIR__ . '/../../whmcs/modules/servers/cdnca/cdnca.php';

$p = ['serverhostname' => '127.0.0.1', 'serverport' => $port, 'serversecure' => '', 'serverusername' => $key,
    'serverpassword' => $secret, 'serviceid' => 5001, 'userid' => 42, 'configoption1' => 'prod-basic',
    'billingcycle' => 'Monthly', 'regdate' => '2026-10-27',
    'clientsdetails' => ['email' => 'b@example.com', 'firstname' => '四', 'lastname' => '李']];
check('cdnca_MetaData', cdnca_MetaData()['DisplayName'] === 'CDNCA CDN' && cdnca_MetaData()['ServiceSingleSignOnLabel'] === '登录 CDN 控制台');
check('cdnca_LoaderProducts', isset(cdnca_LoaderProducts($p)['prod-basic']));
check('cdnca_TestConnection', cdnca_TestConnection($p) === ['success' => true, 'error' => '']);
check('cdnca_CreateAccount', cdnca_CreateAccount($p) === 'success');
check('cdnca_CreateAccount 重试幂等', cdnca_CreateAccount($p) === 'success');
check('cdnca_SuspendAccount', cdnca_SuspendAccount($p + ['suspendreason' => 'Overdue']) === 'success');
$area = cdnca_ClientArea($p);
check('cdnca_ClientArea 停用态', $area['templateVariables']['cdnca_ok'] === true && $area['templateVariables']['cdnca_status'] === '已停用'
    && $area['templateVariables']['cdnca_traffic'] === '5.00 GB' && $area['templateVariables']['cdnca_can_login'] === false);
check('cdnca_UnsuspendAccount', cdnca_UnsuspendAccount($p) === 'success');
$sso = cdnca_ServiceSingleSignOn($p);
check('cdnca_ServiceSingleSignOn', $sso['success'] === true && strpos($sso['redirectTo'], 'ticket=') !== false);
check('cdnca_Renew', cdnca_Renew($p + ['nextduedate' => '2026-11-27']) === 'success');
check('cdnca_ChangePackage', cdnca_ChangePackage($p) === 'success');
$tab = cdnca_AdminServicesTabFields($p);
check('cdnca_AdminServicesTabFields', $tab['CDN 用户名'] === 'whmcs_42' && isset($tab['外部映射'], $tab['最近同步']));
check('cdnca_UsageUpdate（无 Capsule 环境）', is_string(cdnca_UsageUpdate($p + ['serverid' => 1])));
$semi = cdnca_CreateAccount(['serviceid' => 5002, 'billingcycle' => 'Semi-Annually'] + $p);
check('半年付报错中文', strpos($semi, '半年付') !== false, $semi);
$missing = cdnca_SuspendAccount(['serviceid' => 'zzz'] + $p);
check('不存在服务返回中文错误', strpos($missing, 'CDN 侧找不到该服务') !== false && strpos($missing, 'bridge_service_not_found') !== false, $missing);
$bad = cdnca_TestConnection(['serverpassword' => 'cbs_wrong'] + $p);
check('错密钥 TestConnection 中文错误', $bad['success'] === false && strpos($bad['error'], '鉴权失败') !== false, $bad['error']);
check('cdnca_TerminateAccount', cdnca_TerminateAccount($p) === 'success');
$after = cdnca_SuspendAccount($p);
check('终止后操作 → bridge_service_terminated', strpos($after, '已终止') !== false, $after);
$logs = implode("\n", $GLOBALS['module_log']);
check('模块日志已记录', count($GLOBALS['module_log']) >= 12, (string)count($GLOBALS['module_log']));
check('模块日志签名已脱敏', strpos($logs, 'X-Cdnca-Signature: ***') !== false && !preg_match('/X-Cdnca-Signature: [0-9a-f]{64}/', $logs));
check('模块日志 replaceVars 含 secret', strpos($logs, json_encode([$secret])) !== false);

echo "\n$count 项，失败 $failures 项\n";
exit($failures === 0 ? 0 : 1);
