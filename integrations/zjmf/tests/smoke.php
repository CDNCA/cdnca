<?php
/**
 * 冒烟：起门面 mock（php-sdk/tests/mock_server.php），用桩 $params 模拟老版财务系统，
 * 走 create → 重复 create → suspend → unsuspend → renew → change → sso → terminate，
 * 外加 ConfigOptions 下拉、UsageUpdate 写回、Status、周期报错、越权登录。
 *   php integrations/zjmf/tests/smoke.php
 */
namespace think {
    /** 最小 think\Db 桩：记录 update，按表返回预置行。 */
    class Db
    {
        public static $tables = [];
        public static $updates = [];
        private $table;
        private $wheres = [];

        public static function name($table)
        {
            $q = new self();
            $q->table = $table;
            return $q;
        }

        public function __call($method, $args)
        {
            if ($method === 'where' || $method === 'whereIn') {
                $this->wheres[] = [$method, $args[0], $args[1]];
            }
            return $this; // alias/leftJoin/field/order 等链式调用
        }

        public function select()
        {
            $rows = isset(self::$tables[$this->table]) ? self::$tables[$this->table] : [];
            foreach ($this->wheres as $w) {
                $rows = array_values(array_filter($rows, function ($row) use ($w) {
                    $col = substr($w[1], strpos($w[1], '.') === false ? 0 : strpos($w[1], '.') + 1);
                    if (!array_key_exists($col, $row)) {
                        return true;
                    }
                    return $w[0] === 'whereIn' ? in_array($row[$col], $w[2]) : $row[$col] == $w[2];
                }));
            }
            return $rows;
        }

        public function find()
        {
            $rows = $this->select();
            return $rows ? $rows[0] : null;
        }

        public function update(array $data)
        {
            self::$updates[] = [$this->table, $this->wheres, $data];
            return 1;
        }
    }
}

namespace {
    require __DIR__ . '/../../php-sdk/src/CdncaBridgeClient.php';

    $port = getenv('MOCK_PORT') ?: '18766';
    $state = tempnam(sys_get_temp_dir(), 'cdnca-mock');
    file_put_contents($state, '');
    $proc = proc_open(sprintf('MOCK_STATE=%s exec %s -S 127.0.0.1:%s %s > /dev/null 2>&1', escapeshellarg($state),
        escapeshellarg(PHP_BINARY), $port, escapeshellarg(__DIR__ . '/../../php-sdk/tests/mock_server.php')), [], $pipes);
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
        echo ($cond ? 'ok   ' : 'FAIL ') . $name . (!$cond && $detail !== '' ? "\n     " . $detail : '') . "\n";
        if (!$cond) {
            $failures++;
        }
    }
    function calls($state, $suffix)
    {
        $all = json_decode(file_get_contents($state), true)['calls'];
        return array_values(array_filter($all, function ($c) use ($suffix) {
            return substr($c['path'], -strlen($suffix)) === $suffix;
        }));
    }

    // 财务系统公共函数桩
    $GLOBALS['zjmf_logs'] = [];
    $GLOBALS['uid'] = 0;
    function active_log($text)
    {
        $GLOBALS['zjmf_logs'][] = $text;
    }
    function aesPasswordDecode($v)
    {
        return base64_decode($v);
    }
    function request()
    {
        return (object)['uid' => $GLOBALS['uid']];
    }

    $key = 'cbb_AAAAAAAAAAAAAAAAAAAAAA';
    $secret = 'cbs_mock-secret-for-smoke-tests-only';
    \think\Db::$tables['servers'] = [['server_host' => '127.0.0.1', 'server_ip' => '', 'server_username' => $key,
        'server_password' => base64_encode($secret), 'secure' => 0, 'port' => $port]];

    require __DIR__ . '/../modules/servers/cdnca/cdnca.php';

    $p = ['hostid' => 3001, 'uid' => 77, 'serverid' => 5, 'regdate' => 1761552000, 'nextduedate' => 1764230400,
        'billingcycle' => 'monthly', 'domainstatus' => 'Active', 'server_host' => '127.0.0.1', 'server_ip' => '',
        'server_username' => $key, 'server_password' => $secret, 'secure' => 0, 'port' => $port,
        'config_option1' => 'prod-basic', 'configoptions' => ['product_id' => 'prod-basic'],
        'user_info' => ['username' => '王五', 'email' => 'wang@example.com', 'companyname' => '示例 IDC']];

    $meta = cdnca_MetaData();
    check('MetaData', $meta['DisplayName'] === 'CDNCA CDN' && $meta['APIVersion'] === '1.1' && $meta['HelpDoc'] !== '');
    $opts = cdnca_ConfigOptions();
    check('ConfigOptions 下拉（从 /products 拉取）', count($opts) === 1 && $opts[0]['type'] === 'dropdown'
        && $opts[0]['key'] === 'product_id' && isset($opts[0]['options']['prod-basic']), json_encode($opts, JSON_UNESCAPED_UNICODE));
    check('TestLink', cdnca_TestLink($p) === ['status' => 200, 'data' => ['server_status' => 1]]);

    check('CreateAccount', cdnca_CreateAccount($p) === 'success');
    $creates = calls($state, '/services');
    check('create 幂等键 zjmf:{hostid}:create:{regdate}', $creates[0]['idem'] === 'zjmf:3001:create:1761552000');
    check('CreateAccount 写回 username', (function () {
        foreach (\think\Db::$updates as $u) {
            if ($u[0] === 'host' && isset($u[2]['username']) && $u[2]['username'] === 'whmcs_77') {
                return true;
            }
        }
        return false;
    })());
    check('重复 CreateAccount 幂等成功', cdnca_CreateAccount($p) === 'success');
    $svc = (new CdncaBridgeClient("http://127.0.0.1:$port", $key, $secret))->getService('zjmf', '3001');
    check('external_client_id = uid', $svc['external_client_id'] === '77' && $svc['period'] === 'month');

    check('SuspendAccount', cdnca_SuspendAccount($p + ['suspendreason' => '欠费']) === 'success');
    $st = cdnca_Status($p);
    check('Status 暂停 → suspend', $st['status'] === 'success' && $st['data']['status'] === 'suspend');
    $area = cdnca_ClientAreaOutput($p, 'overview');
    check('ClientAreaOutput 暂停态不可登录', $area['template'] === 'templates/overview.html' && $area['vars']['cdnca_ok'] === 1
        && $area['vars']['cdnca_can_login'] === 0 && $area['vars']['cdnca_traffic'] === '5.00 GB');
    check('UnsuspendAccount', cdnca_UnsuspendAccount($p) === 'success');
    check('Status 正常 → on', cdnca_Status($p)['data']['status'] === 'on');
    check('ClientArea 选项卡', isset(cdnca_ClientArea($p)['overview']['name']));

    check('Renew', cdnca_Renew($p) === 'success');
    check('renew 幂等键带 nextduedate', calls($state, '/3001/renew')[0]['idem'] === 'zjmf:3001:renew:1764230400');
    check('ChangePackage', cdnca_ChangePackage(['billingcycle' => 'Annually'] + $p) === 'success');

    $vnc = cdnca_Vnc($p);
    check('Vnc 返回 url', $vnc['status'] === 'success' && strpos($vnc['url'], '/sso/bridge?ticket=') !== false);
    $GLOBALS['uid'] = 99;
    $deny = cdnca_LoginConsole($p);
    check('LoginConsole 非本人拒绝', $deny['status'] === 'error' && count(calls($state, '/3001/sso')) === 1);
    $GLOBALS['uid'] = 77;
    $login = cdnca_LoginConsole($p);
    check('LoginConsole 本人返回 url', $login['status'] === 'success' && strpos($login['url'], 'ticket=') !== false);
    $sso = calls($state, '/3001/sso');
    check('每次 SSO 用新幂等键', count($sso) === 2 && $sso[0]['idem'] !== $sso[1]['idem']);
    check('AllowFunction 只开放 LoginConsole', cdnca_AllowFunction() === ['client' => ['LoginConsole'], 'admin' => []]);

    \think\Db::$updates = [];
    \think\Db::$tables['host'] = [
        ['id' => 3001, 'serverid' => 5, 'domainstatus' => 'Active', 'server_host' => '127.0.0.1', 'server_ip' => '',
            'server_username' => $key, 'server_password' => base64_encode($secret), 'secure' => 0, 'port' => $port],
        ['id' => 3999, 'serverid' => 5, 'domainstatus' => 'Active', 'server_host' => '127.0.0.1', 'server_ip' => '',
            'server_username' => $key, 'server_password' => base64_encode($secret), 'secure' => 0, 'port' => $port],
    ];
    check('UsageUpdate', cdnca_UsageUpdate([3001, 3999]) === 'success');
    $u = \think\Db::$updates;
    check('UsageUpdate 写 bwusage(GB) 与 lastupdate', count($u) === 1 && $u[0][0] === 'host' && $u[0][2]['bwusage'] === 5.0
        && $u[0][2]['lastupdate'] > 0, json_encode($u));
    check('UsageUpdate 接受逗号串', cdnca_UsageUpdate('3001,3999') === 'success');
    check('UsageUpdate 空列表', cdnca_UsageUpdate([]) === 'success');

    $semi = cdnca_CreateAccount(['hostid' => 3002, 'billingcycle' => 'semiannually'] + $p);
    check('半年付 → 中文错误', is_array($semi) && $semi['status'] === 'error' && strpos($semi['msg'], '半年付') !== false, json_encode($semi, JSON_UNESCAPED_UNICODE));
    $noMail = cdnca_CreateAccount(['hostid' => 3003, 'user_info' => ['email' => '']] + $p);
    check('无邮箱 → 中文错误', $noMail['status'] === 'error' && strpos($noMail['msg'], '邮箱') !== false);
    $missing = cdnca_SuspendAccount(['hostid' => 'nope'] + $p);
    check('不存在服务 → bridge_service_not_found', strpos($missing['msg'], 'bridge_service_not_found') !== false && strpos($missing['msg'], 'request_id') !== false);
    $bad = cdnca_TestLink(['server_password' => 'cbs_wrong'] + $p);
    check('错密钥 TestLink → 鉴权失败', $bad['data']['server_status'] === 0 && strpos($bad['data']['msg'], '鉴权失败') !== false);

    check('TerminateAccount', cdnca_TerminateAccount($p) === 'success');
    $after = cdnca_SuspendAccount($p);
    check('终止后操作 → 已终止', strpos($after['msg'], '已终止') !== false);
    $logText = implode("\n", $GLOBALS['zjmf_logs']);
    check('失败写 active_log 且不含 secret', count($GLOBALS['zjmf_logs']) >= 4 && strpos($logText, $secret) === false);

    echo "\n$count 项，失败 $failures 项\n";
    exit($failures === 0 ? 0 : 1);
}
