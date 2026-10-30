<?php
/**
 * 冒烟：起门面 mock（php-sdk/tests/mock_server.php），用最小桩类模拟 V10 的
 * HostModel / ClientModel / ProductModel / ServerModel 与 think\facade\Db，
 * 走 create → 重复 create → suspend → unsuspend → renew → changeProduct → sso → terminate，
 * 外加计价、周期映射、免密登录归属校验。
 *   php integrations/zjmf-v10/tests/smoke.php
 */
namespace app\common\model {
    /** 最小模型桩：ArrayAccess + 静态登记表。 */
    class StubModel implements \ArrayAccess
    {
        public static $rows = [];
        protected $data;

        public function __construct(array $data = [])
        {
            $this->data = $data;
        }

        public static function find($id)
        {
            $rows = isset(static::$rows[static::class]) ? static::$rows[static::class] : [];
            return isset($rows[$id]) ? new static($rows[$id]) : null;
        }

        public static function put(array $row)
        {
            static::$rows[static::class][$row['id']] = $row;
            return new static($row);
        }

        public static function where($col, $val)
        {
            return new StubQuery(static::class, [[$col, $val]]);
        }

        #[\ReturnTypeWillChange]
        public function offsetExists($k)
        {
            return isset($this->data[$k]);
        }

        #[\ReturnTypeWillChange]
        public function offsetGet($k)
        {
            return isset($this->data[$k]) ? $this->data[$k] : null;
        }

        #[\ReturnTypeWillChange]
        public function offsetSet($k, $v)
        {
            $this->data[$k] = $v;
        }

        #[\ReturnTypeWillChange]
        public function offsetUnset($k)
        {
            unset($this->data[$k]);
        }
    }

    class StubQuery
    {
        private $class;
        private $wheres;

        public function __construct($class, $wheres)
        {
            $this->class = $class;
            $this->wheres = $wheres;
        }

        public function where($col, $val)
        {
            $this->wheres[] = [$col, $val];
            return $this;
        }

        public function find()
        {
            $class = $this->class;
            foreach (isset($class::$rows[$class]) ? $class::$rows[$class] : [] as $row) {
                $ok = true;
                foreach ($this->wheres as $w) {
                    $ok = $ok && isset($row[$w[0]]) && $row[$w[0]] == $w[1];
                }
                if ($ok) {
                    return new $class($row);
                }
            }
            return null;
        }
    }

    class ServerModel extends StubModel
    {
    }

    class ClientModel extends StubModel
    {
    }

    class ProductModel extends StubModel
    {
        public function getModule()
        {
            return $this->data['module'];
        }
    }

    class HostModel extends StubModel
    {
        public function getModule()
        {
            $server = ServerModel::find($this->data['server_id']);
            return $server ? $server['module'] : '';
        }

        /** 与 10.4.6 HostModel::getModuleParams 一致：server.password 已解密。 */
        public function getModuleParams()
        {
            $server = ServerModel::find($this->data['server_id']);
            if ($server) {
                $server['password'] = aes_password_decode($server['password']);
            }
            return ['host' => $this, 'client' => ClientModel::find($this->data['client_id']),
                'product' => ProductModel::find($this->data['product_id']), 'server' => $server];
        }
    }
}

namespace think\facade {
    /** 最小 Db 桩：只支持本模块用到的 name/where/find/insert/update/execute。 */
    class Db
    {
        public static $tables = [];
        public static $sql = [];
        private $table;
        private $wheres = [];

        public static function name($table)
        {
            $q = new self();
            $q->table = $table;
            return $q;
        }

        public static function execute($sql)
        {
            self::$sql[] = $sql;
            return 0;
        }

        public function where($col, $val)
        {
            $this->wheres[$col] = $val;
            return $this;
        }

        public function find()
        {
            foreach (isset(self::$tables[$this->table]) ? self::$tables[$this->table] : [] as $row) {
                if (array_intersect_assoc($this->wheres, $row) == $this->wheres) {
                    return $row;
                }
            }
            return null;
        }

        public function insert(array $row)
        {
            self::$tables[$this->table][] = $row;
            return 1;
        }

        public function update(array $data)
        {
            foreach (self::$tables[$this->table] as &$row) {
                if (array_intersect_assoc($this->wheres, $row) == $this->wheres) {
                    $row = array_merge($row, $data);
                }
            }
            return 1;
        }
    }
}

namespace {
    use app\common\model\ClientModel;
    use app\common\model\HostModel;
    use app\common\model\ProductModel;
    use app\common\model\ServerModel;

    $GLOBALS['v10_client_id'] = 0;
    $GLOBALS['v10_logs'] = [];
    $GLOBALS['v10_lang'] = include __DIR__ . '/../public/plugins/server/cdnca/lang/zh-cn.php';
    function lang_plugins($key, $replace = [])
    {
        $text = isset($GLOBALS['v10_lang'][$key]) ? $GLOBALS['v10_lang'][$key] : $key;
        return str_replace(array_keys($replace), array_values($replace), $text);
    }
    function get_client_id()
    {
        return $GLOBALS['v10_client_id'];
    }
    function aes_password_decode($v)
    {
        return base64_decode($v);
    }
    function active_log($text)
    {
        $GLOBALS['v10_logs'][] = $text;
    }
    // ThinkPHP 助手函数桩：request()->param() 返回路由参数，json() 原样返回数组
    $GLOBALS['v10_param'] = [];
    function request()
    {
        return new class {
            public function param()
            {
                return $GLOBALS['v10_param'];
            }
        };
    }
    function json($data)
    {
        return $data;
    }

    // 按系统的 \server\{dir}\{parse_name(dir,1)} 规则加载
    spl_autoload_register(function ($class) {
        if (strpos($class, 'server\\cdnca\\') === 0) {
            $file = __DIR__ . '/../public/plugins/server/cdnca/' . str_replace('\\', '/', substr($class, strlen('server\\cdnca\\'))) . '.php';
            if (is_file($file)) {
                require $file;
            }
        }
    });

    $port = getenv('MOCK_PORT') ?: '18767';
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

    $key = 'cbb_AAAAAAAAAAAAAAAAAAAAAA';
    $secret = 'cbs_mock-secret-for-smoke-tests-only';
    ServerModel::put(['id' => 9, 'module' => 'cdnca', 'url' => "http://127.0.0.1:$port", 'username' => $key,
        'password' => base64_encode($secret), 'server_group_id' => 0]);
    ProductModel::put(['id' => 50, 'name' => 'CDN 基础版', 'module' => 'cdnca', 'type' => 'server', 'rel_id' => 9]);
    ProductModel::put(['id' => 51, 'name' => 'CDN 专业版', 'module' => 'cdnca', 'type' => 'server', 'rel_id' => 9]);
    ClientModel::put(['id' => 8, 'username' => '赵六', 'email' => 'zhao@example.com', 'company' => '']);
    HostModel::put(['id' => 7001, 'client_id' => 8, 'product_id' => 50, 'server_id' => 9, 'status' => 'Active',
        'billing_cycle' => 'recurring_prepayment', 'billing_cycle_name' => '月付', 'billing_cycle_time' => 2592000,
        'due_time' => 1764230400, 'create_time' => 1761552000, 'is_delete' => 0]);

    $m = new \server\cdnca\Cdnca();
    $meta = $m->metaData();
    check('metaData', $meta['display_name'] === 'CDNCA CDN' && $meta['version'] !== '');
    $m->afterCreateFirstServer();
    check('afterCreateFirstServer 建表', strpos(\think\facade\Db::$sql[0], 'idcsmart_module_cdnca_product') !== false);
    // 系统 ServerModel::status() 传入的 server 已经解密过 password
    $plain = ServerModel::find(9);
    $plain['password'] = $secret;
    check('testConnect', $m->testConnect(['server' => $plain])['status'] === 200);

    // 商品配置：后台保存 → 计价
    $save = \server\cdnca\logic\CdncaLogic::saveProductConfig(['product_id' => 50, 'cdn_product_id' => 'prod-basic',
        'cdn_product_name' => '基础版', 'price_month' => '99', 'price_quarter' => '', 'price_year' => '990']);
    check('保存商品配置', $save['status'] === 200, json_encode($save, JSON_UNESCAPED_UNICODE));
    check('保存配置拒绝零周期', \server\cdnca\logic\CdncaLogic::saveProductConfig(['product_id' => 50, 'cdn_product_id' => 'prod-basic'])['status'] === 400);
    \server\cdnca\logic\CdncaLogic::saveProductConfig(['product_id' => 51, 'cdn_product_id' => 'prod-basic', 'cdn_product_name' => '基础版', 'price_year' => '1990']);
    $vars = $m->serverConfigOption(['product' => ProductModel::find(50)]);
    $cfg = json_decode($vars['vars']['cdnca_config_json'], true);
    check('serverConfigOption 拉到套餐列表', $vars['template'] === 'template/admin/product_config.html'
        && $cfg['products'][0]['id'] === 'prod-basic' && $cfg['cdn_product_id'] === 'prod-basic' && $cfg['load_error'] === '', json_encode($cfg, JSON_UNESCAPED_UNICODE));
    $price = $m->cartCalculatePrice(['product' => ProductModel::find(50), 'custom' => ['duration' => 31536000], 'qty' => 1, 'scene' => 'buy']);
    check('cartCalculatePrice 年付', $price['status'] === 200 && $price['data']['price'] == 990 && $price['data']['duration'] === 31536000
        && $price['data']['billing_cycle'] === '年付', json_encode($price, JSON_UNESCAPED_UNICODE));
    check('durationPrice 只含开放周期', count($m->durationPrice(['product' => ProductModel::find(50)])['data']) === 2);
    check('getPriceCycle', $m->getPriceCycle(['product' => ProductModel::find(50)]) === ['price' => 99.0, 'cycle' => '月付']);
    check('clientProductConfigOption', $m->clientProductConfigOption(['product' => ProductModel::find(50)])['template'] === 'template/clientarea/goods.html');

    $p = HostModel::find(7001)->getModuleParams();
    check('createAccount', $m->createAccount($p)['status'] === 200);
    check('create 幂等键（zjmf_cbap→zjmf-cbap）', calls($state, '/services')[0]['idem'] === 'zjmf-cbap:7001:create:1761552000');
    $svc = (new CdncaBridgeClient("http://127.0.0.1:$port", $key, $secret))->getService('zjmf_cbap', '7001');
    check('external_client_id = client_id，period=month', $svc['external_client_id'] === '8' && $svc['period'] === 'month');
    check('重复 createAccount 幂等成功', $m->createAccount($p)['status'] === 200);

    $r = $m->suspendAccount($p + ['suspend_type' => 'overdue', 'suspend_reason' => '到期']);
    check('suspendAccount', $r['status'] === 200 && $r['msg'] === '暂停成功');
    $area = $m->clientArea($p);
    check('clientArea 暂停态不可登录', $area['template'] === 'template/clientarea/product_detail.html'
        && $area['vars']['cdnca_ok'] === 1 && $area['vars']['cdnca_can_login'] === 0 && $area['vars']['cdnca_traffic'] === '5.00 GB');
    check('unsuspendAccount', $m->unsuspendAccount($p)['status'] === 200);
    check('renew', $m->renew($p)['status'] === 200);
    check('renew 幂等键带 due_time', calls($state, '/7001/renew')[0]['idem'] === 'zjmf-cbap:7001:renew:1764230400');

    // 升降级商品：host 关联新商品 51（年付）
    HostModel::put(['product_id' => 51, 'billing_cycle_name' => '年付', 'billing_cycle_time' => 31536000] + HostModel::$rows[HostModel::class][7001]);
    $p = HostModel::find(7001)->getModuleParams();
    check('changeProduct', $m->changeProduct($p + ['custom' => []])['status'] === 200);
    $fields = $m->adminField($p);
    check('adminField', $fields[0]['field'][0]['key'] === 'cdnca_mapping' && count($fields[0]['field']) === 5);
    check('adminArea', $m->adminArea($p)['template'] === 'template/admin/host_detail.html');

    // 免密登录控制器：归属校验
    $ctrl = '\server\cdnca\logic\CdncaLogic';
    check('sso 未登录拒绝', $ctrl::ssoForClient(7001, 0)['status'] === 400);
    check('sso 他人产品拒绝且不调主控', $ctrl::ssoForClient(7001, 99)['msg'] === '产品不存在' && count(calls($state, '/7001/sso')) === 0);
    check('sso 不存在产品', $ctrl::ssoForClient(123456, 8)['status'] === 400);
    $GLOBALS['v10_client_id'] = 8;
    $GLOBALS['v10_param'] = ['id' => '7001'];
    $sso = (new \server\cdnca\controller\home\HostController())->sso();
    check('sso 本人返回一次性链接', $sso['status'] === 200 && strpos($sso['data']['url'], '/sso/bridge?ticket=') !== false, json_encode($sso));
    HostModel::put(['status' => 'Suspended'] + HostModel::$rows[HostModel::class][7001]);
    check('sso 非 Active 拒绝', $ctrl::ssoForClient(7001, 8)['msg'] === '产品当前不可登录');
    HostModel::put(['status' => 'Active'] + HostModel::$rows[HostModel::class][7001]);

    // 周期与错误
    $bad = HostModel::put(['id' => 7002, 'billing_cycle_time' => 15552000, 'billing_cycle_name' => '半年'] + HostModel::$rows[HostModel::class][7001]);
    $semi = $m->createAccount($bad->getModuleParams());
    check('半年周期 → 中文错误', $semi['status'] === 400 && strpos($semi['msg'], '不支持该周期') !== false, $semi['msg']);
    $once = HostModel::put(['id' => 7003, 'billing_cycle' => 'onetime'] + HostModel::$rows[HostModel::class][7001]);
    check('一次性付费 → 中文错误', strpos($m->createAccount($once->getModuleParams())['msg'], '付费类型') !== false);
    check('31 天月付也能识别', \server\cdnca\logic\CdncaLogic::period(['billing_cycle' => 'recurring_prepayment', 'billing_cycle_time' => 31 * 86400]) === 'month');
    $wrong = ServerModel::find(9);
    $wrong['password'] = 'cbs_wrong';
    $t = $m->testConnect(['server' => $wrong]);
    check('错密钥 testConnect → 鉴权失败', $t['status'] === 400 && strpos($t['msg'], '鉴权失败') !== false);

    check('terminateAccount', $m->terminateAccount($p)['status'] === 200);
    $after = $m->suspendAccount($p);
    check('终止后操作 → 已终止', $after['status'] === 400 && strpos($after['msg'], '已终止') !== false);
    $logText = implode("\n", $GLOBALS['v10_logs']);
    check('失败写 active_log 且不含 secret', count($GLOBALS['v10_logs']) >= 2 && strpos($logText, $secret) === false);

    echo "\n$count 项，失败 $failures 项\n";
    exit($failures === 0 ? 0 : 1);
}
