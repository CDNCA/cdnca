<?php
namespace server\cdnca\logic;

use app\common\model\HostModel;
use app\common\model\ServerModel;
use think\facade\Db;

if (is_file(__DIR__ . '/../lib/CdncaBridgeClient.php')) {
    require_once __DIR__ . '/../lib/CdncaBridgeClient.php'; // 打包后的布局
    require_once __DIR__ . '/../lib/CdncaBridgeText.php';
} else {
    require_once __DIR__ . '/../../../../../../php-sdk/src/CdncaBridgeClient.php'; // 仓库内布局
    require_once __DIR__ . '/../../../../../../php-sdk/src/CdncaBridgeText.php';
}

/**
 * CDNCA 模块的共用逻辑：门面客户端、周期映射、商品配置、前台归属校验。
 */
class CdncaLogic
{
    const SYSTEM = 'zjmf_cbap';
    const MODULE = 'cdnca';
    const TABLE = 'module_cdnca_product'; // Db::name 自动加 idcsmart_ 前缀

    /** 主控只支持 month/quarter/year；duration 为本模块报给系统的周期秒数。 */
    const CYCLES = [
        'month' => ['duration' => 2592000, 'column' => 'price_month', 'lang' => 'cdnca_cycle_month', 'days' => [28, 31]],
        'quarter' => ['duration' => 7776000, 'column' => 'price_quarter', 'lang' => 'cdnca_cycle_quarter', 'days' => [89, 92]],
        'year' => ['duration' => 31536000, 'column' => 'price_year', 'lang' => 'cdnca_cycle_year', 'days' => [365, 366]],
    ];

    // ------------------------------------------------------------- 门面调用

    /** @param mixed $server ServerModel 或数组（url/username/password，password 已解密） */
    public static function client($server, array $options = []): \CdncaBridgeClient
    {
        if (empty($server)) {
            throw new \CdncaBridgeException('client_invalid_argument', self::lang('cdnca_server_missing'));
        }
        $url = trim((string)self::attr($server, 'url'));
        if ($url === '') {
            throw new \CdncaBridgeException('client_invalid_argument', self::lang('cdnca_server_url_missing'));
        }
        if (strpos($url, '://') === false) {
            $url = 'https://' . $url;
        }
        return new \CdncaBridgeClient($url, trim((string)self::attr($server, 'username')), trim((string)self::attr($server, 'password')), $options);
    }

    /** 执行一次写操作，返回系统要求的 ['status'=>200|400,'msg'=>...]；失败写系统日志。 */
    public static function run(string $action, array $param, callable $work, string $successKey): array
    {
        $hostId = (string)self::attr(isset($param['host']) ? $param['host'] : null, 'id');
        try {
            if ($hostId === '' || $hostId === '0') {
                throw new \CdncaBridgeException('client_invalid_argument', self::lang('cdnca_host_missing'));
            }
            $work(self::client(isset($param['server']) ? $param['server'] : null), $hostId);
            return ['status' => 200, 'msg' => self::lang($successKey)];
        } catch (\Throwable $e) {
            self::log($action, $hostId, $e);
            return ['status' => 400, 'msg' => self::error($e)];
        }
    }

    public static function key(string $hostId, string $action): string
    {
        // 暂停/解除/删除本身按状态幂等；键只需覆盖本次调用内的重试。
        return \CdncaBridgeClient::idempotencyKey(self::SYSTEM, $hostId, $action, gmdate('YmdHis'));
    }

    public static function error(\Throwable $e): string
    {
        return \CdncaBridgeText::error($e);
    }

    /**
     * host → 主控 period。host.billing_cycle 是商品付费类型（onetime/free/recurring_*），
     * 周期由 billing_cycle_time（秒，来自 cartCalculatePrice/durationPrice 返回的 duration）决定。
     */
    public static function period($host): string
    {
        $payType = (string)self::attr($host, 'billing_cycle');
        if ($payType === 'onetime' || $payType === 'free') {
            throw new \CdncaBridgeException('client_invalid_argument', self::lang('cdnca_pay_type_unsupported', ['{type}' => $payType]));
        }
        $seconds = (int)self::attr($host, 'billing_cycle_time');
        foreach (self::CYCLES as $period => $cycle) {
            if ($seconds === $cycle['duration']) {
                return $period;
            }
        }
        $days = $seconds / 86400;
        foreach (self::CYCLES as $period => $cycle) {
            if ($days >= $cycle['days'][0] && $days <= $cycle['days'][1]) {
                return $period;
            }
        }
        $name = (string)self::attr($host, 'billing_cycle_name');
        throw new \CdncaBridgeException('client_invalid_argument', self::lang('cdnca_cycle_unsupported',
            ['{cycle}' => ($name !== '' ? $name : '-') . ' / ' . $seconds . 's']));
    }

    // ------------------------------------------------------------- 商品配置

    public static function productConfig($product): array
    {
        $productId = (int)self::attr($product, 'id');
        if ($productId <= 0) {
            return [];
        }
        try {
            $row = Db::name(self::TABLE)->where('product_id', $productId)->find();
        } catch (\Throwable $e) {
            return [];
        }
        return is_array($row) ? $row : [];
    }

    public static function cdnProductId($product): string
    {
        $config = self::productConfig($product);
        $id = isset($config['cdn_product_id']) ? trim((string)$config['cdn_product_id']) : '';
        if ($id === '') {
            throw new \CdncaBridgeException('client_invalid_argument', self::lang('cdnca_product_not_configured'));
        }
        return $id;
    }

    public static function cdnProductName($product): string
    {
        $config = self::productConfig($product);
        return isset($config['cdn_product_name']) ? (string)$config['cdn_product_name'] : '';
    }

    /** 商品已开放的周期，键为 duration（字符串），值为系统要求的 {duration, billing_cycle, price}。 */
    public static function productCycles($product): array
    {
        $config = self::productConfig($product);
        if (!$config || (string)$config['cdn_product_id'] === '') {
            return [];
        }
        $cycles = [];
        foreach (self::CYCLES as $cycle) {
            $price = isset($config[$cycle['column']]) ? $config[$cycle['column']] : null;
            if ($price === null || $price === '') {
                continue;
            }
            $cycles[(string)$cycle['duration']] = [
                'duration' => $cycle['duration'],
                'billing_cycle' => self::lang($cycle['lang']),
                'price' => round((float)$price, 2),
            ];
        }
        return $cycles;
    }

    /** serverConfigOption 模板变量：当前配置 + 从商品关联接口拉的套餐列表。 */
    public static function productConfigVars($product): array
    {
        $config = self::productConfig($product);
        $products = [];
        $error = '';
        try {
            $server = self::productServer($product);
            foreach (self::client($server, ['retries' => 0, 'timeout' => 8])->listProducts() as $item) {
                $periods = [];
                foreach (isset($item['periods']) ? $item['periods'] : [] as $period) {
                    $periods[] = (string)$period['period'];
                }
                $products[] = ['id' => (string)$item['id'], 'name' => (string)$item['name'], 'periods' => $periods];
            }
        } catch (\Throwable $e) {
            $error = self::error($e);
        }
        $data = [
            'product_id' => (int)self::attr($product, 'id'),
            'cdn_product_id' => isset($config['cdn_product_id']) ? (string)$config['cdn_product_id'] : '',
            'cdn_product_name' => isset($config['cdn_product_name']) ? (string)$config['cdn_product_name'] : '',
            'price_month' => isset($config['price_month']) ? $config['price_month'] : null,
            'price_quarter' => isset($config['price_quarter']) ? $config['price_quarter'] : null,
            'price_year' => isset($config['price_year']) ? $config['price_year'] : null,
            'products' => $products,
            'load_error' => $error,
        ];
        return ['cdnca_config_json' => self::json($data)];
    }

    /** 保存商品配置（后台控制器调用）。价格为空表示不开放该周期。 */
    public static function saveProductConfig(array $input): array
    {
        $productId = isset($input['product_id']) ? (int)$input['product_id'] : 0;
        $product = $productId > 0 ? \app\common\model\ProductModel::find($productId) : null;
        if (empty($product) || $product->getModule() !== self::MODULE) {
            return ['status' => 400, 'msg' => self::lang('cdnca_product_not_cdnca')];
        }
        $cdnProductId = isset($input['cdn_product_id']) ? trim((string)$input['cdn_product_id']) : '';
        if (!preg_match('/^[\x21-\x7E]{1,64}$/', $cdnProductId)) {
            return ['status' => 400, 'msg' => self::lang('cdnca_cdn_product_invalid')];
        }
        $row = [
            'product_id' => $productId,
            'cdn_product_id' => $cdnProductId,
            'cdn_product_name' => mb_substr(trim(isset($input['cdn_product_name']) ? (string)$input['cdn_product_name'] : ''), 0, 255),
            'update_time' => time(),
        ];
        $open = 0;
        foreach (self::CYCLES as $cycle) {
            $value = isset($input[$cycle['column']]) ? trim((string)$input[$cycle['column']]) : '';
            if ($value === '') {
                $row[$cycle['column']] = null;
                continue;
            }
            if (!is_numeric($value) || (float)$value < 0 || (float)$value > 99999999) {
                return ['status' => 400, 'msg' => self::lang('cdnca_price_invalid')];
            }
            $row[$cycle['column']] = round((float)$value, 2);
            $open++;
        }
        if ($open === 0) {
            return ['status' => 400, 'msg' => self::lang('cdnca_price_required')];
        }
        $exists = Db::name(self::TABLE)->where('product_id', $productId)->find();
        if ($exists) {
            Db::name(self::TABLE)->where('product_id', $productId)->update($row);
        } else {
            Db::name(self::TABLE)->insert($row);
        }
        return ['status' => 200, 'msg' => self::lang('cdnca_save_success')];
    }

    /** 商品关联的接口（type=server 直接取，server_group 取组内第一台），密码解密。 */
    public static function productServer($product)
    {
        $relId = (int)self::attr($product, 'rel_id');
        $type = (string)self::attr($product, 'type');
        $server = null;
        if ($relId > 0 && $type === 'server') {
            $server = ServerModel::find($relId);
        } elseif ($relId > 0 && $type === 'server_group') {
            $server = ServerModel::where('server_group_id', $relId)->where('module', self::MODULE)->find();
        }
        if (empty($server)) {
            throw new \CdncaBridgeException('client_invalid_argument', self::lang('cdnca_server_missing'));
        }
        $server['password'] = aes_password_decode($server['password']);
        return $server;
    }

    // ------------------------------------------------------------- 前台

    /** 产品内页与后台详情的展示变量（实时拉 /services 与 /usage）。 */
    public static function overviewVars(array $param): array
    {
        $hostId = (string)self::attr(isset($param['host']) ? $param['host'] : null, 'id');
        $vars = ['cdnca_ok' => 0, 'cdnca_error' => '', 'cdnca_can_login' => 0, 'cdnca_host_id' => (int)$hostId,
            'cdnca_product' => '', 'cdnca_period' => '', 'cdnca_status' => '', 'cdnca_ends_at' => '-',
            'cdnca_username' => '', 'cdnca_traffic' => '-', 'cdnca_usage_window' => ''];
        try {
            $client = self::client(isset($param['server']) ? $param['server'] : null);
            $service = $client->getService(self::SYSTEM, $hostId);
            $usage = $client->getUsage(self::SYSTEM, [$hostId]);
            $row = $usage ? $usage[0] : null;
            $vars = array_merge($vars, [
                'cdnca_ok' => 1,
                'cdnca_product' => isset($service['product']['name']) ? (string)$service['product']['name'] : '',
                'cdnca_period' => \CdncaBridgeText::period(isset($service['period']) ? (string)$service['period'] : ''),
                'cdnca_status' => \CdncaBridgeText::status(isset($service['status']) ? (string)$service['status'] : ''),
                'cdnca_ends_at' => \CdncaBridgeText::date(isset($service['ends_at']) ? $service['ends_at'] : null),
                'cdnca_username' => isset($service['user']['username']) ? (string)$service['user']['username'] : '',
                'cdnca_traffic' => $row ? \CdncaBridgeText::bytes((float)$row['traffic_bytes']) : '-',
                'cdnca_usage_window' => $row ? \CdncaBridgeText::date($row['period_start']) . ' ～ ' . \CdncaBridgeText::date($row['period_end']) : '',
                'cdnca_can_login' => isset($service['status']) && $service['status'] === 'active'
                    && (string)self::attr($param['host'], 'status') === 'Active' ? 1 : 0,
            ]);
        } catch (\Throwable $e) {
            self::log('clientArea', $hostId, $e);
            $vars['cdnca_error'] = self::error($e);
        }
        return $vars;
    }

    /** 前台导航产品列表：当前登录客户在这些商品下的产品。 */
    public static function clientHosts(array $productIds): array
    {
        $clientId = (int)get_client_id();
        $productIds = array_values(array_filter(array_map('intval', $productIds)));
        if ($clientId <= 0 || !$productIds) {
            return [];
        }
        $rows = Db::name('host')->alias('h')->leftJoin('product p', 'p.id=h.product_id')
            ->field('h.id,h.name,h.status,h.due_time,h.billing_cycle_name,p.name product_name')
            ->where('h.client_id', $clientId)->whereIn('h.product_id', $productIds)->where('h.is_delete', 0)
            ->order('h.id', 'desc')->select()->toArray();
        foreach ($rows as &$row) {
            $row['due_time'] = \CdncaBridgeText::date((int)$row['due_time']);
        }
        return $rows;
    }

    /**
     * 免密登录。路由只做了登录验证，这里必须自己校验：产品存在、未删除、属于当前登录客户、
     * 是本模块的产品、状态为 Active。任何一项不满足一律按「产品不存在」返回，不泄露存在性。
     */
    public static function ssoForClient(int $hostId, int $clientId): array
    {
        if ($hostId <= 0 || $clientId <= 0) {
            return ['status' => 400, 'msg' => self::lang('cdnca_host_not_found')];
        }
        $host = HostModel::find($hostId);
        if (empty($host) || !empty($host['is_delete']) || (int)$host['client_id'] !== $clientId
            || $host->getModule() !== self::MODULE) {
            return ['status' => 400, 'msg' => self::lang('cdnca_host_not_found')];
        }
        if ((string)$host['status'] !== 'Active') {
            return ['status' => 400, 'msg' => self::lang('cdnca_host_not_active')];
        }
        $params = $host->getModuleParams();
        $sid = (string)$hostId;
        try {
            // 每次都要新票据：幂等键带随机后缀，不能命中服务端缓存的旧（已用）票据。
            $sso = self::client($params['server'])->createSso(self::SYSTEM, $sid, '',
                \CdncaBridgeClient::idempotencyKey(self::SYSTEM, $sid, 'sso', bin2hex(random_bytes(8))));
        } catch (\Throwable $e) {
            self::log('sso', $sid, $e);
            return ['status' => 400, 'msg' => self::error($e)];
        }
        if (empty($sso['url'])) {
            return ['status' => 400, 'msg' => self::lang('cdnca_sso_empty')];
        }
        return ['status' => 200, 'msg' => self::lang('cdnca_success'), 'data' => ['url' => (string)$sso['url']]];
    }

    // ------------------------------------------------------------- 工具

    /** 读 Model（ArrayAccess）/数组/对象的字段。 */
    public static function attr($model, string $key)
    {
        if (is_array($model)) {
            return isset($model[$key]) ? $model[$key] : '';
        }
        if ($model instanceof \ArrayAccess) {
            $value = $model[$key];
            return $value === null ? '' : $value;
        }
        if (is_object($model) && isset($model->{$key})) {
            return $model->{$key};
        }
        return '';
    }

    public static function lang(string $key, array $replace = []): string
    {
        return function_exists('lang_plugins') ? (string)lang_plugins($key, $replace) : $key;
    }

    public static function json($data): string
    {
        return (string)json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
    }

    /** 失败写系统日志（不含密钥）。 */
    public static function log(string $action, string $hostId, \Throwable $e)
    {
        if (!function_exists('active_log')) {
            return;
        }
        try {
            active_log('CDNCA ' . $action . ' #' . $hostId . ': ' . self::error($e), 'host', (int)$hostId);
        } catch (\Throwable $ignored) {
            // 日志失败不影响业务
        }
    }
}
