<?php
/**
 * CDNCA CDN —— WHMCS provisioning module（ADR 0019 BB-07）。
 *
 * 服务器配置：Hostname = 控制台域名，Username = 对接密钥 key_id（cbb_...），
 * Password = 对接密钥 secret（cbs_...，WHMCS 加密存储），勾选 Secure 走 HTTPS。
 * 产品配置：configoption1 = CDN 套餐 ID（下拉由 GET /products 加载，失败可手填）。
 */

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

use WHMCS\Database\Capsule;

if (is_file(__DIR__ . '/lib/CdncaBridgeClient.php')) {
    require_once __DIR__ . '/lib/CdncaBridgeClient.php'; // 打包后的布局
} else {
    require_once __DIR__ . '/../../../../php-sdk/src/CdncaBridgeClient.php'; // 仓库内布局
}

defined('CDNCA_SYSTEM') || define('CDNCA_SYSTEM', 'whmcs');
defined('CDNCA_MODULE') || define('CDNCA_MODULE', 'cdnca');

function cdnca_MetaData()
{
    return [
        'DisplayName' => 'CDNCA CDN',
        'APIVersion' => '1.1',
        'RequiresServer' => true,
        'DefaultNonSSLPort' => '80',
        'DefaultSSLPort' => '443',
        'ServiceSingleSignOnLabel' => '登录 CDN 控制台',
    ];
}

function cdnca_ConfigOptions()
{
    return [
        'product_id' => [
            'FriendlyName' => 'CDN 套餐',
            'Type' => 'text',
            'Size' => '40',
            'Loader' => 'cdnca_LoaderProducts',
            'SimpleMode' => true,
            'Description' => '从 CDN 主控拉取已上架套餐；拉取失败时可直接填写套餐 ID',
        ],
    ];
}

/**
 * ConfigOptions 的 Loader：返回 [套餐ID => 显示名]。抛异常时 WHMCS 显示错误并
 * 保留文本框供手填（待真实 WHMCS 核对）。
 */
function cdnca_LoaderProducts(array $params)
{
    $client = null;
    try {
        $client = cdnca_client($params);
        $products = $client->listProducts();
        cdnca_log('LoaderProducts', $client, $params, $products);
    } catch (CdncaBridgeException $e) {
        cdnca_log('LoaderProducts', $client, $params, $e->getMessage());
        throw new \Exception(cdnca_error_text($e));
    }
    $options = [];
    foreach ($products as $product) {
        $periods = [];
        foreach (isset($product['periods']) ? $product['periods'] : [] as $period) {
            $periods[] = cdnca_period_label((string)$period['period']);
        }
        $options[(string)$product['id']] = $product['name'] . ($periods ? '（' . implode('/', $periods) . '）' : '');
    }
    return $options;
}

function cdnca_CreateAccount(array $params)
{
    return cdnca_run('CreateAccount', $params, function (CdncaBridgeClient $client) use ($params) {
        $productId = cdnca_product_id($params);
        $sid = (string)$params['serviceid'];
        $details = isset($params['clientsdetails']) && is_array($params['clientsdetails']) ? $params['clientsdetails'] : [];
        $client_ = ['email' => isset($details['email']) ? (string)$details['email'] : ''];
        $name = trim((isset($details['firstname']) ? $details['firstname'] : '') . ' ' . (isset($details['lastname']) ? $details['lastname'] : ''));
        if (!empty($details['companyname'])) {
            $name = $name === '' ? (string)$details['companyname'] : $name . ' (' . $details['companyname'] . ')';
        }
        if ($name !== '') {
            $client_['display_name'] = $name;
        }
        $service = $client->createService([
            'external_system' => CDNCA_SYSTEM,
            'external_service_id' => $sid,
            'external_client_id' => (string)$params['userid'],
            'client' => $client_,
            'product_id' => $productId,
            'period' => cdnca_period($params),
        ], CdncaBridgeClient::idempotencyKey(CDNCA_SYSTEM, $sid, 'create', cdnca_service_field($params, 'regdate', 'v1')));
        cdnca_store_username($params, $service);
        return $service;
    });
}

function cdnca_SuspendAccount(array $params)
{
    return cdnca_run('SuspendAccount', $params, function (CdncaBridgeClient $client) use ($params) {
        $sid = (string)$params['serviceid'];
        $reason = isset($params['suspendreason']) ? (string)$params['suspendreason'] : '';
        return $client->suspendService(CDNCA_SYSTEM, $sid, $reason, cdnca_key($sid, 'suspend'));
    });
}

function cdnca_UnsuspendAccount(array $params)
{
    return cdnca_run('UnsuspendAccount', $params, function (CdncaBridgeClient $client) use ($params) {
        $sid = (string)$params['serviceid'];
        return $client->unsuspendService(CDNCA_SYSTEM, $sid, cdnca_key($sid, 'unsuspend'));
    });
}

function cdnca_TerminateAccount(array $params)
{
    return cdnca_run('TerminateAccount', $params, function (CdncaBridgeClient $client) use ($params) {
        $sid = (string)$params['serviceid'];
        return $client->terminateService(CDNCA_SYSTEM, $sid, cdnca_key($sid, 'terminate'));
    });
}

function cdnca_Renew(array $params)
{
    return cdnca_run('Renew', $params, function (CdncaBridgeClient $client) use ($params) {
        $sid = (string)$params['serviceid'];
        // 以下次到期日作幂等参照：cron 重试同一次续费不会重复续期，下个周期换新键。
        $ref = cdnca_service_field($params, 'nextduedate', gmdate('Ymd'));
        return $client->renewService(CDNCA_SYSTEM, $sid, cdnca_period($params),
            CdncaBridgeClient::idempotencyKey(CDNCA_SYSTEM, $sid, 'renew', $ref));
    });
}

function cdnca_ChangePackage(array $params)
{
    return cdnca_run('ChangePackage', $params, function (CdncaBridgeClient $client) use ($params) {
        $sid = (string)$params['serviceid'];
        $productId = cdnca_product_id($params);
        $period = cdnca_period($params);
        // 同一天同目标套餐+周期视为同一次变更（模块队列重试不会重复扣差价）。
        return $client->changeService(CDNCA_SYSTEM, $sid, ['product_id' => $productId, 'period' => $period],
            CdncaBridgeClient::idempotencyKey(CDNCA_SYSTEM, $sid, 'change', $productId . '.' . $period . '.' . gmdate('Ymd')));
    });
}

function cdnca_TestConnection(array $params)
{
    $client = null;
    try {
        $client = cdnca_client($params);
        $ping = $client->ping();
        cdnca_log('TestConnection', $client, $params, $ping);
        if (empty($ping['module_enabled'])) {
            return ['success' => false, 'error' => 'CDN 主控未启用财务对接插件'];
        }
        return ['success' => true, 'error' => ''];
    } catch (\Throwable $e) {
        cdnca_log('TestConnection', $client, $params, $e->getMessage());
        return ['success' => false, 'error' => cdnca_error_text($e)];
    }
}

function cdnca_ServiceSingleSignOn(array $params)
{
    $client = null;
    try {
        $client = cdnca_client($params);
        $sid = (string)$params['serviceid'];
        // 每次都要新票据：幂等键带随机后缀，不能命中服务端缓存的旧（已用）票据。
        $sso = $client->createSso(CDNCA_SYSTEM, $sid, '',
            CdncaBridgeClient::idempotencyKey(CDNCA_SYSTEM, $sid, 'sso', bin2hex(random_bytes(8))));
        cdnca_log('ServiceSingleSignOn', $client, $params, ['expires_at' => isset($sso['expires_at']) ? $sso['expires_at'] : null]);
        if (empty($sso['url'])) {
            return ['success' => false, 'errorMsg' => 'CDN 主控没有返回登录链接'];
        }
        return ['success' => true, 'redirectTo' => (string)$sso['url']];
    } catch (\Throwable $e) {
        cdnca_log('ServiceSingleSignOn', $client, $params, $e->getMessage());
        return ['success' => false, 'errorMsg' => cdnca_error_text($e)];
    }
}

/**
 * 每日 cron：按服务器批量拉本周期流量，写 tblhosting.bwusage（MB）与 lastupdate。
 * CDN 无磁盘概念，diskusage/disklimit 不动。
 */
function cdnca_UsageUpdate(array $params)
{
    $client = null;
    try {
        if (!class_exists(Capsule::class)) {
            return 'WHMCS 数据库不可用';
        }
        $client = cdnca_client($params);
        $ids = Capsule::table('tblhosting')
            ->where('server', (int)$params['serverid'])
            ->whereIn('domainstatus', ['Active', 'Suspended'])
            ->pluck('id');
        $ids = array_map('strval', is_array($ids) ? $ids : $ids->all());
        if (!$ids) {
            return 'success';
        }
        $rows = $client->getUsage(CDNCA_SYSTEM, $ids);
        cdnca_log('UsageUpdate', $client, $params, ['services' => count($ids), 'rows' => count($rows)]);
        $now = date('Y-m-d H:i:s');
        foreach ($rows as $row) {
            Capsule::table('tblhosting')
                ->where('id', (int)$row['external_service_id'])
                ->where('server', (int)$params['serverid'])
                ->update([
                    'bwusage' => (int)round(((float)$row['traffic_bytes']) / 1048576),
                    'lastupdate' => $now,
                ]);
        }
        return 'success';
    } catch (\Throwable $e) {
        cdnca_log('UsageUpdate', $client, $params, $e->getMessage());
        return cdnca_error_text($e);
    }
}

function cdnca_ClientArea(array $params)
{
    $client = null;
    try {
        $client = cdnca_client($params);
        $sid = (string)$params['serviceid'];
        $service = $client->getService(CDNCA_SYSTEM, $sid);
        $usage = $client->getUsage(CDNCA_SYSTEM, [$sid]);
        $row = $usage ? $usage[0] : null;
        return [
            'tabOverviewModuleOutputTemplate' => 'templates/clientarea.tpl',
            'templateVariables' => [
                'cdnca_ok' => true,
                'cdnca_product' => isset($service['product']['name']) ? $service['product']['name'] : '',
                'cdnca_period' => cdnca_period_label(isset($service['period']) ? (string)$service['period'] : ''),
                'cdnca_status' => cdnca_status_label(isset($service['status']) ? (string)$service['status'] : ''),
                'cdnca_ends_at' => cdnca_date(isset($service['ends_at']) ? $service['ends_at'] : null),
                'cdnca_username' => isset($service['user']['username']) ? $service['user']['username'] : '',
                'cdnca_traffic' => $row ? cdnca_bytes((float)$row['traffic_bytes']) : '-',
                'cdnca_usage_window' => $row ? cdnca_date($row['period_start']) . ' ～ ' . cdnca_date($row['period_end']) : '',
                'cdnca_can_login' => isset($service['status']) && $service['status'] === 'active',
                'cdnca_serviceid' => (int)$params['serviceid'],
            ],
        ];
    } catch (\Throwable $e) {
        cdnca_log('ClientArea', $client, $params, $e->getMessage());
        return [
            'tabOverviewModuleOutputTemplate' => 'templates/clientarea.tpl',
            'templateVariables' => ['cdnca_ok' => false, 'cdnca_error' => cdnca_error_text($e)],
        ];
    }
}

function cdnca_AdminServicesTabFields(array $params)
{
    $sid = (string)$params['serviceid'];
    $fields = [
        '外部映射' => cdnca_h(CDNCA_SYSTEM . ' / service ' . $sid . ' / client ' . $params['userid']),
    ];
    $client = null;
    try {
        $client = cdnca_client($params);
        $service = $client->getService(CDNCA_SYSTEM, $sid);
        $fields['CDN 用户名'] = cdnca_h(isset($service['user']['username']) ? $service['user']['username'] : '-');
        $fields['CDN 状态'] = cdnca_h(cdnca_status_label((string)$service['status'])
            . ' · ' . (isset($service['product']['name']) ? $service['product']['name'] : '')
            . ' · 到期 ' . cdnca_date(isset($service['ends_at']) ? $service['ends_at'] : null));
    } catch (\Throwable $e) {
        cdnca_log('AdminServicesTabFields', $client, $params, $e->getMessage());
        $fields['CDN 用户名'] = cdnca_h('读取失败：' . cdnca_error_text($e));
    }
    $fields['最近同步'] = cdnca_h(cdnca_service_field($params, 'lastupdate', '') ?: '尚未同步');
    return $fields;
}

// ------------------------------------------------------------------ 内部函数

function cdnca_client(array $params): CdncaBridgeClient
{
    $host = trim(isset($params['serverhostname']) && $params['serverhostname'] !== '' ? (string)$params['serverhostname']
        : (isset($params['serverip']) ? (string)$params['serverip'] : ''));
    if ($host === '') {
        throw new CdncaBridgeException('client_invalid_argument', '服务器未填写 Hostname（控制台域名）');
    }
    if (strpos($host, '://') === false) {
        $secure = !empty($params['serversecure']) && $params['serversecure'] !== 'off';
        $port = isset($params['serverport']) ? (int)$params['serverport'] : 0;
        $host = ($secure ? 'https' : 'http') . '://' . $host
            . ($port > 0 && $port !== ($secure ? 443 : 80) ? ':' . $port : '');
    }
    return new CdncaBridgeClient($host, trim((string)$params['serverusername']), trim((string)$params['serverpassword']));
}

/** 执行一次写操作：成功返回 'success'，失败记日志并返回中文错误文本。 */
function cdnca_run(string $action, array $params, callable $work)
{
    $client = null;
    try {
        $client = cdnca_client($params);
        $result = $work($client);
        cdnca_log($action, $client, $params, $result);
        return 'success';
    } catch (\Throwable $e) {
        cdnca_log($action, $client, $params, $e->getMessage());
        return cdnca_error_text($e);
    }
}

function cdnca_key(string $sid, string $action): string
{
    // 停用/恢复/终止本身按状态幂等；键只需覆盖本次调用内的重试。
    return CdncaBridgeClient::idempotencyKey(CDNCA_SYSTEM, $sid, $action, gmdate('YmdHis'));
}

function cdnca_log(string $action, ?CdncaBridgeClient $client, array $params, $processed)
{
    if (!function_exists('logModuleCall')) {
        return;
    }
    $exchange = $client ? $client->getLastExchange() : null;
    $replace = array_values(array_filter([isset($params['serverpassword']) ? (string)$params['serverpassword'] : ''],
        function ($v) { return $v !== ''; }));
    logModuleCall(CDNCA_MODULE, $action,
        $exchange ? $exchange['request'] : ['serviceid' => isset($params['serviceid']) ? $params['serviceid'] : null],
        $exchange ? $exchange['response'] : '',
        $processed, $replace);
}

function cdnca_product_id(array $params): string
{
    $id = trim(isset($params['configoption1']) ? (string)$params['configoption1'] : '');
    if ($id === '') {
        throw new CdncaBridgeException('client_invalid_argument', '产品未配置 CDN 套餐（模块设置 → CDN 套餐）');
    }
    return $id;
}

/** WHMCS billingcycle → 主控 period（主控只支持 month/quarter/year）。 */
function cdnca_period(array $params): string
{
    $cycle = cdnca_service_field($params, 'billingcycle', '');
    $map = ['monthly' => 'month', 'quarterly' => 'quarter', 'annually' => 'year'];
    $key = strtolower(trim($cycle));
    if (isset($map[$key])) {
        return $map[$key];
    }
    if ($key === 'semi-annually') {
        throw new CdncaBridgeException('client_invalid_argument', 'CDN 主控暂不支持半年付（Semi-Annually），请改为月付/季付/年付');
    }
    throw new CdncaBridgeException('client_invalid_argument', '不支持的计费周期：' . ($cycle === '' ? '（空）' : $cycle) . '，仅支持 Monthly / Quarterly / Annually');
}

/** 从 $params['model']（WHMCS\Service\Service）或 tblhosting 读服务字段。 */
function cdnca_service_field(array $params, string $field, string $default): string
{
    if (isset($params[$field]) && $params[$field] !== '') {
        return (string)$params[$field];
    }
    if (isset($params['model']) && is_object($params['model'])) {
        $value = $params['model']->{$field};
        if ($value !== null && $value !== '') {
            return (string)$value;
        }
    }
    if (class_exists(Capsule::class) && !empty($params['serviceid'])) {
        try {
            $value = Capsule::table('tblhosting')->where('id', (int)$params['serviceid'])->value($field);
            if ($value !== null && $value !== '') {
                return (string)$value;
            }
        } catch (\Throwable $e) {
            // 读不到时回落默认值
        }
    }
    return $default;
}

/** 开户成功后把 CDN 用户名写回 tblhosting.username，供后台与客户区展示。 */
function cdnca_store_username(array $params, array $service)
{
    if (empty($service['user']['username']) || !class_exists(Capsule::class)) {
        return;
    }
    try {
        Capsule::table('tblhosting')->where('id', (int)$params['serviceid'])
            ->update(['username' => (string)$service['user']['username']]);
    } catch (\Throwable $e) {
        // 不影响开户结果
    }
}

function cdnca_error_text(\Throwable $e): string
{
    if (!$e instanceof CdncaBridgeException) {
        return '模块内部错误：' . $e->getMessage();
    }
    $hints = [
        'bridge_unauthenticated' => '对接密钥鉴权失败：检查 key_id / secret、本机出口 IP 是否在白名单、服务器时间是否准确',
        'unauthorized' => '对接密钥鉴权失败：检查 key_id / secret、本机出口 IP 是否在白名单、服务器时间是否准确',
        'entitlement_feature_denied' => 'CDN 主控未启用财务对接插件',
        'bridge_service_not_found' => 'CDN 侧找不到该服务（可能尚未开通，或不属于此对接密钥）',
        'bridge_product_not_found' => 'CDN 套餐不存在或已下架，请在产品模块设置中重新选择',
        'bridge_service_conflict' => '该服务已用不同参数开通过，参数冲突',
        'bridge_service_terminated' => '该服务在 CDN 侧已终止，不能再操作',
        'reseller_prepaid_insufficient' => '代理商预付余额不足，请先在 CDN 平台充值',
        'reseller_wholesale_unpriced' => '该套餐此周期未设置批发价，请联系 CDN 平台',
        'reseller_change_irreversible' => '代理商升降级订单不可退款或作废',
        'bridge_validation_error' => '请求参数不合法',
        'network_error' => '无法连接 CDN 主控',
        'invalid_response' => 'CDN 主控响应异常',
        'client_invalid_argument' => '配置或参数错误',
    ];
    $code = $e->getErrorCode();
    $hint = isset($hints[$code]) ? $hints[$code] : 'CDN 主控返回错误';
    $text = $hint;
    $message = $e->getMessage();
    if ($message !== '' && $message !== $hint) {
        $text .= '：' . $message;
    }
    $meta = [$code];
    if ($e->getHttpStatus() > 0) {
        $meta[] = 'HTTP ' . $e->getHttpStatus();
    }
    if ($e->getRequestId() !== '') {
        $meta[] = 'request_id ' . $e->getRequestId();
    }
    return $text . '（' . implode('，', $meta) . '）';
}

function cdnca_period_label(string $period): string
{
    $labels = ['month' => '月付', 'quarter' => '季付', 'year' => '年付'];
    return isset($labels[$period]) ? $labels[$period] : $period;
}

function cdnca_status_label(string $status): string
{
    $labels = ['active' => '正常', 'suspended' => '已停用', 'terminated' => '已终止'];
    return isset($labels[$status]) ? $labels[$status] : $status;
}

function cdnca_date($value): string
{
    if (!is_string($value) || $value === '') {
        return '-';
    }
    $ts = strtotime($value);
    return $ts === false ? $value : date('Y-m-d H:i', $ts);
}

function cdnca_bytes(float $bytes): string
{
    $units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    $i = 0;
    while ($bytes >= 1024 && $i < count($units) - 1) {
        $bytes /= 1024;
        $i++;
    }
    return ($i === 0 ? (string)(int)$bytes : number_format($bytes, 2)) . ' ' . $units[$i];
}

function cdnca_h(string $text): string
{
    return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
}
