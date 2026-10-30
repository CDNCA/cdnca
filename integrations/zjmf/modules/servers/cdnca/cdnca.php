<?php
/**
 * CDNCA CDN —— 智简魔方「财务系统」（老版）服务器模块（ADR 0019，external_system=zjmf）。
 *
 * 接口（服务器）配置：主机名 = 控制台域名（也可填完整 https://...），用户名 = 对接密钥
 * key_id（cbb_...），密码 = 对接密钥 secret（cbs_...，财务系统加密存储），勾选 SSL 走 HTTPS。
 * 选 password 而不是 accesshash：password 列加密存储，accesshash 为明文且只有 50 字符。
 * 商品模块设置：CDN 套餐（key=product_id；能连上主控时为下拉，否则手填套餐 ID）。
 * 映射：external_service_id = hostid，external_client_id = uid。
 */

if (is_file(__DIR__ . '/lib/CdncaBridgeClient.php')) {
    require_once __DIR__ . '/lib/CdncaBridgeClient.php'; // 打包后的布局
    require_once __DIR__ . '/lib/CdncaBridgeText.php';
} else {
    require_once __DIR__ . '/../../../../php-sdk/src/CdncaBridgeClient.php'; // 仓库内布局
    require_once __DIR__ . '/../../../../php-sdk/src/CdncaBridgeText.php';
}

defined('CDNCA_ZJMF_SYSTEM') || define('CDNCA_ZJMF_SYSTEM', 'zjmf');

function cdnca_MetaData()
{
    return [
        'DisplayName' => 'CDNCA CDN',
        'APIVersion' => '1.1',
        // 打包时 README.md 放在模块目录，模块目录位于 public/ 下可直接访问（路径待真机核对）。
        'HelpDoc' => '/plugins/servers/cdnca/README.md',
    ];
}

/**
 * 商品模块设置。ConfigOptions 不带参数，只能自己找一台 cdnca 模块的接口去拉 /products；
 * 拉不到（未建接口、网络不通）就退回文本框手填。同一进程内只拉一次。
 */
function cdnca_ConfigOptions()
{
    $option = [
        'type' => 'text',
        'name' => 'CDN 套餐',
        'placeholder' => '套餐 ID',
        'description' => '填写 CDN 主控上已上架套餐的 ID（建好接口后此处会变成下拉）',
        'default' => '',
        'key' => 'product_id',
    ];
    $products = cdnca_products_for_options();
    if ($products) {
        $options = [];
        foreach ($products as $product) {
            $periods = [];
            foreach (isset($product['periods']) ? $product['periods'] : [] as $period) {
                $periods[] = CdncaBridgeText::period((string)$period['period']);
            }
            $options[(string)$product['id']] = $product['name'] . ($periods ? '（' . implode('/', $periods) . '）' : '');
        }
        $option['type'] = 'dropdown';
        $option['options'] = $options;
        $option['description'] = '从 CDN 主控拉取的已上架套餐';
        $option['default'] = (string)key($options);
        unset($option['placeholder']);
    }
    return [$option];
}

/** 财务系统「测试连接」（V10 兼容层与内置模块都用 TestLink，文档未列，待真机核对）。 */
function cdnca_TestLink($params)
{
    try {
        $ping = cdnca_client($params, ['retries' => 0])->ping();
        if (empty($ping['module_enabled'])) {
            return ['status' => 200, 'data' => ['server_status' => 0, 'msg' => 'CDN 主控未启用财务对接插件']];
        }
        return ['status' => 200, 'data' => ['server_status' => 1]];
    } catch (\Throwable $e) {
        return ['status' => 200, 'data' => ['server_status' => 0, 'msg' => CdncaBridgeText::error($e)]];
    }
}

function cdnca_CreateAccount($params)
{
    return cdnca_run('CreateAccount', $params, function (CdncaBridgeClient $client) use ($params) {
        $hostId = cdnca_host_id($params);
        $info = cdnca_user_info($params);
        $email = trim((string)cdnca_pick($info, 'email'));
        if ($email === '') {
            throw new CdncaBridgeException('client_invalid_argument', '客户未填写邮箱，无法在 CDN 侧开户');
        }
        $client_ = ['email' => $email];
        $name = trim((string)cdnca_pick($info, 'username'));
        $company = trim((string)cdnca_pick($info, 'companyname'));
        if ($company !== '') {
            $name = $name === '' ? $company : $name . ' (' . $company . ')';
        }
        if ($name !== '') {
            $client_['display_name'] = $name;
        }
        $service = $client->createService([
            'external_system' => CDNCA_ZJMF_SYSTEM,
            'external_service_id' => $hostId,
            'external_client_id' => (string)$params['uid'],
            'client' => $client_,
            'product_id' => cdnca_product_id($params),
            'period' => cdnca_period($params),
        ], CdncaBridgeClient::idempotencyKey(CDNCA_ZJMF_SYSTEM, $hostId, 'create', cdnca_ref($params, 'regdate', 'v1')));
        cdnca_store_username($hostId, $service);
    });
}

function cdnca_SuspendAccount($params)
{
    return cdnca_run('SuspendAccount', $params, function (CdncaBridgeClient $client) use ($params) {
        $hostId = cdnca_host_id($params);
        $reason = isset($params['suspendreason']) ? (string)$params['suspendreason'] : '';
        $client->suspendService(CDNCA_ZJMF_SYSTEM, $hostId, $reason, cdnca_key($hostId, 'suspend'));
    });
}

function cdnca_UnsuspendAccount($params)
{
    return cdnca_run('UnsuspendAccount', $params, function (CdncaBridgeClient $client) use ($params) {
        $hostId = cdnca_host_id($params);
        $client->unsuspendService(CDNCA_ZJMF_SYSTEM, $hostId, cdnca_key($hostId, 'unsuspend'));
    });
}

function cdnca_TerminateAccount($params)
{
    return cdnca_run('TerminateAccount', $params, function (CdncaBridgeClient $client) use ($params) {
        $hostId = cdnca_host_id($params);
        $client->terminateService(CDNCA_ZJMF_SYSTEM, $hostId, cdnca_key($hostId, 'terminate'));
    });
}

function cdnca_Renew($params)
{
    return cdnca_run('Renew', $params, function (CdncaBridgeClient $client) use ($params) {
        $hostId = cdnca_host_id($params);
        // 以到期时间作幂等参照：同一次续费重试不会重复续期，下个周期换新键。
        $ref = cdnca_ref($params, 'nextduedate', gmdate('Ymd'));
        $client->renewService(CDNCA_ZJMF_SYSTEM, $hostId, cdnca_period($params),
            CdncaBridgeClient::idempotencyKey(CDNCA_ZJMF_SYSTEM, $hostId, 'renew', $ref));
    });
}

function cdnca_ChangePackage($params)
{
    return cdnca_run('ChangePackage', $params, function (CdncaBridgeClient $client) use ($params) {
        $hostId = cdnca_host_id($params);
        $productId = cdnca_product_id($params);
        $period = cdnca_period($params);
        // 同一天同目标套餐+周期视为同一次变更（重试不会重复扣差价）。
        $client->changeService(CDNCA_ZJMF_SYSTEM, $hostId, ['product_id' => $productId, 'period' => $period],
            CdncaBridgeClient::idempotencyKey(CDNCA_ZJMF_SYSTEM, $hostId, 'change', $productId . '.' . $period . '.' . gmdate('Ymd')));
    });
}

/**
 * 免密登录：文档写明 Vnc「可以返回一个 url，成功会打开该 url」，是唯一由财务系统
 * 负责打开链接的内置入口（前台在「控制台」下拉，后台为 VNC 按钮）；ClientButton 的
 * 自定义方法文档没有说明返回值如何处理，不能保证会跳转。
 */
function cdnca_Vnc($params)
{
    try {
        $url = cdnca_sso_url($params);
        return ['status' => 'success', 'msg' => '登录链接已生成', 'url' => $url];
    } catch (\Throwable $e) {
        cdnca_log('Vnc', $params, $e);
        return ['status' => 'error', 'msg' => CdncaBridgeText::error($e)];
    }
}

/** 概览页里的「登录 CDN 控制台」按钮（AllowFunction 自定义方法，由本模块模板自行打开链接）。 */
function cdnca_AllowFunction()
{
    return ['client' => ['LoginConsole'], 'admin' => []];
}

function cdnca_LoginConsole($params)
{
    // 自定义方法的归属校验不在文档范围内，这里自己核对当前登录用户就是产品所有人；
    // 拿不到登录用户时一律拒绝（宁可不能用，不能越权）。
    $uid = cdnca_current_uid();
    if ($uid <= 0 || $uid !== (int)$params['uid']) {
        return ['status' => 'error', 'msg' => '无权操作该产品'];
    }
    if (isset($params['domainstatus']) && $params['domainstatus'] !== 'Active') {
        return ['status' => 'error', 'msg' => '产品当前不可登录'];
    }
    return cdnca_Vnc($params);
}

function cdnca_Status($params)
{
    try {
        $service = cdnca_client($params)->getService(CDNCA_ZJMF_SYSTEM, cdnca_host_id($params));
        $map = ['active' => 'on', 'suspended' => 'suspend', 'terminated' => 'off'];
        $status = isset($map[$service['status']]) ? $map[$service['status']] : 'unknown';
        return ['status' => 'success', 'data' => ['status' => $status, 'des' => CdncaBridgeText::status((string)$service['status'])]];
    } catch (\Throwable $e) {
        return ['status' => 'error', 'msg' => CdncaBridgeText::error($e)];
    }
}

/**
 * 定时用量同步。入参是本模块所有可用产品的 hostID（数组或逗号串，形态待真机核对）。
 * 按接口分组批量拉 /usage，写 shd_host.bwusage（GB，两位小数，与内置 nokvm 模块一致）
 * 与 lastupdate（时间戳）。CDN 无磁盘概念，diskusage 不动。
 */
function cdnca_UsageUpdate($hostIds)
{
    $ids = cdnca_id_list($hostIds);
    if (!$ids || !class_exists('think\Db')) {
        return 'success';
    }
    try {
        $rows = cdnca_rows(\think\Db::name('host')->alias('h')
            ->leftJoin('servers s', 's.id=h.serverid')
            ->field('h.id,h.serverid,s.hostname server_host,s.ip_address server_ip,s.username server_username,'
                . 's.password server_password,s.secure,s.port')
            ->whereIn('h.id', $ids)
            ->whereIn('h.domainstatus', ['Active', 'Suspended'])
            ->select());
    } catch (\Throwable $e) {
        cdnca_log('UsageUpdate', ['hostid' => 0], $e);
        return CdncaBridgeText::error($e);
    }
    $byServer = [];
    foreach ($rows as $row) {
        $byServer[(int)$row['serverid']][] = $row;
    }
    $errors = [];
    foreach ($byServer as $serverId => $hosts) {
        try {
            $server = $hosts[0];
            $server['server_password'] = cdnca_decrypt((string)$server['server_password']);
            $usage = cdnca_client($server)->getUsage(CDNCA_ZJMF_SYSTEM, array_column($hosts, 'id'));
            $now = time();
            foreach ($usage as $item) {
                \think\Db::name('host')->where('id', (int)$item['external_service_id'])->where('serverid', $serverId)
                    ->update(['bwusage' => round(((float)$item['traffic_bytes']) / 1073741824, 2), 'lastupdate' => $now]);
            }
        } catch (\Throwable $e) {
            cdnca_log('UsageUpdate', ['hostid' => 0, 'serverid' => $serverId], $e);
            $errors[] = '接口 ' . $serverId . '：' . CdncaBridgeText::error($e);
        }
    }
    return $errors ? implode('；', $errors) : 'success';
}

function cdnca_ClientArea($params)
{
    return ['overview' => ['name' => 'CDN 概览']];
}

function cdnca_ClientAreaOutput($params, $key)
{
    if ($key !== 'overview') {
        return '';
    }
    $vars = ['cdnca_ok' => 0, 'cdnca_error' => '', 'cdnca_can_login' => 0];
    try {
        $client = cdnca_client($params);
        $hostId = cdnca_host_id($params);
        $service = $client->getService(CDNCA_ZJMF_SYSTEM, $hostId);
        $usage = $client->getUsage(CDNCA_ZJMF_SYSTEM, [$hostId]);
        $row = $usage ? $usage[0] : null;
        $vars = [
            'cdnca_ok' => 1,
            'cdnca_error' => '',
            'cdnca_product' => isset($service['product']['name']) ? (string)$service['product']['name'] : '',
            'cdnca_period' => CdncaBridgeText::period(isset($service['period']) ? (string)$service['period'] : ''),
            'cdnca_status' => CdncaBridgeText::status(isset($service['status']) ? (string)$service['status'] : ''),
            'cdnca_ends_at' => CdncaBridgeText::date(isset($service['ends_at']) ? $service['ends_at'] : null),
            'cdnca_username' => isset($service['user']['username']) ? (string)$service['user']['username'] : '',
            'cdnca_traffic' => $row ? CdncaBridgeText::bytes((float)$row['traffic_bytes']) : '-',
            'cdnca_usage_window' => $row ? CdncaBridgeText::date($row['period_start']) . ' ～ ' . CdncaBridgeText::date($row['period_end']) : '',
            'cdnca_can_login' => isset($service['status']) && $service['status'] === 'active' ? 1 : 0,
        ];
    } catch (\Throwable $e) {
        cdnca_log('ClientAreaOutput', $params, $e);
        $vars['cdnca_error'] = CdncaBridgeText::error($e);
    }
    return ['template' => 'templates/overview.html', 'vars' => $vars];
}

// ------------------------------------------------------------------ 内部函数

function cdnca_client(array $params, array $options = []): CdncaBridgeClient
{
    $host = trim(!empty($params['server_host']) ? (string)$params['server_host']
        : (isset($params['server_ip']) ? (string)$params['server_ip'] : ''));
    if ($host === '') {
        throw new CdncaBridgeException('client_invalid_argument', '接口未填写主机名（控制台域名）');
    }
    if (strpos($host, '://') === false) {
        $secure = !empty($params['secure']);
        $port = isset($params['port']) ? (int)$params['port'] : 0;
        $host = ($secure ? 'https' : 'http') . '://' . $host
            . ($port > 0 && $port !== ($secure ? 443 : 80) ? ':' . $port : '');
    }
    return new CdncaBridgeClient($host, trim((string)(isset($params['server_username']) ? $params['server_username'] : '')),
        trim((string)(isset($params['server_password']) ? $params['server_password'] : '')), $options);
}

/** 执行一次写操作：成功返回 'success'，失败记日志并返回 ['status'=>'error','msg'=>中文原因]。 */
function cdnca_run(string $action, $params, callable $work)
{
    try {
        $work(cdnca_client($params));
        return 'success';
    } catch (\Throwable $e) {
        cdnca_log($action, $params, $e);
        return ['status' => 'error', 'msg' => CdncaBridgeText::error($e)];
    }
}

function cdnca_sso_url(array $params): string
{
    $hostId = cdnca_host_id($params);
    // 每次都要新票据：幂等键带随机后缀，不能命中服务端缓存的旧（已用）票据。
    $sso = cdnca_client($params)->createSso(CDNCA_ZJMF_SYSTEM, $hostId, '',
        CdncaBridgeClient::idempotencyKey(CDNCA_ZJMF_SYSTEM, $hostId, 'sso', bin2hex(random_bytes(8))));
    if (empty($sso['url'])) {
        throw new CdncaBridgeException('invalid_response', 'CDN 主控没有返回登录链接');
    }
    return (string)$sso['url'];
}

function cdnca_key(string $hostId, string $action): string
{
    // 暂停/解除/删除本身按状态幂等；键只需覆盖本次调用内的重试。
    return CdncaBridgeClient::idempotencyKey(CDNCA_ZJMF_SYSTEM, $hostId, $action, gmdate('YmdHis'));
}

function cdnca_host_id($params): string
{
    $id = isset($params['hostid']) ? trim((string)$params['hostid']) : '';
    if ($id === '' || $id === '0') {
        throw new CdncaBridgeException('client_invalid_argument', '缺少产品 ID（hostid）');
    }
    return $id;
}

function cdnca_product_id($params): string
{
    $id = '';
    if (isset($params['configoptions']['product_id']) && $params['configoptions']['product_id'] !== '') {
        $id = (string)$params['configoptions']['product_id'];
    } elseif (isset($params['config_option1'])) {
        $id = (string)$params['config_option1'];
    }
    $id = trim($id);
    if ($id === '') {
        throw new CdncaBridgeException('client_invalid_argument', '商品未配置 CDN 套餐（商品 → 模块设置 → CDN 套餐）');
    }
    return $id;
}

/** 财务系统 billingcycle → 主控 period（主控只支持 month/quarter/year）。 */
function cdnca_period($params): string
{
    $cycle = trim(isset($params['billingcycle']) ? (string)$params['billingcycle'] : '');
    $key = strtolower($cycle);
    $map = ['monthly' => 'month', 'quarterly' => 'quarter', 'annually' => 'year'];
    if (isset($map[$key])) {
        return $map[$key];
    }
    $names = ['semiannually' => '半年付', 'biennially' => '两年付', 'triennially' => '三年付', 'onetime' => '一次性',
        'free' => '免费', 'ontrial' => '试用', 'hour' => '按小时', 'day' => '按天'];
    $label = isset($names[$key]) ? $names[$key] . '（' . $cycle . '）' : ($cycle === '' ? '（空）' : $cycle);
    throw new CdncaBridgeException('client_invalid_argument', 'CDN 主控不支持该付款周期：' . $label . '，仅支持月付 / 季付 / 年付');
}

function cdnca_ref($params, string $field, string $default): string
{
    return isset($params[$field]) && (string)$params[$field] !== '' && (string)$params[$field] !== '0'
        ? (string)$params[$field] : $default;
}

function cdnca_user_info($params): array
{
    $info = isset($params['user_info']) ? $params['user_info'] : [];
    if (is_object($info) && method_exists($info, 'toArray')) {
        $info = $info->toArray();
    }
    return is_array($info) ? $info : [];
}

function cdnca_pick(array $data, string $key)
{
    return isset($data[$key]) ? $data[$key] : '';
}

/** 开户成功后把 CDN 用户名写回 shd_host.username，供后台与前台展示。 */
function cdnca_store_username(string $hostId, array $service)
{
    if (empty($service['user']['username']) || !class_exists('think\Db')) {
        return;
    }
    try {
        \think\Db::name('host')->where('id', (int)$hostId)->update(['username' => (string)$service['user']['username']]);
    } catch (\Throwable $e) {
        // 不影响开户结果
    }
}

/** 当前前台登录用户 ID；老版核心加密不可读，按 V10 兼容层的 request()->uid 读取（待真机核对）。 */
function cdnca_current_uid(): int
{
    if (!function_exists('request')) {
        return 0;
    }
    $request = request();
    return isset($request->uid) ? (int)$request->uid : 0;
}

function cdnca_decrypt(string $password): string
{
    if (function_exists('aesPasswordDecode')) {
        return (string)aesPasswordDecode($password);
    }
    throw new CdncaBridgeException('client_invalid_argument', '找不到财务系统的密码解密函数 aesPasswordDecode');
}

function cdnca_id_list($hostIds): array
{
    if (is_object($hostIds) && method_exists($hostIds, 'toArray')) {
        $hostIds = $hostIds->toArray();
    }
    if (!is_array($hostIds)) {
        $hostIds = explode(',', (string)$hostIds);
    }
    $ids = [];
    array_walk_recursive($hostIds, function ($v) use (&$ids) {
        if (is_numeric($v) && (int)$v > 0) {
            $ids[] = (int)$v;
        }
    });
    return array_values(array_unique($ids));
}

function cdnca_rows($result): array
{
    if (is_object($result) && method_exists($result, 'toArray')) {
        $result = $result->toArray();
    }
    return is_array($result) ? $result : [];
}

/** 找一台 cdnca 模块的可用接口拉套餐列表；失败返回空数组。 */
function cdnca_products_for_options(): array
{
    static $cache = null;
    if ($cache !== null) {
        return $cache;
    }
    $cache = [];
    if (!class_exists('think\Db')) {
        return $cache;
    }
    try {
        $server = \think\Db::name('servers')->alias('s')
            ->leftJoin('server_groups g', 'g.id=s.gid')
            ->field('s.hostname server_host,s.ip_address server_ip,s.username server_username,s.password server_password,s.secure,s.port')
            ->where('g.type', 'cdnca')
            ->where('s.disabled', 0)
            ->order('s.id', 'asc')
            ->find();
        if (is_object($server) && method_exists($server, 'toArray')) {
            $server = $server->toArray();
        }
        if (!is_array($server) || !$server) {
            return $cache;
        }
        $server['server_password'] = cdnca_decrypt((string)$server['server_password']);
        $products = cdnca_client($server, ['retries' => 0, 'timeout' => 5, 'connect_timeout' => 3])->listProducts();
        $cache = is_array($products) ? $products : [];
    } catch (\Throwable $e) {
        cdnca_log('ConfigOptions', ['hostid' => 0], $e);
    }
    return $cache;
}

/** 失败写系统日志（active_log 为财务系统公共函数，存在才写；不含密钥）。 */
function cdnca_log(string $action, $params, \Throwable $e)
{
    if (!function_exists('active_log')) {
        return;
    }
    try {
        $hostId = is_array($params) && isset($params['hostid']) ? $params['hostid'] : 0;
        active_log('CDNCA 模块 ' . $action . ' 失败（产品 #' . $hostId . '）：' . CdncaBridgeText::error($e));
    } catch (\Throwable $ignored) {
        // 日志失败不影响业务
    }
}
