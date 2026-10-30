<?php
namespace server\cdnca;

use server\cdnca\logic\CdncaLogic;
use think\facade\Db;

/**
 * CDNCA CDN —— 智简魔方 V10 业务系统服务器模块（ADR 0019，external_system=zjmf_cbap）。
 *
 * 系统按 \server\{目录名}\{parse_name(目录名, 1)} 实例化：目录 cdnca → 类 Cdnca、文件 Cdnca.php。
 * 接口配置：接口地址 = 控制台地址（https://cdn.example.com），用户名 = 对接密钥 key_id，
 * 密码 = 对接密钥 secret（系统 AES 加密存储，getModuleParams 解密后传入）。
 * 商品接口配置（serverConfigOption）：选 CDN 套餐，存表 idcsmart_module_cdnca_product。
 * 映射：external_service_id = host.id，external_client_id = host.client_id。
 */
class Cdnca
{
    public function metaData()
    {
        return ['display_name' => 'CDNCA CDN', 'version' => '1.0.0'];
    }

    public function afterCreateFirstServer()
    {
        Db::execute("CREATE TABLE IF NOT EXISTS `idcsmart_module_cdnca_product` (
  `product_id` int(11) unsigned NOT NULL DEFAULT '0' COMMENT '商品ID',
  `cdn_product_id` varchar(64) NOT NULL DEFAULT '' COMMENT 'CDN 主控套餐ID',
  `cdn_product_name` varchar(255) NOT NULL DEFAULT '' COMMENT 'CDN 套餐名称（展示用）',
  `price_month` decimal(10,2) DEFAULT NULL COMMENT '月付售价，NULL=不开放',
  `price_quarter` decimal(10,2) DEFAULT NULL COMMENT '季付售价，NULL=不开放',
  `price_year` decimal(10,2) DEFAULT NULL COMMENT '年付售价，NULL=不开放',
  `update_time` int(11) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`product_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='CDNCA 商品与 CDN 套餐映射';");
    }

    public function afterDeleteLastServer()
    {
        Db::execute('DROP TABLE IF EXISTS `idcsmart_module_cdnca_product`;');
    }

    public function testConnect($param)
    {
        try {
            $ping = CdncaLogic::client($param['server'], ['retries' => 0])->ping();
            if (empty($ping['module_enabled'])) {
                return ['status' => 400, 'msg' => lang_plugins('cdnca_module_disabled')];
            }
            return ['status' => 200, 'msg' => lang_plugins('cdnca_connect_success')];
        } catch (\Throwable $e) {
            return ['status' => 400, 'msg' => CdncaLogic::error($e)];
        }
    }

    public function createAccount($param)
    {
        return CdncaLogic::run('createAccount', $param, function (\CdncaBridgeClient $client, string $hostId) use ($param) {
            $email = trim((string)CdncaLogic::attr($param['client'], 'email'));
            if ($email === '') {
                throw new \CdncaBridgeException('client_invalid_argument', lang_plugins('cdnca_client_email_required'));
            }
            $info = ['email' => $email];
            $name = trim((string)CdncaLogic::attr($param['client'], 'username'));
            $company = trim((string)CdncaLogic::attr($param['client'], 'company'));
            if ($company !== '') {
                $name = $name === '' ? $company : $name . ' (' . $company . ')';
            }
            if ($name !== '') {
                $info['display_name'] = $name;
            }
            $hostRef = (string)CdncaLogic::attr($param['host'], 'create_time');
            $client->createService([
                'external_system' => CdncaLogic::SYSTEM,
                'external_service_id' => $hostId,
                'external_client_id' => (string)CdncaLogic::attr($param['host'], 'client_id'),
                'client' => $info,
                'product_id' => CdncaLogic::cdnProductId($param['product']),
                'period' => CdncaLogic::period($param['host']),
            ], \CdncaBridgeClient::idempotencyKey(CdncaLogic::SYSTEM, $hostId, 'create', $hostRef !== '' && $hostRef !== '0' ? $hostRef : 'v1'));
        }, 'cdnca_create_success');
    }

    public function suspendAccount($param)
    {
        return CdncaLogic::run('suspendAccount', $param, function (\CdncaBridgeClient $client, string $hostId) use ($param) {
            $reason = trim((isset($param['suspend_type']) ? '[' . $param['suspend_type'] . '] ' : '')
                . (isset($param['suspend_reason']) ? (string)$param['suspend_reason'] : ''));
            $client->suspendService(CdncaLogic::SYSTEM, $hostId, $reason, CdncaLogic::key($hostId, 'suspend'));
        }, 'cdnca_suspend_success');
    }

    public function unsuspendAccount($param)
    {
        return CdncaLogic::run('unsuspendAccount', $param, function (\CdncaBridgeClient $client, string $hostId) {
            $client->unsuspendService(CdncaLogic::SYSTEM, $hostId, CdncaLogic::key($hostId, 'unsuspend'));
        }, 'cdnca_unsuspend_success');
    }

    public function terminateAccount($param)
    {
        return CdncaLogic::run('terminateAccount', $param, function (\CdncaBridgeClient $client, string $hostId) {
            $client->terminateService(CdncaLogic::SYSTEM, $hostId, CdncaLogic::key($hostId, 'terminate'));
        }, 'cdnca_terminate_success');
    }

    /** 续费后调用（系统忽略返回值，失败只记日志）。 */
    public function renew($param)
    {
        return CdncaLogic::run('renew', $param, function (\CdncaBridgeClient $client, string $hostId) use ($param) {
            // 以新到期时间作幂等参照：同一次续费重试不会重复续期。
            $ref = (string)CdncaLogic::attr($param['host'], 'due_time');
            $client->renewService(CdncaLogic::SYSTEM, $hostId, CdncaLogic::period($param['host']),
                \CdncaBridgeClient::idempotencyKey(CdncaLogic::SYSTEM, $hostId, 'renew', $ref !== '' && $ref !== '0' ? $ref : gmdate('Ymd')));
        }, 'cdnca_renew_success');
    }

    /** 配置项升降级：本模块没有配置项，按商品当前套餐同步一次（通常无变化，主控按同套餐幂等处理）。 */
    public function changePackage($param)
    {
        return $this->changeProduct($param);
    }

    /** 升降级商品：host 已关联新商品，按新商品映射的 CDN 套餐变更（系统忽略返回值）。 */
    public function changeProduct($param)
    {
        return CdncaLogic::run('changeProduct', $param, function (\CdncaBridgeClient $client, string $hostId) use ($param) {
            $productId = CdncaLogic::cdnProductId($param['product']);
            $period = CdncaLogic::period($param['host']);
            $client->changeService(CdncaLogic::SYSTEM, $hostId, ['product_id' => $productId, 'period' => $period],
                \CdncaBridgeClient::idempotencyKey(CdncaLogic::SYSTEM, $hostId, 'change', $productId . '.' . $period . '.' . gmdate('Ymd')));
        }, 'cdnca_change_success');
    }

    /**
     * 购物车计价（必须实现）。CDN 商品价格由业务系统自己维护：按 custom.duration 选周期，
     * 价格从模块周期价表读（商品接口配置页填写），只允许月/季/年。
     */
    public function cartCalculatePrice($param)
    {
        $cycles = CdncaLogic::productCycles($param['product']);
        if (!$cycles) {
            return ['status' => 400, 'msg' => lang_plugins('cdnca_product_not_configured')];
        }
        $want = isset($param['custom']['duration']) ? (string)$param['custom']['duration'] : '';
        $cycle = isset($cycles[$want]) ? $cycles[$want] : reset($cycles);
        return [
            'status' => 200,
            'msg' => lang_plugins('success_message'),
            'data' => [
                'price' => $cycle['price'],
                'renew_price' => $cycle['price'],
                'billing_cycle' => $cycle['billing_cycle'],
                'duration' => $cycle['duration'],
                'description' => lang_plugins('cdnca_order_description', ['{product}' => CdncaLogic::cdnProductName($param['product']), '{cycle}' => $cycle['billing_cycle']]),
                'base_price' => $cycle['price'],
            ],
        ];
    }

    /** 续费可选周期（与购买相同的月/季/年价）。 */
    public function durationPrice($param)
    {
        return ['status' => 200, 'msg' => lang_plugins('success_message'), 'data' => array_values(CdncaLogic::productCycles($param['product']))];
    }

    public function getPriceCycle($param)
    {
        $cycles = CdncaLogic::productCycles($param['product']);
        if (!$cycles) {
            return ['price' => 0, 'cycle' => ''];
        }
        $first = reset($cycles);
        return ['price' => $first['price'], 'cycle' => $first['billing_cycle']];
    }

    /** 后台商品接口配置：选 CDN 套餐 + 各周期售价。 */
    public function serverConfigOption($param)
    {
        return ['template' => 'template/admin/product_config.html', 'vars' => CdncaLogic::productConfigVars($param['product'])];
    }

    /** 前台购买页（必须实现，否则不能购买）：只选周期。 */
    public function clientProductConfigOption($param)
    {
        $cycles = array_values(CdncaLogic::productCycles($param['product']));
        return ['template' => 'template/clientarea/goods.html', 'vars' => [
            'cdnca_product_id' => (int)CdncaLogic::attr($param['product'], 'id'),
            'cdnca_cycles' => $cycles,
            'cdnca_cycles_json' => json_encode($cycles, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT),
            'cdnca_product_name' => CdncaLogic::cdnProductName($param['product']),
        ]];
    }

    /** 前台导航产品列表（必须实现）。 */
    public function hostList($param)
    {
        return ['template' => 'template/clientarea/host_list.html', 'vars' => [
            'cdnca_hosts' => CdncaLogic::clientHosts(isset($param['product_id']) ? (array)$param['product_id'] : []),
        ]];
    }

    /** 前台产品内页（必须实现）：套餐、到期、本周期流量（实时拉 /usage）、登录按钮。 */
    public function clientArea($param)
    {
        return ['template' => 'template/clientarea/product_detail.html', 'vars' => CdncaLogic::overviewVars($param)];
    }

    public function adminArea($param)
    {
        return ['template' => 'template/admin/host_detail.html', 'vars' => CdncaLogic::overviewVars($param)];
    }

    /** 后台产品内页配置信息（只读展示）。 */
    public function adminField($param)
    {
        $vars = CdncaLogic::overviewVars($param);
        $hostId = (string)CdncaLogic::attr($param['host'], 'id');
        $fields = [
            ['name' => lang_plugins('cdnca_field_mapping'), 'key' => 'cdnca_mapping',
                'value' => CdncaLogic::SYSTEM . ' / host ' . $hostId . ' / client ' . CdncaLogic::attr($param['host'], 'client_id'), 'disable' => true],
        ];
        if ($vars['cdnca_ok']) {
            $fields[] = ['name' => lang_plugins('cdnca_field_username'), 'key' => 'cdnca_username', 'value' => $vars['cdnca_username'], 'disable' => true];
            $fields[] = ['name' => lang_plugins('cdnca_field_product'), 'key' => 'cdnca_product', 'value' => $vars['cdnca_product'] . ' ' . $vars['cdnca_period'], 'disable' => true];
            $fields[] = ['name' => lang_plugins('cdnca_field_status'), 'key' => 'cdnca_status', 'value' => $vars['cdnca_status'] . ' · ' . $vars['cdnca_ends_at'], 'disable' => true];
            $fields[] = ['name' => lang_plugins('cdnca_field_traffic'), 'key' => 'cdnca_traffic', 'value' => $vars['cdnca_traffic'], 'disable' => true];
        } else {
            $fields[] = ['name' => lang_plugins('cdnca_field_status'), 'key' => 'cdnca_status', 'value' => $vars['cdnca_error'], 'disable' => true];
        }
        return [['name' => lang_plugins('cdnca_field_group'), 'field' => $fields]];
    }

    /** 管理员在产品内页保存时调用；本模块字段全部只读，无需处理。 */
    public function hostUpdate($param)
    {
        return ['status' => 200, 'msg' => lang_plugins('success_message')];
    }
}
