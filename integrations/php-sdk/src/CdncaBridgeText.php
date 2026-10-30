<?php
/**
 * 财务系统模块共用的中文文案与格式化（智简魔方老版 / V10 模块共用）。
 * 与具体财务系统无关，只做纯函数；兼容 PHP 7.4 ～ 8.3。
 */
require_once __DIR__ . '/CdncaBridgeException.php';

class CdncaBridgeText
{
    const ERROR_HINTS = [
        'bridge_unauthenticated' => '对接密钥鉴权失败：检查 key_id / secret、本机出口 IP 是否在白名单、服务器时间是否准确',
        'unauthorized' => '对接密钥鉴权失败：检查 key_id / secret、本机出口 IP 是否在白名单、服务器时间是否准确',
        'entitlement_feature_denied' => 'CDN 主控未启用财务对接插件',
        'bridge_service_not_found' => 'CDN 侧找不到该服务（可能尚未开通，或不属于此对接密钥）',
        'bridge_product_not_found' => 'CDN 套餐不存在或已下架，请在商品的接口设置中重新选择',
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

    /** 异常 → 中文错误文本，末尾附错误码、HTTP 状态与 request_id。 */
    public static function error(\Throwable $e): string
    {
        if (!$e instanceof CdncaBridgeException) {
            return '模块内部错误：' . $e->getMessage();
        }
        $code = $e->getErrorCode();
        $hint = isset(self::ERROR_HINTS[$code]) ? self::ERROR_HINTS[$code] : 'CDN 主控返回错误';
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

    public static function period(string $period): string
    {
        $labels = ['month' => '月付', 'quarter' => '季付', 'year' => '年付'];
        return isset($labels[$period]) ? $labels[$period] : $period;
    }

    public static function status(string $status): string
    {
        $labels = ['active' => '正常', 'suspended' => '已暂停', 'terminated' => '已终止'];
        return isset($labels[$status]) ? $labels[$status] : $status;
    }

    /** ISO 8601 / 时间戳 → Y-m-d H:i；空值返回 - */
    public static function date($value): string
    {
        if (is_int($value) || (is_string($value) && ctype_digit($value))) {
            return (int)$value > 0 ? date('Y-m-d H:i', (int)$value) : '-';
        }
        if (!is_string($value) || $value === '') {
            return '-';
        }
        $ts = strtotime($value);
        return $ts === false ? $value : date('Y-m-d H:i', $ts);
    }

    public static function bytes(float $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
        $i = 0;
        while ($bytes >= 1024 && $i < count($units) - 1) {
            $bytes /= 1024;
            $i++;
        }
        return ($i === 0 ? (string)(int)$bytes : number_format($bytes, 2)) . ' ' . $units[$i];
    }

    public static function h($text): string
    {
        return htmlspecialchars((string)$text, ENT_QUOTES, 'UTF-8');
    }
}
