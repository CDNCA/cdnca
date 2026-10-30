<?php
/**
 * CDNCA 财务对接门面客户端（ADR 0019 §4.1 签名、§4.4 接口契约）。
 *
 * 与具体财务系统无关：WHMCS、智简魔方模块共用。只依赖 ext-curl、ext-json，
 * 兼容 PHP 7.4 ～ 8.3。
 *
 * 签名：X-Cdnca-Signature = hex(HMAC-SHA256(secret,
 *   METHOD\nPATH\nCANONICAL_QUERY\nTIMESTAMP\nNONCE\nhex(sha256(body))))
 * 与 services/control-api/internal/billingbridge/credential.go 逐字节一致
 * （tests/vectors.json 由 Go 实现生成）。
 */
require_once __DIR__ . '/CdncaBridgeException.php';

class CdncaBridgeClient
{
    const VERSION = '1.0.0';
    const API_PREFIX = '/v1/billing-bridge';
    const SYSTEMS = ['whmcs', 'zjmf', 'zjmf_cbap'];
    const USAGE_BATCH = 100;
    const IDEMPOTENCY_PATTERN = '/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/';

    /** @var string scheme://host[:port][/prefix]，无末尾斜杠 */
    private $baseUrl;
    /** @var string 基址里的路径前缀（参与签名） */
    private $basePath;
    /** @var string */
    private $keyId;
    /** @var string */
    private $secret;
    /** @var array */
    private $options;
    /** @var array|null 最近一次请求/响应（签名已脱敏），供财务系统写模块日志 */
    private $lastExchange;

    /**
     * @param string $baseUrl 控制台地址，如 https://cdn.example.com
     * @param array  $options timeout(秒,15) connect_timeout(秒,5) retries(2)
     *                        retry_delay_ms(300) verify_tls(true) ca_file user_agent
     */
    public function __construct(string $baseUrl, string $keyId, string $secret, array $options = [])
    {
        $baseUrl = rtrim(trim($baseUrl), '/');
        $parts = parse_url($baseUrl);
        if ($parts === false || empty($parts['scheme']) || empty($parts['host'])
            || !in_array(strtolower($parts['scheme']), ['http', 'https'], true)) {
            throw new CdncaBridgeException('client_invalid_argument', '控制台地址无效：' . $baseUrl);
        }
        if ($keyId === '' || $secret === '') {
            throw new CdncaBridgeException('client_invalid_argument', '对接密钥 key_id / secret 不能为空');
        }
        $this->baseUrl = $baseUrl;
        $this->basePath = isset($parts['path']) ? rtrim($parts['path'], '/') : '';
        $this->keyId = $keyId;
        $this->secret = $secret;
        $this->options = array_merge([
            'timeout' => 15,
            'connect_timeout' => 5,
            'retries' => 2,
            'retry_delay_ms' => 300,
            'verify_tls' => true,
            'ca_file' => '',
            'user_agent' => 'cdnca-bridge-php/' . self::VERSION,
        ], $options);
    }

    // ---------------------------------------------------------------- 签名

    /**
     * 规范化 query：按 key 再按 value 字节序排序，RFC 3986 编码（空格 %20）。
     *
     * @param array $query [[key, value], ...] 或 ['key' => 'v' | ['v1','v2']]
     */
    public static function canonicalQuery(array $query): string
    {
        $pairs = [];
        foreach (self::queryPairs($query) as $pair) {
            $pairs[] = [(string)$pair[0], (string)$pair[1]];
        }
        usort($pairs, function ($a, $b) {
            $c = strcmp($a[0], $b[0]);
            return $c !== 0 ? $c : strcmp($a[1], $b[1]);
        });
        $parts = [];
        foreach ($pairs as $pair) {
            $parts[] = rawurlencode($pair[0]) . '=' . rawurlencode($pair[1]);
        }
        return implode('&', $parts);
    }

    public static function stringToSign(string $method, string $path, string $canonicalQuery, string $timestamp, string $nonce, string $body): string
    {
        return implode("\n", [strtoupper($method), $path, $canonicalQuery, $timestamp, $nonce, hash('sha256', $body)]);
    }

    public static function sign(string $secret, string $stringToSign): string
    {
        return hash_hmac('sha256', $stringToSign, $secret);
    }

    /** 24 位 base64url，满足服务端 ^[A-Za-z0-9_-]{16,64}$ */
    public static function newNonce(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(18)), '+/', '-_'), '=');
    }

    /**
     * 幂等键 {system}:{service_id}:{action}:{ref}（ADR §4.4）。
     * 含非法字符或超长时退化为 {system}:h{sha256 前 40 位}，仍然稳定。
     * 键不允许下划线，system 里的 _ 写成 -（zjmf_cbap → zjmf-cbap）。
     */
    public static function idempotencyKey(string $system, string $serviceId, string $action, string $ref): string
    {
        $prefix = str_replace('_', '-', $system);
        $key = $prefix . ':' . $serviceId . ':' . $action . ':' . $ref;
        if (preg_match(self::IDEMPOTENCY_PATTERN, $key)) {
            return $key;
        }
        return $prefix . ':h' . substr(hash('sha256', $key), 0, 40);
    }

    private static function queryPairs(array $query): array
    {
        $pairs = [];
        foreach ($query as $key => $value) {
            if (is_int($key) && is_array($value) && count($value) === 2 && array_keys($value) === [0, 1]) {
                $pairs[] = $value;
            } elseif (is_array($value)) {
                foreach ($value as $item) {
                    $pairs[] = [$key, $item];
                }
            } else {
                $pairs[] = [$key, $value];
            }
        }
        return $pairs;
    }

    // ------------------------------------------------------------ 门面接口

    /** GET /ping → {owner_kind, owner_scope_id, module_enabled, server_time} */
    public function ping(): array
    {
        return $this->request('GET', '/ping');
    }

    /** GET /products → [{id, revision, name, periods:[...], site_limit, node_limit}] */
    public function listProducts(): array
    {
        return $this->request('GET', '/products');
    }

    /**
     * POST /services。$payload 按 §4.4：external_system, external_service_id,
     * external_client_id, client{email, username?, display_name?}, product_id,
     * product_revision?, period。
     */
    public function createService(array $payload, string $idempotencyKey): array
    {
        self::checkSystem(isset($payload['external_system']) ? (string)$payload['external_system'] : '');
        self::checkExternalId(isset($payload['external_service_id']) ? (string)$payload['external_service_id'] : '');
        self::checkExternalId(isset($payload['external_client_id']) ? (string)$payload['external_client_id'] : '');
        return $this->request('POST', '/services', [], $payload, $idempotencyKey);
    }

    public function getService(string $system, string $serviceId): array
    {
        return $this->request('GET', self::servicePath($system, $serviceId));
    }

    public function suspendService(string $system, string $serviceId, string $reason, string $idempotencyKey): array
    {
        $body = $reason === '' ? [] : ['reason' => $reason];
        return $this->request('POST', self::servicePath($system, $serviceId) . '/suspend', [], $body, $idempotencyKey);
    }

    public function unsuspendService(string $system, string $serviceId, string $idempotencyKey): array
    {
        return $this->request('POST', self::servicePath($system, $serviceId) . '/unsuspend', [], [], $idempotencyKey);
    }

    public function renewService(string $system, string $serviceId, ?string $period, string $idempotencyKey): array
    {
        $body = $period === null || $period === '' ? [] : ['period' => $period];
        return $this->request('POST', self::servicePath($system, $serviceId) . '/renew', [], $body, $idempotencyKey);
    }

    /** $payload: {product_id, product_revision?, period?} */
    public function changeService(string $system, string $serviceId, array $payload, string $idempotencyKey): array
    {
        return $this->request('POST', self::servicePath($system, $serviceId) . '/change', [], $payload, $idempotencyKey);
    }

    public function terminateService(string $system, string $serviceId, string $idempotencyKey): array
    {
        return $this->request('POST', self::servicePath($system, $serviceId) . '/terminate', [], [], $idempotencyKey);
    }

    /** POST /sso → {url, expires_at}；$redirect 为站内相对路径，空则服务端默认 / */
    public function createSso(string $system, string $serviceId, string $redirect, string $idempotencyKey): array
    {
        $body = $redirect === '' ? [] : ['redirect' => $redirect];
        return $this->request('POST', self::servicePath($system, $serviceId) . '/sso', [], $body, $idempotencyKey);
    }

    /**
     * GET /usage，自动按 100 个一批拆分并合并结果。
     * @param string[] $serviceIds
     */
    public function getUsage(string $system, array $serviceIds): array
    {
        self::checkSystem($system);
        $result = [];
        foreach (array_chunk(array_values(array_unique(array_map('strval', $serviceIds))), self::USAGE_BATCH) as $chunk) {
            foreach ($chunk as $id) {
                self::checkExternalId($id);
            }
            $rows = $this->request('GET', '/usage', ['external_system' => $system, 'ids' => implode(',', $chunk)]);
            foreach ($rows as $row) {
                $result[] = $row;
            }
        }
        return $result;
    }

    /** 最近一次请求/响应（签名头已脱敏，secret 从不出现在其中） */
    public function getLastExchange(): ?array
    {
        return $this->lastExchange;
    }

    // ---------------------------------------------------------------- 传输

    /**
     * 发一次签名请求，返回 data。只对网络错误与 5xx 重试；每次重试换新
     * nonce/时间戳，写请求沿用同一个 Idempotency-Key。
     */
    public function request(string $method, string $route, array $query = [], ?array $body = null, ?string $idempotencyKey = null)
    {
        $method = strtoupper($method);
        $isWrite = $method !== 'GET' && $method !== 'HEAD';
        if ($isWrite) {
            if ($idempotencyKey === null || !preg_match(self::IDEMPOTENCY_PATTERN, $idempotencyKey)) {
                throw new CdncaBridgeException('client_invalid_argument', '写请求必须带合法的 Idempotency-Key');
            }
        }
        $path = $this->basePath . self::API_PREFIX . $route;
        $canonical = self::canonicalQuery($query);
        $bodyText = '';
        if ($isWrite) {
            $bodyText = json_encode((object)($body === null ? [] : $body), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            if ($bodyText === false) {
                throw new CdncaBridgeException('client_invalid_argument', '请求体无法编码为 JSON：' . json_last_error_msg());
            }
        }
        // 发送的 query 就是规范化后的 query，服务端解析后再规范化结果不变。
        $url = $this->baseUrl . self::API_PREFIX . $route . ($canonical === '' ? '' : '?' . $canonical);
        $attempts = max(0, (int)$this->options['retries']) + 1;
        $last = null;
        for ($attempt = 0; $attempt < $attempts; $attempt++) {
            if ($attempt > 0) {
                usleep((int)$this->options['retry_delay_ms'] * 1000 * (1 << ($attempt - 1)));
            }
            $timestamp = (string)time();
            $nonce = self::newNonce();
            $signature = self::sign($this->secret, self::stringToSign($method, $path, $canonical, $timestamp, $nonce, $bodyText));
            $headers = [
                'Accept: application/json',
                'X-Cdnca-Bridge-Key: ' . $this->keyId,
                'X-Cdnca-Timestamp: ' . $timestamp,
                'X-Cdnca-Nonce: ' . $nonce,
                'X-Cdnca-Signature: ' . $signature,
            ];
            if ($isWrite) {
                $headers[] = 'Content-Type: application/json';
                $headers[] = 'Idempotency-Key: ' . $idempotencyKey;
            }
            $response = $this->send($method, $url, $headers, $bodyText);
            $this->lastExchange = [
                'request' => ['method' => $method, 'url' => $url, 'attempt' => $attempt + 1,
                    'headers' => str_replace($signature, '***', $headers), 'body' => $bodyText],
                'response' => ['status' => $response['status'], 'error' => $response['error'], 'body' => $response['body']],
            ];
            if ($response['error'] !== '') {
                $last = new CdncaBridgeException('network_error', '无法连接 CDN 主控：' . $response['error']);
                continue;
            }
            try {
                return self::parse($response['status'], $response['body'], $response['request_id']);
            } catch (CdncaBridgeException $e) {
                if ($response['status'] >= 500) {
                    $last = $e;
                    continue;
                }
                throw $e;
            }
        }
        throw $last;
    }

    /** @return array{status:int, body:string, error:string, request_id:string} */
    private function send(string $method, string $url, array $headers, string $body): array
    {
        $requestId = '';
        $ch = curl_init($url);
        $curlOptions = [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => array_merge($headers, ['Expect:']),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => (int)$this->options['connect_timeout'],
            CURLOPT_TIMEOUT => (int)$this->options['timeout'],
            CURLOPT_USERAGENT => (string)$this->options['user_agent'],
            CURLOPT_SSL_VERIFYPEER => (bool)$this->options['verify_tls'],
            CURLOPT_SSL_VERIFYHOST => $this->options['verify_tls'] ? 2 : 0,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_HEADERFUNCTION => function ($handle, $line) use (&$requestId) {
                if (stripos($line, 'X-Request-ID:') === 0) {
                    $requestId = trim(substr($line, 13));
                }
                return strlen($line);
            },
        ];
        if ($method !== 'GET' && $method !== 'HEAD') {
            $curlOptions[CURLOPT_POSTFIELDS] = $body;
        }
        if ($this->options['ca_file'] !== '') {
            $curlOptions[CURLOPT_CAINFO] = (string)$this->options['ca_file'];
        }
        curl_setopt_array($ch, $curlOptions);
        $raw = curl_exec($ch);
        $error = $raw === false ? (curl_error($ch) !== '' ? curl_error($ch) : 'curl errno ' . curl_errno($ch)) : '';
        $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        return ['status' => $status, 'body' => $raw === false ? '' : (string)$raw, 'error' => $error, 'request_id' => $requestId];
    }

    private static function parse(int $status, string $body, string $headerRequestId)
    {
        $decoded = json_decode($body, true);
        if (!is_array($decoded)) {
            throw new CdncaBridgeException('invalid_response', 'CDN 主控返回了非 JSON 响应（HTTP ' . $status . '）', $status, $headerRequestId);
        }
        if ($status >= 200 && $status < 300 && array_key_exists('data', $decoded)) {
            return $decoded['data'];
        }
        if (isset($decoded['error']) && is_array($decoded['error'])) {
            $error = $decoded['error'];
            $requestId = isset($error['request_id']) && is_string($error['request_id']) ? $error['request_id'] : $headerRequestId;
            throw new CdncaBridgeException(
                isset($error['code']) && is_string($error['code']) ? $error['code'] : 'unknown_error',
                isset($error['message']) && is_string($error['message']) ? $error['message'] : '',
                $status,
                $requestId
            );
        }
        throw new CdncaBridgeException('invalid_response', 'CDN 主控响应缺少 data/error（HTTP ' . $status . '）', $status, $headerRequestId);
    }

    private static function servicePath(string $system, string $serviceId): string
    {
        self::checkSystem($system);
        self::checkExternalId($serviceId);
        return '/services/' . rawurlencode($system) . '/' . rawurlencode($serviceId);
    }

    private static function checkSystem(string $system): void
    {
        if (!in_array($system, self::SYSTEMS, true)) {
            throw new CdncaBridgeException('client_invalid_argument', 'external_system 只能是 ' . implode('、', self::SYSTEMS));
        }
    }

    /** 1–64 位可见 ASCII */
    private static function checkExternalId(string $id): void
    {
        if (!preg_match('/^[\x21-\x7E]{1,64}$/', $id)) {
            throw new CdncaBridgeException('client_invalid_argument', '外部 ID 必须是 1–64 位可见 ASCII：' . $id);
        }
    }
}
