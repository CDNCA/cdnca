<?php
/**
 * CDNCA 财务对接门面（/v1/billing-bridge）调用失败。
 *
 * code 取服务端 error.code（如 bridge_service_not_found）；本地错误用
 * network_error（网络/超时）、invalid_response（响应不是约定 JSON）、
 * client_invalid_argument（调用参数不合法，未发请求）。
 * httpStatus 为 0 表示没有拿到 HTTP 响应。
 */
class CdncaBridgeException extends \RuntimeException
{
    /** @var string */
    private $errorCode;
    /** @var int */
    private $httpStatus;
    /** @var string */
    private $requestId;

    public function __construct(string $errorCode, string $message, int $httpStatus = 0, string $requestId = '', ?\Throwable $previous = null)
    {
        parent::__construct($message, $httpStatus, $previous);
        $this->errorCode = $errorCode;
        $this->httpStatus = $httpStatus;
        $this->requestId = $requestId;
    }

    public function getErrorCode(): string
    {
        return $this->errorCode;
    }

    public function getHttpStatus(): int
    {
        return $this->httpStatus;
    }

    public function getRequestId(): string
    {
        return $this->requestId;
    }
}
