# 认证、RBAC、幂等、限流与错误

## 身份域

| 调用方 | 凭据 | 可调用边界 |
| --- | --- | --- |
| 客户管理员或租户浏览器 | `Authorization: Bearer <access-token>`，refresh 使用 `cdnca_refresh` Cookie | 对应 `control-api` operation，仍需活动 scope 的实时 RBAC |
| 租户服务端集成 | `Authorization: CdncaKey <key_id>.<secret>` | 仅 OpenAPI `security` 明确包含 `cdncaApiKey` 的 operation |
| 平台 Operator 浏览器 | `OperatorSession` Cookie | `license-service` 的 `/operator/v1`，写请求还需精确 Origin |
| 客户主控安装实例 | 请求体中的安装 Ed25519 PoP | 激活、续租、使用量、升级授权和平台策略 resolve/ACK |
| Edge Agent | 节点 mTLS | `agent.v1.AgentGatewayService`，不使用 HTTP 用户身份 |

API key 只被 OpenAPI `security` 含 `cdncaApiKey` 的 operation 接受；当前清单见官网“开发者 → 开放 API”接口目录
（`apps/www/src/generated/api-catalog.json`，由 OpenAPI 生成）。
登录、refresh、logout、`/v1/auth/me`、改密和全部 API key 管理接口明确拒绝该凭据；
其他 OpenAPI 未列出 `cdncaApiKey` 的接口也不能推断为可用。

API key 的有效权限是 key scope 与所有者当前 RBAC grant 的实时交集。key scope
不能包含 `platform.admin`、`identity.*` 或 `api_keys.*`。创建响应只显示一次 secret，
后续列表和详情不返回 secret。

## RBAC

- `control-api` 依据主体类型和活动 platform/tenant scope 授权。平台主体执行跨租户
  操作时，服务端验证目标 scope；租户主体不能通过请求字段改变租户或 owner。
- `license-service` 使用独立 Operator RBAC。需要权限的 operation 在
  `license.yaml` 使用 `x-required-permissions` 标记，例如
  `licensing.platform_policies.manage` 和 `licensing.plugin_catalogs.manage`。
- API key、Operator Cookie、安装 PoP 和节点证书不能在身份域之间互换。
- `403` 是权限、scope、entitlement 或安装状态拒绝，调用方不得无限重试或改用更高
  身份绕过。

## 幂等与并发

只有 OpenAPI 显式声明 `Idempotency-Key` 的 operation 才承诺对应的幂等语义。
key 为 1 到 128 字符的有界字符串。一次业务动作生成一个 key；网络结果未知时，
使用相同主体、operation、scope、正文和前置 revision 精确重试。

- 相同 key 和规范请求摘要返回第一次已提交结果。
- 相同 key 配不同正文、目标或关键前置条件返回 `409`。
- 确定性 `4xx` 修正后使用新的业务动作和新 key。
- 超时、连接中断或 `5xx` 只在 operation 声明幂等时用原 key 重试。

带 revision 的接口使用 `If-Match` 或正文 `expected_revision`。收到
`version_conflict`、`scope_revision_conflict` 或同类 `409` 后重新读取当前资源，
不能自动覆盖。平台策略安装 API 的 `request_id` 同时进入 PoP 和请求账本，具体字节
算法见 [`platform-policy-distribution.md`](../licensing/platform-policy-distribution.md)。

## 限流与重试

当前契约没有发布一个适用于全部 API 的统一数字限额。只有 operation 响应中明确
列出 `429` 时，调用方才能按该响应处理限流。Operator 登录/邀请恢复路径使用共享
持久限流；DNS provider 验证可能透传经过校验的上游 `Retry-After`。

| 状态 | 默认处理 |
| --- | --- |
| `400` | 修正输入，不原样重试 |
| `401` | 获取合法凭据；仅对仍安全的原幂等请求重试一次 |
| `403` | 不自动重试 |
| `404` | 检查资源和 scope，不自动创建替代对象 |
| `409` | 按稳定 code 读取当前状态或定位幂等冲突 |
| `408`、`429`、`502`、`503`、`504` | 对查询或已声明幂等请求做有上限、带抖动退避，并尊重合法 `Retry-After` |
| 其他 `5xx` 或断线 | 写结果可能未知；只按 operation 的幂等契约重放 |

## 错误形状

`control.yaml`、`sites.yaml` 和 `dns-acme.yaml` 使用嵌套错误：

```json
{
  "error": {
    "code": "version_conflict",
    "message": "本地化安全消息",
    "request_id": "request-example"
  }
}
```

`license.yaml` 当前使用顶层错误：

```json
{
  "code": "idempotency_conflict",
  "request_id": "request-example"
}
```

客户端只依赖 HTTP 状态和稳定 `code`，记录响应 `X-Request-ID` 或正文
`request_id`。不得解析 `message`、数据库错误或英文异常。由于各领域稳定 code
集合仍由 operation 和实现演进，本版不制造全局 code 枚举；平台策略的已冻结 code
见其专项契约。

## 请求关联

支持时发送合法 W3C `traceparent`，并保存服务端 request ID。request ID、trace ID
和 task ID 只用于关联，不承担认证或幂等含义。日志不得记录 access token、API key
secret、Cookie、安装 proof、证书私钥、DNS 凭据或完整敏感请求体。
