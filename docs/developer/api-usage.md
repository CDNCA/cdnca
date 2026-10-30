# API 接入指南

<!-- contract-doc:openapi file="../../api/openapi/v1/control.yaml" -->
<!-- contract-doc:openapi file="../../api/openapi/v1/sites.yaml" -->
<!-- contract-doc:openapi file="../../api/openapi/v1/dns-acme.yaml" -->
<!-- contract-doc:openapi file="../../api/openapi/v1/license.yaml" -->

本指南说明公开 HTTP API 的共同调用规则。字段、路径、权限和响应 Schema 仍以 [`api/openapi/v1`](../../api/openapi/v1/) 中对应 OpenAPI 文件为准；参考站抓包记录只用于兼容性研究，不是本系统的调用契约。

## 1. 选择正确的身份域

| 调用方 | API | 身份方式 | 禁止事项 |
| --- | --- | --- | --- |
| 客户管理员和租户用户 | `control-api` | 短时 bearer access token；可撤销 refresh cookie | 不能用于授权运营中心 |
| 租户服务端集成 | 仅 OpenAPI `security` 含 `cdncaApiKey` 的 operation；完整清单以官网“开发者 → 开放 API”接口目录（由 OpenAPI 生成，标“API Key”）为准 | `Authorization: CdncaKey <key_id>.<secret>` | 不能调用其他业务 API，也不能登录、刷新、读取 `/auth/me`、改密或管理 API key |
| 平台授权运营人员 | `license-service` 的 `/operator/v1` | 独立 Secure、HttpOnly、SameSite=Strict session cookie | 不能用于客户主控或 Edge Agent |
| 客户主控安装实例 | `license-service` 的 `/control/v1` | 安装 Ed25519 公钥 PoP | 不能声明 operator 权限 |
| Edge Agent | `agent-gateway` gRPC | 节点 mTLS 证书 | 不调用公开 HTTP API，不直连存储 |
| 未来插件服务 | 公开 API 和 Webhook | 尚未交付的短时工作负载凭据 | 当前不能用用户 token 或全局共享 key 替代 |

浏览器调用授权运营 API 时必须发送凭据 Cookie，并满足服务端配置的精确 Origin 校验。插件或服务端集成不应模拟浏览器 Cookie；工作负载认证正式进入 OpenAPI 后才能用于生产。

### API key 生命周期与最小权限

租户用户通过 bearer 会话创建自己的 API key；创建响应只返回一次 secret。完整凭据由响应中的 `key.key_id`、一个点和 `secret` 组成，后续请求使用 `Authorization: CdncaKey <key_id>.<secret>`。列表、详情和后续管理响应不会再次返回 secret，调用方必须在首次响应后存入自己的密钥管理系统，不能写入日志、URL、配置仓库或工单。

平台管理员只能为目标用户创建 `pending_activation` 元数据或撤销密钥，不能激活、轮换或读取 secret。目标用户必须使用自己的 bearer 会话执行 activate，状态才会从 `pending_activation` 进入 `active`。`active` 可轮换 secret；轮换提交后旧凭据立即失效。`pending_activation -> active -> revoked` 是唯一正常状态路径，`revoked` 为终态。

API key scope 必须是密钥所有者当前 RBAC 权限的严格安全子集，并且不能包含 `platform.admin`、`identity.*` 或 `api_keys.*`。每次认证都会取 key scope 与所有者当前有效权限的交集，所以撤销用户权限会同步收窄 API key，而不是等待 key 到期。API key 管理端点本身始终只接受 bearer 会话。

所有 API key 写请求必须发送 `Idempotency-Key`。创建时还必须发送 `If-Match: "0"`；修改、激活、轮换和撤销时发送当前资源的带引号 revision，例如 `If-Match: "3"`。网络结果未知时只能使用完全相同的正文、revision 和幂等 key 重试。

主控启动必须配置 `API_KEY_PEPPER_BASE64`，其值应由受控密钥管理系统注入，并且严格 Base64 解码后至少 32 字节。数据库只保存域分离 HMAC-SHA256 摘要，不保存可恢复 secret。当前版本只支持一个活动 pepper：丢失或替换它会让全部现存 API key 立即认证失败。轮换必须先通知租户、为所有集成重发 key、验证切换，再在维护窗口更换 pepper 并撤销旧 key；在实现带版本 pepper 的双读迁移前，不得把直接替换描述为无中断轮换。

## 2. 请求关联与错误

服务端为响应返回 `X-Request-ID`，错误正文使用：

```json
{
  "error": {
    "code": "version_conflict",
    "message": "资源已被其他操作修改",
    "request_id": "request-019b143c"
  }
}
```

调用方必须记录 `request_id`，逻辑判断只使用稳定 `code` 和 HTTP 状态，不能解析会随语言变化的 `message`。界面以 `code` 映射 `zh-CN`/`en-US` 文案；未知 code 显示通用本地化错误和 request ID，不回显服务端内部错误。

支持链路追踪的调用方发送合法 W3C `traceparent`。request ID 和 trace ID 只用于关联，不承担认证、授权或幂等语义。

## 3. 写入幂等

OpenAPI 标记 `Idempotency-Key` 的请求必须发送 1 到 128 字符的稳定 key，字符范围为字母、数字、点、下划线和连字符。推荐每次用户动作生成 UUIDv7，并在网络结果不确定时使用相同 key 和完全相同的正文重试。

- 相同身份、操作、作用域、key 和规范请求摘要：返回第一次已提交结果。
- 相同 key 但正文、目标或关键前置条件不同：返回 `409`，调用方不得换 key 盲目重复副作用。
- 已收到确定性 `4xx`：修正输入或权限后发起新动作和新 key。
- 超时、连接中断或 `5xx`：只有端点声明幂等时才使用原 key 重试。

不得把密码、令牌、证书私钥或 DNS Secret 编入幂等 key。

## 4. 乐观并发

带资源 revision 的接口通过 OpenAPI 指定的 `If-Match` 或 `expected_revision` 防止丢失更新。收到 `409 version_conflict` 后应重新读取资源、向用户展示当前值，再基于新 revision 提交；不能自动覆盖其他操作员的修改。

批量接口逐项返回结果时，调用方必须保留所有项目状态。部分成功不能显示为整体成功，也不能只重试已成功项目；重试集合和幂等规则以该批量端点契约为准。

## 5. 分页与筛选

各领域根据一致性需要使用 cursor 或 page/limit，调用方不能在两种模型间自行换算：

- cursor 分页把服务端返回的 `next_cursor` 原样用于下一页；筛选或页大小变化时清空历史 cursor。
- page/limit 分页从 1 开始，最大 limit 以 OpenAPI 为准。
- 列表响应中的总数、presence、同步状态和读模型字段不代表可以原样写回。
- 租户作用域由认证主体决定；管理员跨租户操作必须使用契约明确的目标 scope，并由服务端重新授权，不能依赖任意 `uid` 查询参数。

## 6. 重试矩阵

| 结果 | 默认行为 |
| --- | --- |
| `400` | 修正请求；不重试原内容 |
| `401` | 刷新或重新获取合法凭据；只重试一次原幂等请求 |
| `403` | 权限或 entitlement 拒绝；不自动重试 |
| `404` | 校验资源和作用域；不自动创建替代资源 |
| `409` | 按错误 code 重新读取状态或返回幂等冲突 |
| `408`、`429`、`502`、`503`、`504` | 对幂等请求使用有上限、带抖动指数退避；尊重 `Retry-After` |
| 其他 `5xx` 或连接中断 | 结果可能未知；查询操作可重试，写操作仅按端点幂等规则重放 |

客户端必须设置连接、请求和整体操作超时。退避必须有最大次数和最大间隔，不能因授权中心或插件故障形成无限请求风暴。

## 7. 契约升级

- OpenAPI 文件是代码生成和兼容性审查输入；实现与契约必须在同一变更中更新。
- 同一 API 大版本只增加向后兼容字段和端点。删除字段、收紧已有值域、改变权限语义或改变幂等范围需要新大版本或明确迁移期。
- 生成客户端应锁定输入文件摘要，CI 中重新生成并检查无漂移。
- 新错误必须先分配稳定 code 和中英翻译，再进入用户可触发路径。
- 弃用必须在 OpenAPI 标记、开发文档、功能矩阵和发布说明中同时登记。

## 8. 本地验证

```sh
./scripts/check-contract-docs.sh
./scripts/ci-check.sh contracts
pnpm contracts:validate
```

第一条命令检查契约与开发文档的交叉引用、OpenAPI 示例/认证/权限/幂等/错误、protobuf 文档符号、插件示例签名及版本/弃用标记。第二条命令执行 protobuf 和 OpenAPI 的结构/兼容性检查；第三条可单独运行 marketplace Schema、目录、事件和清单签名校验。
