# 身份认证与通信设计

本文定义登录认证、Token、权限决策、Agent 通信和 WebSocket 事件的统一契约。平台授权中心、客户主控和租户用户是不同信任域；它们不能共享管理员会话或数据库凭据。

## 1. 登录与会话

浏览器访问 `apps/web` 或 `apps/operator-console` 时使用同源 HTTPS。客户主控登录请求为 `POST /v1/auth/login`；平台授权运营端登录请求为 `POST /operator/v1/sessions`。服务端校验 Argon2id 密码哈希、账户状态、作用域和风险策略。授权运营端初始登录只提交用户名和密码，不要求动态验证码或恢复码；动态验证码仅用于敏感操作重新认证，恢复码仅用于账户恢复或明确的兼容恢复登录。成功后创建 `AuthSession`，只把随机 opaque refresh token 放入 `HttpOnly; Secure` Cookie；访问令牌只在内存中保存，避免落入 localStorage。

访问令牌是 10 分钟有效的 JWT，当前 Control API 使用 HMAC-SHA256 和进程外注入的高熵 `ACCESS_TOKEN_SECRET` 签名，包含 `iss`、`aud`、`sub`、`session_id`、`tenant_id`、`scope`、`iat`、`exp`、`jti` 和权限快照版本。API 每次验证算法白名单、签名、时间窗口、受众、会话撤销版本和租户状态。高风险操作要求最近一次 MFA 或短时 step-up token。平台租约、策略包和 Agent 制品仍使用独立的 Ed25519 签名域，不能复用访问令牌密钥。

刷新请求为 `POST /v1/auth/refresh`，服务端轮换 refresh token 并撤销旧 token；检测到重放时撤销整条会话链。退出、改密、管理员撤销和租户禁用都能按会话、用户或租户维度立即撤销。密码找回令牌一次性、短期、只保存哈希，并写入审计。

登录、刷新、找回和 MFA 接口按 IP、账户和设备组合限流，错误只返回稳定错误码，不暴露“用户不存在”或密码细节。所有日期和提示由前端 i18n 渲染，服务端不返回可直接展示的英文消息。

## 2. 权限检查

请求管线依次执行 TLS、令牌验证、会话状态、租户上下文、RBAC 权限、资源归属/范围和业务配额检查。权限以 `resource.action` 表示，例如 `sites.read`、`sites.manage`、`nodes.deploy`；角色只是一组权限，管理员也必须经过租户和资源范围检查。

控制 API 是唯一的授权执行点。前端路由和按钮仅作体验优化，不能作为安全边界。每次拒绝记录稳定 `reason_code`、主体、租户、资源、request/trace ID 和策略版本，禁止记录令牌或秘密。

## 3. Agent 与内部服务

Agent 首次注册使用一次性 enrollment token + CSR。Gateway 的 enrollment 端口只做服务器认证 TLS；注册成功后由在线中间 CA 签发 URI SAN 为 `spiffe://cdn-platform/node/{node_id}` 的短期客户端证书。日常 Agent 端口要求 TLS 1.3 双向认证，并拒绝仅凭请求体中的 `node_id` 建立身份。

Gateway 通过独立的 ControlInternal mTLS gRPC 客户端调用 control-api；Gateway 没有数据库、CA 私钥或租户写权限。证书续期、禁用节点、协议版本和能力快照均由 control-api 决策，Gateway 负责连接、会话接管、背压和协议转发。

## 4. WebSocket 事件

浏览器事件端点为 `GET /v1/events` 的 WebSocket 升级请求。升级时验证访问令牌和租户范围，服务端发送 `hello`（连接 ID、协议版本、心跳间隔、重放窗口），客户端以 `last_event_id` 请求有限重放。事件 envelope 固定包含 `event_id`、`schema_version`、`type`、`occurred_at`、`tenant_id`、`correlation_id` 和 payload。

服务端按租户和用户权限过滤事件；部署、任务、节点状态和通知事件不携带秘密或完整请求体。客户端必须处理重复、乱序、过期游标和 `resync_required`，真实状态通过 REST 查询校正。连接使用 ping/pong、发送队列上限和租户级速率限制；慢客户端被关闭并记录原因。跨实例广播通过 NATS，不能把单个 WebSocket 进程内存当作事实源。

## 5. 失败与验收

必须测试过期/篡改/错误受众 Token、刷新重放、权限拒绝、跨租户 IDOR、MFA step-up、WebSocket 重连与重复事件、Agent 证书轮换、旧证书拒绝、Gateway 接管和 Redis 不可用降级。验收以服务端审计和数据库状态为准，不能只根据浏览器按钮是否隐藏判断成功。

## 6. 对外接口契约

| 接口 | 用途 | 成功结果 | 关键失败码 |
| --- | --- | --- | --- |
| `POST /v1/auth/login` | 创建客户主控浏览器会话 | 访问令牌在响应内存中返回，refresh cookie 写入浏览器 | `authentication_failed`、`mfa_required`、`rate_limited` |
| `POST /operator/v1/sessions` | 创建平台授权运营会话 | 用户名和密码验证成功后写入独立 operator cookie | `authentication_failed`、`operator_login_locked`、`rate_limited` |
| `POST /v1/auth/refresh` | 轮换会话 | 新访问令牌和新 refresh cookie | `session_revoked`、`refresh_replay` |
| `POST /v1/auth/logout` | 撤销当前会话 | `204` | `authentication_required` |
| `POST /v1/auth/step-up` | 强授权 | 短时 step-up 证明 | `step_up_required`、`step_up_expired` |
| `GET /v1/events` | WebSocket 事件流 | `hello` envelope 后发送事件 | `authentication_required`、`scope_denied`、`resync_required` |

所有接口使用统一错误 envelope：`code`、`params`、`request_id`、`trace_id`。`message` 只用于诊断，客户端按 locale 将 `code` 映射为可见文案。登录请求不得通过 URL 传递密码、Token、OTP 或回调凭据。

访问令牌的 `jti`、会话 ID、权限快照修订和租户作用域必须互相绑定。撤销检查不能只依赖 JWT 的 `exp`；缓存命中也必须验证会话撤销版本。refresh token 只以哈希形式保存，并用一次性 family/revision 防止并发刷新产生两条有效链。

## 7. Agent RPC

ControlInternal protobuf 至少提供 `GetNodeAuthorization`、`BeginEnrollment`、`CompleteEnrollment`、`RenewNodeCertificate`、`OpenAgentSession`、`ReadArtifact`、`ReportHeartbeat` 和 `ReportDeploymentStatus`。每个写入或状态推进请求包含协议版本、请求 ID、幂等键和 trace context；Gateway 不接受租户 ID 作为授权依据。

Agent 命令使用不可变 artifact ID 和摘要，不直接携带大配置。Gateway 对每个节点保持一个有界发送队列，队列满时返回稳定的背压码；Control API 通过任务状态查询确认最终结果。Agent 回报允许重复和乱序，服务端按 deployment/attempt/event ID 做单调推进。

## 8. WebSocket 事件规则

事件类型采用注册表管理，例如 `node.status_changed.v1`、`deployment.progressed.v1`、`task.finished.v1` 和 `notification.created.v1`。每个版本有 JSON Schema 或 protobuf 映射、最大 payload 大小、权限要求和重放保留期。服务端先发送 `hello`，随后发送 `event`；客户端发送 `ack` 或 `resync`，服务端不把客户端 ack 当作业务事实。

事件游标只允许在同一主体、租户、过滤器和协议版本下使用。游标过期、签名不匹配或租户改变时返回 `resync_required`，客户端重新读取 REST 事实后再建立连接。单连接缓冲区、单租户连接数、事件速率和最大重放条数均有限制，超过限制关闭连接并审计 `slow_consumer` 或 `replay_limit`。

## 9. 密钥与寿命参数

开发环境使用独立 CA 和短期测试密钥；生产环境的访问令牌密钥通过 Secret Manager 注入并支持双密钥平滑轮换，Ed25519 签名密钥使用 KMS/HSM 或等价的不可导出能力。建议参数为：访问令牌 10 分钟、refresh token 30 天并轮换、step-up 5 分钟、enrollment token 10 分钟、Agent 客户端证书 24 小时、WebSocket 重放窗口 15 分钟。参数由版本化策略配置，修改必须有审计和回滚值。
