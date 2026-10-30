# 架构与信任边界

## 四个控制端与数据面

| 边界 | 入口与服务 | 持有的身份和事实 | 不得拥有 |
| --- | --- | --- | --- |
| 平台授权运营端 | `apps/operator-console`、`services/license-service` | 平台操作员、客户、主控安装、许可证、签名租约、版本渠道、平台策略和平台审计 | 客户主控数据库连接、客户管理员会话、边缘执行能力 |
| 客户主控服务端 | `services/control-api`、`services/agent-gateway` | 客户业务事实、RBAC、配置、任务、节点、已验签租约和策略缓存 | 平台签名私钥、第三方插件进程内执行权 |
| 客户管理员端 | `apps/web` 的平台作用域 | 用户、节点、线路、套餐和系统资源的已授权操作 | 授权中心 Operator 身份、跨客户数据库后门 |
| 租户用户端 | `apps/web` 的租户作用域 | 当前租户的网站、证书、安全策略、用量、订单和账户 | 其他租户资源、平台作用域写权限 |
| 独立数据面 | `agents/edge-agent`、`edge/openresty` | 已签名制品、当前和前一健康版本、本机运行状态 | PostgreSQL、Redis、NATS、ClickHouse 或授权中心凭据 |

平台授权运营端与客户主控使用不同入口、会话、数据库和审计。客户管理员端与
租户用户端可以共享前端外壳，但服务端依据主体和活动 scope 重新授权，不能依赖
前端隐藏按钮隔离权限。

## 数据与调用路径

```text
平台操作员 -> operator-console -> license-service -> 独立 PostgreSQL
                                      -> 外部 Ed25519 signer 边界

客户管理员/租户 -> web -> control-api -> 客户 PostgreSQL
                                      -> Redis / NATS / ClickHouse

control-api -> 安装公钥 PoP -> license-service
license-service -> 签名 lease / 签名 platform policy -> control-api 本地验签缓存

control-api <-> ControlInternal mTLS <-> agent-gateway
agent-gateway <-> AgentGatewayService mTLS <-> edge-agent -> OpenResty
```

边缘请求只读取本地已激活配置。授权中心、客户数据库、Redis、NATS、Gateway
或控制 API 不得进入每个 HTTP/TCP 请求的同步处理路径。

## 存储所有权

- PostgreSQL 保存控制面业务事实、事务、审计、outbox 和幂等结果。
- Redis 只保存带 TTL、可重建的缓存、协调、限流和在线租约。
- ClickHouse 保存高吞吐访问和安全事件；当前 Helm 只预留连接配置，
  `control-api` 尚未完成 ClickHouse 摄取接线。
- NATS JetStream 承载可重放任务和领域事件，不是最终查询事实源。
- Agent 本地不可变 release 目录保存当前与回滚版本，控制面故障不得删除它们。

## 身份边界

| 链路 | 当前身份机制 |
| --- | --- |
| 客户浏览器到 `control-api` | 短时 bearer access token 和可撤销 refresh cookie |
| 租户服务集成到部分 `control-api` API | `CdncaKey <key_id>.<secret>`，仅限 OpenAPI 明确列出 `cdncaApiKey` 的 operation |
| Operator 浏览器到 `license-service` | 独立 Secure、HttpOnly、SameSite=Strict Cookie 和精确 Origin 检查 |
| 客户主控到 `license-service` | 安装 Ed25519 私钥 proof-of-possession |
| Edge Agent 到 Gateway | 首次一次性 enrollment token，之后使用短期节点 mTLS 证书 |
| Gateway 到 `control-api` | 独立工作负载 mTLS 和固定 URI SAN |

Agent 协议的 `Enroll` 必须位于仅服务器 TLS 的独立 listener；`RenewCertificate`、
`Connect` 和 `FetchArtifact` 位于强制客户端证书的 mTLS listener。不得使用
“可选客户端证书” listener 再靠业务字段补认证。

## 授权租约与平台策略

签名 entitlement lease 决定主控可执行的 feature、quota、版本范围和发布渠道。
主控在服务端事务内检查正向增长；租约失效可以阻止新建、扩容、发布和升级，
但不能发送停流配置或撤销已激活边缘流量。

平台策略使用独立的 `cdnca-platform-policy-signature/v1` 签名域和连续 scope
revision。实例策略整包优先于全局策略，全局策略优先于二进制内置默认策略。
未知 schema、错误目标、签名失败、乱序、版本不兼容或首次应用时过期都保持最近
有效策略并告警。策略不能提高 lease 授权，也不能携带代码、URL、凭据或客户数据。

策略投递和 ACK 的详细 wire contract 见
[`platform-policy-distribution.md`](../licensing/platform-policy-distribution.md)。

## 故障边界

| 故障 | 保持运行 | 暂停或降级 |
| --- | --- | --- |
| 授权中心不可用 | 已缓存租约、已应用策略、已有边缘流量 | 续租、策略同步和受限的新操作 |
| `control-api` 或 PostgreSQL 不可用 | Agent 本地守护和已激活边缘流量 | 新登录、业务变更、结算和新发布 |
| Redis 不可用 | PostgreSQL 事实和边缘流量 | 缓存旁路，节点租约信号显示不可用，不推断离线 |
| NATS 不可用 | 已提交 PostgreSQL 事实和当前边缘版本 | outbox 积压，新异步动作和遥测投递暂停 |
| Gateway 不可用 | Agent 继续当前版本和本地健康检查 | 新命令、状态回传和制品获取 |
| 插件 Webhook 失败 | 控制面事务和边缘流量 | 仅对应安装的异步投递重试或进入 DLQ |

更完整的状态机和存储原则见 [`docs/architecture.md`](../architecture.md) 和
[`docs/protocol-contracts.md`](../protocol-contracts.md)。
