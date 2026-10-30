# 开发者与集成文档

<!-- contract-doc:policy file="contract-policy.json" -->

本目录面向控制面 API 使用方、集成开发者和未来插件市场发布者。系统界面默认使用简体中文，稳定标识符、错误码和协议字段保持与语言无关；展示名称和说明必须至少提供 `zh-CN`，可同时提供 `en-US`。

## 权威来源与交付边界

| 内容 | 权威来源 | 当前边界 |
| --- | --- | --- |
| 客户主控 HTTP API | [`control.yaml`](../../api/openapi/v1/control.yaml) | 已实现部分纵向切片；OpenAPI 中存在不等于运行时已经接线 |
| 站点 API | [`sites.yaml`](../../api/openapi/v1/sites.yaml) | 已实现站点与源站基础切片；边缘激活仍按独立发布状态验收 |
| DNS/ACME API | [`dns-acme.yaml`](../../api/openapi/v1/dns-acme.yaml) | 契约已定义，部分能力仍在实现队列 |
| 授权运营 API | [`license.yaml`](../../api/openapi/v1/license.yaml) | 独立信任域，已实现范围以运行测试和功能矩阵为准 |
| Agent 和内部服务协议 | [gRPC 契约索引](grpc-contracts.md)与 [`proto/`](../../proto/) | protobuf 是 service、method、message 和字段的唯一事实源 |
| API 调用约定 | [API 接入指南](api-usage.md) | 认证域、权限、幂等、并发、错误与重试规则 |
| 插件与 Webhook | [插件集成契约](plugin-integration.md) | 目录注册/同步、清单验签、安装生命周期、短时工作负载授权和 test-event 投递运行时已有版本化实现；通用领域事件 producer 与跨进程生产验收仍未完成 |
| 发布者签名 | [cdnca-plugin 签名工具](plugin-signing.md) | 生成密钥、签公钥登记挑战、签 manifest，离线执行 |
| 契约防漂移 | [契约文档检查](contract-checks.md) | 一条命令校验 OpenAPI、protobuf、插件示例和本地引用 |
| 最小调用示例 | [开发者快速开始](quickstart.md) | Bearer、API key、幂等写入和 Webhook 验签顺序 |
| 系统与 API 文档 | [系统文档](../system/README.md)、[API 文档](../api/README.md) | 架构、部署、运行、OpenAPI 与 gRPC 索引 |
| 发布边界 | [文档对应的实现状态](release-status.md) | 区分已实现、仅内核、仅契约和未交付能力 |
| 基线完成度 | [`docs/parity-matrix.md`](../parity-matrix.md) | 唯一功能完成度登记表；契约检查不替代运行验收 |

## 集成边界

- 外部集成只通过公开 HTTPS API 和受管 Webhook 接入，不直连 PostgreSQL、Redis、ClickHouse、NATS 或内部 gRPC。
- `control-api`、`license-service` 和 Agent 身份不可互换；平台授权运营端不能借插件进入客户数据库。
- 调用已声明 `Idempotency-Key` 的写接口时必须复用相同 key 和相同正文进行网络重试，并保存响应中的 `X-Request-ID`。
- 调用方只依赖稳定错误 `code`，不解析中文或英文 `message`。
- API、事件和清单独立版本化。客户端必须忽略其已声明可扩展对象中的未知字段，但不能猜测未知枚举的含义。
- 插件安装授予的权限只能是清单申请权限的子集，租户范围由服务端身份确定，不能由请求参数提升。

## 当前未交付或未对外承诺

通用领域事件 producer、业务事务 outbox 到插件投递的完整接线、公开 OAuth 2.0/client-credentials 工作负载端点，以及生产级 Webhook 投递查询/replay 和真实插件服务故障注入仍未完成。当前插件安装/升级/禁用/卸载、短时工作负载授权和 test-event Webhook 路径已有 Control API、审计、幂等和中文 UI，但必须以功能矩阵中的跨进程依赖与浏览器证据作为生产发布边界；不能把 OpenAPI、focused 测试或 test-event 自身当作通用业务事件已自动投递的证明。
