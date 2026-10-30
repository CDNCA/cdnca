# 文档对应的实现状态

本页防止把“已有契约”“已有内核”和“已完成生产闭环”混为一谈。日期为
2026-08-10，2026-10-27 按当前事件目录、Webhook 页面与认证口径更新；持续完成度仍以功能矩阵为准。

| 能力 | 当前证据 | 状态边界 |
| --- | --- | --- |
| OpenAPI 和统一契约检查 | 版本化契约及 lint、bundle、contract-doc 检查入口 | 契约存在不证明检查当前全绿，也不证明每个运行路由和外部依赖已完成生产验收 |
| Agent gRPC 与 ControlInternal | 2 个 service、Buf baseline、生成 Go、mTLS listener 实现 | 隔离节点的完整灰度/故障注入仍按功能矩阵验收 |
| Operator 身份、许可证、lease、发布、平台策略 | OpenAPI、数据库集成测试、Operator Console 和签名 fixture | 生产 KMS/HSM signer、完整账单关联仍未交付 |
| 主控本地 lease 和平台策略 consumer | durable cache、high-water、fail-stale、ACK outbox | 所有业务领域 entitlement guard 尚未全部接入 |
| 插件受信目录 | 注册、禁用、签名快照同步、SSRF/重放防护 | 目录同步本身不等于业务事件运行；manifest 验证和安装授权由独立 Control API 负责 |
| Operator manifest 验证 | operator GET/POST 路由已挂载，执行 HTTPS 拉取、raw digest、严格解析、发布者签名校验和结果持久化 | 验证成功只生成不可变证据；插件运行仍受安装授权、短时工作负载身份和运行时状态约束 |
| 插件安装与工作负载身份 | Control API 已提供 tenant-scope 隔离的 list/get/confirm/upgrade/disable/uninstall、幂等与审计；License candidate/lifecycle 同步和短时签名 workload authorization 已接入 | 真实跨进程 License/Control/mTLS、多版本兼容和最终桌面/390px 证据仍待统一生产验收；不允许用长期共享密钥或数据库写入替代 |
| 插件 manifest/event Schema | JSON Schema、Ed25519/HMAC 固定向量 | 扩展目录中 7 类领域事件及对应 `events.*.read` 权限为 `available`（见 [`plugin-integration.md`](plugin-integration.md) 第 8.1 节）；`dns.records.*`、`notifications.send` 仍为 `reserved`，不能用于生产安装 |
| Webhook | `PLUGIN_WEBHOOK_RUNTIME_ENABLED=true` 时挂载订阅/测试事件控制、每安装加密 secret、签名、重放保护、持久投递、重试与 DLQ；开发者文档提供已进入示例 CI 的 v2 reference receiver；deployment status 的 source fact 已由 migration 187 在状态投影同一 PostgreSQL 事务写入独立 durable outbox；migration 188、Control API、HTTP/OpenAPI 和 Web API 已将正式事件订阅绑定到同租户、enabled 的安装授权及 approved event scope，绑定字段纳入幂等 digest，并保持 test-only 订阅不绑定；deployment source fanout/dispatch 已由 migration 189 和 control-api runtime composition 挂载 | 7 类领域事件经通用 outbox（迁移 368 起）扇出；Web“插件 Webhook 订阅”页可选择这些事件、绑定已启用安装并按站点过滤，订阅下的投递列表、单条重放（`.../deliveries/{delivery_id}/replays`）和按时间段补发（`.../delivery-replays`）已在 `control.yaml`。运行时由 `PLUGIN_WEBHOOK_RUNTIME_ENABLED` 控制，原生安装器默认写 `false`（需另配 NATS 凭据与 CA），未开启的主控上订阅接口不可用；真实 PostgreSQL/NATS 执行、跨进程投递和外部插件故障注入仍待统一生产验收 |
| Analytics query/log/ingest | query/log 与 ingest runtime 已接入 `control-api`，分别按配置可选挂载 | OpenResty 到查询的完整单链 E2E、权威水位和生产容量闭环仍待验 |
| Control upgrade | 本地资格预检、durable rollout create/list/detail/start/pause/resume/rollback API、签名 v2 execution、outbox/status runtime、Agent durable claim/receipt 和 Web 操作页已有实现 | 当前候选仍需 A/B/C/Web 组合门禁、真实对象存储与签名服务、多节点灰度/断线/重启/自动回滚、生产 KMS/HSM 和浏览器到真实节点 E2E；不得标记为生产完成 |
| Kubernetes chart | Helm templates、探针、PDB/HPA/NetworkPolicy 和配置入口 | Helm template 不等于生产可用；仍需生产镜像、Secret/KMS/HSM、依赖预创建、集群升级/回滚和真实验收 |

## 明确未发布或未对外承诺的接口

- 领域事件的真实外部发布与生产证据：7 类事件的事务内 source fact、安装授权绑定、fanout/dispatch worker 及 control-api composition 已实现，但 PG/NATS、跨进程投递和插件故障注入尚未统一验收；
- 插件运行时的公开 OAuth 2.0/client credentials 端点和第三方资源调用 API。插件工作负载身份
  （`cdnca.plugin-workload-identity/v1`）当前只用于主控内部逐次授权 Webhook 投递
  （`services/control-api/cmd/control-api/plugin_runtime_composition.go`），Control OpenAPI 没有接受
  插件工作负载凭据的 operation；第三方服务调用主控目前只能用租户 API Key（`cdncaApiKey`）。
  官网开发者页按此口径描述；
- 跨订阅、跨租户的通用投递查询及市场级插件执行编排（订阅内的投递查询与重放见上表）；
- control upgrade 编排接口已经进入候选契约；生产 artifact 供应、发布审批和对外稳定性承诺尚未发布；
- 第三方插件调用客户主控资源的公开细粒度 API；
- 平台方直连客户数据库或获取客户万能后台会话的任何接口。

这些能力进入 OpenAPI、实现、集成测试、审计和浏览器验收之前，文档和集成方不得
自定义临时路径、长期共享密钥或数据库写入来替代。
