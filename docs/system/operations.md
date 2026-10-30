# 运行与恢复

本文只提供运行入口。具体命令、数据不变量和恢复条件以对应运行手册为准。

## 日常检查

1. 检查进程/Pod liveness 和 readiness，不把 readiness 失败改成忽略依赖。
2. 检查两套 PostgreSQL 的迁移状态、备份新鲜度和恢复抽检。
3. 检查 Redis 可用性，但不把 Redis 状态当成业务事实。
4. 检查 NATS stream/consumer 配置、lag、redelivery 和 DLQ。
5. 检查 Agent 在线投影、租约信号、部署状态和当前/前一配置版本。
6. 检查授权 lease、平台策略 revision/ACK、signer/keyset 和时钟偏差。
7. 使用 request ID、trace ID、task ID 关联日志；不搜索或输出 secret。

## 变更顺序

- 数据库迁移独立执行。应用启动不得隐式修改 `control-api` schema。
- 先备份并完成恢复抽检，再迁移；默认前向兼容 schema，不因应用回滚自动执行 down。
- 控制面配置生成不可变版本，经校验、灰度、健康确认后扩批。
- 进入 activated 后失败必须走显式 reverting，并终止于 reverted 或 rollback_failed。
- signer、证书和信封密钥使用重叠验证窗口；不能直接替换仍被历史记录引用的旧 key。

## 故障处理原则

- 先读取健康、日志、数据库事实、JetStream 状态和 Agent journal，再做变更。
- 不直接修改数据库“修状态”，不删除 append-only 审计、幂等、策略、ACK 或账本记录。
- Redis 错误不是“租约不存在”，NATS 暂停不是“任务成功”，Gateway PubAck 也不等于
  PostgreSQL 投影已经完成。
- 授权或策略故障只收紧新的控制面动作，不向 Edge 发送停流或清理当前版本的命令。
- Webhook test-event/control 失败隔离在对应订阅的异步投递路径，不阻塞领域事务或边缘请求。

## 运行手册索引

状态标签只描述当前 composition 证据，不是发布批准：

- `mounted`：当前生产 composition 或固定运维入口已经接通；仍需按手册验证依赖。
- `optional`：只有显式配置开启且依赖校验通过时挂载，默认关闭。
- `package-only`：包、脚本或模板存在，但没有完整生产 composition 证据。
- `pending`：所述端到端生产链仍缺实现或真实验收。

| 领域 | 状态 | 入口与边界 |
| --- | --- | --- |
| Kubernetes 部署、Secret、升级和回滚 | `package-only` | [`kubernetes-control-plane.md`](../runbooks/kubernetes-control-plane.md)；Helm templates 不等于 production-ready |
| 控制面迁移 | `package-only` | [`control-migrations.md`](../runbooks/control-migrations.md)；应用不会隐式执行迁移 |
| 备份与恢复 | `package-only` | [`control-backup-restore.md`](../runbooks/control-backup-restore.md)；仍需目标环境恢复抽检 |
| 授权 lease 和离线行为 | `mounted` | [`control-entitlement.md`](../runbooks/control-entitlement.md) |
| signer 轮换与吊销 | `mounted` | [`license-signing-rotation.md`](../runbooks/license-signing-rotation.md)、[`license-signer-revocation.md`](../runbooks/license-signer-revocation.md) |
| API key 生命周期 | `mounted` | [`api-key-lifecycle.md`](../runbooks/api-key-lifecycle.md) |
| 自定义 RBAC | `mounted` | [`custom-rbac.md`](../runbooks/custom-rbac.md) |
| Agent systemd、身份和配置激活 | `package-only` | [`edge-agent-systemd.md`](../runbooks/edge-agent-systemd.md)、[`node-certificate-identity-contract.md`](../runbooks/node-certificate-identity-contract.md)、[`edge-config-activation.md`](../runbooks/edge-config-activation.md)；跨 Control/Gateway/Agent 验收另行判定 |
| 插件目录与同步 | `mounted` | [`plugin-catalog-registry.md`](../runbooks/plugin-catalog-registry.md)、[`plugin-catalog-sync.md`](../runbooks/plugin-catalog-sync.md) |
| Operator manifest 验证 | `mounted` | [`plugin-supply-chain.md`](../developer/plugin-supply-chain.md)；仅产生不可变验证证据，不安装或运行插件 |
| Webhook test-event/control delivery | `optional` | [`plugin-webhook-control.md`](../runbooks/plugin-webhook-control.md)、[`plugin-webhook-delivery.md`](../runbooks/plugin-webhook-delivery.md)、[`plugin-webhook-key.md`](../runbooks/plugin-webhook-key.md)（投递证明密钥与轮换）；generic domain outbox/install lifecycle 仍为 `pending` |
| Analytics query/log/ingest runtime | `optional` | [`analytics-runtime-wiring.md`](../runbooks/analytics-runtime-wiring.md)、[`analytics-storage.md`](../runbooks/analytics-storage.md)、[`analytics-logs-query-api.md`](../runbooks/analytics-logs-query-api.md) |
| OpenResty 到 analytics query 单链 E2E | `pending` | [`analytics-wire-red-handoff.md`](../runbooks/analytics-wire-red-handoff.md) |
| Control upgrade durable rollout | `candidate` | [`control-upgrade-policy.md`](../runbooks/control-upgrade-policy.md)；资格检查、创建/查询、金丝雀分批、暂停/继续、状态跟踪和自动/人工回滚候选已实现，仍待统一组合门禁和真实进程/浏览器生产 E2E |
| Gateway/Agent 下载、安装与状态回执 | `candidate` | [`edge-agent-upgrade.md`](../runbooks/edge-agent-upgrade.md)；v2 命令、durable claim、签名下载、helper 安装/回滚和状态回执候选已实现，仍待统一组合门禁和真实多节点生产 E2E |

其余 DNS、ACME、缓存、WAF、L4、日志和计费手册位于
[`docs/runbooks`](../runbooks/)。未在本表标为 `mounted` 或 `optional` 的手册默认按
`package-only` 或 `pending` 对待；某个手册存在不等于对应生产闭环已经完成。
