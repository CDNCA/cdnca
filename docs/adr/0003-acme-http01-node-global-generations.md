# ADR-0003：ACME HTTP-01 节点全局 Overlay Generation

- 状态：已接受，仍须按本文的迁移和启用门禁分阶段上线
- 日期：2026-07-23
- 关联文档：[平台架构](../architecture.md)、[HTTP-01 控制面](../runbooks/acme-http01-overlay-control-plane.md)、[边缘 Overlay](../runbooks/acme-http01-edge-overlay.md)

## 背景

迁移 063 以站点为 revision/version 域生成全量 token 快照，但 Edge Agent 当前只有一个节点全局 current pointer 和一个全量 HTTP-01 snapshot root。直接把站点快照投到节点会产生不可接受的覆盖：站点 A 与站点 B 可以生成相同 revision、不同 version；任一站点的空 cleanup 还会删除节点上其他站点仍有效的 token。

因此旧 063 facts 只能作为站点 desired-state 输入和迁移证据，不能继续直接作为 Agent 的全量激活单元。新模型必须先把一个节点上所有站点的当前 desired token 聚合为单调 node generation，再把该 generation 作为唯一可激活的全量快照。

## 决策边界

本 ADR 固定 node-global generation 契约。迁移、protobuf、Gateway 和 Agent 必须按本文的依赖顺序分别实现和验收；任何单一阶段完成都不能宣称 HTTP-01 已生产可用。容量、锁等待和调度域 serving gate 仍是实现验收项，而不是可以省略的后续优化。

- 保留 063 全部表、事实和审计，不覆写旧记录，也不把旧 healthy receipt 回填成 aggregate healthy。
- 新建独立的 node generation、generation token、site coverage、deployment/outbox 和 cleanup debt 账本；不把新状态硬套进 063 deployment。
- Agent 的 `OverlayVersionID`、`OverlayRevision` 和 previous pointer 改为 node generation 域；revision 对单节点严格递增。
- 一个 generation 的 canonical snapshot 是该节点所有 current desired site token 的并集，不允许站点级 partial full snapshot。

`CLEANUP_ONLY` 只用于 deployments-disabled 且已经全局 non-serving 的节点，并强制发布节点全局空集合。普通站点移除始终使用 `APPLY`：节点仍服务其他站点时保留那些站点的完整 required coverage，并为被移除站点写零 token cleanup-debt coverage；活跃节点移除最后一个站点时允许 `APPLY` 空 union，但必须覆盖该节点全部 unresolved debt，且不能据此生成任何 required healthy 事实。

控制面只有在同一事务证明节点不属于任何 current immutable `site_serving_targets`、节点状态为 `draining` 或 `retired`，且 generation 包含该节点全部 unresolved debt 的零 token coverage 时，才可创建 `CLEANUP_ONLY`。`CLEANUP_ONLY` 的 `token_count` 和 `required_coverage_count` 必须为零；成功健康回执只能解析其显式列出的 debt，不能生成站点 required healthy 事实。节点尚在任一 current serving target、遗漏 debt、包含任意 token 或 required coverage 时必须拒绝提交。

## 建议 Schema

以下名称和列是评审契约，不是已经落盘的迁移。

### 节点 generation

`acme_http01_node_overlay_states` 每节点一行：

- `tenant_scope_id`、`node_id` 组成主键和租户外键。
- `current_generation` 单调递增；`latest_healthy_generation` 只能前进且不得大于 current。
- `current_generation_id`、`latest_healthy_generation_id` 精确绑定不可变 generation。
- `created_at`、`updated_at` 单调；禁止删除、truncate 和任意回退。

`acme_http01_node_overlay_generations` 是不可变事实：

- `id`、`tenant_scope_id`、`node_id`、`expected_generation`、`generation`。
- `purpose` 只能是 `apply` 或 `cleanup_only`。`cleanup_only` 必须绑定同事务读取的全局 non-serving 证明版本。
- `canonical_snapshot_sha256`、`token_count`、`required_coverage_count`、`cleanup_debt_coverage_count`。
- `idempotency_key`、`request_digest`、`request_id`、`deadline_at`、`max_attempts`、`created_at`。
- 唯一 `(node_id, generation)` 和 `(node_id, idempotency_key)`；`generation=expected_generation+1`。
- `cleanup_only` 必须 `token_count=0`、`required_coverage_count=0`，且 `cleanup_debt_coverage_count` 精确等于该节点全部 unresolved debt 数量。`apply` 可以包含 current serving target 的 required coverage 和站点移除产生的 cleanup debt；活跃节点 current serving membership 为空时，`apply` 也可以是覆盖全部 unresolved debt 的空 union。

`acme_http01_node_overlay_generation_tokens` 固化 canonical union：

- 主键 `(generation_id, ordinal)`，并唯一 `(generation_id, source_site_version_id, operation_id, challenge_attempt_id)`。
- 保存 `site_id`、`source_site_version_id`、operation/attempt、domain、token/value/AAD digest 和引用顺序。
- 通过复合外键引用 063 的 immutable token fact，不复制或改变 challenge 明文/密文。
- canonical 顺序固定为 `site_id, domain, token_sha256, operation_id, challenge_attempt_id`；重复 identity 不得因输入顺序产生不同摘要。

### Site coverage

`acme_http01_node_overlay_generation_coverages` 把站点 desired version 映射到 node generation：

- 主键 `(generation_id, site_id)`；列含 `site_version_id`、`coverage_kind`、`site_token_set_sha256`、`site_token_count`、`required_epoch_id`、可选 `cleanup_debt_id`。
- `required` 必须精确覆盖该 site version 的完整 token set，且 `site_token_count>0`。
- `cleanup_debt` 必须 `site_token_count=0`，该 generation 中不得存在该 site 的 token，并必须引用未解决 debt。
- deferred trigger 重新计算 generation token 子集摘要，禁止伪 coverage、缺 token、额外 token 或跨租户引用。
- `apply` 可以同时包含其他站点的 `required` 和已移除站点的 `cleanup_debt`；这正是活跃节点局部清理的唯一合法形式。
- `cleanup_only` 不得包含 `required`，并必须为节点当前全部 unresolved debt 各包含一条 `cleanup_debt`；它不表示任何站点仍由该节点服务。

站点健康是派生查询，不由调用方写 projection：

- 非空 site version 必须 `required_count>0`，且 frozen required epoch 中每个节点都有一个已 healthy node generation；该 generation 的 `required` coverage 必须精确引用此 site version 和 token-set digest。
- 后继 node generation 可以满足旧 site version，只要 coverage 仍精确；旧 generation receipt 不能满足后继 site version。
- 最终空 cleanup 可以 `required_count=0`，但必须证明上一非空 epoch 的每个 required node 已生成 unresolved debt 或已有 healthy cleanup coverage，禁止 vacuous healthy。
- debt deployment 的 pending/failed 不阻塞其他 required site issuance；它会阻止该节点重新进入相关 site 的 serving target。

### Cleanup debt

`acme_http01_node_overlay_cleanup_debts` 为 `(node_id, site_id, required_epoch_id)` 建立一个不可变、确定性 debt fact：

- 记录 `earliest_uncovered_site_version_id`、原 token-set digest、opened reason/time。
- 同一 epoch 跨 g1/g2/g3 不复制 debt；始终保留最早未覆盖来源。

`acme_http01_node_overlay_cleanup_debt_events` 是追加账本，事件仅允许：

- `opened`：节点从 frozen required membership 移除、离线或站点转空。
- `coalesced`：desired site version 前进，但 earliest debt 身份不变。
- `scheduled`：最高 node generation 包含该 debt 的 cleanup coverage。
- `resolved_cleanup`：healthy generation 对该 site 为零 token coverage。
- `resolved_required`：节点重新成为 required，且 healthy generation 已精确覆盖当前非空 site version。

可重建 projection 只保存 latest event。删除 debt、跳过 earliest debt 或仅因节点重新 active 而清债均禁止。

### Deployment 与 outbox

新 generation 使用独立的 deployment/event/outbox/attempt/projection 表，沿用 063 已验证的 lease、幂等、审计、原子失败和 retry 状态机，但外键指向 node generation。

- 新 generation 入库时，所有旧 generation 的未投递 backlog 在同事务追加 `superseded` 终态；claim 只选择每节点最高、未 superseded generation。
- 已发布旧命令无法撤回时，由 Agent 的 generation fence 拒绝；旧 status 可归档，但不得推进 current generation、coverage 或 site healthy。
- generation、token、coverage、debt event、deployment、outbox 和 audit 任一点失败都回滚整个 generation 事务。
- `failed` 是否可自动 retry 必须有持久 retryable 事实；没有该事实时只允许已批准的 `timed_out` 自动 retry。

## Target Epoch 与并发

### Required membership

- 一个 site 的非空 token epoch 首次发布时，从调度域读取 immutable site-serving target snapshot，并冻结 required membership。
- 同一非空 epoch 内节点 membership 变化只产生 drift 告警并 fail closed，不静默扩大或缩小 required 集合。
- 只有最终空 cleanup 关闭 epoch；下一次非空 epoch 才重新解析 required membership。
- 被移除的节点全部进入 durable debt。offline/retired 节点不阻塞当前 required issuance，但未清债前不得重新服务该 site。
- 没有开放 epoch 的站点，节点离开不记 debt，这是有意的：节点 generation 的 required coverage 只取“开放 epoch 的未释放成员 × 当前非空 site version”（`regenerateNode`，`node_store.go` 的 desired coverage 查询），其余只有未解决 debt 的空 cleanup coverage。站点没有开放 epoch 时任何节点都不持有它的 token，离开无需清理；epoch 关闭时（最后 token 撤回或过期，`site_emptied`）全体剩余成员已各记一笔 debt，下一次非空 epoch 重新冻结成员。
- drift 告警（迁移 347）：事件 `acme.http01.epoch_drift` 进通知中心，收件人为平台 scope 内持 `nodes.manage` 的成员；同一 epoch、同一漂移节点集只告警一次（source = epoch + 节点集摘要），重复发送只在 epoch 开放时保留。Publish 与 Reconcile 都会检测（Reconcile 覆盖“最后一次 Publish 之后才加入线路组”的节点）。

### 多站点更新

一次 site desired 变更按 node UUID 排序锁所有受影响 `node_overlay_states`，锁后重新读取每个节点全部 current desired site facts，再生成 union。两个交叠站点并发更新遵循相同排序，不允许死锁或 lost union。

在 PostgreSQL `READ COMMITTED` 下，后取得节点锁的事务必须在取得锁后重新读取 desired facts。若 A 先生成 g1，B 随后生成 g2，g2 必须同时覆盖 A 与 B；outbox coalescing 保证节点只执行最高代。A 的 site coverage 可以由包含同一 A version/digest 的 g2 healthy 结果满足。

同一站点重试使用 site request digest 和 idempotency key 返回同一 desired fact/mapping，不重新选 membership。迟到 cleanup 必须同时通过 expected site revision 和 node generation fence，不能删除其他站点或新 attempt。

## 调度与恢复顺序

serving gate 归调度/站点投递域，不归 ACME worker 或 Gateway：

1. Gateway 通过 mTLS session 获得当前 capability，不能使用注册时陈旧 capability 冒充当前事实。
2. 离线节点恢复后只接收该节点最高 generation，并完成签名、预检、原子激活和 healthy receipt。
3. 控制面重建 generation coverage 与 debt projection。
4. 调度域确认该 node 对该 site 无 unresolved debt 且 required coverage healthy 后，才把节点加入 immutable site-serving target snapshot。

retired/draining 节点只有在已经从所有 current immutable serving target 排除后才是本契约中的全局 non-serving。若要让它们清债，protobuf command 必须增加可信 `purpose=APPLY|CLEANUP_ONLY`：

- `APPLY` 仍要求 deployments allowed 和当前 overlay v1 capability。
- `CLEANUP_ONLY` 仅投递签名的全局空集合，并绑定全局 non-serving 证明版本和完整 debt coverage 摘要；Gateway 不自行推导或放宽该事实。
- Gateway 必须验证 purpose 与签名 artifact binding；不能仅因 `deploymentsAllowed=false` 就无条件开放所有 overlay。
- capability 过期、缺失或版本不匹配时不投递；debt 保持未解决。

## Backfill 与兼容

旧 063 facts 原样保留。新 migration 的 backfill 只做以下动作：

1. 对每个节点收集其所有站点最新 063 current version/target，按上述 canonical 顺序计算 union。
2. bootstrap generation 起点必须大于该节点所有历史 site revision；不得复用站点 revision。
3. 生成 site coverage 和必要 debt，但全部保持未 healthy；旧 latest healthy/receipt 不继承。
4. 新 site coverage projection 在 bootstrap generation 获得新协议 healthy receipt 前 fail closed。
5. 旧 NATS backlog 标记 superseded；升级后只投最高 bootstrap generation。

合法多站点 union 不是冲突。以下任一情况会 quarantine 整节点 aggregate bootstrap：同一 `(host, token)` 不同 value、同 challenge identity 不同 digest、缺 immutable source fact、跨租户引用或无法证明当前 desired version。不能隔离单个冲突 site 后发送 partial full snapshot；只有证明冲突 site 已空且 non-serving并建立 debt，或未来 Agent 改成真正 per-site store，才可解除 quarantine。

升级顺序必须是 `067` serving-target/binding schema 与 readiness -> `068` node-generation schema/readiness -> control aggregate writer -> Gateway purpose/fence -> Agent node generation store -> dispatcher -> site provider。`site_config_version_bindings` 必须先把已激活配置版本和 current immutable serving membership 绑定，aggregate writer 才能证明 `CLEANUP_ONLY` 的零成员条件。任一阶段不兼容时 provider fail closed，已有边缘配置继续服务。

## Up/Down 门禁

Up migration 只新增 node-global 表、约束、projection/view 和 backfill 记录，不修改或删除 063。启用 aggregate writer 前必须完成 catalog、backfill、quarantine 和 fresh healthy 验证。

Down 仅在以下条件同时成立时允许：没有 node generation 被投递或确认、没有 debt event、没有 aggregate audit 被外部引用、feature flag 尚未切读。否则以 SQLSTATE `P0001` 拒绝，防止丢失 generation/debt 事实。回滚应用版本后仍可读取旧 063，但不得把旧站点 snapshot 再投给全局 Agent。

## 必须通过的测试

- 同节点站点 A/B 并发更新，最终 generation 是完整 union；同站点重试幂等。
- A cleanup 后 A 为 404、B 继续 200；过期 A challenge 不删除 B token。
- 节点离线跨 g1/g2/g3 保留 earliest debt，重连只消费最高代。
- debt 节点重新 required 后，只有 required coverage healthy 才清债并允许 serving。
- 迟到旧 cleanup 和旧 generation receipt 被 fence；NATS backlog 不先执行旧代。
- 非空 required、debt 和最终空 cleanup 三类健康门禁均不可 vacuous healthy。
- 交叠 node 集合按 UUID 锁定，无死锁、union 丢失或重复 generation。
- coverage/token/latest healthy/debt projection 直接 SQL 篡改在提交时拒绝。
- 活跃节点移除站点时只能接收 `APPLY`；仍有其他站点时必须保留其 required coverage，移除最后一个站点时必须验证空 union 和全部 debt coverage；不得使用 `CLEANUP_ONLY`。
- retired/draining 只有 current serving membership 为空时才接收合法全局空集合 `CLEANUP_ONLY`；current capability 缺失或过期不投递。
- 伪造零成员证明、遗漏 unresolved debt、在 `CLEANUP_ONLY` 中夹带 token/required coverage，或用 cleanup healthy 推进 required serving 状态都必须在提交时拒绝。
- 旧 063 backfill 未 fresh 验收时不继承 healthy；冲突节点整体 quarantine。
- generation/token/coverage/debt/deployment/outbox/audit 任一点失败全事务回滚。
- 固定时钟验证 deadline、attempt timeout、max attempts、离线恢复和 generation 单调。

## 结果

该方案增加一个独立的 node aggregate 控制面，但这是修复“站点 desired state”与“节点全量激活单元”不一致所需的最小边界。它不会让授权中心或 Gateway进入边缘请求链路，也不以旧 receipt 冒充新 generation 健康。现有 per-site 063 provider 必须继续 fail closed，直到 `067`、`068`、Gateway、Agent、dispatcher 和真实 Pebble/OpenResty 纵向验收全部通过。
