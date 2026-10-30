# 套餐监控 Runtime：BILL-10A 078 persistence/runtime core

## 当前结论

状态：`OWNED_PRODUCTION_ADAPTERS_READY_PENDING_SHARED_MAIN_COMPOSITION`。

本文件不是最终生产 readiness 证明。BILL-10A 在冻结的 077 current head 之后实现了 078
PostgreSQL facts、Store transaction kernel 和复用 jobstate 的 Runtime core；BILL-10B 已补齐
114 finalized metric authority、独立连接数/带宽事实、正式 entitlement/notification/audit
adapter、跨租户 producer/supervisor，以及 tenant row ID 与 tenant scope ID 的严格分离。
这些 owned 组件仍需由 `cmd/control-api` 的共享 composition root 启动后，才能宣布进程级 readiness。
仓库没有 `HEAD`，GitNexus 对相关符号返回 `Target not found`，blast radius 仍为 `UNKNOWN`，
不能解释为 LOW。

078 没有创建第二套 claim ledger，也没有用内存 map、notification event 反查或临时表
冒充持久事实。生产接线仍缺已仲裁 entitlement feature 与 finalized subscription metric；
这些边界属于 BILL-10B。

## 为什么既有事实不能替代

| 既有事实 | 可复用边界 | 不足 |
| --- | --- | --- |
| `package_subscription_state_versions` | 订阅 lifecycle、周期和 revision 快照 | `owner_user_id` 来自 `created_by_user_id`；platform 直接创建时不是可靠租户接收人 |
| `package_subscription_entitlement_versions` | 固定时钟下选择生效且未被后继覆盖的产品/额度快照 | 不含实际流量、当前带宽或连接数 |
| `product_snapshot.spec.limits` | 售出时的流量、带宽、连接数限制 | SQL 只验证 `spec` 是对象；必须严格解码，不能回读当前 catalog |
| ClickHouse `access_events/access_hourly_v1` | tenant/site/node 的字节与小时平均带宽 | 无 `subscription_id`、无资源到订阅绑定、无连接数；平均带宽不是当前/短窗 finalized 整数事实 |
| `traffic_package_*` | 独立流量包 grant/consume/refund 账本 | 无基础套餐 subscription FK，不能作为套餐周期用量 |
| `packagesubscription.Evaluate` | 调用方传入 usage 后的纯可用性判断 | 没有生产 usage source、持久告警状态或 worker 调用链；硬配额语义与通知阈值也不是同一契约 |
| `notification_events/outbox/attempts` | `EnqueueTx` 同事务入事件、outbox、审计；投递 lease/retry | 是投递事实而非告警业务事实；不能表达 before/suppressed_stale；接收人检查只验证 membership 行存在 |
| `background_jobs/items/attempts/results` | durable claim、heartbeat、lease takeover、单赢家与失败重试 | 只表示工作执行，不表示 policy、metric 证据或告警状态；应复用，不能复制一套 monitor claim 表 |
| 本地签名 entitlement lease | 授权中心离线时由主控缓存并验签 | `ReadValidVersion` 只证明租约和版本有效；现有 guard 没有 package-monitor feature check，且不能猜测 `packages.count` 就代表告警授权 |

notification 交付只承诺 at-least-once。provider 接收后、settlement 前崩溃可能重投，
不得声称 exactly-once。

## 上游 metric 契约（078 前置）

高基数原始事件继续只进 ClickHouse。必须先有版本化、finalized 的订阅级投影，单条
observation 至少返回：

| 字段 | 类型/约束 |
| --- | --- |
| `schema_version` | `package-monitor-metric/v1` |
| `tenant_scope_id` | canonical UUID |
| `subscription_id` | canonical UUID |
| `metric` | `traffic_bytes\|bandwidth_bps\|connections` |
| `period_key` | 1..256 bytes，计费时区与半开周期的 canonical key |
| `value` | exact UInt64；禁止 float |
| `observed_at` | UTC instant |
| `finalized_through` | UTC instant，不能倒退 |
| `source_watermark` | monotonic UInt64 |
| `evidence_digest` | SHA-256 over canonical observation |

`bandwidth_bps` 必须定义固定短窗的 finalized peak/current 语义；不能复用当前查询窗口
平均值。`connections` 必须来自版本化 gauge/max 投影。采集链必须在事件发生时写入
`subscription_id`，或使用带有效期且不重叠的资源绑定；按当前 owner 或当前 catalog
事后归集会污染历史周期。

114 metric authority 通过版本化 site/subscription/config installation 绑定和 finalized
watermark 约束生产读取；流量、短窗带宽与独立连接数均拒绝 request-derived fallback。
到期指标使用 state revision 与 deadline digest 形成稳定 period identity，并允许 producer
持续评估到 `ends_at + stale_after_seconds`，从而真实到达 `suppressed_stale`，而不是在
`ends_at` 提前停止。最终生产 readiness 仍要求共享 composition root 和真实 ClickHouse/PG
统一波次通过。

## 078 最小 PostgreSQL 契约

建议名：`078_package_monitor_runtime`。只有 077 up/down 的 formal hash 冻结后才能创建。

### `package_monitor_subscription_owners`

| 列 | 约束 |
| --- | --- |
| `subscription_id` | UUID PK |
| `state_revision` | bigint > 0 |
| `tenant_scope_id` | UUID NOT NULL |
| `owner_user_id` | UUID NOT NULL |
| `source_kind` | `commerce_fulfillment\|subscription_state` |
| `source_fulfillment_id` | commerce 时 UUID，state 时 NULL |
| `migration_backfilled` | 仅 078 backfill 为 true；后续 INSERT 固定 false |
| `created_at` | finite timestamptz |

先在 `package_subscription_state_versions` 上增加唯一索引
`(subscription_id, revision, tenant_scope_id, owner_user_id)`，owner 表用四列 exact FK；
另用 `(tenant_scope_id, owner_user_id)` FK 到 `memberships(scope_id,user_id)`。
commerce 来源必须通过 fulfillment -> order 的约束触发器证明相同 subscription、tenant
且 `package_orders.user_id = owner_user_id`。只有 owner 同时是 active tenant member 的
旧 state 才能 backfill；platform creator 或歧义记录保持无 owner，runtime 对该订阅
fail closed，不猜接收人。
078 在 backfill INSERT 中持久标记 exact migration-created row；随后启用 provenance trigger，
拒绝任何 post-up INSERT 伪造该标记。

索引：`(tenant_scope_id, owner_user_id, subscription_id)`。表为 append-only；一期不支持
owner 改绑，后续改绑必须另建版本化审计契约。另建唯一键
`(subscription_id, tenant_scope_id, owner_user_id)`，供所有下游 owner exact FK 使用。

### `package_monitor_policy_versions`

| 列 | 约束 |
| --- | --- |
| `policy_id, revision` | UUID + bigint，复合 PK |
| `tenant_scope_id, subscription_id, owner_user_id` | exact FK 到 monitor owner |
| `metric` | `traffic_bytes\|bandwidth_bps\|connections\|expiration` |
| `trigger_value` | numeric(20,0)；expiration 为 1..UInt64 max，其它 metric 为 0..UInt64 max |
| `recovery_value` | numeric(20,0)，高水位时 `< trigger_value` |
| `stale_after_seconds` | 仅 expiration，正 bigint；其它 metric 必须 NULL |
| `threshold_identity` | 32-byte SHA-256，包含 policy revision、metric 和三个整数值 |
| `enabled` | boolean |
| `created_by_user_id, created_at` | membership FK + finite time |

expiration 中 `trigger_value/recovery_value` 表示秒，`trigger_value` 必须为正数：触发条件为
`now >= ends_at-trigger_value`，恢复条件为 `now < ends_at-recovery_value`，且
`recovery_value > trigger_value`；首次扫描满足
`now >= ends_at+stale_after_seconds` 时进入 `suppressed_stale`，不 enqueue。
其它三类使用 exact integer：`value >= trigger_value` 触发，
`value <= recovery_value` 恢复。硬配额原有严格 `used > limit` 语义不被修改。

唯一键：`(tenant_scope_id, subscription_id, metric, revision)` 和
`(tenant_scope_id, subscription_id, metric, threshold_identity)`。所有版本 append-only。
阈值数值没有 observed 证据，078 不得擅自 seed 默认值；必须由产品仲裁或显式策略写入。
policy 使用 `(subscription_id, tenant_scope_id, owner_user_id)` exact FK 到 owner，并使用
`(tenant_scope_id, created_by_user_id)` FK 到 membership。另建包含
`(policy_id, revision, tenant_scope_id, subscription_id, owner_user_id, metric, threshold_identity)`
的唯一键，供 head/transition exact FK 使用。

### `package_monitor_policy_templates`

列：`policy_id, policy_revision, transition, channel, template_id, template_version`。
PK 为 `(policy_id, policy_revision, transition, channel)`；transition 只允许
`triggered|recovered`，channel 只允许 `sms|email`。FK 到 policy version，以及 exact FK
`(template_id, template_version, channel)` 到 `notification_templates`。

必须有新 template seed，不能在启动时调用 `SaveTemplate` 或在代码中内联正文。建议固定
v1 ID：

- `package.monitor.traffic.triggered.zh-cn` / `recovered.zh-cn`
- `package.monitor.bandwidth.triggered.zh-cn` / `recovered.zh-cn`
- `package.monitor.connections.triggered.zh-cn` / `recovered.zh-cn`
- `package.monitor.expiration.triggered.zh-cn` / `recovered.zh-cn`

每个 ID 各有 sms/email 两行。模板正文、变量集和逐行 SHA 必须另行 formal freeze；
当前 notification schema 无 locale 列，ID 后缀是首期 locale 边界，不代表完整 i18n 已完成。
notification event type 固定为 `package.monitor.<metric>.<transition>`，其中 metric 为
`traffic|bandwidth|connections|expiration`，transition 为 `triggered|recovered`；delivery
policy 固定为 `tenant_subscribed`。`SourceEventID` 是同一 alert identity/transition 的稳定
去重键，provider delivery 仍只承诺 at-least-once。

### `package_monitor_policy_heads`

列：`policy_id` PK、`tenant_scope_id`、`subscription_id`、`owner_user_id`、`metric`、
`current_revision`、`current_threshold_identity`、`next_evaluation_at`、`revision`、
`updated_at`。全部 identity 列复合 FK 到 policy version；唯一键
`(tenant_scope_id, subscription_id, metric)`。

调度索引：`(next_evaluation_at, tenant_scope_id, policy_id) WHERE next_evaluation_at IS NOT NULL`。
scheduler 只创建 kind=`package.monitor.evaluate.v1` 的 `background_jobs`。生产 supervisor
先按 `(next_evaluation_at, tenant_scope_id, policy_id)` 扫描 due policy，再用
`access_scopes.tenant_id` 写入 jobstate 的物理 tenant FK；worker 同时携带独立
`tenant_scope_id` 约束 metric 与 evaluation，不再假定两个 UUID 相等。其 idempotency
key 固定为
`package.monitor.evaluate.v1.<policy_uuid>.<policy_revision>.<UTC YYYYMMDDTHHMMSS.000000000Z>`，
长度和字符集满足既有 jobstate 约束，并由完整 policy version identity + due instant 决定。
claim/lease/attempt 全部复用 `jobstate`，078 不新增 worker claim 表。

### `package_monitor_evaluation_clocks`

每个首次提交的 evaluation 事务通过 `package_monitor_transaction_clock_078()` 取得唯一
`evaluation_clock_id` 和 PostgreSQL `clock_timestamp()`。表同时保存不可伪造的 current
`pg_current_xact_id()`；BEFORE INSERT trigger 覆盖 caller 提供的 transaction/time，表整体
append-only。alert head、transition fact 和 receipt 均以 `(evaluation_clock_id,evaluated_at)`
exact FK 引用该事实，并由 BEFORE trigger 证明 clock 属于当前事务。caller 即使让所有业务行
和 audit payload 相互一致，只要时间比 DB-owned instant 早或晚 1 微秒也会拒绝。head
`updated_at` 与 receipt `created_at` 也必须逐值等于该 instant。

历史 receipt replay 的只读事务会 rollback 本次临时 clock 行，不产生孤立 clock fact；原始
receipt 及其首次提交 clock 保持不变。

### `package_monitor_alert_heads`

| 列 | 约束 |
| --- | --- |
| `id` | UUID PK |
| `tenant_scope_id, subscription_id, owner_user_id` | exact owner FK |
| `policy_id, policy_revision` | 与 tenant/subscription/owner/metric/threshold 一起组成 exact policy FK |
| `metric, period_key, threshold_identity` | canonical alert identity |
| `state` | `before\|triggered\|recovered\|suppressed_stale` |
| `revision` | bigint > 0 |
| `last_source_watermark` | numeric(20,0)，monotonic |
| `last_finalized_through` | finite timestamptz，monotonic |
| `last_evidence_digest` | 32 bytes |
| `last_evaluated_at, updated_at` | finite timestamptz |

唯一键：`(tenant_scope_id, subscription_id, metric, period_key, threshold_identity)`。
索引：`(tenant_scope_id, owner_user_id, updated_at DESC, id DESC)` 和
`(policy_id, policy_revision, period_key)`。保护触发器只允许 revision +1、watermark
前进、finalized boundary 不倒退和状态 `before -> triggered -> recovered` 或
`before -> suppressed_stale`；
`suppressed_stale` 与 `recovered` 为终态。
另建包含 alert id、owner、policy 和全部 alert identity 列的唯一键，供 transition exact FK。

### `package_monitor_transition_facts`

| 列 | 约束 |
| --- | --- |
| `alert_id, revision` | 复合 PK；FK 到 alert head identity |
| `tenant_scope_id, subscription_id, owner_user_id` | 与 head 完全一致 |
| `policy_id, policy_revision, metric, period_key, threshold_identity` | 与 head 完全一致 |
| `phase` | `before\|triggered\|recovered\|suppressed_stale` |
| `observed_value` | numeric(20,0)；expiration 可保存 signed seconds remaining |
| `metric_schema_version` | 固定 `package-monitor-metric/v1` 或 `deadline/v1` |
| `source_watermark, observed_at, finalized_through` | metric provenance |
| `evidence_digest` | 32 bytes |
| `evaluated_at, reason_code` | fixed clock + 稳定 reason |
| `source_event_id` | triggered/recovered 必填，其它 NULL |
| `notification_event_id, notification_event_type` | triggered/recovered 必填，其它 NULL |

唯一键：`(alert_id, phase)`、partial unique `(tenant_scope_id, source_event_id)`。078 先在
`notification_events` 增加
`(scope_id,id,recipient_user_id,source_event_id,event_type)` 唯一索引，再由 transition 的
`(tenant_scope_id,notification_event_id,owner_user_id,source_event_id,notification_event_type)`
建立单个 exact FK；禁止用两个可分别命中不同 event 的弱 FK。表 UPDATE/DELETE/TRUNCATE
全拒绝。deferred constraint trigger 证明事务结束时 head revision/state 与最后 transition 一致。

同一 `(subscription, metric, period, threshold)` 最多一个 triggered 和一个 recovered；
recovered 后同 identity 不重开。新周期或新阈值产生新 identity。expiration 的 period key
必须包含 subscription state revision 与 `ends_at` 摘要。续期时先用新 deadline evidence
恢复旧 triggered identity，再为新 revision/`ends_at` 建立新的 before identity，不能覆写旧事实。

### `package_monitor_evaluation_receipts`

每个首次提交的 evaluation 都写一条不可变 receipt，包括没有 transition、只推进 head
watermark/finalized boundary 的提交。receipt 保存 deterministic `receipt_id`、完整 alert/policy
exact FK、result revision/state/transition、metric schema/watermark/timestamps/evidence digest、
可选 transition fact revision/notification event，以及原始 `job_id`、attempt、item、request 和
owner actor。`UPDATE/DELETE/TRUNCATE` 均由 078 触发器拒绝。

head 每次 INSERT/UPDATE 在事务结束时必须恰有一条 receipt 与最新 watermark、digest、state、
revision、evaluated-at 完全一致。旧 observation 在 head 后续前进后重试时按 receipt 返回原始
`EvaluationResult` 和同一 receipt ID，不从当前 head 猜结果，也不会把 no-transition 重试误判为 stale。
每条新 receipt 还在 INSERT 时逐列匹配当时 current head 的 tenant/subscription/owner/policy、
threshold、revision/state、watermark/observed/finalized/digest/evaluated-at 和 transition fact；因此 head
前进后不能补写伪造的旧 receipt，但已经合法提交的历史 receipt 仍可精确 replay。
receipt 与 head/fact 同时保存 exact `evaluation_clock_id`，不能只靠相等时间冒充 provenance。
receipt 的通知 UUID 通过 exact FK 和 validator 绑定同 revision transition fact。

### Audit exact contract

复用现有 `audit.Log.Append` 和同一 `audit_events` hash chain，不修改或复制 audit 事实源。
078-owned BEFORE INSERT trigger 只处理 package-monitor action：从当前事务的 immutable clock
fact 读取 `evaluated_at`，要求 payload 的 clock ID/time 是 exact RFC3339Nano canonical bytes，再将
`occurred_at` 绑定为同一 instant，并按现有 audit canonical v1 编码重算 `event_hash`；offset、冗余
小数位或其它等价 timestamp spelling 均拒绝，payload 不能选择时间。
shared `audit.Log.VerifyScope` 必须继续通过。每个持久 phase 保留 transition audit；
每个首次提交的 evaluation 另写一条 `package_monitor.evaluation.commit`，resource 固定为
`package_monitor_evaluation_receipt/<receipt_id>`，actor 固定为 owner，payload 与 receipt 的
结果、digest 和 job identity 完全一致。transition audit 的 job ID、attempt、item、request 与
外层 `audit_events.request_id` 也逐值绑定同一 receipt。transition action 只允许
`package_monitor.alert.observe_before`、`package_monitor.alert.trigger`、
`package_monitor.alert.recover`、`package_monitor.alert.suppress_stale`；resource type 固定为
`package_monitor_alert_transition`，resource ID 固定为 canonical `alert_id:revision`，request
ID 使用 background job item 的稳定幂等键。payload 必须完整包含 tenant/subscription/owner、
policy revision、metric/period/threshold、source watermark、evidence digest、reason code 和
notification event ID（无通知时为 null），以及与 fact/receipt 完全相等且 canonical 编码的
`observed_at` 和 `evaluated_at`。

由于当前 `audit.Log.Append` 不返回 event ID，078 在 `audit_events` 上增加仅限上述 action 的
唯一索引 `(scope_id,action,resource_type,resource_id)`，并用 deferred constraint trigger 验证
每个 transition 在事务结束时有且仅有一条同 scope、同 phase、同 identity/digest 的 success
audit。audit append、唯一性或 deferred 校验失败都必须回滚 transition、head 和 outbox；
不得在 packagemonitor 内另写 audit 表。

## 事务与锁序

metric observation 在事务外读取并验 schema/digest/finalization；数据库事务中重新验证
policy/head 没有变化。每次业务尝试的固定顺序：

1. fresh transaction，`iam_global_lock_shared_v1()` 是首个有效锁。
2. `iam_scope_locks_v1()`，完整 scope UUID 集合 canonical sort。
3. 锁并验证 tenant、access scope、owner user、membership 均 active。
4. 上述 IAM lock wait 完成后，通过 078 transaction-clock function 在 transaction 内只调用一次
   PostgreSQL `clock_timestamp()`，并持久化 exact clock ID/transaction ID；
   该 immutable physical instant 是 future-boundary、effective entitlement、expiration 和 audit
   的唯一时间权威，不接收 process clock。
5. 通过 transaction-bound `TransactionEntitlementChecker` port 只读主控缓存的签名 lease；
   不请求授权中心。package-monitor feature code 仍待 BILL-10B 仲裁，不能用
   `packages.count` 猜测授权；生产 adapter 缺失时构造失败。
6. 锁 current subscription state、fixed-now effective entitlement 和 exact owner；严格解码 immutable product snapshot limits。
7. 锁 policy head/version，再锁 alert identity head；顺序为 metric、period key、threshold digest。
8. 拒绝 stale、倒退、坏 digest、错误 scope/owner/period 的 observation。
9. 拒绝晚于 transaction physical clock 的 `observed_at/finalized_through`；等于边界允许。
10. 计算纯 transition；无 transition 推进安全 watermark/head，有 transition 时先 enqueue 再写 fact/head。
11. 写不可变 evaluation receipt 和 exact evaluation audit；任一失败回滚 head/fact/outbox。
12. commit 后才通过 `jobstate.Report` 报告成功；ack 丢失时确定性 receipt 收敛为 replay。

任何 IAM、owner、subscription、entitlement、metric、policy、template、audit、outbox、commit
失败都回滚，无成功 transition。现有 Edge traffic 不读这些表，也不在请求热路径访问授权中心。

## Down guard

down 必须先以 `pg_advisory_xact_lock(1229016321, 1)` 取得 IAM v1 global key；migration runner
已先持有独立 ledger advisory lock，不能调用要求 first-effective-lock 的 runtime helper。该 gate
只序列化遵守 IAM protocol 的 package-monitor policy/fact writer；notification enqueue/outbox worker
不持有 IAM shared gate，不能假定所有 writer 都受此 gate 保护。通过全局门后，down 用一个
`LOCK TABLE ... IN ACCESS EXCLUSIVE MODE NOWAIT` statement 原子请求以下完整表集：
`package_monitor_subscription_owners`、`package_monitor_evaluation_clocks`、
`package_monitor_policy_versions`、`package_monitor_policy_templates`、
`package_monitor_policy_heads`、
`package_monitor_alert_heads`、`package_monitor_transition_facts`、
`package_monitor_evaluation_receipts`、`background_jobs`、
`notification_events`、`notification_templates`、`notification_outbox`，最后锁
`audit_events`。任一 ungated writer 正持有其中任意 relation lock 时，NOWAIT 以稳定可重试
SQLSTATE `55P03` 失败，migration transaction 整体回滚，不留下部分 lock、ledger 或 teardown；
调用方可在 writer 完成后重试。取得完整锁集后才能执行以下 existence checks；任一存在即以稳定错误
`P7809 package_monitor_runtime_facts_prevent_rollback` 原子拒绝：

- 任意 alert head、transition 或 evaluation receipt；
- 任意 committed evaluation clock fact；
- 任意 policy/head 或 `migration_backfilled=false` owner；只有 078 持久标记的 exact backfill 可清理；
- kind=`package.monitor.evaluate.v1` 的 background job/attempt/result；
- `package.monitor.*` notification event/outbox；
- `package_monitor.alert.*` 或 `package_monitor.evaluation.commit` audit event；
- template seed 已被 outbox 或 policy template 引用；
- seed 内容/变量/逐行 hash 与 formal manifest 不同。

空事实 down 可临时禁用 `notification_templates_immutable` 触发器，仅删除 exact manifest 中且
未被引用的 16 行，立即恢复触发器，再按 FK 逆序删除 monitor 表、函数、权限和索引。
禁止 CASCADE、禁止删除非 078 seed、禁止在 guard 失败后留下部分 down。

## BILL-10A ownership 与交付状态

077 formal freeze gate（只读，当前任务不修改）：

| 文件 | 当前 SHA-256 |
| --- | --- |
| `services/control-api/migrations/077_signer_revocation_checkpoint_lkg.up.sql` | `db0f37f09ef1de36fc050f3b26b60fb09468d652d9f23daa8b6f3898f62cf30e` |
| `services/control-api/migrations/077_signer_revocation_checkpoint_lkg.down.sql` | `825a2723031b689143143decd7a128bf233bd5bdef208ad0ec7ebe71b859f2fb` |

本轮只修改下列 BILL-10A 文件；没有触碰 main/http/OpenAPI/UI、entitlement、jobstate、
notification、audit、ClickHouse、Gateway/Agent 或 001..077。最终 SHA-256 随 integrator
handoff 一并提供。

| 文件 | 状态 | 用途 |
| --- | --- | --- |
| `services/control-api/migrations/078_package_monitor_runtime.up.sql` | implemented | 八表、DB-owned clock、exact FK、ACL、template manifest seed |
| `services/control-api/migrations/078_package_monitor_runtime.down.sql` | implemented | writer-order guarded rollback / `P7809` |
| `services/control-api/migrations/package_monitor_078_integration_test.go` | implemented | ledger、roundtrip、tamper、race、rollback |
| `services/control-api/migrations/testdata/package_monitor_templates_v1.json` | implemented | 16 行逐行 SHA manifest |
| `services/control-api/internal/packagemonitor/store.go` | implemented | PostgreSQL transition/head/receipt/notification/audit transaction |
| `services/control-api/internal/packagemonitor/store_test.go` | implemented | canonical digest、deadline key、validation |
| `services/control-api/internal/packagemonitor/store_integration_test.go` | implemented | replay、single winner、rollback、revoke-first |
| `services/control-api/internal/packagemonitor/runtime.go` | implemented | jobstate worker、readiness/failure、Close/restart |
| `services/control-api/internal/packagemonitor/runtime_test.go` | implemented | dependency、job key、failure/recovery、Close |
| `services/control-api/internal/packagemonitor/runtime_integration_test.go` | implemented | lease takeover、response loss、final DB facts |
| `scripts/package-monitor-runtime-smoke.sh` | implemented | PostgreSQL 17.9 Unix-socket smoke and cleanup |
| `docs/runbooks/package-monitor-runtime.md` | implemented | BILL-10A/B boundary and operational contract |

`notification_runtime_open.go` 后续必须把 tenant active 纳入 queued delivery 的 contact
resolution，并与 IAM revocation 顺序做集成测试；否则 enqueue 后 suspend tenant 仍无完整
抑制证明。HTTP/OpenAPI 不是 078 runtime kernel 的前置，本次不申请其 ownership。

### 最终门禁与旧测试 handoff

078 scoped ordinary/race、`go vet`、`gofmt`、PostgreSQL 17.9 integration、隔离 078
up/down/up roundtrip、当前 001..084 apply/ledger、down/writer race、RR/SERIALIZABLE
revoke-first、以 `pg_blocking_pids` 证明交错的双 worker/down-writer、heartbeat/takeover/terminal
join、historical replay、forged-old-receipt 拒绝、corrupt claim zero-heartbeat/report、tenant
mismatch、PostgreSQL physical clock/skew/wait/same-transaction exact boundary、audit exact clock、
DB-owned ±1 微秒拒绝、audit-v1 JSON/RFC3339Nano/hash-chain cross-language vectors、
exact backfill provenance、UTF-8、
tamper/rollback、template/audit/notification rollback 与 smoke 均通过；
smoke 清理结果为 `task residual=0`、`PPID=1 orphan=0`。

## 只读依赖冻结

| 文件 | SHA-256 |
| --- | --- |
| `services/control-api/migrations/027_background_jobs.up.sql` | `d6e0fdbcb6bbb16677a0696da4e8a02f5ddd6611c2bf5f814d1a35479e7ffb2c` |
| `services/control-api/migrations/028_package_subscriptions.up.sql` | `8ea5d38d75ad4f95485742d6f75f2d15db95090ed540569d08a8149df8cdec31` |
| `services/control-api/migrations/029_notification_outbox.up.sql` | `7bf4b5df1e7739e39655252468d3d1ab910b88740e3335befedd7ee2f22ddd10` |
| `services/control-api/migrations/051_package_commerce.up.sql` | `90b976b2d7d5a52e9d238c2f5a4292abe2104bb8783f069d286a61aaa661ae62` |
| `services/control-api/migrations/062_package_commerce_subscription_state_snapshot.up.sql` | `9e733b74f1cd9a5a3524b13cd68512381d5292bc98cde423946528050f7f532a` |
| `services/control-api/migrations/069_iam_global_lock_protocol.up.sql` | `7870a7344c8ad1476b7848ee59ce29713c943fad1562418bc9428f97f609f0de` |
| `services/control-api/migrations/001_identity.up.sql` | `ea12431f6febebced7de7bf3eb16bdb2ad32793525e56323781c0c8204f767f6` |
| `services/control-api/internal/jobstate/store.go` | `3ea193b35d87bd47df4d63de25a484f30066ae3ddb71343da7e78bfe0cb47c8d` |
| `services/control-api/internal/notification/store.go` | `f9640f2ee47c2ec8529cb7330b25254a2b2dac8826d943c42a42ad2c0d077500` |
| `services/control-api/internal/notification/outbox_store.go` | `ca36e6b1f91971f80d26aec6fa0a24f474da1f34b2008bb67a23b32768324df4` |
| `services/control-api/internal/audit/log.go` | `83eaab49637821c9dd0634e121e239e473d2c0841e90b5fa1ddf04427e524777` |
| `libs/entitlement/lease.go` | `c4c2f01d5fdd48d972f171d8e5eb307d4323cae93866c4c343544d244ca4a9ee` |
| `infra/clickhouse/migrations/001_analytics.up.sql` | `1213c9da79aefb7332eb24f0c789b145e6e63c2cbacdca53eff736cc38bee8a3` |

## 078 对外 kernel

`internal/packagemonitor` 在原有纯状态机之外导出：

- `NewStore(... TransactionEntitlementChecker, NotificationEnqueuer, AuditAppender ...)`；
- `Store.Evaluate(EvaluationInput)`；
- `PackageMonitorJobKey(policyID, revision, dueAt)` 与 canonical parser；
- `NewRuntime(config, RuntimeDependencies)`，其中仅 MetricSource、jobstate、Evaluator 任一缺失即
  构造失败；entitlement、notification 与 audit 由 Store/Evaluator 拥有，Runtime 不接收也不丢弃。

Store 只以 078 facts 为业务事实源；Runtime 只通过 jobstate Claim/Heartbeat/Report 工作，
每项 work 使用显式且短于 lease 的 deadline，并在 accepted work 期间续租。Runtime config、
claim job 与 observation tenant 必须相同。JobState Claim 只能返回 requested tenant；corrupt
cross-tenant 或 wrong-kind claim 在任何 MetricSource readiness/Observe 之前拒绝，且不 Heartbeat、
不 Report、不调用 evaluator。可信 claim 的 observation
tenant mismatch 只向 configured tenant 写稳定 failed result。heartbeat 在任何 terminal Report
前先取消并 join；真实 pre-report heartbeat failure 仍 fail closed。commit 后才 Report。
`Close` 取消并等待 accepted work；旧 worker 退出且 lease 到期前 replacement
不能并发执行同一 job。上述
测试通过不代表 production wiring 或 production readiness。

## BILL-10B 当前接线边界

- entitlement feature 固定为 `package_monitor.manage`；transaction adapter 使用 evaluation
  事务内的 PostgreSQL physical clock 验证本地主控缓存签名租约，不访问授权中心，也不借用
  `packages.count`。
- `PostgresProductionCoordinator` 只为 active tenant/user/membership、active subscription 和
  enabled current policy 生产任务。job create 先于 policy CAS advance；崩溃或并发时依靠固定
  payload/idempotency key 收敛，避免 advance-first 丢任务。
- `ProductionRuntime` 每轮同时发现新 due policy 和历史可领取 job，以物理 tenant ID claim，
  以 tenant scope ID 校验 observation；readiness 覆盖 114 schema、coordinator 与 metric source，
  `Close` 取消并等待当前轮完成。
- HTTP/OpenAPI/UI 已包含 durable acknowledgement；前端在网络结果不确定时保留同一
  `Idempotency-Key` 重试，不把未知结果当失败后创建新命令。
- 待共享 owner 一次挂入 `cmd/control-api` 的 config/start/readiness/shutdown；之后只运行受影响
  composition gate。真实 PG/ClickHouse/NATS/全进程、通知发送与桌面/390 浏览器验证进入统一
  验收波次，不在本阶段重复启动依赖。
