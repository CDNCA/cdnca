# ADR-0003 实现对照表（HTTP-01 节点全局 generation）

本表逐条对照 [ADR-0003](../adr/0003-acme-http01-node-global-generations.md) 与当前代码。
“337”指迁移 `337_acme_http01_node_generations`（fx05-http01），“339”指本次迁移 `339_acme_http01_cleanup_debt`（占位号，合入时可能改号）。
代码路径相对 `services/control-api/`。

## 模型映射

ADR 以 063 的“站点 desired version”为输入；337 改为以 047 `acme_issuance_challenge_attempts` 为 token 事实来源，challenge 冻结目标节点。339 在 337 之上补齐站点维度：

| ADR 概念 | 实现 |
| --- | --- |
| site desired version | `acme_http01_site_overlay_versions` + `_version_tokens`：站点当前存活 challenge 集合（去重后按 domain、token 摘要排序），集合变化即新版本 |
| 非空 token epoch / required membership | `acme_http01_site_overlay_epochs` + `_epoch_members`：站点首个非空版本时冻结候选节点（站点线路组内 active、未 hold、启用 endpoint 的节点）；`_epoch_releases` 记录成员被移出 |
| site coverage | `acme_http01_node_overlay_generation_coverages`，`coverage_kind ∈ {required, cleanup_debt}` |
| cleanup debt / 事件账本 / projection | `acme_http01_node_overlay_cleanup_debts`、`_cleanup_debt_events`、视图 `acme_http01_node_overlay_cleanup_debt_states`（每 debt 最新事件） |
| immutable site-serving target snapshot | 仓库没有 `site_serving_targets` 表；站点对外服务集合由 DNS 决定（`cname_allocation_targets` 冻结值、`dns_cname_retargets`，来源视图 `node_line_endpoint_published`）。serving gate 落在这些 DNS 值的计算处 |

## 逐条对照

| # | ADR 条款 | 337 已实现位置 | 339 本次实现 | 仍未实现及原因 |
| --- | --- | --- | --- | --- |
| 1 | 保留 063 全部表、事实、审计，不覆写、不回填 healthy | 337 未触碰 063 | 回填只读 063，新写 `acme_http01_overlay_backfill_*` 标记；不继承任何 063 healthy | — |
| 2 | 独立的 node generation / token / coverage / deployment / debt 账本 | generation、token、state、delivery（337） | coverage、debt、debt event、site version/epoch（339） | deployment 与 outbox 合一为 `acme_http01_node_overlay_deliveries`（337），未拆 event/outbox/attempt 三表；状态机等价（lease、幂等、retry、superseded），拆表无新增约束价值 |
| 3 | `OverlayVersionID`/`OverlayRevision`/previous pointer 改为 node generation 域，单节点严格递增 | `internal/acmehttp01/node_artifact.go`、337 state guard | — | — |
| 4 | canonical snapshot = 节点全部 current desired site token 并集，禁止 partial | `regenerateNode`（337） | 并集改由各站点当前版本 token 组成；339 触发器校验每个 required coverage 的 token 子集与站点版本逐一相等 | — |
| 5 | `purpose ∈ {apply, cleanup_only}`；cleanup_only 只用于 draining/retired 且全局 non-serving 节点，`token_count=0`、`required_coverage_count=0`、`cleanup_debt_coverage_count`=全部 unresolved debt | 无 | generation 新增 `purpose`、`required_coverage_count`、`cleanup_debt_coverage_count`、`non_serving_proof_sha256`；339 提交时触发器强制计数约束与 non-serving 证明（admin_state、无 serving endpoint、不在任何 open epoch 活跃成员中） | 已补（http01-followup eb3cbc3e）：`AcmeHTTP01OverlayCommand.purpose`=11、`FetchArtifactRequest.cleanup_only`=9，purpose 写进签名快照；Gateway 对非 deployments 会话只转 CLEANUP_ONLY，Agent 校验命令与快照 purpose 一致且 cleanup_only 必须 0 token |
| 6 | 普通站点移除用 apply：保留其他站点 required，被移除站点写零 token cleanup_debt coverage；活跃节点移除最后一个站点允许空 union 但须覆盖全部 debt | 337 只是从并集里去掉 token | `regenerateNode` 同时写 required 与 cleanup_debt coverage；339 触发器要求节点当前 generation 覆盖其全部 unresolved debt | — |
| 7 | generation 唯一 `(node_id, generation)`、`generation=expected+1` | 唯一约束、state guard 链式前进（337） | — | conflict/stale_attempt 时 337 会跳到 agent revision+1（`previous_generation < generation`），不是严格 +1；这是 Agent fence 要求的已知偏差 |
| 8 | generation `idempotency_key`/`request_digest`/`request_id` | 无 | 无 | 337 的 generation 由控制面内部状态机生成，不接受外部请求，幂等由 challenge 主键与“并集不变不出新代”保证；无外部重试入口，加这些列没有调用方 |
| 9 | generation token 引用 063 immutable token fact | 引用 047 attempt（337） | 同 337 | 337 起 token 事实来源改为 047，063 token fact 只作回填证据 |
| 10 | coverage 主键 `(generation_id, site_id)`；required 精确覆盖完整 token set 且 `site_token_count>0`；cleanup_debt `site_token_count=0`、无该站 token、引用未解决 debt；deferred trigger 重算子集摘要 | 无 | `validate_acme_http01_generation_coverage_339`（提交时） | — |
| 11 | 站点健康为派生查询；非空版本要 frozen epoch 每个活跃成员的 healthy generation 精确覆盖此版本；最终空 cleanup 禁止 vacuous healthy | `ChallengeStatus` 按 token 判（337） | SQL 函数 `acme_http01_site_version_healthy`（派生，不落 projection）；`ChallengeStatus` 排除已 release 的目标 | — |
| 12 | debt deployment 的 pending/failed 不阻塞其他站点签发，但阻止节点重新进入相关站点 serving target | — | debt 只出现在 cleanup_debt coverage；`ChallengeStatus` 只看 challenge 的活跃目标；serving gate 见 #18 | — |
| 13 | debt `(node_id, site_id, required_epoch_id)` 不可变确定性；记录 earliest uncovered site version、原 token-set digest、opened reason/time；跨代不复制 | 无 | `acme_http01_node_overlay_cleanup_debts`（append-only）；同一 `(node, site)` 未解决时不新开 debt，只追加 `coalesced` | — |
| 14 | 事件只允许 opened/coalesced/scheduled/resolved_cleanup/resolved_required；projection 只保存 latest；禁止删 debt、跳过 earliest、仅因节点重新 active 清债 | 无 | 事件表 append-only，插入触发器校验序号、首事件 opened、resolved 后无事件、resolved_* 必须由 latest healthy generation 的对应 coverage 证明；projection 为视图 | — |
| 15 | 新 generation 入库时旧未投递 backlog 同事务 superseded；只投最高代 | `regenerateNode`（337） | — | — |
| 16 | 任一点失败全事务回滚 | 337 单事务 | 339 所有新事实同事务、提交时校验 | — |
| 17 | 首次非空 epoch 冻结 required membership；epoch 内成员变化只告警并 fail closed；只有最终空 cleanup 关闭 epoch；被移除节点全部进入 durable debt；offline/retired 不阻塞当前签发 | challenge 级冻结目标（337） | epoch/member/release 三表；`PublishChallenge` 与 `Reconcile` 检测成员移除（release + debt）与漂移（新候选不加入，告警日志，且被 serving gate 挡在 DNS 外）；站点转空时全员 release(site_emptied) 并关闭 epoch | 漂移告警已接通知中心（http01-followup，迁移 347，事件 `acme.http01.epoch_drift`，Publish 与 Reconcile 都检测）。未开 epoch 的站点上节点离开不记 debt：此时没有节点持有该站点 token（required coverage 只来自开放 epoch 的活跃成员），无需清理，见 ADR 0003 与 `node_leave_no_epoch_integration_test.go` |
| 18 | 调度域确认节点对该站点无 unresolved debt 且 required coverage healthy 后才加入 serving target | 无 | SQL 函数 `acme_http01_site_node_serving_blocked`：未清 gating debt、站点 open epoch 非活跃成员、回填隔离 → 挡住；接入 `cnameallocation` 冻结目标与 retarget（只对 `acme_http01_gated_sites()` 内的站点逐站点过滤，其余仍按线路组缓存）、`dnsmaintenance.ServingValues`；HTTP-01 challenge 目标取 epoch 活跃成员。过滤后为空时 retarget 保留已发布值（既有 fail-open） | 节点配置下发（edge target snapshot）不受 gate 影响：gate 只控制 DNS 是否把该站点解析到节点 |
| 19 | 多站点更新按 node UUID 排序锁，锁后重读 | `lockNodeStates`（337） | 所有 HTTP-01 写事务先取同一个事务级 advisory lock 再按 UUID 锁节点：站点与节点两类锁不会交叉死锁，后到者在锁后重读 | 写入吞吐被串行化；ACME 签发频率低，可接受 |
| 20 | Gateway 用 mTLS session 当前 capability | gateway hello capability（既有） | — | — |
| 21 | Backfill：每节点收集 063 最新 version/target 并集；bootstrap generation 大于全部历史 site revision；coverage/debt 全不 healthy；旧 backlog superseded；冲突整节点 quarantine | 无 | SQL 函数 `acme_http01_backfill_063()`（迁移调用一次，可重跑幂等）：为每个 063 站点建已关闭 epoch（成员=063 目标）与 debt；节点标记 pending，Go 首次 regenerate 以 `max(063 revision)+1` 为下限生成 bootstrap generation；冲突/缺事实/跨租户 → quarantine 标记并在 gate 中 fail closed | 063 token 不再复活进新 generation：063 provider 自 FX05 起未接线，没有签发流程在等这些 token，bootstrap 只负责清理；063 outbox 没有 superseded 状态且禁止覆写，保持原样（无发布者，Agent 也会以 revision fence 拒绝） |
| 22 | 升级顺序 067→068→writer→Gateway→Agent→dispatcher→provider | — | — | ADR 写的 067/068 编号在仓库中已被其他迁移占用（公告、实名），无对应 serving-target binding schema；按 #18 的 DNS gate 代替 |
| 23 | Down 只在无 generation 投递、无 debt event、无外部引用时允许，否则 P0001 | 337 down 有 P3378 | 339 down：存在 epoch/debt/coverage/回填标记时 `P0001` 拒绝 | — |
| 24 | 必须通过的测试 | 337 集成测试（并集、撤回、超时、冲突跳代、篡改、NATS 闭环） | `internal/acmehttp01/node_debt_integration_test.go`：成员移除→debt→cleanup coverage→resolved、跨代保留 earliest debt 直到 resolved_required、epoch 冻结防漂移与最终空 cleanup、cleanup_only 计数与伪造拒绝、063 回填幂等与隔离、debt 经真实 NATS 解析；`internal/site/cname_retarget_integration_test.go` 验证 gate 经真实 retarget 规划器生效；迁移 339 up/down/up 与 P0001 | 真实 Pebble 端到端签发、并发交叠更新压测仍未做（写事务已串行化） |
| 25 | 节点 purge | — | — | 已补（http01-followup，迁移 346）：外键保持 RESTRICT，purge 在 `DELETE FROM nodes` 前调用 `acme_http01_purge_node_346` 按子先父后删除，epoch 冻结成员由墓碑表补足，见 ADR 0006 |

## 迁移 339 对 337 在途 challenge 的处理

339 之前发布的 challenge 没有 epoch 关联。迁移把它们一次性标记 withdrawn（337 允许的唯一变更），reconciler 随后为相关节点出不含这些 token 的新代。正在等待的 ACME 签发会收到 `ErrChallengeWithdrawn` 并由 worker 重试为新 challenge。337 与 339 同属 1.0.35，尚未发布，不需要更早版本兼容。
