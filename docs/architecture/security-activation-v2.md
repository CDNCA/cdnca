# 安全规则（WAF/CC）灰度激活移植到 site runtime v2

状态：1.0.35（缺口 8，用户定方案 A：完整移植）。迁移占位 329（守卫指向 328，合入时改号）。

## 问题

安全激活（`securityactivation`）的全链路假设“一个候选配置 = 一个产物摘要”：

- 候选行 `security_policy_activation_candidates.candidate_artifact_sha256` 只有一个值，`security_policy_activation_rollouts`、`..._recovery_pending_095`、`..._recovery_proofs_095` 都抄这一个值。
- 判定“节点已经在跑候选”的地方全都拿节点上报的 `active_config_artifact_sha256` / `node_config_state.current_config_artifact_sha256` 去和这一个值比：
  - 迁移 088 `validate_security_policy_activation_rollout_088`（阶段身份写入）、`security_policy_activation_phase_healthy_088`（阶段健康判定，晋升前置）；
  - 迁移 095 版 `validate_security_policy_activation_recovery_rollout_088`（排队态恢复 rollout 的校验）；
  - Go：`state.go` `aggregateReceiptFacts`（206/254 行）、`store.go` `lockCandidateTargetsHealthy`、`service.go` `createRecoveryRollouts`、`cancelPendingActivationDeployments`。

v2 产物按节点 HPKE 加密（`edgedeployment/validate.go:184`；AAD 绑定 node、deployment_id、event_id、attempt=1、artifact_id、recipient_key_id，见 `edgepublish/configuration_artifact_hpke.go`），每个节点拿到的密文不同，节点上报的就是自己那份密文的摘要（`edgestatus/store.go` 写 `node_config_state`，`active_config_identity_artifact_valid_087` 校验它是绑定到该 deployment 的那份产物）。所以 v2 下“一个摘要”无法表达。

另外 v1 候选编译对 TLS 站点直接拒绝（`edgepublish/security_candidate.go` `ErrTLSMaterialUnavailable`），HTTPS 站点只能走 v2，因此移植也是 HTTPS 站点能做安全灰度的前提。

## 身份取舍

两种做法：

1. 候选身份改为“每节点摘要集合”：候选表、阶段表、恢复事实表的 `candidate_artifact_sha256` 列都要改成集合或另建关联表，088/095 的约 85 处比较全部重写，候选行受保护触发器（`protect_security_policy_activation_candidate`）也要改，v1 行要迁移成单元素集合。改动面大，v1 也被迫跟着变。
2. 候选身份 = 加密前的规范内容摘要，加密后的产物摘要按节点另记一张表。现有各表的 `candidate_artifact_sha256` 列语义不变（“候选的身份摘要”），只有“拿节点上报值做比较”的少数位置改为查“该节点期望的摘要”。

选 2。理由：身份比较（候选行 ↔ 阶段行 ↔ 恢复事实行，约 80 处）是候选内部的一致性检查，和加密无关，保持原样；真正和节点上报值比较的位置只有上面列出的 3 个 SQL 函数和 4 处 Go 代码。v1 不写新表，查找函数回落到候选摘要，行为逐字不变。

### 具体定义

- v2 候选的 `candidate_artifact_sha256` = 加密前的明文 bundle（`site-runtime.v2.json` + 遥测清单、回源路由、HTTP 策略等全部文件的 wire bytes）的 SHA-256，`security_policy_activation_config_facts.artifact_sha256` 同值。
- 新表 `security_policy_activation_node_artifacts_333`（追加写，禁止改删）：每个目标节点一行，`(tenant_scope_id, config_version_id, node_id)` 唯一，记录该节点那份密文产物（`artifact_id`、`sha256`、`recipient_key_id`）以及加密时预先分配的 `deployment_id`、`event_id`。外键指向 `config_facts` 和 `configuration_artifacts`（摘要必须等于该产物的 `sha256`）。不对 `nodes`、`node_deployments` 建外键：deployment 在建 rollout 时才产生，且节点清除（迁移 284）不应级联到这张历史事实表。
- 查找函数 `security_policy_activation_node_artifact_sha256_333(scope, config, node, fallback)`：
  - 该配置没有任何节点行（v1）：返回 `fallback`（候选摘要）。
  - 有节点行：返回该节点那一行的摘要；该节点没有行返回 NULL（比较一律失败，不会误判健康）。

## 生成时机

v2 普通发布在同一事务里建配置、按节点加密、建 rollout。安全激活不同：Start 时建配置和 canary rollout，expand rollout 在后续 Reconcile 才建；而配置一旦 `releasable` 就不能再追加产物。所以 v2 候选在 Start 时一次性为全部目标节点（canary + expand）加密并落库，每份产物预先分配 deployment_id/event_id；建各阶段 rollout 时从新表读出该阶段节点的绑定，作为 `NodeArtifactBindings` 交给 `CreateRolloutTx`。

- HPKE 绑定 attempt=1，所以 v2 阶段 rollout 的 `MaxAttempts` 固定为 1（`normalizeRolloutRequest` 对带绑定的请求本来就要求 1）。失败不重试，走自动恢复，和 v2 普通发布一致。
- expand 节点的产物在 Start 时按当时的节点密钥加密。若 canary 期间 expand 节点轮换了密钥，该节点解不开，部署失败，候选进入 failed 并自动恢复，不会产生错误配置。
- 候选的 `required_capabilities` 直接用 v2 文档要求的能力（不做 v1 的 WAF/CC 版本改写），因为 `requireReleasableConfig` 要求 rollout 能力与 v2 文档完全一致。节点不具备时按现有门控拒绝（`finishSiteRuntimeV2` / `ValidateFeatureCapabilityTargets`，点名节点，可进入能力等待）。
- 同普通 v2 发布一样写 `config_version_telemetry_site_bindings`，否则节点跑候选期间的遥测会被拒。

## 触发器改造

新迁移 329 不改旧迁移文件，用 `pg_get_functiondef` 取出现有函数定义，对唯一出现的那段比较做替换后重新 `CREATE OR REPLACE`（同迁移 228 的做法；每处替换前断言恰好出现一次，否则报 P3290）：

| 函数 | 原比较 | 改为 |
|---|---|---|
| `validate_security_policy_activation_rollout_088` | `active_config_identity_artifact_valid_087(deployment.node_id, …, candidate.candidate_artifact_sha256, …)` | 第三个参数用该节点期望摘要 |
| `security_policy_activation_phase_healthy_088` | `latest.active_config_artifact_sha256=candidate.candidate_artifact_sha256` | 与该节点期望摘要比较 |
| `validate_security_policy_activation_recovery_rollout_088`（095 版） | `node_state.current_config_artifact_sha256=candidate.candidate_artifact_sha256` | 与该节点期望摘要比较 |

095 的 pending/proof 记录、`security_policy_activation_recovered_095` 只比较“节点当前摘要 = 恢复目标摘要”或身份列之间的一致性，恢复目标摘要本来就取自节点自己的 `node_config_state`，按节点天然正确，不需要改。

下行迁移：存在 v2 节点行时拒绝回退（P3291）；否则按反向替换恢复三个函数，删表删函数。

## v2 上的灰度失败自动恢复

和 v1 同一条状态机（`decideReconcile`），只是比较对象换成每节点期望摘要：

1. canary（或 expand）任一节点 failed/reverted → 候选 failed（过期 → expired，权限撤销 → cancelled）。
2. `cancelPendingActivationDeployments`：仍在排队的 apply 部署取消（节点当前仍是旧配置，或已是该节点的候选产物）。
3. `createRecoveryRollouts`：对“当前正在跑该节点候选产物”的节点下发 rollback，回到 apply 时记录的上一版（`recovery_pending_095` 从节点自己的 `node_config_state` 取的 config + 摘要）。rollback 命令不带产物，节点恢复本地保留的上一版，所以 v2→v2 回退无需重新加密。
   - 分组键是 (上一版 config, 上一版摘要)。上一版若是 v2，每个节点摘要都不同，于是每个节点一个恢复 rollout；需要恢复的只有已加载候选的节点（失败通常发生在 canary），数量有限，接受。
   - rollback rollout 的 `required_capabilities` 取恢复目标配置自己的：v2 目标取其文档能力（`requireReleasableConfig` 要求一致），v1 目标取候选能力去掉 site_runtime（与原 v1 行为一致）。
4. 节点上报 reverted 后 095 记录恢复证明，`recovered_at` 落地，绑定的目标节点释放。

## 测试计划

- 迁移 329：契约测试（校验和、守卫、三处替换、P3290/P3291）；集成测试 up/down/up，查找函数的 v1 回落、v2 命中、v2 缺行返回 NULL，追加写保护，有 v2 行时 down 拒绝。
- 单测：`aggregateReceiptFacts` 按节点期望摘要计数（v2 各节点不同摘要都算健康，用错节点的摘要判冲突；v1 回落不变）；rollback 能力推导。
- edgepublish 集成：v2 安全候选为每个目标节点生成可解密的产物，解出的文档带该站点的安全策略，节点行与产物一致；TLS 站点可用。
- securityactivation 集成（部署状态机端到端，按节点上报各自摘要）：
  - 成功：canary 健康 → expand → 全部健康 → 晋升，绑定生效、source_revision 前进。
  - 失败恢复：canary 节点加载候选后失败 → 候选 failed → 自动 rollback → reverted 证明 → recovered_at。
  - 过期恢复：expand 节点排队中过期 → 取消排队部署并恢复已加载节点。
- v1 回归：securityactivation、securitybinding、edgepublish 安全候选相关集成测试原样通过。

## 晋升 CAS 与站点 IPv6 投影（迁移 335）

各阶段 rollout 终态时 `edgedeployment/site_ipv6_projection.go` 回写 `sites.ipv6_runtime_state` / `ipv6_runtime_source_revision` / `updated_at`。迁移 021 的 sites 触发器曾因此推高作用域 `source_revision`，晋升 CAS（`store.go`，`source_revision = 候选 - 1`）必然冲突，真实上报下激活永远晋升失败（v1/v2 同）。这三列是节点上报的观测结果，不进编译输入（`edgepublish.loadSiteFacts` 只读期望值 `ipv6_enabled`），迁移 335 让只改这三列的 UPDATE 不再推高；其余列变化、INSERT、DELETE 照旧。手动发布仍是一个 source_revision 只发一次，同一内容再发给新节点要先推进版本（同节点调度的重发）。

## 不在本次范围

- 默认切 v2（已完成）：`StartInput.SiteRuntimeSchema` / `RollbackInput.SiteRuntimeSchema` 为空时取 `edgepublish.ResolveSiteRuntimeSchema`（`DefaultSiteRuntimeSchema` = v2），与手动/自动/挑战/错误页/系统配置/系统重发布、套餐同步同一规则；v1 只作显式选择。节点不具备文档所需 site_runtime 时按节点拒绝，不回落 v1。HTTP 接口不变。
- 外部 Claim 接口（`Store.Claim`）只接受 v1 单产物候选，保持不变。
