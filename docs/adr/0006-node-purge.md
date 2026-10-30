# ADR 0006：节点删除为物理删除（迁移 284）

状态：已采纳（1.0.34 起；需要原生 runner 执行管理端迁移）

## 决策

管理端「删除节点」（`PATCH /v1/nodes/{id}` 或批量接口的 `admin_state=retired`）物理删除节点行。
节点自身的明细随外键 `ON DELETE CASCADE` 一并删除；操作事实只保留在 `audit_events`
（`node.delete`，不引用 `nodes`）。不再保留 retired 占位行，节点名立即释放。

## 外键分类（迁移 284 起）

经 `nodes` 直接或间接可达的 68 张表、102 条外键。除下表「保持 RESTRICT」一行外，全部改为 `ON DELETE CASCADE`。

| 分类 | 表（外键数） | 删除行为 |
| --- | --- | --- |
| 证书与身份 | node_certificates(5)、node_certificate_renewal_requests(4)、node_certificate_revocations(2)、node_certificate_events(2)、node_identity_state(2)、node_identity_authorizations(3)、node_enrollment_tokens、node_enrollment_authorizations、node_artifact_encryption_keys(2)、node_session_capabilities(3)、node_network_inventory_reports(2) | CASCADE |
| 心跳、会话、监控 | node_presence、node_metric_samples、node_serving_holds、node_serving_events、node_monitoring_overrides(2)、node_monitoring_command_outbox、node_auto_disable_usage、node_isolation_states(2)、node_isolation_reports、node_isolation_alert_events | CASCADE |
| 部署回执与对账 | node_deployments、node_deployment_artifacts、deployment_status_events、artifact_fetch_requests(2)、edge_command_outbox(2)、node_config_state(2)、node_config_reconciliations(2)、deployment_domain_event_source_outbox(2)、deployment_domain_event_fanout_receipts、security_policy_activation_recovery_pending_095(2)、security_policy_activation_recovery_proofs_095(2)、security_policy_publication_targets、package_monitor_config_installations_114、site_protocol_node_results | CASCADE |
| 节点任务与指令 | cache_operation_nodes、cache_operation_node_targets、cache_operation_node_attempts、cache_operation_target_results(2)、firewall_command_outbox、ja4_block_edge_receipt_queue_158、node_gateway_port_transitions、node_gateway_port_transition_command_outbox(2)、node_gateway_port_transition_status_events(2)、node_traffic_policies(2)、node_traffic_policy_evaluations、node_traffic_sync_tasks(2)、l4_node_drain_counters、l4_line_switch_drain_plans | CASCADE（进行中的缓存任务由应用层先拒绝） |
| ACME / CC / 快照 / 错误页 | acme_http01_overlay_targets、acme_http01_overlay_deployments、acme_http01_overlay_deployment_events、acme_http01_overlay_outbox(3)、acme_http01_overlay_outbox_states、acme_http01_overlay_outbox_attempts、cc_coordination_setting_targets、cc_coordination_facts、cc_coordination_states、cc_coordination_actions、cc_coordination_releases(2)、edge_target_snapshot_nodes、edge_target_snapshot_identities(2)、error_page_scope_overrides、error_page_scope_override_revisions、error_page_scope_override_items | CASCADE（活跃 CC 协同由应用层先拒绝） |
| 线路分组端点 | node_line_endpoints、node_line_endpoint_health | CASCADE + 守卫触发器：仍被**存活线路分组当前版本**列出的端点拒绝删除（23001 → `node_in_use`）；历史版本、已删除分组随节点删除 |
| L2 成员 | l2_topology_nodes → nodes | **保持 RESTRICT**；应用层拒绝存活成员（`node_in_use`），并在删除前清掉已软删除的成员/配置历史 |
| ACME HTTP-01 节点全局代际（337/342，迁移 346） | acme_http01_node_challenge_targets、acme_http01_node_overlay_generations(+tokens)、acme_http01_node_overlay_states、acme_http01_node_overlay_deliveries、acme_http01_site_overlay_epoch_members(+releases)、acme_http01_node_overlay_cleanup_debts(+events)、acme_http01_node_overlay_generation_coverages、acme_http01_overlay_backfill_nodes、acme_http01_overlay_backfill_quarantines | **保持 RESTRICT**；删除流程在 `DELETE FROM nodes` 前调用 `acme_http01_purge_node_346(node)`（SECURITY DEFINER，应用角色只有 EXECUTE）显式删除，见下文 |

站点（sites）、线路分组本身、L2 配置本身不引用 nodes，不受影响。
不带外键的 node_id 列（control_upgrade_*、background_job_items、analytics_access_source_window_contributions_208、
audit_events.resource_id）保留历史，不级联。

## 防篡改触发器

58 个带 DELETE 的保护/完整性触发器（含 018/019/020/034 等）拆成两条：原名触发器保留 INSERT/UPDATE/TRUNCATE，
新增 `<原名>_del`（只剩 DELETE 的触发器原名重建）带 `WHEN (NOT node_purge_permits(OLD.node_id))`；
无 node_id 的子表与语句级触发器用 `node_purge_in_progress()`。放行条件同时满足：

1. 事务内 `SET LOCAL cdnca.node_purge = '<node_id>'`（应用在 `DELETE FROM nodes` 前设置，删除后清空）；
2. `pg_trigger_depth() > 0`：行由外键级联（或触发器）删除，顶层语句的 DELETE 深度为 0，永远不放行；
3. 该节点行在当前快照中已不存在，只有它的 DELETE 已执行后才成立；
4. 有 node_id 的行还要求 `OLD.node_id` 等于该节点。

因此：UPDATE 一律仍被拒绝；直接 DELETE 受保护行（带不带标记）仍被拒绝；标记指向别的节点时级联被拒绝。
迁移末尾自检：闭包内所有外键为 CASCADE（L2 除外），所有 DELETE 守卫均带 WHEN 门控。

## 删除流程（单事务）

取 HTTP-01 overlay 事务锁（`hashtextextended('acme-http01-overlay',0)`，必须在锁节点行之前：HTTP-01 写者持该锁时会因外键
等待节点行的 KEY SHARE 锁，反序会死锁）→ 锁节点 → 引用检查（存活线路分组当前版本、存活 L2、排队/运行中的缓存任务、未过期且未结束的 CC 协同，均返回
`node_in_use`）→ 吊销有效证书 → 清理已软删除的 L2 成员 → 写 `node.delete` 审计（节点 ID、显示 ID、名称、IPv4/IPv6、
区域、原状态、创建时间、被吊销证书 ID 与序列号、删除者、删除时间）→ 设标记 → 删除 HTTP-01 事实 → `DELETE FROM nodes` 级联 →
清标记 → 记入 `node_purged_ids`。批量删除每项一个 savepoint，逐项返回结果。

### HTTP-01 事实（迁移 346）

节点已不存在，其残留 token 无意义，HTTP-01 代际、token、投递、状态、challenge 目标、epoch 成员与释放、debt 与事件、coverage、
回填标记一并删除。这些表的 DELETE 守卫拆成 `<表>_del_346`（`WHEN (NOT acme_http01_node_purge_permits_346(...))`，只认本事务
`cdnca.node_purge` 标记的节点），带 node_id 的表另有提交时约束触发器 `<表>_purged_346`：节点行仍在则拒绝（P3462）。
站点 epoch 冻结了成员数与摘要，被删成员写入 `acme_http01_site_overlay_epoch_purged_members` 墓碑，epoch 校验把墓碑计入；
之后该节点既不算活跃成员也不欠释放，存活成员照常确认 challenge、最终空 cleanup 照常关闭 epoch。墓碑存在时 346 down 以 P0001 拒绝。

## 节点 ID 不复用

自注册节点 ID 由机器指纹派生（64 代）。删除后 ID 记入 `node_purged_ids`，同机重装取下一代 ID。原因：网关的
JetStream 持久消费者按节点 ID 命名、control_upgrade_* 历史无外键，复用旧 ID 可能让新节点继承旧消息/历史。
节点名不受此限制，可直接复用原名。

## 网关

授权快照 TTL 1 分钟、半衰期刷新。节点行消失后快照查询返回 `ErrCertificateNotFound`（gRPC NotFound），
会话在下次刷新（≤30 秒）结束，重连同样被拒。

## retired 状态

`admin_state=retired` 作为请求目标表示删除，不再产生 retired 行。数据库约束与网关/流量策略对 retired 的拒绝逻辑保留，
用于 1.0.33 及更早版本遗留的 retired 行：它们在列表中正常显示（标签「已退役」），只能删除。列表不再接受
`status=retired` 筛选。

## 回滚

down 恢复 283 的外键与触发器原样（catalog 逐项一致，已测试）。已删除的节点不会恢复；`node_purged_ids` 被删除，
回到 283 后被删除节点的 ID 可能被再次分配。
