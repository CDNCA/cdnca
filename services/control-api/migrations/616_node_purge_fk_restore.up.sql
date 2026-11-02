-- 616（r136 fix-nodepurge，生产缺陷：节点删不掉；前驱 615_billing_adjustment_mfa_waiver，合入时按连号改号）：
--   管理端删除节点（internal/node/purge.go）最后 DELETE FROM nodes。284 把只描述该节点的行设为
--   ON DELETE CASCADE，但 287 把其中 9 张表的外键重建为 <表>_node_287_fkey ... ON DELETE RESTRICT，
--   284 的级联被覆盖；之后 321/343 新表又以 RESTRICT 引用 nodes，348/477 的事实表以 RESTRICT 引用
--   node_deployments（由 nodes 级联删除）且守卫拒绝任何 DELETE。节点只要执行过一次缓存清理、
--   有过可用性告警状态、挑战补发行、部署超时或状态拒收，删除就报 23503（node_in_use），永远删不掉。
--
--   逐表结论（进行中的引用仍由 purge.go ensureNodeUnreferenced 拒绝，见该函数）：
--   * 287 的 9 张表恢复 284 的 ON DELETE CASCADE（约束名保持 _node_287_fkey，287 的 down 按名删除）：
--     cache_operation_nodes（缓存任务的节点投影；未结束的任务由 purge 拒绝）、
--     security_policy_publication_targets、acme_http01_overlay_targets、firewall_command_outbox、
--     cc_coordination_setting_targets、cc_coordination_facts（活跃协同由 purge 拒绝）、
--     l4_node_drain_counters、l4_line_switch_drain_plans、ja4_block_edge_receipt_queue_158。
--     都是节点的下发/回执/投影事实，节点不存在后没有意义；删除守卫已按 284 只放行该节点的级联。
--     发生过什么留在 audit_events（node.delete 事件，不引用 nodes）。
--   * node_availability_alert_states（321，节点当前告警状态，每节点一行）：CASCADE。
--   * edge_challenge_redeliveries（343，"节点需要该策略期间存在"的补发工作行）：CASCADE。
--   * node_deployment_timeouts（348）/ node_deployment_status_refusals（477）：部署失败所依据的事实，
--     部署本身（node_deployments）随节点级联删除，事实随部署删除：外键改 CASCADE，守卫只在该节点的
--     purge 级联中放行 DELETE（node_purge_in_progress），其余 UPDATE/DELETE 仍拒绝。
--   * 保持 RESTRICT：l2_topology_nodes（284 起有意保留，purge 先删已软删成员、拒绝活跃成员）；
--     acme_http01_* 8 张表（346 由 acme_http01_purge_node_346 在 purge 中显式删除并留墓碑）。
--   没有账本/计费类表引用节点，无需在 purge 前另行保留。
LOCK TABLE schema_migrations, nodes, node_deployments,
    cache_operation_nodes, security_policy_publication_targets, acme_http01_overlay_targets,
    firewall_command_outbox, cc_coordination_setting_targets, cc_coordination_facts,
    l4_node_drain_counters, l4_line_switch_drain_plans, ja4_block_edge_receipt_queue_158,
    node_availability_alert_states, edge_challenge_redeliveries,
    node_deployment_timeouts, node_deployment_status_refusals IN ACCESS EXCLUSIVE MODE;

DO $migration_616_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 615 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 615 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=615 AND
        migration_id='615_billing_adjustment_mfa_waiver' AND
        checksum_sha256='bc37a458ac1a6c9c3370123ba4aa350b085273439951956aa50877dd4c0f44b9' AND
        down_checksum_sha256='dd6b5d142e5e7791913dc06dd580fc9bede95a3c5f508bf9b06bea2896344244' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM pg_constraint constraint_row
        WHERE constraint_row.contype = 'f' AND constraint_row.confdeltype = 'c'
          AND constraint_row.conname IN (
            'cache_operation_nodes_node_287_fkey', 'security_policy_publication_targets_node_287_fkey',
            'acme_http01_overlay_targets_node_287_fkey', 'firewall_command_outbox_node_287_fkey',
            'cc_coordination_setting_targets_node_287_fkey', 'cc_coordination_facts_node_287_fkey',
            'l4_node_drain_counters_node_287_fkey', 'l4_line_switch_drain_plans_node_287_fkey',
            'ja4_block_edge_receipt_queue_158_node_287_fkey', 'node_availability_alert_states_node_id_fkey',
            'edge_challenge_redeliveries_node_id_fkey', 'node_deployment_timeouts_deployment_id_attempt_fkey',
            'node_deployment_status_refusals_deployment_id_attempt_fkey')
          AND constraint_row.connamespace = current_schema()::regnamespace
       ) THEN
        RAISE EXCEPTION 'migration 616 requires the exact verified 615 release head' USING ERRCODE='P6160';
    END IF;
END;
$migration_616_up$;

DO $migration_616_cascade$
DECLARE
    target record;
BEGIN
    FOR target IN SELECT * FROM (VALUES
        ('cache_operation_nodes'), ('security_policy_publication_targets'), ('acme_http01_overlay_targets'),
        ('firewall_command_outbox'), ('cc_coordination_setting_targets'), ('cc_coordination_facts'),
        ('l4_node_drain_counters'), ('l4_line_switch_drain_plans'), ('ja4_block_edge_receipt_queue_158')
    ) AS t(table_name) LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_constraint
            WHERE conrelid = to_regclass(current_schema() || '.' || target.table_name)
              AND conname = target.table_name || '_node_287_fkey' AND confdeltype = 'r'
              AND confrelid = to_regclass(current_schema() || '.nodes')) THEN
            RAISE EXCEPTION 'migration 616: % lacks the 287 restrict key', target.table_name USING ERRCODE='P6161';
        END IF;
        EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I, ADD CONSTRAINT %I FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE',
            target.table_name, target.table_name || '_node_287_fkey', target.table_name || '_node_287_fkey');
    END LOOP;
END;
$migration_616_cascade$;

ALTER TABLE node_availability_alert_states DROP CONSTRAINT node_availability_alert_states_node_id_fkey,
    ADD CONSTRAINT node_availability_alert_states_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE edge_challenge_redeliveries DROP CONSTRAINT edge_challenge_redeliveries_node_id_fkey,
    ADD CONSTRAINT edge_challenge_redeliveries_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE node_deployment_timeouts DROP CONSTRAINT node_deployment_timeouts_deployment_id_attempt_fkey,
    ADD CONSTRAINT node_deployment_timeouts_deployment_id_attempt_fkey FOREIGN KEY (deployment_id, attempt)
        REFERENCES node_deployments (id, attempt) ON DELETE CASCADE;
ALTER TABLE node_deployment_status_refusals DROP CONSTRAINT node_deployment_status_refusals_deployment_id_attempt_fkey,
    ADD CONSTRAINT node_deployment_status_refusals_deployment_id_attempt_fkey FOREIGN KEY (deployment_id, attempt)
        REFERENCES node_deployments (id, attempt) ON DELETE CASCADE;

-- The 348/477 guards keep rejecting UPDATE and every DELETE except the purge
-- cascade of the node the deployment belongs to (284's node_purge_in_progress:
-- the marked node row is already gone and the delete is a referential action).
DROP TRIGGER node_deployment_timeouts_guard_348 ON node_deployment_timeouts;
CREATE TRIGGER node_deployment_timeouts_guard_348
BEFORE INSERT OR UPDATE ON node_deployment_timeouts
FOR EACH ROW EXECUTE FUNCTION guard_node_deployment_timeout_348();
CREATE TRIGGER node_deployment_timeouts_guard_348_del
BEFORE DELETE ON node_deployment_timeouts
FOR EACH ROW WHEN (NOT node_purge_in_progress()) EXECUTE FUNCTION guard_node_deployment_timeout_348();

DROP TRIGGER node_deployment_status_refusals_guard_477 ON node_deployment_status_refusals;
CREATE TRIGGER node_deployment_status_refusals_guard_477
BEFORE INSERT OR UPDATE ON node_deployment_status_refusals
FOR EACH ROW EXECUTE FUNCTION guard_node_deployment_status_refusal_477();
CREATE TRIGGER node_deployment_status_refusals_guard_477_del
BEFORE DELETE ON node_deployment_status_refusals
FOR EACH ROW WHEN (NOT node_purge_in_progress()) EXECUTE FUNCTION guard_node_deployment_status_refusal_477();

-- After 616 the only keys a node delete can trip on are the intended ones.
DO $migration_616_closure$
DECLARE
    unexpected text;
BEGIN
    WITH RECURSIVE reach(relation) AS (
        SELECT (current_schema() || '.nodes')::regclass::oid
        UNION
        SELECT constraint_row.conrelid FROM pg_constraint constraint_row JOIN reach ON constraint_row.confrelid = reach.relation
        WHERE constraint_row.contype = 'f' AND constraint_row.confdeltype = 'c'
    )
    SELECT string_agg(constraint_row.conrelid::regclass::text || '.' || constraint_row.conname, ', ' ORDER BY 1) INTO unexpected
    FROM pg_constraint constraint_row JOIN reach ON constraint_row.confrelid = reach.relation
    WHERE constraint_row.contype = 'f' AND constraint_row.confdeltype IN ('r', 'a')
      AND constraint_row.conrelid::regclass::text NOT IN (
          'l2_topology_nodes', 'acme_http01_node_challenge_targets', 'acme_http01_node_overlay_generations',
          'acme_http01_node_overlay_states', 'acme_http01_site_overlay_epoch_members',
          'acme_http01_node_overlay_cleanup_debts', 'acme_http01_node_overlay_generation_coverages',
          'acme_http01_overlay_backfill_nodes', 'acme_http01_overlay_backfill_quarantines');
    IF unexpected IS NOT NULL THEN
        RAISE EXCEPTION 'migration 616: node delete is still restricted by %', unexpected USING ERRCODE='P6162';
    END IF;
END;
$migration_616_closure$;
