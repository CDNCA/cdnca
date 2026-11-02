-- 616 回退：恢复 287/321/343/348/477 的 ON DELETE RESTRICT 与 348/477 的 INSERT/UPDATE/DELETE 守卫。
-- 外键行为不改变已有数据，回退总是可行（回退后节点删除重新被这些历史行挡住）。
LOCK TABLE schema_migrations, nodes, node_deployments,
    cache_operation_nodes, security_policy_publication_targets, acme_http01_overlay_targets,
    firewall_command_outbox, cc_coordination_setting_targets, cc_coordination_facts,
    l4_node_drain_counters, l4_line_switch_drain_plans, ja4_block_edge_receipt_queue_158,
    node_availability_alert_states, edge_challenge_redeliveries,
    node_deployment_timeouts, node_deployment_status_refusals IN ACCESS EXCLUSIVE MODE;

DO $migration_616_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 616 OR
       (SELECT max(version) FROM schema_migrations) <> 616 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=616 AND
        migration_id='616_node_purge_fk_restore' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 616 down requires the exact verified migration head' USING ERRCODE='P6163';
    END IF;
END;
$migration_616_down$;

DROP TRIGGER node_deployment_status_refusals_guard_477_del ON node_deployment_status_refusals;
DROP TRIGGER node_deployment_status_refusals_guard_477 ON node_deployment_status_refusals;
CREATE TRIGGER node_deployment_status_refusals_guard_477
BEFORE INSERT OR UPDATE OR DELETE ON node_deployment_status_refusals
FOR EACH ROW EXECUTE FUNCTION guard_node_deployment_status_refusal_477();

DROP TRIGGER node_deployment_timeouts_guard_348_del ON node_deployment_timeouts;
DROP TRIGGER node_deployment_timeouts_guard_348 ON node_deployment_timeouts;
CREATE TRIGGER node_deployment_timeouts_guard_348
BEFORE INSERT OR UPDATE OR DELETE ON node_deployment_timeouts
FOR EACH ROW EXECUTE FUNCTION guard_node_deployment_timeout_348();

ALTER TABLE node_deployment_status_refusals DROP CONSTRAINT node_deployment_status_refusals_deployment_id_attempt_fkey,
    ADD CONSTRAINT node_deployment_status_refusals_deployment_id_attempt_fkey FOREIGN KEY (deployment_id, attempt)
        REFERENCES node_deployments (id, attempt) ON DELETE RESTRICT;
ALTER TABLE node_deployment_timeouts DROP CONSTRAINT node_deployment_timeouts_deployment_id_attempt_fkey,
    ADD CONSTRAINT node_deployment_timeouts_deployment_id_attempt_fkey FOREIGN KEY (deployment_id, attempt)
        REFERENCES node_deployments (id, attempt) ON DELETE RESTRICT;
ALTER TABLE edge_challenge_redeliveries DROP CONSTRAINT edge_challenge_redeliveries_node_id_fkey,
    ADD CONSTRAINT edge_challenge_redeliveries_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE RESTRICT;
ALTER TABLE node_availability_alert_states DROP CONSTRAINT node_availability_alert_states_node_id_fkey,
    ADD CONSTRAINT node_availability_alert_states_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE RESTRICT;

DO $migration_616_restrict$
DECLARE
    target record;
BEGIN
    FOR target IN SELECT * FROM (VALUES
        ('cache_operation_nodes'), ('security_policy_publication_targets'), ('acme_http01_overlay_targets'),
        ('firewall_command_outbox'), ('cc_coordination_setting_targets'), ('cc_coordination_facts'),
        ('l4_node_drain_counters'), ('l4_line_switch_drain_plans'), ('ja4_block_edge_receipt_queue_158')
    ) AS t(table_name) LOOP
        EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I, ADD CONSTRAINT %I FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE RESTRICT',
            target.table_name, target.table_name || '_node_287_fkey', target.table_name || '_node_287_fkey');
    END LOOP;
END;
$migration_616_restrict$;
