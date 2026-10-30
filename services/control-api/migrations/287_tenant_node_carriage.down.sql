LOCK TABLE schema_migrations, nodes, cache_operation_nodes, security_policy_publication_targets,
    acme_http01_overlay_targets, firewall_command_outbox, cc_coordination_setting_targets,
    cc_coordination_facts, l4_node_drain_counters, l4_line_switch_drain_plans,
    ja4_block_edge_receipt_queue_158, cname_allocation_targets IN ACCESS EXCLUSIVE MODE;

DO $migration_287_down$
DECLARE
    target record;
    foreign_rows boolean;
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 287 OR
       (SELECT max(version) FROM schema_migrations) <> 287 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=287 AND
        migration_id='287_tenant_node_carriage' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 287 down requires the exact verified migration head' USING ERRCODE='P2870';
    END IF;
    -- Rows that put a tenant's resource on a platform node cannot be expressed
    -- in the 286 schema; rolling back must not silently drop them.
    FOR target IN SELECT * FROM (VALUES
        ('cache_operation_nodes', 'scope_id'), ('security_policy_publication_targets', 'tenant_scope_id'),
        ('acme_http01_overlay_targets', 'tenant_scope_id'), ('firewall_command_outbox', 'tenant_scope_id'),
        ('cc_coordination_setting_targets', 'tenant_scope_id'), ('cc_coordination_facts', 'tenant_scope_id'),
        ('l4_node_drain_counters', 'configuration_scope_id'), ('l4_line_switch_drain_plans', 'configuration_scope_id'),
        ('ja4_block_edge_receipt_queue_158', 'tenant_scope_id')
    ) AS t(table_name, scope_column) LOOP
        EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I row JOIN nodes node ON node.id=row.node_id
            WHERE node.scope_id <> row.%I)', target.table_name, target.scope_column) INTO foreign_rows;
        IF foreign_rows THEN
            RAISE EXCEPTION 'migration 287 down refused: % holds rows on nodes outside their scope; restore from backup instead',
                target.table_name USING ERRCODE='P2871';
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM cname_allocation_targets WHERE node_group_scope_id <> tenant_scope_id) THEN
        RAISE EXCEPTION 'migration 287 down refused: CNAME targets froze platform node groups; restore from backup instead'
            USING ERRCODE='P2871';
    END IF;
    IF EXISTS (SELECT 1 FROM security_policy_publication_targets WHERE released_at IS NULL
        GROUP BY node_id HAVING count(*) > 1) THEN
        RAISE EXCEPTION 'migration 287 down refused: several open security publications share a node'
            USING ERRCODE='P2871';
    END IF;

    FOR target IN SELECT * FROM (VALUES
        ('cache_operation_nodes', 'cache_operation_nodes_scope_id_node_id_fkey', 'scope_id'),
        ('security_policy_publication_targets', 'security_policy_publication_target_tenant_scope_id_node_id_fkey', 'tenant_scope_id'),
        ('acme_http01_overlay_targets', 'acme_http01_overlay_targets_tenant_scope_id_node_id_fkey', 'tenant_scope_id'),
        ('firewall_command_outbox', 'firewall_command_outbox_tenant_scope_id_node_id_fkey', 'tenant_scope_id'),
        ('cc_coordination_setting_targets', 'cc_coordination_setting_targets_tenant_scope_id_node_id_fkey', 'tenant_scope_id'),
        ('cc_coordination_facts', 'cc_coordination_facts_tenant_scope_id_node_id_fkey', 'tenant_scope_id'),
        ('l4_node_drain_counters', 'l4_node_drain_counters_configuration_scope_id_node_id_fkey', 'configuration_scope_id'),
        ('l4_line_switch_drain_plans', 'l4_line_switch_drain_plans_configuration_scope_id_node_id_fkey', 'configuration_scope_id'),
        ('ja4_block_edge_receipt_queue_158', 'ja4_block_edge_receipt_queue_158_tenant_scope_id_node_id_fkey', 'tenant_scope_id')
    ) AS t(table_name, constraint_name, scope_column) LOOP
        EXECUTE format('DROP TRIGGER %I ON %I', target.table_name || '_carriage_287', target.table_name);
        EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', target.table_name, target.table_name || '_node_287_fkey');
        EXECUTE format('ALTER TABLE %I ADD CONSTRAINT %I FOREIGN KEY (%I, node_id) REFERENCES nodes(scope_id, id) ON DELETE RESTRICT',
            target.table_name, target.constraint_name, target.scope_column);
    END LOOP;
END;
$migration_287_down$;

DROP TRIGGER cname_allocation_targets_node_group_287 ON cname_allocation_targets;
DROP FUNCTION guard_cname_target_node_group_287();
ALTER TABLE cname_allocation_targets
    DROP CONSTRAINT cname_allocation_targets_node_group_287_fkey,
    DROP CONSTRAINT cname_allocation_targets_node_group_revision_287_fkey,
    ADD CONSTRAINT cname_allocation_targets_tenant_scope_id_node_group_id_fkey FOREIGN KEY (tenant_scope_id, node_group_id)
        REFERENCES node_line_groups(tenant_scope_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT cname_allocation_targets_tenant_scope_id_node_group_id_nod_fkey
        FOREIGN KEY (tenant_scope_id, node_group_id, node_group_revision)
        REFERENCES node_line_group_revisions(tenant_scope_id, line_group_id, revision) ON DELETE RESTRICT,
    DROP COLUMN node_group_scope_id;

DROP INDEX security_policy_publication_targets_open_node_tenant_287_idx;
CREATE UNIQUE INDEX security_policy_publication_targets_one_open_per_node_idx
    ON security_policy_publication_targets (node_id) WHERE released_at IS NULL;
DROP FUNCTION guard_tenant_node_carriage_287();
DROP FUNCTION tenant_carries_node_287(uuid, uuid);
