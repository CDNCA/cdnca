LOCK TABLE schema_migrations, nodes, cache_operation_nodes, security_policy_publication_targets,
    acme_http01_overlay_targets, firewall_command_outbox, cc_coordination_setting_targets,
    cc_coordination_facts, l4_node_drain_counters, l4_line_switch_drain_plans,
    ja4_block_edge_receipt_queue_158, cname_allocation_targets IN ACCESS EXCLUSIVE MODE;

DO $migration_287_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 286 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 286 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=286 AND
        migration_id='286_cname_market_target' AND
        checksum_sha256='29a9ca3e22c23af8882814dc320d6dedd702a1e30191eba0afafd7374e2a51a8' AND
        down_checksum_sha256='2855a70ddbfd1b807f925a2c54d446078344aeff88c3345b38782d7d454e1b23' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.node_line_endpoint_serving') IS NULL
         OR to_regprocedure(current_schema() || '.tenant_carries_node_287(uuid,uuid)') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 287 requires the exact verified 286 release head' USING ERRCODE='P2870';
    END IF;
END;
$migration_287_up$;

-- Nodes live in the platform scope while every user has a tenant scope
-- (docs/architecture/multi-tenant-node-sharing.md). A tenant may place its
-- resources (certificates, cache operations, security publications, ...) on
-- a node it owns, on a platform node it has a configuration on, or on a
-- platform node serving a node group one of its active sites uses. The node
-- group is the site's own or its package's (primary or backup), which tenants
-- cannot set themselves. Phase 1 (per-scope node configuration) only changes
-- the second branch, so callers depend on this function alone.
CREATE FUNCTION tenant_carries_node_287(checked_tenant_scope_id uuid, checked_node_id uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1 FROM nodes node
        WHERE node.id = checked_node_id AND node.admin_state <> 'retired' AND (
            node.scope_id = checked_tenant_scope_id OR (
                EXISTS (SELECT 1 FROM access_scopes scope WHERE scope.id = node.scope_id AND scope.kind = 'platform')
                AND (
                    EXISTS (SELECT 1 FROM node_config_state state
                        WHERE state.node_id = node.id AND state.configuration_scope_id = checked_tenant_scope_id)
                    OR EXISTS (
                        SELECT 1 FROM sites site
                        LEFT JOIN package_subscriptions subscription
                          ON subscription.tenant_scope_id = site.scope_id AND subscription.id = site.package_subscription_id
                         AND subscription.deleted_at IS NULL
                        JOIN node_line_groups line_group ON line_group.deleted_at IS NULL
                         AND line_group.tenant_scope_id IN (node.scope_id, site.scope_id)
                         AND line_group.id IN (
                             site.node_group_id,
                             (subscription.product_snapshot->'spec'->>'node_group_id')::uuid,
                             (subscription.product_snapshot->'spec'->>'backup_node_group_id')::uuid)
                        JOIN node_line_endpoint_serving endpoint
                          ON endpoint.tenant_scope_id = line_group.tenant_scope_id
                         AND endpoint.line_group_id = line_group.id
                         AND endpoint.config_revision = line_group.current_revision
                         AND endpoint.node_id = node.id
                        WHERE site.scope_id = checked_tenant_scope_id AND site.deleted_at IS NULL
                    )
                )
            )
        )
    )
$$;

-- Insert-time guard: the node foreign keys below no longer pin the node to
-- the row's tenant scope, so the carriage rule is enforced here instead.
CREATE FUNCTION guard_tenant_node_carriage_287() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    row_value jsonb := to_jsonb(NEW);
    checked_scope uuid := (row_value ->> TG_ARGV[0])::uuid;
    checked_node uuid := (row_value ->> TG_ARGV[1])::uuid;
BEGIN
    IF NOT tenant_carries_node_287(checked_scope, checked_node) THEN
        RAISE EXCEPTION 'node % is not carried by scope % (%)', checked_node, checked_scope, TG_TABLE_NAME
            USING ERRCODE = '23503', CONSTRAINT = 'tenant_node_carriage_287';
    END IF;
    RETURN NEW;
END;
$$;

-- Both functions read application tables: pin the path like 273 does.
DO $migration_287_path$
BEGIN
    EXECUTE format('ALTER FUNCTION %I.tenant_carries_node_287(uuid, uuid) SET search_path = pg_catalog, %I, pg_temp',
        current_schema(), current_schema());
    EXECUTE format('ALTER FUNCTION %I.guard_tenant_node_carriage_287() SET search_path = pg_catalog, %I, pg_temp',
        current_schema(), current_schema());
END;
$migration_287_path$;
GRANT EXECUTE ON FUNCTION tenant_carries_node_287(uuid, uuid) TO cdnca_control_app, cdnca_control_runtime;

DO $migration_287_rebind$
DECLARE
    target record;
BEGIN
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
        IF NOT EXISTS (SELECT 1 FROM pg_constraint
            WHERE conrelid = to_regclass(current_schema() || '.' || target.table_name)
              AND conname = target.constraint_name AND confrelid = to_regclass(current_schema() || '.nodes')) THEN
            RAISE EXCEPTION 'migration 287: % lacks %', target.table_name, target.constraint_name USING ERRCODE='P2870';
        END IF;
        EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', target.table_name, target.constraint_name);
        EXECUTE format('ALTER TABLE %I ADD CONSTRAINT %I FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE RESTRICT',
            target.table_name, target.table_name || '_node_287_fkey');
        EXECUTE format('CREATE TRIGGER %I BEFORE INSERT ON %I FOR EACH ROW EXECUTE FUNCTION guard_tenant_node_carriage_287(%L, %L)',
            target.table_name || '_carriage_287', target.table_name, target.scope_column, 'node_id');
    END LOOP;
END;
$migration_287_rebind$;

-- Different tenants on one platform node must not queue behind each other:
-- one open security publication per node and tenant.
DROP INDEX security_policy_publication_targets_one_open_per_node_idx;
CREATE UNIQUE INDEX security_policy_publication_targets_open_node_tenant_287_idx
    ON security_policy_publication_targets (node_id, tenant_scope_id) WHERE released_at IS NULL;

-- A tenant site may use a platform node group (the package's or a market
-- pool). The frozen CNAME target records whose group it froze; existing rows
-- froze their own tenant's group. The column is as durable as the rest.
ALTER TABLE cname_allocation_targets ADD COLUMN node_group_scope_id uuid;
ALTER TABLE cname_allocation_targets DISABLE TRIGGER cname_allocation_targets_protect_126;
UPDATE cname_allocation_targets SET node_group_scope_id = tenant_scope_id;
ALTER TABLE cname_allocation_targets ENABLE TRIGGER cname_allocation_targets_protect_126;
ALTER TABLE cname_allocation_targets
    ALTER COLUMN node_group_scope_id SET NOT NULL,
    DROP CONSTRAINT cname_allocation_targets_tenant_scope_id_node_group_id_fkey,
    DROP CONSTRAINT cname_allocation_targets_tenant_scope_id_node_group_id_nod_fkey,
    ADD CONSTRAINT cname_allocation_targets_node_group_287_fkey FOREIGN KEY (node_group_scope_id, node_group_id)
        REFERENCES node_line_groups(tenant_scope_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT cname_allocation_targets_node_group_revision_287_fkey
        FOREIGN KEY (node_group_scope_id, node_group_id, node_group_revision)
        REFERENCES node_line_group_revisions(tenant_scope_id, line_group_id, revision) ON DELETE RESTRICT;

CREATE FUNCTION guard_cname_target_node_group_287() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.node_group_scope_id <> NEW.tenant_scope_id AND NOT EXISTS (
        SELECT 1 FROM access_scopes WHERE id = NEW.node_group_scope_id AND kind = 'platform') THEN
        RAISE EXCEPTION 'CNAME target node group must belong to the tenant or the platform'
            USING ERRCODE = '23503', CONSTRAINT = 'cname_allocation_targets_node_group_scope_287';
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.node_group_scope_id IS DISTINCT FROM OLD.node_group_scope_id THEN
        RAISE EXCEPTION 'CNAME target facts are durable' USING ERRCODE = 'P1261';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER cname_allocation_targets_node_group_287
BEFORE INSERT OR UPDATE ON cname_allocation_targets
FOR EACH ROW EXECUTE FUNCTION guard_cname_target_node_group_287();
DO $migration_287_cname_path$
BEGIN
    EXECUTE format('ALTER FUNCTION %I.guard_cname_target_node_group_287() SET search_path = pg_catalog, %I, pg_temp',
        current_schema(), current_schema());
END;
$migration_287_cname_path$;
