LOCK TABLE schema_migrations, rollouts, node_config_state, node_deployments, node_isolation_states
    IN ACCESS EXCLUSIVE MODE;

DO $migration_288_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 287 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 287 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=287 AND
        migration_id='287_tenant_node_carriage' AND
        checksum_sha256='92f74575dc1f67555becf5b46e120c9e40c994f244fceee147b41ee071f00440' AND
        down_checksum_sha256='e250ee0e790beaa7c3fb1253dff4d2470a341e4d15332b4378e0ba170056f2fd' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure(current_schema() || '.bind_node_deployment_scope_288()') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 288 requires the exact verified 287 release head' USING ERRCODE='P2880';
    END IF;
    -- A row without a scope is an unclaimed placeholder. It can hold no
    -- version and no reconciliation, so dropping it loses nothing.
    IF EXISTS (SELECT 1 FROM node_config_state WHERE configuration_scope_id IS NULL AND (
        current_config_version_id IS NOT NULL OR previous_config_version_id IS NOT NULL OR
        reconciliation_required)) THEN
        RAISE EXCEPTION 'migration 288 found an unscoped node configuration with state' USING ERRCODE='P2880';
    END IF;
END;
$migration_288_up$;

-- Multi-tenant phase 1 (docs/architecture/multi-tenant-node-sharing.md 6.2):
-- a node keeps one configuration state per configuration scope. A node is
-- claimed by inserting its (node, scope) row; there is no unscoped row.
DELETE FROM node_config_state WHERE configuration_scope_id IS NULL;
ALTER TABLE node_config_state ALTER COLUMN configuration_scope_id SET NOT NULL;
ALTER TABLE node_config_state DROP CONSTRAINT node_config_state_pkey;
ALTER TABLE node_config_state ADD CONSTRAINT node_config_state_node_scope_288_pkey
    PRIMARY KEY (node_id, configuration_scope_id);
-- Until nodes declare MULTI_TENANT_RUNTIME, a node still serves one scope.
-- Dropping this index is what lets a second tenant onto the node.
CREATE UNIQUE INDEX node_config_state_single_scope_288_idx ON node_config_state (node_id);

-- Every deployment belongs to its rollout's configuration scope.
ALTER TABLE node_deployments ADD COLUMN configuration_scope_id uuid;
UPDATE node_deployments deployment SET configuration_scope_id = rollout.configuration_scope_id
FROM rollouts rollout WHERE rollout.id = deployment.rollout_id;
ALTER TABLE node_deployments ALTER COLUMN configuration_scope_id SET NOT NULL;
ALTER TABLE node_deployments ADD CONSTRAINT node_deployments_rollout_scope_288_fkey
    FOREIGN KEY (configuration_scope_id, rollout_id) REFERENCES rollouts (configuration_scope_id, id)
    ON DELETE RESTRICT;

-- Writers name only the rollout; the scope follows it and never changes.
CREATE FUNCTION bind_node_deployment_scope_288() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.configuration_scope_id IS DISTINCT FROM OLD.configuration_scope_id THEN
            RAISE EXCEPTION 'node deployment configuration scope is immutable'
                USING ERRCODE = '23514', CONSTRAINT = 'node_deployments_scope_288';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.configuration_scope_id IS NULL THEN
        SELECT configuration_scope_id INTO NEW.configuration_scope_id FROM rollouts WHERE id = NEW.rollout_id;
    END IF;
    RETURN NEW;
END;
$$;
DO $migration_288_search_path$
BEGIN
    EXECUTE format('ALTER FUNCTION bind_node_deployment_scope_288() SET search_path = pg_catalog, %I, pg_temp',
        current_schema());
END;
$migration_288_search_path$;
-- "a_" sorts first among the BEFORE triggers, so the reconciliation gate
-- and attempt checks already see the scope.
CREATE TRIGGER a_node_deployments_scope_288 BEFORE INSERT OR UPDATE OF configuration_scope_id
    ON node_deployments FOR EACH ROW EXECUTE FUNCTION bind_node_deployment_scope_288();

-- One running deployment per (node, scope). The per-node index stays until
-- MULTI_TENANT_RUNTIME nodes can take commands for several scopes.
CREATE UNIQUE INDEX node_deployments_one_active_per_node_scope_288_idx
    ON node_deployments (node_id, configuration_scope_id)
    WHERE state <> ALL (ARRAY['healthy','failed','reverted','rollback_failed','cancelled']);

-- Isolation stops a node serving at all, so it belongs to the node and its
-- owner scope (node_isolation_states_scope_id_node_id_fkey), not to one
-- tenant's configuration: a platform node claimed by a tenant has no single
-- current identity to bind. The desired identity stays the agent's report.
ALTER TABLE node_isolation_states DROP CONSTRAINT node_isolation_states_scope_id_desired_config_version_id_fkey;
ALTER TABLE node_isolation_states ADD CONSTRAINT node_isolation_states_desired_config_288_fkey
    FOREIGN KEY (desired_config_version_id) REFERENCES config_versions (id) ON DELETE RESTRICT;
CREATE OR REPLACE FUNCTION protect_node_isolation_state_182()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP='UPDATE' AND (
       ROW(NEW.scope_id,NEW.node_id) IS DISTINCT FROM ROW(OLD.scope_id,OLD.node_id) OR
       NEW.revision<>OLD.revision+1 OR NEW.updated_at<OLD.updated_at OR
       NEW.last_session_epoch<OLD.last_session_epoch OR
       NEW.last_session_epoch=OLD.last_session_epoch AND NEW.last_health_sequence<OLD.last_health_sequence
    ) THEN
        RAISE EXCEPTION 'node isolation state identity, revision, time, and health evidence are monotonic';
    END IF;
    RETURN NEW;
END;
$$;
