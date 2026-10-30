LOCK TABLE schema_migrations, rollouts, node_config_state, node_deployments, node_isolation_states
    IN ACCESS EXCLUSIVE MODE;

DO $migration_288_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 288 OR
       (SELECT max(version) FROM schema_migrations) <> 288 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=288 AND
        migration_id='288_node_scope_config_state' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 288 down requires the exact verified migration head' USING ERRCODE='P2881';
    END IF;
    -- The 287 schema keeps one configuration state and one running
    -- deployment per node; refuse rather than drop a tenant's state.
    IF to_regclass(current_schema() || '.node_config_state_single_scope_288_idx') IS NULL OR
       to_regclass(current_schema() || '.node_deployments_one_active_per_node_idx') IS NULL OR
       EXISTS (SELECT 1 FROM node_config_state GROUP BY node_id HAVING count(*) > 1) OR
       -- 287 isolation binds the node's current configuration identity.
       EXISTS (SELECT 1 FROM node_isolation_states isolation
           LEFT JOIN node_config_state config ON config.node_id = isolation.node_id
           WHERE ROW(config.configuration_scope_id, config.current_config_version_id,
                     config.current_config_identity_schema, config.current_config_artifact_sha256)
                 IS DISTINCT FROM ROW(isolation.scope_id, isolation.desired_config_version_id,
                     isolation.desired_identity_schema, isolation.desired_artifact_sha256)) THEN
        RAISE EXCEPTION 'migration 288 down cannot fold several configuration scopes onto one node'
            USING ERRCODE='P2881';
    END IF;
END;
$migration_288_down$;

CREATE OR REPLACE FUNCTION protect_node_isolation_state_182()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_scope_id uuid;
    current_config_version_id uuid;
    current_identity_schema integer;
    current_artifact_sha256 bytea;
BEGIN
    SELECT configuration_scope_id,current_config_version_id,current_config_identity_schema,
           current_config_artifact_sha256
    INTO current_scope_id,current_config_version_id,current_identity_schema,current_artifact_sha256
    FROM node_config_state WHERE node_id=NEW.node_id;
    IF current_scope_id IS DISTINCT FROM NEW.scope_id OR
       current_config_version_id IS DISTINCT FROM NEW.desired_config_version_id OR
       current_identity_schema IS DISTINCT FROM NEW.desired_identity_schema OR
       current_artifact_sha256 IS DISTINCT FROM NEW.desired_artifact_sha256 THEN
        RAISE EXCEPTION 'node isolation state must bind the current node configuration identity';
    END IF;
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
ALTER TABLE node_isolation_states DROP CONSTRAINT node_isolation_states_desired_config_288_fkey;
ALTER TABLE node_isolation_states ADD CONSTRAINT node_isolation_states_scope_id_desired_config_version_id_fkey
    FOREIGN KEY (scope_id, desired_config_version_id) REFERENCES config_versions (configuration_scope_id, id)
    ON DELETE RESTRICT;

DROP INDEX node_deployments_one_active_per_node_scope_288_idx;
DROP TRIGGER a_node_deployments_scope_288 ON node_deployments;
DROP FUNCTION bind_node_deployment_scope_288();
ALTER TABLE node_deployments DROP CONSTRAINT node_deployments_rollout_scope_288_fkey;
ALTER TABLE node_deployments DROP COLUMN configuration_scope_id;

DROP INDEX node_config_state_single_scope_288_idx;
ALTER TABLE node_config_state DROP CONSTRAINT node_config_state_node_scope_288_pkey;
ALTER TABLE node_config_state ADD CONSTRAINT node_config_state_pkey PRIMARY KEY (node_id);
ALTER TABLE node_config_state ALTER COLUMN configuration_scope_id DROP NOT NULL;
