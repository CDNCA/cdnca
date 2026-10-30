LOCK TABLE schema_migrations, node_presence, node_config_state IN ACCESS EXCLUSIVE MODE;

DO $migration_290_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 289 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 289 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=289 AND
        migration_id='289_node_deployment_agent_queue' AND
        checksum_sha256='9d8ae1ddf95d2294fd325de2dde4a338bb651c6d157dcbc31500723abbff74b6' AND
        down_checksum_sha256='125c561a5978826554cbd621bfc83e500d8cb5fb86bb99d556f3f31512ec4f72' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.node_presence_scope_identities') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 290 requires the exact verified 289 release head' USING ERRCODE='P2900';
    END IF;
END;
$migration_290_up$;

-- A MULTI_TENANT_RUNTIME heartbeat reports one identity per configuration
-- scope (agent.v1 ScopedConfigIdentity). node_presence keeps the node-level
-- facts; with several scopes its legacy current/previous columns are empty.
-- Each heartbeat replaces the node's rows, so a scope the agent dropped
-- disappears. A row needs the scope's claim, so unclaiming removes it.
CREATE TABLE node_presence_scope_identities (
    node_id uuid NOT NULL REFERENCES node_presence (node_id) ON DELETE CASCADE,
    configuration_scope_id uuid NOT NULL,
    session_epoch bigint NOT NULL CHECK (session_epoch > 0),
    heartbeat_sequence bigint NOT NULL CHECK (heartbeat_sequence > 0),
    current_config_version_id uuid,
    current_config_identity_schema integer,
    current_config_artifact_sha256 bytea,
    previous_config_version_id uuid,
    previous_config_identity_schema integer,
    previous_config_artifact_sha256 bytea,
    last_apply_deployment_id uuid,
    last_apply_attempt integer,
    last_apply_config_version_id uuid,
    last_apply_state text,
    last_apply_finished_at timestamptz,
    last_apply_error_code text,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (node_id, configuration_scope_id),
    FOREIGN KEY (node_id, configuration_scope_id) REFERENCES node_config_state (node_id, configuration_scope_id)
        ON DELETE CASCADE,
    FOREIGN KEY (configuration_scope_id, current_config_version_id)
        REFERENCES config_versions (configuration_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (configuration_scope_id, previous_config_version_id)
        REFERENCES config_versions (configuration_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (last_apply_deployment_id, last_apply_attempt) REFERENCES node_deployments (id, attempt)
        ON DELETE CASCADE,
    CONSTRAINT node_presence_scope_identities_current_290_chk CHECK (
        (current_config_identity_schema IS NULL AND current_config_artifact_sha256 IS NULL) OR
        (current_config_identity_schema = 1 AND current_config_version_id IS NOT NULL AND
         octet_length(current_config_artifact_sha256) = 32)),
    CONSTRAINT node_presence_scope_identities_previous_290_chk CHECK (
        (previous_config_version_id IS NULL AND previous_config_identity_schema IS NULL AND
         previous_config_artifact_sha256 IS NULL) OR
        (current_config_version_id IS NOT NULL AND previous_config_version_id <> current_config_version_id AND
         (previous_config_identity_schema IS NULL AND previous_config_artifact_sha256 IS NULL OR
          previous_config_identity_schema = 1 AND octet_length(previous_config_artifact_sha256) = 32))),
    CONSTRAINT node_presence_scope_identities_apply_290_chk CHECK (
        (last_apply_deployment_id IS NULL AND last_apply_attempt IS NULL AND last_apply_config_version_id IS NULL AND
         last_apply_state IS NULL AND last_apply_finished_at IS NULL AND last_apply_error_code IS NULL) OR
        (last_apply_deployment_id IS NOT NULL AND last_apply_attempt > 0 AND last_apply_config_version_id IS NOT NULL AND
         last_apply_state IN ('healthy','failed','reverted','rollback_failed','superseded') AND
         (last_apply_state IN ('failed','rollback_failed')) = (last_apply_error_code IS NOT NULL) AND
         (last_apply_error_code IS NULL OR last_apply_error_code ~ '^[A-Z][A-Z0-9_]{0,127}$'))),
    -- Every reported scope carries a current version or the result of its
    -- first apply (agent.v1 ScopedConfigIdentity rule).
    CONSTRAINT node_presence_scope_identities_present_290_chk CHECK (
        current_config_version_id IS NOT NULL OR last_apply_deployment_id IS NOT NULL)
);

-- Reported identities must name an artifact this node was sent for the scope.
CREATE FUNCTION validate_node_presence_scope_identity_290() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.current_config_identity_schema IS NOT NULL AND NOT active_config_identity_artifact_valid_087(
        NEW.node_id, NEW.current_config_version_id, NEW.current_config_artifact_sha256) THEN
        RAISE EXCEPTION 'invalid scoped current active config identity' USING ERRCODE = 'P8702';
    END IF;
    IF NEW.previous_config_identity_schema IS NOT NULL AND NOT active_config_identity_artifact_valid_087(
        NEW.node_id, NEW.previous_config_version_id, NEW.previous_config_artifact_sha256) THEN
        RAISE EXCEPTION 'invalid scoped previous active config identity' USING ERRCODE = 'P8702';
    END IF;
    IF NEW.last_apply_deployment_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM node_deployments deployment
        WHERE deployment.id = NEW.last_apply_deployment_id AND deployment.attempt = NEW.last_apply_attempt
          AND deployment.node_id = NEW.node_id AND deployment.configuration_scope_id = NEW.configuration_scope_id
          AND deployment.config_version_id = NEW.last_apply_config_version_id) THEN
        RAISE EXCEPTION 'scoped apply result names another deployment' USING ERRCODE = 'P8702';
    END IF;
    RETURN NEW;
END;
$$;
DO $migration_290_search_path$
BEGIN
    EXECUTE format('ALTER FUNCTION validate_node_presence_scope_identity_290() SET search_path = pg_catalog, %I, pg_temp',
        current_schema());
END;
$migration_290_search_path$;
CREATE TRIGGER node_presence_scope_identities_validate_290 BEFORE INSERT OR UPDATE ON node_presence_scope_identities
    FOR EACH ROW EXECUTE FUNCTION validate_node_presence_scope_identity_290();

GRANT SELECT, INSERT, UPDATE, DELETE ON node_presence_scope_identities TO cdnca_control_app, cdnca_control_runtime;
