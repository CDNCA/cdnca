LOCK TABLE schema_migrations,
    node_presence,
    deployment_status_events,
    node_config_state
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 87 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 87 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state <> 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 87 AND migration_id = '087_active_config_identity_control'
          AND integrity_state = 'verified'
    ) THEN
        RAISE EXCEPTION 'migration 087 rollback requires the verified 087 head'
            USING ERRCODE = 'P8700';
    END IF;
    IF EXISTS (
        SELECT 1 FROM node_presence
        WHERE active_config_identity_api_version IS NOT NULL OR
              current_config_identity_schema IS NOT NULL OR current_config_artifact_sha256 IS NOT NULL OR
              previous_config_identity_schema IS NOT NULL OR previous_config_artifact_sha256 IS NOT NULL OR
              loaded_config_identity_schema IS NOT NULL OR loaded_config_artifact_sha256 IS NOT NULL OR EXISTS (
                SELECT 1 FROM jsonb_array_elements(active_deployments) deployment
                WHERE deployment ? 'observed_active_config_identity'
              )
    ) OR EXISTS (
        SELECT 1 FROM deployment_status_events
        WHERE active_config_identity_api_version IS NOT NULL OR active_config_identity_schema IS NOT NULL OR
              active_config_version_id IS NOT NULL OR active_config_artifact_sha256 IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM node_config_state
        WHERE current_config_identity_schema IS NOT NULL OR current_config_artifact_sha256 IS NOT NULL OR
              previous_config_identity_schema IS NOT NULL OR previous_config_artifact_sha256 IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 087 rollback would discard active config capability or identity facts'
            USING ERRCODE = 'P8701';
    END IF;
END;
$$;

DROP TRIGGER node_config_active_identity_validate_087 ON node_config_state;
DROP FUNCTION validate_node_config_active_identity_087();
DROP TRIGGER deployment_status_active_identity_validate_087 ON deployment_status_events;
DROP FUNCTION validate_deployment_status_active_identity_087();
DROP TRIGGER node_presence_active_identity_validate_087 ON node_presence;
DROP FUNCTION validate_node_presence_active_identity_087();
DROP FUNCTION active_config_identity_artifact_valid_087(uuid, uuid, bytea, uuid, integer, text);

ALTER TABLE node_config_state
    DROP CONSTRAINT node_config_previous_identity_087_chk,
    DROP CONSTRAINT node_config_current_identity_087_chk,
    DROP COLUMN previous_config_artifact_sha256,
    DROP COLUMN previous_config_identity_schema,
    DROP COLUMN current_config_artifact_sha256,
    DROP COLUMN current_config_identity_schema;

ALTER TABLE deployment_status_events
    DROP CONSTRAINT deployment_status_active_identity_087_chk,
    DROP CONSTRAINT deployment_status_active_identity_api_087_chk,
    DROP COLUMN active_config_artifact_sha256,
    DROP COLUMN active_config_version_id,
    DROP COLUMN active_config_identity_schema,
    DROP COLUMN active_config_identity_api_version;

ALTER TABLE node_presence
    DROP CONSTRAINT node_presence_loaded_identity_087_chk,
    DROP CONSTRAINT node_presence_previous_identity_087_chk,
    DROP CONSTRAINT node_presence_current_identity_087_chk,
    DROP CONSTRAINT node_presence_active_identity_api_087_chk,
    DROP COLUMN loaded_config_artifact_sha256,
    DROP COLUMN loaded_config_identity_schema,
    DROP COLUMN previous_config_artifact_sha256,
    DROP COLUMN previous_config_identity_schema,
    DROP COLUMN current_config_artifact_sha256,
    DROP COLUMN current_config_identity_schema,
    DROP COLUMN active_config_identity_api_version;
