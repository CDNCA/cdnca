LOCK TABLE schema_migrations,
    node_presence,
    deployment_status_events,
    node_config_state
IN ACCESS EXCLUSIVE MODE;

LOCK TABLE nodes,
    config_versions,
    configuration_artifacts,
    node_deployments,
    node_deployment_artifacts
IN SHARE ROW EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 86 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 86 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state <> 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 86
          AND migration_id = '086_site_l4_automatic_publication'
          AND checksum_sha256 = '35ba7924b2b90a0efbd4c8d2fc3082c2be040595f4f7daa0874b54fb57dcf207'
          AND down_checksum_sha256 = '0f5e8eaaf08e8a05912d60b69a74cd46e9ed75057546827c26e853c827e15b0c'
          AND integrity_state = 'verified'
    ) THEN
        RAISE EXCEPTION 'migration 087 requires the exact verified 086 release head'
            USING ERRCODE = 'P8700';
    END IF;
END;
$$;

ALTER TABLE node_presence
    ADD COLUMN active_config_identity_api_version integer,
    ADD COLUMN current_config_identity_schema integer,
    ADD COLUMN current_config_artifact_sha256 bytea,
    ADD COLUMN previous_config_identity_schema integer,
    ADD COLUMN previous_config_artifact_sha256 bytea,
    ADD COLUMN loaded_config_identity_schema integer,
    ADD COLUMN loaded_config_artifact_sha256 bytea,
    ADD CONSTRAINT node_presence_active_identity_api_087_chk CHECK (
        active_config_identity_api_version IS NULL OR active_config_identity_api_version = 1
    ),
    ADD CONSTRAINT node_presence_current_identity_087_chk CHECK (
        (current_config_identity_schema IS NULL AND current_config_artifact_sha256 IS NULL) OR
        (current_config_identity_schema = 1 AND current_config_version_id IS NOT NULL AND
         octet_length(current_config_artifact_sha256) = 32 AND active_config_identity_api_version = 1)
    ),
    ADD CONSTRAINT node_presence_previous_identity_087_chk CHECK (
        (previous_config_identity_schema IS NULL AND previous_config_artifact_sha256 IS NULL) OR
        (previous_config_identity_schema = 1 AND previous_config_version_id IS NOT NULL AND
         octet_length(previous_config_artifact_sha256) = 32 AND active_config_identity_api_version = 1)
    ),
    ADD CONSTRAINT node_presence_loaded_identity_087_chk CHECK (
        (loaded_config_identity_schema IS NULL AND loaded_config_artifact_sha256 IS NULL) OR
        (loaded_config_identity_schema = 1 AND loaded_config_version_id IS NOT NULL AND
         octet_length(loaded_config_artifact_sha256) = 32 AND active_config_identity_api_version = 1)
    );

ALTER TABLE deployment_status_events
    ADD COLUMN active_config_identity_api_version integer,
    ADD COLUMN active_config_identity_schema integer,
    ADD COLUMN active_config_version_id uuid,
    ADD COLUMN active_config_artifact_sha256 bytea,
    ADD CONSTRAINT deployment_status_active_identity_api_087_chk CHECK (
        active_config_identity_api_version IS NULL OR active_config_identity_api_version = 1
    ),
    ADD CONSTRAINT deployment_status_active_identity_087_chk CHECK (
        (active_config_identity_schema IS NULL AND active_config_version_id IS NULL AND
         active_config_artifact_sha256 IS NULL) OR
        (active_config_identity_schema = 1 AND active_config_version_id IS NOT NULL AND
         octet_length(active_config_artifact_sha256) = 32 AND active_config_identity_api_version = 1)
    );

ALTER TABLE node_config_state
    ADD COLUMN current_config_identity_schema integer,
    ADD COLUMN current_config_artifact_sha256 bytea,
    ADD COLUMN previous_config_identity_schema integer,
    ADD COLUMN previous_config_artifact_sha256 bytea,
    ADD CONSTRAINT node_config_current_identity_087_chk CHECK (
        (current_config_identity_schema IS NULL AND current_config_artifact_sha256 IS NULL) OR
        (current_config_identity_schema = 1 AND current_config_version_id IS NOT NULL AND
         octet_length(current_config_artifact_sha256) = 32)
    ),
    ADD CONSTRAINT node_config_previous_identity_087_chk CHECK (
        (previous_config_identity_schema IS NULL AND previous_config_artifact_sha256 IS NULL) OR
        (previous_config_identity_schema = 1 AND previous_config_version_id IS NOT NULL AND
         octet_length(previous_config_artifact_sha256) = 32)
    );

CREATE FUNCTION active_config_identity_artifact_valid_087(
    checked_node_id uuid,
    checked_config_version_id uuid,
    checked_artifact_sha256 bytea,
    checked_deployment_id uuid DEFAULT NULL,
    checked_attempt integer DEFAULT NULL,
    checked_state text DEFAULT NULL
)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT checked_node_id IS NOT NULL AND checked_config_version_id IS NOT NULL AND
           octet_length(checked_artifact_sha256) = 32 AND EXISTS (
        SELECT 1
        FROM nodes node
        JOIN config_versions version
          ON version.configuration_scope_id = node.scope_id
         AND version.id = checked_config_version_id
        JOIN configuration_artifacts artifact
          ON artifact.config_version_id = version.id
         AND artifact.kind = 'configuration'
         AND artifact.sha256 = checked_artifact_sha256
         AND artifact.sha256 = sha256(artifact.wire_bytes)
        WHERE node.id = checked_node_id AND (
            (checked_deployment_id IS NULL AND checked_attempt IS NULL AND checked_state IS NULL) OR
            (checked_deployment_id IS NOT NULL AND checked_attempt > 0 AND
             checked_state IN ('healthy', 'reverted') AND EXISTS (
                SELECT 1
                FROM node_deployments deployment
                WHERE deployment.id = checked_deployment_id
                  AND deployment.attempt = checked_attempt
                  AND deployment.node_id = checked_node_id
                  AND deployment.config_version_id = checked_config_version_id
                  AND deployment.command_sha256 = sha256(deployment.command_bytes)
                  AND ((deployment.action = 'apply' AND checked_state = 'healthy' AND EXISTS (
                          SELECT 1 FROM node_deployment_artifacts binding
                          WHERE binding.deployment_id = deployment.id
                            AND binding.deployment_attempt = deployment.attempt
                            AND binding.config_version_id = artifact.config_version_id
                            AND binding.artifact_id = artifact.id
                      )) OR (deployment.action = 'rollback' AND checked_state = 'reverted'))
            ))
        )
    )
$$;

CREATE FUNCTION validate_node_presence_active_identity_087()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    deployment jsonb;
    identity jsonb;
    identity_config_id uuid;
    identity_deployment_id uuid;
    identity_attempt integer;
BEGIN
    IF NEW.active_config_identity_api_version IS NOT NULL AND NEW.active_config_identity_api_version <> 1 THEN
        RAISE EXCEPTION 'invalid active config identity capability' USING ERRCODE = 'P8702';
    END IF;
    IF (NEW.current_config_identity_schema IS NULL) <> (NEW.current_config_artifact_sha256 IS NULL) OR
       (NEW.previous_config_identity_schema IS NULL) <> (NEW.previous_config_artifact_sha256 IS NULL) OR
       (NEW.loaded_config_identity_schema IS NULL) <> (NEW.loaded_config_artifact_sha256 IS NULL) THEN
        RAISE EXCEPTION 'incomplete active config identity tuple' USING ERRCODE = 'P8702';
    END IF;
    IF NEW.current_config_identity_schema IS NOT NULL AND
       (NEW.current_config_identity_schema <> 1 OR NEW.active_config_identity_api_version <> 1 OR
        NOT active_config_identity_artifact_valid_087(NEW.node_id, NEW.current_config_version_id,
            NEW.current_config_artifact_sha256)) THEN
        RAISE EXCEPTION 'invalid current active config identity' USING ERRCODE = 'P8702';
    END IF;
    IF NEW.previous_config_identity_schema IS NOT NULL AND
       (NEW.previous_config_identity_schema <> 1 OR NEW.active_config_identity_api_version <> 1 OR
        NOT active_config_identity_artifact_valid_087(NEW.node_id, NEW.previous_config_version_id,
            NEW.previous_config_artifact_sha256)) THEN
        RAISE EXCEPTION 'invalid previous active config identity' USING ERRCODE = 'P8702';
    END IF;
    IF NEW.loaded_config_identity_schema IS NOT NULL AND
       (NEW.loaded_config_identity_schema <> 1 OR NEW.active_config_identity_api_version <> 1 OR
        NOT active_config_identity_artifact_valid_087(NEW.node_id, NEW.loaded_config_version_id,
            NEW.loaded_config_artifact_sha256)) THEN
        RAISE EXCEPTION 'invalid loaded active config identity' USING ERRCODE = 'P8702';
    END IF;
    FOR deployment IN SELECT value FROM jsonb_array_elements(NEW.active_deployments)
    LOOP
        IF deployment ? 'observed_active_config_identity' THEN
            identity := deployment->'observed_active_config_identity';
            BEGIN
                -- Non-nil lowercase RFC 4122/9562 canonical UUID, versions 1 through 8.
                IF jsonb_typeof(identity) IS DISTINCT FROM 'object' OR
                   (SELECT count(*) FROM jsonb_object_keys(identity)) <> 3 OR
                   jsonb_typeof(identity->'schema') IS DISTINCT FROM 'number' OR
                   identity->>'schema' IS DISTINCT FROM '1' OR
                   jsonb_typeof(identity->'config_version_id') IS DISTINCT FROM 'string' OR
                   jsonb_typeof(identity->'artifact_sha256') IS DISTINCT FROM 'string' OR
                   coalesce(identity->>'config_version_id', '') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' OR
                   coalesce(identity->>'artifact_sha256', '') !~ '^[0-9a-f]{64}$' OR
                   jsonb_typeof(deployment->'deployment_id') IS DISTINCT FROM 'string' OR
                   coalesce(deployment->>'deployment_id', '') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' OR
                   jsonb_typeof(deployment->'attempt') IS DISTINCT FROM 'number' OR
                   coalesce(deployment->>'attempt', '') !~ '^[1-9][0-9]*$' OR
                   jsonb_typeof(deployment->'config_version_id') IS DISTINCT FROM 'string' OR
                   coalesce(deployment->>'config_version_id', '') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' OR
                   jsonb_typeof(deployment->'state') IS DISTINCT FROM 'string' OR
                   coalesce(deployment->>'state', '') NOT IN ('healthy', 'reverted') THEN
                    RAISE EXCEPTION 'invalid observed active config identity';
                END IF;
                identity_config_id := (identity->>'config_version_id')::uuid;
                identity_deployment_id := (deployment->>'deployment_id')::uuid;
                identity_attempt := (deployment->>'attempt')::integer;
            EXCEPTION WHEN OTHERS THEN
                RAISE EXCEPTION 'invalid observed active config identity encoding' USING ERRCODE = 'P8702';
            END;
            IF NEW.active_config_identity_api_version <> 1 OR identity_attempt <= 0 OR
               deployment->>'config_version_id' IS DISTINCT FROM identity_config_id::text OR
               NOT active_config_identity_artifact_valid_087(NEW.node_id, identity_config_id,
                   decode(identity->>'artifact_sha256', 'hex'), identity_deployment_id, identity_attempt,
                   deployment->>'state') THEN
                RAISE EXCEPTION 'unbound observed active config identity' USING ERRCODE = 'P8702';
            END IF;
        END IF;
    END LOOP;
    RETURN NEW;
END;
$$;

CREATE TRIGGER node_presence_active_identity_validate_087
BEFORE INSERT OR UPDATE ON node_presence
FOR EACH ROW EXECUTE FUNCTION validate_node_presence_active_identity_087();

CREATE FUNCTION validate_deployment_status_active_identity_087()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    deployment_node_id uuid;
    deployment_config_id uuid;
    deployment_action text;
BEGIN
    SELECT node_id, config_version_id, action
      INTO deployment_node_id, deployment_config_id, deployment_action
    FROM node_deployments
    WHERE id = NEW.deployment_id AND attempt = NEW.attempt;
    IF deployment_node_id IS NULL OR NEW.active_config_identity_api_version NOT IN (1) AND
       NEW.active_config_identity_api_version IS NOT NULL OR
       (NEW.active_config_identity_schema IS NULL) <> (NEW.active_config_version_id IS NULL) OR
       (NEW.active_config_identity_schema IS NULL) <> (NEW.active_config_artifact_sha256 IS NULL) THEN
        RAISE EXCEPTION 'invalid deployment status active identity tuple' USING ERRCODE = 'P8702';
    END IF;
    IF deployment_action = 'apply' AND NEW.state = 'healthy' AND
       NEW.active_config_identity_api_version = 1 AND NEW.active_config_identity_schema IS NULL THEN
        RAISE EXCEPTION 'v1 healthy status requires active identity' USING ERRCODE = 'P8702';
    END IF;
    IF NEW.active_config_identity_schema IS NOT NULL AND (
       NEW.active_config_identity_schema <> 1 OR NEW.active_config_identity_api_version <> 1 OR
       NOT (deployment_action = 'apply' AND NEW.state = 'healthy' OR
            deployment_action = 'rollback' AND NEW.state = 'reverted') OR
       NEW.active_config_version_id <> deployment_config_id OR
       NOT active_config_identity_artifact_valid_087(deployment_node_id, NEW.active_config_version_id,
           NEW.active_config_artifact_sha256, NEW.deployment_id, NEW.attempt, NEW.state)) THEN
        RAISE EXCEPTION 'unbound deployment status active identity' USING ERRCODE = 'P8702';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER deployment_status_active_identity_validate_087
BEFORE INSERT ON deployment_status_events
FOR EACH ROW EXECUTE FUNCTION validate_deployment_status_active_identity_087();

CREATE FUNCTION validate_node_config_active_identity_087()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF (NEW.current_config_identity_schema IS NULL) <> (NEW.current_config_artifact_sha256 IS NULL) OR
       (NEW.previous_config_identity_schema IS NULL) <> (NEW.previous_config_artifact_sha256 IS NULL) OR
       (NEW.current_config_identity_schema IS NOT NULL AND
        (NEW.current_config_identity_schema <> 1 OR NOT active_config_identity_artifact_valid_087(
            NEW.node_id, NEW.current_config_version_id, NEW.current_config_artifact_sha256))) OR
       (NEW.previous_config_identity_schema IS NOT NULL AND
        (NEW.previous_config_identity_schema <> 1 OR NOT active_config_identity_artifact_valid_087(
            NEW.node_id, NEW.previous_config_version_id, NEW.previous_config_artifact_sha256))) THEN
        RAISE EXCEPTION 'invalid node config active identity' USING ERRCODE = 'P8702';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER node_config_active_identity_validate_087
BEFORE INSERT OR UPDATE ON node_config_state
FOR EACH ROW EXECUTE FUNCTION validate_node_config_active_identity_087();
