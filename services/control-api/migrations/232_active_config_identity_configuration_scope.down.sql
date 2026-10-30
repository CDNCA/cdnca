LOCK TABLE schema_migrations, nodes, node_config_state, config_versions,
    configuration_artifacts, rollouts, node_deployments, node_deployment_artifacts,
    node_presence, deployment_status_events
IN ACCESS EXCLUSIVE MODE;

DO $migration_232_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 232 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 232 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 232 AND migration_id = '232_active_config_identity_configuration_scope' AND
              checksum_sha256 = 'a034c7c7036d2af6be7fd99094d0ea938170339e0dc937db54a1c333973bfa0a' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 232 rollback requires the exact verified 232 head'
            USING ERRCODE = 'P2321';
    END IF;
END;
$migration_232_down$;

CREATE OR REPLACE FUNCTION active_config_identity_artifact_valid_087(
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
