-- 687 回滚：身份校验函数的无部署分支恢复为只认 activated/healthy（232 版）。
-- 已写入、来源为 rollback_failed apply 的身份行保留；回滚后同样的上报会再次被 P8702 拒绝。
LOCK TABLE schema_migrations, node_config_state, config_versions, configuration_artifacts, rollouts,
    node_deployments, node_deployment_artifacts, node_presence, node_presence_scope_identities
IN ACCESS EXCLUSIVE MODE;

DO $migration_687_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 687 OR
       (SELECT max(version) FROM schema_migrations) <> 687 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=687 AND
        migration_id='687_active_config_identity_rollback_failed_serving' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 687 down requires the exact verified migration head' USING ERRCODE='P6871';
    END IF;
END;
$migration_687_down$;

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
        FROM node_config_state config_state
        JOIN config_versions version
          ON version.configuration_scope_id = config_state.configuration_scope_id
         AND version.id = checked_config_version_id
        JOIN configuration_artifacts artifact
          ON artifact.config_version_id = version.id
         AND artifact.kind = 'configuration'
         AND artifact.sha256 = checked_artifact_sha256
         AND artifact.sha256 = sha256(artifact.wire_bytes)
        WHERE config_state.node_id = checked_node_id AND
              config_state.configuration_scope_id IS NOT NULL AND (
            (checked_deployment_id IS NULL AND checked_attempt IS NULL AND checked_state IS NULL AND EXISTS (
                SELECT 1
                FROM node_deployments deployment
                JOIN rollouts rollout
                  ON rollout.id = deployment.rollout_id
                 AND rollout.config_version_id = deployment.config_version_id
                 AND rollout.configuration_scope_id = config_state.configuration_scope_id
                JOIN node_deployment_artifacts binding
                  ON binding.deployment_id = deployment.id
                 AND binding.deployment_attempt = deployment.attempt
                 AND binding.config_version_id = deployment.config_version_id
                 AND binding.artifact_id = artifact.id
                WHERE deployment.node_id = checked_node_id
                  AND deployment.config_version_id = checked_config_version_id
                  AND deployment.action = 'apply'
                  AND deployment.state IN ('activated', 'healthy')
                  AND deployment.command_sha256 = sha256(deployment.command_bytes)
            )) OR
            (checked_deployment_id IS NOT NULL AND checked_attempt > 0 AND
             checked_state IN ('healthy', 'reverted') AND EXISTS (
                SELECT 1
                FROM node_deployments deployment
                JOIN rollouts rollout
                  ON rollout.id = deployment.rollout_id
                 AND rollout.config_version_id = deployment.config_version_id
                 AND rollout.configuration_scope_id = config_state.configuration_scope_id
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
