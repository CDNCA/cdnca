-- 687（前驱 686_dns_cleanup_plan_records）。
-- 首代激活后回滚补偿失败，这一代一直在服务。新版 agent 核验索引与全部 worker 都在这一代后，
-- 把这份发布记为作用域当前发布，并在心跳里上报它的身份（版本 + 配置制品摘要），旁边仍是 rollback_failed 结果。
-- 主控 Go 侧（nodepresence requireBoundIdentityArtifact）已接受「本节点收到并已绑定该制品的 rollback_failed
-- apply」作为身份来源，但数据库校验函数（232 版）的无部署分支只认 activated/healthy，
-- 作用域身份行写入时报 P8702，整条心跳被判为无效。这里把无部署分支放宽到 rollback_failed，其余条件不变
-- （仍须本节点、本作用域的 apply，制品已绑定且摘要与字节一致）。不改表、不回填。
-- 错误码：头检查 P6870；down 头检查 P6871。
LOCK TABLE schema_migrations, node_config_state, config_versions, configuration_artifacts, rollouts,
    node_deployments, node_deployment_artifacts, node_presence, node_presence_scope_identities
IN ACCESS EXCLUSIVE MODE;

DO $migration_687_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 686 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 686 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=686 AND
        migration_id='686_dns_cleanup_plan_records' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure('active_config_identity_artifact_valid_087(uuid,uuid,bytea,uuid,integer,text)') IS NULL THEN
        RAISE EXCEPTION 'migration 687 requires the exact verified 686 release head' USING ERRCODE='P6870';
    END IF;
END;
$migration_687_up$;

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
                  AND deployment.state IN ('activated', 'healthy', 'rollback_failed')
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
