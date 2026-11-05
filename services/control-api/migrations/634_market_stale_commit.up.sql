-- 634（前驱 633 control_db_pool_alerts）：
--   1. security_policy_activation_recovered_095：失败/取消/过期的安全激活候选，其已下发节点若已改跑本作用域
--      更新的普通配置（候选 apply 发出之后才建的健康 apply，配置不是候选本身），也算已恢复。原判定只认
--      「回到恢复配置」或「回滚已证明」，节点被普通发布带到新配置后两者都不会再成立：候选永远不恢复，
--      绑定上的开放候选唯一索引与节点发布目标一直占着，之后每个版本的 Start 都被拒（例如叶子 CC
--      策略 v2 候选失败后 v3/v4 一直 security activation conflict）。
--   2. market_supply_site_revisions（叶子/供货方）：每个市场站点（租户作用域 + 订阅方站点 ID）已应用的订阅方
--      修订。relay 重启曾从 0 重放全部历史（旧 supply.commit_site 又执行一遍，把站点和
--      CC 策略写回旧值），叶子据此只应用不比已应用的旧的提交（internal/marketsupply/applied.go）：
--        applied_revision：当前在跑的订阅方修订（删除后 0）；
--        high_revision：到过的最高修订（回滚到旧修订后不降），比它旧的非回滚提交不再执行；
--        relay_seq：最后一次应用的 relay 消息序号（同一收件人严格递增），不大于它的是重放，删除也按它判断。
LOCK TABLE schema_migrations, security_policy_activation_candidates IN ACCESS EXCLUSIVE MODE;

DO $migration_634_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 633 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 633 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=633 AND
        migration_id='633_control_db_pool_alerts' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure(current_schema() || '.security_policy_activation_recovered_095(uuid)') IS NULL OR
          to_regclass(current_schema() || '.market_supply_site_revisions') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 634 requires the exact verified 633 release head' USING ERRCODE='P6340';
    END IF;
END;
$migration_634_up$;

CREATE OR REPLACE FUNCTION security_policy_activation_recovered_095(checked_candidate_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1 FROM security_policy_activation_candidates candidate
        WHERE candidate.id=checked_candidate_id
          AND candidate.candidate_status IN ('failed','cancelled','expired')
          AND EXISTS (
              SELECT 1 FROM security_policy_activation_recovery_pending_095 pending
              WHERE pending.candidate_id=candidate.id AND pending.action='apply'
                AND pending.generation=(
                    SELECT max(latest.generation)
                    FROM security_policy_activation_recovery_pending_095 latest
                    WHERE latest.candidate_id=pending.candidate_id
                      AND latest.node_id=pending.node_id AND latest.action='apply'
                )
          )
          AND NOT EXISTS (
              SELECT 1 FROM security_policy_activation_recovery_pending_095 apply_pending
              WHERE apply_pending.candidate_id=candidate.id AND apply_pending.action='apply'
                AND apply_pending.generation=(
                    SELECT max(latest.generation)
                    FROM security_policy_activation_recovery_pending_095 latest
                    WHERE latest.candidate_id=apply_pending.candidate_id
                      AND latest.node_id=apply_pending.node_id AND latest.action='apply'
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM node_deployments deployment
                    JOIN edge_command_outbox outbox
                      ON outbox.id=apply_pending.outbox_id
                     AND outbox.deployment_id=deployment.id
                     AND outbox.deployment_attempt=deployment.attempt
                     AND outbox.node_id=deployment.node_id
                    WHERE deployment.id=apply_pending.deployment_id
                      AND deployment.attempt=apply_pending.deployment_attempt
                      AND deployment.rollout_id=apply_pending.rollout_id
                      AND deployment.node_id=apply_pending.node_id
                      AND deployment.action='apply'
                      AND deployment.config_version_id=apply_pending.candidate_config_version_id
                      AND deployment.previous_config_version_id=apply_pending.recovery_config_version_id
                      AND deployment.attempt=(
                          SELECT max(latest_attempt.attempt)
                          FROM node_deployments latest_attempt
                          WHERE latest_attempt.rollout_id=apply_pending.rollout_id
                            AND latest_attempt.node_id=apply_pending.node_id
                      )
                      AND outbox.payload=deployment.command_bytes
                      AND outbox.payload_sha256=deployment.command_sha256
                      AND outbox.payload_sha256=sha256(outbox.payload)
                      AND (
                          (deployment.state='cancelled' AND outbox.status='cancelled') OR
                          (deployment.state IN ('healthy','failed','reverted','rollback_failed') AND
                           outbox.status='published')
                      )
                      AND (
                          EXISTS (
                              SELECT 1 FROM node_config_state state
                              WHERE state.node_id=apply_pending.node_id
                                AND state.configuration_scope_id=apply_pending.tenant_scope_id
                                AND ROW(state.current_config_identity_schema,
                                        state.current_config_version_id,
                                        state.current_config_artifact_sha256)
                                    IS NOT DISTINCT FROM
                                    ROW(1,apply_pending.recovery_config_version_id,
                                        apply_pending.recovery_artifact_sha256)
                          ) OR EXISTS (
                              SELECT 1
                              FROM security_policy_activation_recovery_pending_095 rollback_pending
                              JOIN security_policy_activation_recovery_proofs_095 proof
                                ON proof.candidate_id=rollback_pending.candidate_id
                               AND proof.node_id=rollback_pending.node_id
                               AND proof.generation=rollback_pending.generation
                              JOIN node_deployments rollback_deployment
                                ON rollback_deployment.id=rollback_pending.deployment_id
                               AND rollback_deployment.attempt=rollback_pending.deployment_attempt
                               AND rollback_deployment.rollout_id=rollback_pending.rollout_id
                               AND rollback_deployment.node_id=rollback_pending.node_id
                              JOIN edge_command_outbox rollback_outbox
                                ON rollback_outbox.id=rollback_pending.outbox_id
                               AND rollback_outbox.deployment_id=rollback_deployment.id
                               AND rollback_outbox.deployment_attempt=rollback_deployment.attempt
                               AND rollback_outbox.node_id=rollback_deployment.node_id
                              WHERE rollback_pending.candidate_id=apply_pending.candidate_id
                                AND rollback_pending.node_id=apply_pending.node_id
                                AND rollback_pending.action='rollback'
                                AND rollback_pending.generation=(
                                    SELECT max(latest_rollback.generation)
                                    FROM security_policy_activation_recovery_pending_095 latest_rollback
                                    WHERE latest_rollback.candidate_id=rollback_pending.candidate_id
                                      AND latest_rollback.node_id=rollback_pending.node_id
                                      AND latest_rollback.action='rollback'
                                )
                                AND rollback_pending.recovery_config_version_id=
                                    apply_pending.recovery_config_version_id
                                AND rollback_pending.recovery_artifact_sha256=
                                    apply_pending.recovery_artifact_sha256
                                AND rollback_deployment.attempt=(
                                    SELECT max(latest_attempt.attempt)
                                    FROM node_deployments latest_attempt
                                    WHERE latest_attempt.rollout_id=rollback_pending.rollout_id
                                      AND latest_attempt.node_id=rollback_pending.node_id
                                )
                                AND rollback_deployment.action='rollback'
                                AND rollback_deployment.state='reverted'
                                AND rollback_outbox.status='published'
                          ) OR EXISTS (
                              -- 634: the node has moved on to a newer configuration of the scope (an
                              -- ordinary publication applied after this candidate's apply was sent);
                              -- it does not run the candidate, so nothing is left to roll back.
                              SELECT 1
                              FROM node_config_state newer_state
                              JOIN node_deployments newer
                                ON newer.node_id=newer_state.node_id
                               AND newer.config_version_id=newer_state.current_config_version_id
                               AND newer.action='apply' AND newer.state IN ('activated','healthy')
                              JOIN rollouts newer_rollout
                                ON newer_rollout.id=newer.rollout_id
                               AND newer_rollout.config_version_id=newer.config_version_id
                               AND newer_rollout.configuration_scope_id=newer_state.configuration_scope_id
                              WHERE newer_state.node_id=apply_pending.node_id
                                AND newer_state.configuration_scope_id=apply_pending.tenant_scope_id
                                AND newer_state.current_config_identity_schema=1
                                AND newer_state.current_config_version_id IS DISTINCT FROM
                                    apply_pending.candidate_config_version_id
                                AND newer.created_at > deployment.created_at
                          )
                      )
                )
          )
    )
$$;

CREATE TABLE market_supply_site_revisions (
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE CASCADE,
    site_id uuid NOT NULL,
    leaf_site_id uuid,
    applied_revision bigint NOT NULL CHECK (applied_revision >= 0),
    high_revision bigint NOT NULL CHECK (high_revision >= applied_revision),
    relay_seq bigint NOT NULL CHECK (relay_seq >= 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, site_id)
);
