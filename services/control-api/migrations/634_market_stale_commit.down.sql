-- 634 回退：恢复判定恢复 095 原文（只认回到恢复配置或回滚已证明）。已按 634 判定恢复的候选不受影响
-- （recovered_at 已写入，触发器只在写入时检查）。叶子的已应用修订表直接删除：回退后的叶子不再拒绝旧提交。
LOCK TABLE schema_migrations, security_policy_activation_candidates IN ACCESS EXCLUSIVE MODE;

DO $migration_634_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 634 OR
       (SELECT max(version) FROM schema_migrations) <> 634 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=634 AND
        migration_id='634_market_stale_commit' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 634 down requires the exact verified migration head' USING ERRCODE='P6341';
    END IF;
END;
$migration_634_down$;

DROP TABLE market_supply_site_revisions;

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
                          )
                      )
                )
          )
    )
$$;
