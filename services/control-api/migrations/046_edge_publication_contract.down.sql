DO $migration$
BEGIN
    IF EXISTS (SELECT 1 FROM edge_config_publications WHERE contract_version = 1) OR
       EXISTS (SELECT 1 FROM rollouts WHERE contract_version = 1 OR revision > 1) OR
       EXISTS (SELECT 1 FROM node_deployments WHERE state = 'cancelled') OR
       EXISTS (SELECT 1 FROM edge_command_outbox WHERE status = 'cancelled') OR
       EXISTS (SELECT 1 FROM edge_rollout_write_requests) THEN
        RAISE EXCEPTION 'migration 046 cannot be rolled back while edge publication contract facts exist'
            USING ERRCODE = 'P0001';
    END IF;
END;
$migration$;

DROP TRIGGER node_deployments_fact_046 ON node_deployments;
DROP FUNCTION assert_node_deployment_fact_046();
DROP TRIGGER rollouts_contract_audited_046 ON rollouts;
DROP FUNCTION assert_rollout_contract_046();
DROP TRIGGER edge_config_publications_audited_046 ON edge_config_publications;
DROP FUNCTION assert_edge_publication_audit_046();
DROP TRIGGER edge_config_publications_contract_046 ON edge_config_publications;
DROP FUNCTION assert_edge_publication_contract_046();

DROP TRIGGER edge_command_outbox_state_046 ON edge_command_outbox;
DROP FUNCTION enforce_edge_outbox_state_046();
DROP TRIGGER node_deployments_state_046 ON node_deployments;
DROP FUNCTION enforce_node_deployment_state_046();
DROP TRIGGER node_deployments_attempt_046 ON node_deployments;
DROP FUNCTION enforce_node_deployment_attempt_046();
DROP TRIGGER rollouts_state_046 ON rollouts;
DROP FUNCTION enforce_rollout_state_046();

ALTER TABLE edge_command_outbox DROP CONSTRAINT edge_command_outbox_status_046;
ALTER TABLE edge_command_outbox ADD CONSTRAINT edge_command_outbox_status_check CHECK (
    status IN ('pending', 'publishing', 'published', 'failed')
);

DROP INDEX node_deployments_one_active_per_node_idx;
CREATE UNIQUE INDEX node_deployments_one_active_per_node_idx
    ON node_deployments (node_id)
    WHERE state NOT IN ('healthy', 'failed', 'reverted', 'rollback_failed');
ALTER TABLE node_deployments DROP CONSTRAINT node_deployments_state_046;
ALTER TABLE node_deployments ADD CONSTRAINT node_deployments_state_check CHECK (
    state IN ('queued', 'delivered', 'staged', 'prechecked', 'activated', 'healthy',
              'failed', 'reverting', 'reverted', 'rollback_failed')
);

DROP TRIGGER edge_rollout_write_requests_immutable_046 ON edge_rollout_write_requests;
DROP FUNCTION protect_edge_rollout_write_request_046();
DROP TABLE edge_rollout_write_requests;

DROP INDEX edge_config_publications_one_contract_source_idx;
ALTER TABLE edge_config_publications
    DROP CONSTRAINT edge_config_publications_actor_membership_046,
    DROP CONSTRAINT edge_config_publications_contract_046,
    DROP CONSTRAINT edge_config_publications_target_digest_046,
    DROP CONSTRAINT edge_config_publications_expected_revision_046,
    DROP COLUMN contract_version,
    DROP COLUMN target_snapshot_sha256,
    DROP COLUMN target_resolver_sha256,
    DROP COLUMN target_snapshot_revision,
    DROP COLUMN target_snapshot_id,
    DROP COLUMN target_kind,
    DROP COLUMN actor_scope_id,
    DROP COLUMN actor_user_id,
    DROP COLUMN expected_source_revision;

ALTER TABLE rollouts
    DROP CONSTRAINT rollouts_updated_at_046,
    DROP CONSTRAINT rollouts_contract_version_046,
    DROP CONSTRAINT rollouts_max_attempts_046,
    DROP CONSTRAINT rollouts_revision_positive_046,
    DROP COLUMN contract_version,
    DROP COLUMN updated_at,
    DROP COLUMN max_attempts,
    DROP COLUMN revision;

DELETE FROM role_permissions
WHERE permission_name IN ('edge_publications.read', 'edge_publications.manage');
DELETE FROM permissions
WHERE name IN ('edge_publications.read', 'edge_publications.manage');
