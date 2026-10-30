LOCK TABLE schema_migrations,
    edge_rollout_write_requests,
    security_policy_activation_recovery_proofs_095,
    security_policy_activation_recovery_pending_095
IN ACCESS EXCLUSIVE MODE;
LOCK TABLE security_policy_activation_config_facts,
    security_policy_activation_candidates,
    security_policy_activation_rollouts,
    security_policy_activation_recovery_rollouts,
    security_policy_activation_events,
    rollouts,
    node_deployments,
    node_deployment_artifacts,
    edge_command_outbox,
    deployment_status_events,
    node_config_state,
    config_versions,
    configuration_artifacts
IN SHARE ROW EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 95 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 95 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL
           OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 95
          AND migration_id = '095_security_activation'
          AND checksum_sha256 = 'a3f87e9b0e29162e86e2011a26961a78b424ab2c0f5d20dd6a8d6827a2d81ecf'
          AND integrity_state = 'verified'
          AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 095 rollback requires the exact verified 095 head'
            USING ERRCODE = 'P9500';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 94
          AND migration_id = '094_background_job_commands'
          AND checksum_sha256 = '68da50b82c6597f264d66a3ca366f8738652ae608ddf04edccc6b4a191bfebc8'
          AND down_checksum_sha256 = '45539ad704fd82aaea1eaa9cb6d540a6f3c875f28a0ae3b158bc8a9c9c52de80'
          AND integrity_state = 'verified'
          AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 095 rollback requires the exact verified 094 parent'
            USING ERRCODE = 'P9500';
    END IF;
    IF EXISTS (SELECT 1 FROM security_policy_activation_recovery_pending_095) OR
       EXISTS (SELECT 1 FROM security_policy_activation_recovery_proofs_095) THEN
        RAISE EXCEPTION 'migration 095 rollback would discard security activation recovery facts'
            USING ERRCODE = 'P9501';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION validate_security_policy_activation_recovery_rollout_088()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    candidate security_policy_activation_candidates%ROWTYPE;
    rollout_record rollouts%ROWTYPE;
BEGIN
    SELECT * INTO candidate FROM security_policy_activation_candidates
    WHERE id=NEW.candidate_id AND tenant_scope_id=NEW.tenant_scope_id;
    SELECT * INTO rollout_record FROM rollouts
    WHERE id=NEW.rollout_id AND configuration_scope_id=NEW.tenant_scope_id;
    IF candidate.id IS NULL OR rollout_record.id IS NULL OR rollout_record.contract_version <> 1 OR
       rollout_record.status NOT IN ('queued','completed') OR rollout_record.action <> 'rollback' OR
       rollout_record.config_version_id <> NEW.recovery_config_version_id OR
       rollout_record.request_id <> NEW.request_id OR
       NEW.target_snapshot_sha256 <> candidate.target_snapshot_sha256 OR
       NOT EXISTS (
           SELECT 1 FROM configuration_artifacts artifact
           WHERE artifact.config_version_id=NEW.recovery_config_version_id
             AND artifact.kind='configuration' AND artifact.sha256=NEW.recovery_artifact_sha256
             AND artifact.sha256=sha256(artifact.wire_bytes)
       ) OR
       (SELECT count(*) FROM node_deployments deployment
        WHERE deployment.rollout_id=NEW.rollout_id AND deployment.attempt=1) <> cardinality(NEW.node_ids) OR
       EXISTS (
           SELECT 1 FROM node_deployments deployment
           WHERE deployment.rollout_id=NEW.rollout_id AND deployment.attempt=1 AND
                 (NOT deployment.node_id=ANY(NEW.node_ids) OR deployment.action <> 'rollback' OR
                  deployment.config_version_id <> NEW.recovery_config_version_id OR
                  NOT active_config_identity_artifact_valid_087(
                      deployment.node_id, NEW.recovery_config_version_id,
                      NEW.recovery_artifact_sha256, deployment.id, deployment.attempt,
                      (SELECT event.state FROM deployment_status_events event
                       WHERE event.deployment_id=deployment.id AND event.attempt=deployment.attempt
                       ORDER BY event.transition_sequence DESC LIMIT 1)
                  ))
       ) THEN
        RAISE EXCEPTION 'invalid security policy activation recovery rollout identity' USING ERRCODE = 'P8802';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION security_policy_activation_recovered_088(checked_candidate_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM security_policy_activation_candidates candidate
        WHERE candidate.id=checked_candidate_id
          AND candidate.candidate_status IN ('failed','cancelled','expired')
          AND EXISTS (
              SELECT 1 FROM security_policy_activation_rollouts activation_rollout
              WHERE activation_rollout.candidate_id=candidate.id
          )
          AND NOT EXISTS (
              SELECT 1
              FROM security_policy_activation_rollouts activation_rollout
              CROSS JOIN LATERAL unnest(activation_rollout.node_ids) expected_node_id
              WHERE activation_rollout.candidate_id=candidate.id
                AND NOT EXISTS (
                    SELECT 1
                    FROM node_deployments apply_deployment
                    JOIN security_policy_activation_recovery_rollouts recovery
                      ON recovery.candidate_id=candidate.id
                     AND recovery.tenant_scope_id=candidate.tenant_scope_id
                     AND expected_node_id=ANY(recovery.node_ids)
                     AND recovery.recovery_config_version_id=apply_deployment.previous_config_version_id
                     AND recovery.target_snapshot_sha256=candidate.target_snapshot_sha256
                    JOIN rollouts recovery_rollout
                      ON recovery_rollout.id=recovery.rollout_id
                     AND recovery_rollout.configuration_scope_id=candidate.tenant_scope_id
                     AND recovery_rollout.config_version_id=recovery.recovery_config_version_id
                     AND recovery_rollout.contract_version=1
                     AND recovery_rollout.action='rollback'
                     AND recovery_rollout.status IN ('queued','completed')
                     AND recovery_rollout.request_id=recovery.request_id
                    JOIN node_deployments rollback_deployment
                      ON rollback_deployment.rollout_id=recovery.rollout_id
                     AND rollback_deployment.node_id=expected_node_id
                     AND rollback_deployment.attempt=(
                         SELECT max(retry.attempt)
                         FROM node_deployments retry
                         WHERE retry.rollout_id=recovery.rollout_id
                           AND retry.node_id=expected_node_id
                     )
                     AND rollback_deployment.action='rollback'
                     AND rollback_deployment.config_version_id=recovery.recovery_config_version_id
                     AND rollback_deployment.previous_config_version_id=candidate.candidate_config_version_id
                    JOIN LATERAL (
                        SELECT event.state,event.active_config_identity_api_version,
                               event.active_config_identity_schema,event.active_config_version_id,
                               event.active_config_artifact_sha256
                        FROM deployment_status_events event
                        WHERE event.deployment_id=rollback_deployment.id
                          AND event.attempt=rollback_deployment.attempt
                        ORDER BY event.transition_sequence DESC
                        LIMIT 1
                    ) rollback_event ON true
                    JOIN node_config_state node_state
                      ON node_state.node_id=expected_node_id
                     AND node_state.configuration_scope_id=candidate.tenant_scope_id
                    WHERE apply_deployment.rollout_id=activation_rollout.rollout_id
                      AND apply_deployment.node_id=expected_node_id
                      AND apply_deployment.attempt=(
                          SELECT max(retry.attempt)
                          FROM node_deployments retry
                          WHERE retry.rollout_id=activation_rollout.rollout_id
                            AND retry.node_id=expected_node_id
                      )
                      AND apply_deployment.action='apply'
                      AND apply_deployment.config_version_id=candidate.candidate_config_version_id
                      AND apply_deployment.previous_config_version_id IS NOT NULL
                      AND recovery.created_at=(
                          SELECT max(latest_recovery.created_at)
                          FROM security_policy_activation_recovery_rollouts latest_recovery
                          WHERE latest_recovery.candidate_id=candidate.id
                            AND expected_node_id=ANY(latest_recovery.node_ids)
                      )
                      AND (
                          SELECT count(*)
                          FROM security_policy_activation_recovery_rollouts tied_recovery
                          WHERE tied_recovery.candidate_id=candidate.id
                            AND expected_node_id=ANY(tied_recovery.node_ids)
                            AND tied_recovery.created_at=recovery.created_at
                      )=1
                      AND EXISTS (
                          SELECT 1 FROM configuration_artifacts artifact
                          WHERE artifact.config_version_id=recovery.recovery_config_version_id
                            AND artifact.kind='configuration'
                            AND artifact.sha256=recovery.recovery_artifact_sha256
                            AND artifact.sha256=sha256(artifact.wire_bytes)
                      )
                      AND rollback_event.state='reverted'
                      AND rollback_event.active_config_identity_api_version=1
                      AND rollback_event.active_config_identity_schema=1
                      AND rollback_event.active_config_version_id=recovery.recovery_config_version_id
                      AND rollback_event.active_config_artifact_sha256=recovery.recovery_artifact_sha256
                      AND active_config_identity_artifact_valid_087(
                          expected_node_id, recovery.recovery_config_version_id,
                          recovery.recovery_artifact_sha256, rollback_deployment.id,
                          rollback_deployment.attempt, rollback_event.state
                      )
                      AND node_state.current_config_identity_schema=1
                      AND node_state.current_config_version_id=recovery.recovery_config_version_id
                      AND node_state.current_config_artifact_sha256=recovery.recovery_artifact_sha256
                )
          )
    )
$$;

CREATE OR REPLACE FUNCTION protect_security_policy_activation_candidate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE') OR
       ROW(NEW.id,NEW.tenant_scope_id,NEW.site_id,NEW.binding_id,NEW.binding_revision,
           NEW.last_bundle_id,NEW.last_claimed_policy_version,NEW.expected_active_policy_version,
           NEW.candidate_source_revision,NEW.candidate_config_version_id,
           NEW.candidate_artifact_sha256,NEW.target_snapshot_sha256,NEW.required_capabilities,
           NEW.canary_node_ids,NEW.expand_node_ids,NEW.idempotency_key,NEW.request_digest,
           NEW.request_id,NEW.actor_scope_id,NEW.actor_user_id,NEW.expires_at,NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id,OLD.tenant_scope_id,OLD.site_id,OLD.binding_id,OLD.binding_revision,
           OLD.last_bundle_id,OLD.last_claimed_policy_version,OLD.expected_active_policy_version,
           OLD.candidate_source_revision,OLD.candidate_config_version_id,
           OLD.candidate_artifact_sha256,OLD.target_snapshot_sha256,OLD.required_capabilities,
           OLD.canary_node_ids,OLD.expand_node_ids,OLD.idempotency_key,OLD.request_digest,
           OLD.request_id,OLD.actor_scope_id,OLD.actor_user_id,OLD.expires_at,OLD.created_at) OR
       NEW.updated_at < OLD.updated_at OR
       (NEW.candidate_status <> 'promoted' AND NEW.promoted_at IS DISTINCT FROM OLD.promoted_at) OR
       (OLD.promoted_at IS NOT NULL AND NEW.promoted_at IS DISTINCT FROM OLD.promoted_at) OR
       (OLD.recovered_at IS NOT NULL AND NEW.recovered_at IS DISTINCT FROM OLD.recovered_at) OR
       (NEW.recovered_at IS DISTINCT FROM OLD.recovered_at AND (
           OLD.recovered_at IS NOT NULL OR NEW.recovered_at IS NULL OR
           NEW.candidate_status NOT IN ('failed','cancelled','expired') OR
           NOT security_policy_activation_recovered_088(NEW.id)
       )) OR
       NOT (
           NEW.candidate_status = OLD.candidate_status OR
           (OLD.candidate_status = 'claimed' AND NEW.candidate_status IN ('canary','failed','cancelled','expired')) OR
           (OLD.candidate_status = 'canary' AND NEW.candidate_status IN ('expanding','healthy','failed','cancelled','expired')) OR
           (OLD.candidate_status = 'expanding' AND NEW.candidate_status IN ('healthy','failed','cancelled','expired')) OR
           (OLD.candidate_status = 'healthy' AND NEW.candidate_status IN ('promoted','failed','cancelled','expired'))
       ) OR
       (NEW.candidate_status='canary' AND NOT EXISTS (
           SELECT 1 FROM security_policy_activation_rollouts rollout
           WHERE rollout.candidate_id=NEW.id AND rollout.phase='canary'
       )) OR
       (NEW.candidate_status='expanding' AND (
           NOT security_policy_activation_phase_healthy_088(NEW.id,'canary') OR NOT EXISTS (
               SELECT 1 FROM security_policy_activation_rollouts rollout
               WHERE rollout.candidate_id=NEW.id AND rollout.phase='expand'
           )
       )) OR
       (NEW.candidate_status IN ('healthy','promoted') AND (
           NOT security_policy_activation_phase_healthy_088(NEW.id,'canary') OR
           (cardinality(NEW.expand_node_ids)>0 AND
            NOT security_policy_activation_phase_healthy_088(NEW.id,'expand'))
       )) THEN
        RAISE EXCEPTION 'invalid security policy activation candidate transition' USING ERRCODE = 'P8802';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION assert_rollout_contract_046()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.contract_version <> 1 OR NEW.status = 'building' THEN
        RETURN NULL;
    END IF;
    IF NEW.revision = 1 THEN
        IF NOT EXISTS (
            SELECT 1 FROM edge_config_publications publication
            WHERE publication.rollout_id = NEW.id AND publication.contract_version = 1
        ) AND NOT EXISTS (
            SELECT 1 FROM security_policy_activation_rollouts activation
            JOIN security_policy_activation_candidates candidate ON candidate.id=activation.candidate_id
            WHERE activation.rollout_id=NEW.id
              AND activation.tenant_scope_id=NEW.configuration_scope_id
              AND activation.candidate_config_version_id=NEW.config_version_id
              AND candidate.candidate_artifact_sha256=activation.candidate_artifact_sha256
              AND candidate.target_snapshot_sha256=activation.target_snapshot_sha256
              AND NEW.action='apply'
        ) AND NOT EXISTS (
            SELECT 1 FROM security_policy_activation_recovery_rollouts recovery
            WHERE recovery.rollout_id=NEW.id
              AND recovery.tenant_scope_id=NEW.configuration_scope_id
              AND recovery.recovery_config_version_id=NEW.config_version_id
              AND NEW.action='rollback'
        ) THEN
            RAISE EXCEPTION 'contract rollout requires an audited publication or security activation fact' USING ERRCODE = 'P0001';
        END IF;
        RETURN NULL;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM edge_rollout_write_requests request
        JOIN audit_events event
          ON event.scope_id = request.actor_scope_id
         AND event.actor_user_id = request.actor_user_id
         AND event.action = request.operation
         AND event.resource_type = 'edge_rollout'
         AND event.resource_id = request.rollout_id::text
         AND event.request_id = request.request_id::text
         AND event.result = 'success'
        WHERE request.configuration_scope_id = NEW.configuration_scope_id
          AND request.rollout_id = NEW.id
          AND request.expected_revision = NEW.revision - 1
          AND request.operation = CASE
              WHEN NEW.status = 'cancelled' THEN 'edge_rollout.cancel'
              ELSE 'edge_rollout.retry'
          END
          AND request.completed_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'rollout command requires matching request and audit' USING ERRCODE = 'P0001';
    END IF;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION enforce_edge_outbox_state_046()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status = NEW.status THEN
        RETURN NEW;
    END IF;
    IF OLD.status IN ('pending', 'failed') AND NEW.status = 'publishing' THEN
        RETURN NEW;
    END IF;
    IF OLD.status = 'pending' AND NEW.status = 'cancelled' THEN
        RETURN NEW;
    END IF;
    IF OLD.status = 'publishing' AND NEW.status IN ('published', 'failed') THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid edge outbox state transition' USING ERRCODE = 'P0001';
END;
$$;

DROP TRIGGER node_config_state_security_activation_proof_095 ON node_config_state;
DROP TRIGGER deployment_status_security_activation_proof_095 ON deployment_status_events;
DROP TRIGGER edge_command_outbox_security_activation_pending_095 ON edge_command_outbox;
DROP TRIGGER edge_rollout_write_request_security_activation_lock_095 ON edge_rollout_write_requests;

DROP FUNCTION lock_security_policy_activation_retry_candidates_095();

DROP FUNCTION record_security_policy_activation_recovery_proof_state_095();
DROP FUNCTION record_security_policy_activation_recovery_proof_event_095();
DROP FUNCTION record_security_policy_activation_recovery_proofs_095();
DROP FUNCTION record_security_policy_activation_recovery_pending_outbox_095();
DROP FUNCTION record_security_policy_activation_recovery_pending_095(uuid);
DROP FUNCTION security_policy_activation_recovered_095(uuid);

DROP TABLE security_policy_activation_recovery_proofs_095;
DROP TABLE security_policy_activation_recovery_pending_095;

DROP FUNCTION prevent_security_policy_activation_recovery_fact_mutation_095();
DROP FUNCTION validate_security_policy_activation_recovery_proof_095();
DROP FUNCTION validate_security_policy_activation_recovery_pending_095();
DROP FUNCTION security_policy_activation_recovery_target_sha256_095(uuid,uuid,uuid,bytea,uuid[]);
