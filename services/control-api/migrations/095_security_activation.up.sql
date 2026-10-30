LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
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
    IF (SELECT count(*) FROM schema_migrations) <> 94 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 94 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL
           OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 94
          AND migration_id = '094_background_job_commands'
          AND checksum_sha256 = '68da50b82c6597f264d66a3ca366f8738652ae608ddf04edccc6b4a191bfebc8'
          AND down_checksum_sha256 = '45539ad704fd82aaea1eaa9cb6d540a6f3c875f28a0ae3b158bc8a9c9c52de80'
          AND integrity_state = 'verified'
          AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 095 requires the exact verified 094 release head'
            USING ERRCODE = 'P9500';
    END IF;
END;
$$;

CREATE FUNCTION security_policy_activation_recovery_target_sha256_095(
    tenant_scope_id uuid,
    site_id uuid,
    recovery_config_version_id uuid,
    recovery_artifact_sha256 bytea,
    node_ids uuid[]
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT CASE
        WHEN tenant_scope_id IS NULL OR site_id IS NULL OR recovery_config_version_id IS NULL OR
             octet_length(recovery_artifact_sha256) <> 32 OR node_ids IS NULL OR
             cardinality(node_ids) = 0 OR EXISTS (
                 SELECT 1 FROM unnest(node_ids) node_id WHERE node_id IS NULL
             ) OR cardinality(node_ids) <> (
                 SELECT count(DISTINCT node_id) FROM unnest(node_ids) node_id
             ) THEN NULL
        ELSE sha256(convert_to(
            'cdnca.security-activation-recovery-targets/v1' || E'\n' ||
            tenant_scope_id::text || E'\n' || site_id::text || E'\n' ||
            recovery_config_version_id::text || E'\n' ||
            encode(recovery_artifact_sha256, 'hex') || E'\n' ||
            (SELECT string_agg(node_id::text, ',' ORDER BY node_id::text COLLATE "C")
             FROM unnest(node_ids) node_id),
            'UTF8'
        ))
    END
$$;

CREATE TABLE security_policy_activation_recovery_pending_095 (
    candidate_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    rollout_id uuid NOT NULL,
    deployment_id uuid NOT NULL,
    deployment_attempt integer NOT NULL CHECK (deployment_attempt > 0),
    node_id uuid NOT NULL,
    generation integer NOT NULL CHECK (generation > 0),
    action text NOT NULL CHECK (action IN ('apply','rollback')),
    candidate_config_version_id uuid NOT NULL,
    candidate_artifact_sha256 bytea NOT NULL CHECK (octet_length(candidate_artifact_sha256) = 32),
    recovery_config_version_id uuid,
    recovery_artifact_sha256 bytea,
    candidate_target_snapshot_sha256 bytea NOT NULL
        CHECK (octet_length(candidate_target_snapshot_sha256) = 32),
    recovery_target_snapshot_sha256 bytea NOT NULL
        CHECK (octet_length(recovery_target_snapshot_sha256) = 32),
    outbox_id uuid NOT NULL,
    request_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    CHECK ((recovery_config_version_id IS NULL) = (recovery_artifact_sha256 IS NULL)),
    CHECK (recovery_artifact_sha256 IS NULL OR octet_length(recovery_artifact_sha256) = 32),
    UNIQUE (candidate_id, node_id, generation),
    UNIQUE (rollout_id, node_id, deployment_attempt),
    UNIQUE (deployment_id, deployment_attempt),
    UNIQUE (outbox_id),
    FOREIGN KEY (tenant_scope_id, candidate_id)
        REFERENCES security_policy_activation_candidates(tenant_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, rollout_id)
        REFERENCES rollouts(configuration_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (deployment_id, deployment_attempt)
        REFERENCES node_deployments(id, attempt) ON DELETE RESTRICT,
    FOREIGN KEY (outbox_id)
        REFERENCES edge_command_outbox(id) ON DELETE RESTRICT
);

CREATE TABLE security_policy_activation_recovery_proofs_095 (
    candidate_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    rollout_id uuid NOT NULL,
    deployment_id uuid NOT NULL,
    deployment_attempt integer NOT NULL CHECK (deployment_attempt > 0),
    node_id uuid NOT NULL,
    generation integer NOT NULL CHECK (generation > 0),
    action text NOT NULL CHECK (action = 'rollback'),
    candidate_config_version_id uuid NOT NULL,
    candidate_artifact_sha256 bytea NOT NULL CHECK (octet_length(candidate_artifact_sha256) = 32),
    recovery_config_version_id uuid NOT NULL,
    recovery_artifact_sha256 bytea NOT NULL CHECK (octet_length(recovery_artifact_sha256) = 32),
    candidate_target_snapshot_sha256 bytea NOT NULL
        CHECK (octet_length(candidate_target_snapshot_sha256) = 32),
    recovery_target_snapshot_sha256 bytea NOT NULL
        CHECK (octet_length(recovery_target_snapshot_sha256) = 32),
    outbox_id uuid NOT NULL,
    status_event_id uuid NOT NULL,
    transition_sequence bigint NOT NULL CHECK (transition_sequence > 0),
    proved_at timestamptz NOT NULL,
    UNIQUE (candidate_id, node_id, generation),
    UNIQUE (rollout_id, node_id, deployment_attempt),
    UNIQUE (deployment_id, deployment_attempt),
    UNIQUE (status_event_id),
    FOREIGN KEY (candidate_id, node_id, generation)
        REFERENCES security_policy_activation_recovery_pending_095(candidate_id, node_id, generation)
        ON DELETE RESTRICT,
    FOREIGN KEY (status_event_id)
        REFERENCES deployment_status_events(id) ON DELETE RESTRICT
);

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
    IF OLD.status IN ('pending', 'failed') AND NEW.status = 'cancelled' THEN
        RETURN NEW;
    END IF;
    IF OLD.status = 'publishing' AND NEW.status IN ('published', 'failed') THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid edge outbox state transition' USING ERRCODE = 'P0001';
END;
$$;

CREATE OR REPLACE FUNCTION validate_security_policy_activation_recovery_rollout_088()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    candidate security_policy_activation_candidates%ROWTYPE;
    rollout_record rollouts%ROWTYPE;
    proven_mode boolean;
    queued_mode boolean;
BEGIN
    SELECT * INTO candidate FROM security_policy_activation_candidates
    WHERE id=NEW.candidate_id AND tenant_scope_id=NEW.tenant_scope_id
    FOR UPDATE;
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
        WHERE deployment.rollout_id=NEW.rollout_id AND deployment.attempt=1) <> cardinality(NEW.node_ids) THEN
        RAISE EXCEPTION 'invalid security policy activation recovery rollout identity' USING ERRCODE = 'P8802';
    END IF;

    proven_mode := NOT EXISTS (
        SELECT 1 FROM node_deployments deployment
        WHERE deployment.rollout_id=NEW.rollout_id AND deployment.attempt=1 AND
              (NOT deployment.node_id=ANY(NEW.node_ids) OR deployment.action <> 'rollback' OR
               deployment.config_version_id <> NEW.recovery_config_version_id OR
               NOT EXISTS (
                   SELECT 1
                   FROM deployment_status_events event
                   WHERE event.deployment_id=deployment.id AND event.attempt=deployment.attempt
                     AND event.transition_sequence=(
                         SELECT max(latest.transition_sequence)
                         FROM deployment_status_events latest
                         WHERE latest.deployment_id=deployment.id
                           AND latest.attempt=deployment.attempt
                     )
                     AND event.state='reverted'
                     AND event.active_config_identity_api_version=1
                     AND event.active_config_identity_schema=1
                     AND event.active_config_version_id=NEW.recovery_config_version_id
                     AND event.active_config_artifact_sha256=NEW.recovery_artifact_sha256
                     AND active_config_identity_artifact_valid_087(
                         deployment.node_id,NEW.recovery_config_version_id,
                         NEW.recovery_artifact_sha256,deployment.id,deployment.attempt,event.state
                     )
               ))
    );

    queued_mode := rollout_record.status='queued' AND NEW.created_at=rollout_record.created_at AND
        NEW.node_ids=ARRAY(
            SELECT deployment.node_id
            FROM node_deployments deployment
            WHERE deployment.rollout_id=NEW.rollout_id AND deployment.attempt=1
            ORDER BY deployment.node_id::text COLLATE "C"
        ) AND NOT EXISTS (
            SELECT 1 FROM node_deployments deployment
            WHERE deployment.rollout_id=NEW.rollout_id AND (
                deployment.attempt <> 1 OR deployment.action <> 'rollback' OR
                deployment.state <> 'queued' OR NOT deployment.node_id=ANY(NEW.node_ids) OR
                deployment.config_version_id <> NEW.recovery_config_version_id OR
                deployment.previous_config_version_id IS DISTINCT FROM candidate.candidate_config_version_id OR
                deployment.command_sha256 <> sha256(deployment.command_bytes) OR
                EXISTS (
                    SELECT 1 FROM deployment_status_events event
                    WHERE event.deployment_id=deployment.id AND event.attempt=deployment.attempt
                ) OR NOT EXISTS (
                    SELECT 1 FROM edge_command_outbox outbox
                    WHERE outbox.deployment_id=deployment.id
                      AND outbox.deployment_attempt=deployment.attempt
                      AND outbox.node_id=deployment.node_id
                      AND outbox.subject='cdnca.agent.commands.'||deployment.node_id::text
                      AND outbox.payload=deployment.command_bytes
                      AND outbox.payload_sha256=deployment.command_sha256
                      AND outbox.payload_sha256=sha256(outbox.payload)
                      AND outbox.status='pending' AND outbox.publish_attempts=0
                      AND outbox.published_at IS NULL AND outbox.last_error IS NULL
                      AND outbox.available_at=deployment.created_at
                      AND outbox.created_at=deployment.created_at
                      AND outbox.updated_at=deployment.created_at
                ) OR NOT EXISTS (
                    SELECT 1
                    FROM security_policy_activation_recovery_pending_095 pending
                    JOIN rollouts apply_rollout
                      ON apply_rollout.id=pending.rollout_id
                     AND apply_rollout.configuration_scope_id=pending.tenant_scope_id
                    JOIN node_deployments apply_deployment
                      ON apply_deployment.id=pending.deployment_id
                     AND apply_deployment.attempt=pending.deployment_attempt
                     AND apply_deployment.rollout_id=pending.rollout_id
                     AND apply_deployment.node_id=pending.node_id
                    JOIN edge_command_outbox apply_outbox ON apply_outbox.id=pending.outbox_id
                    JOIN nodes node ON node.id=pending.node_id
                    JOIN node_config_state node_state
                      ON node_state.node_id=pending.node_id
                     AND node_state.configuration_scope_id=pending.tenant_scope_id
                    WHERE pending.candidate_id=NEW.candidate_id
                      AND pending.tenant_scope_id=NEW.tenant_scope_id
                      AND pending.node_id=deployment.node_id
                      AND pending.action='apply'
                      AND pending.candidate_config_version_id=candidate.candidate_config_version_id
                      AND pending.candidate_artifact_sha256=candidate.candidate_artifact_sha256
                      AND pending.candidate_target_snapshot_sha256=candidate.target_snapshot_sha256
                      AND pending.recovery_config_version_id=NEW.recovery_config_version_id
                      AND pending.recovery_artifact_sha256=NEW.recovery_artifact_sha256
                      AND pending.generation=(
                          SELECT max(latest.generation)
                          FROM security_policy_activation_recovery_pending_095 latest
                          WHERE latest.candidate_id=NEW.candidate_id
                            AND latest.node_id=deployment.node_id
                            AND latest.action='apply'
                      )
                      AND node.scope_id=NEW.tenant_scope_id
                      AND apply_rollout.action='apply'
                      AND apply_rollout.config_version_id=candidate.candidate_config_version_id
                      AND apply_rollout.request_id=pending.request_id
                      AND apply_rollout.created_at=pending.created_at
                      AND apply_deployment.action='apply'
                      AND apply_deployment.config_version_id=candidate.candidate_config_version_id
                      AND apply_deployment.previous_config_version_id=NEW.recovery_config_version_id
                      AND apply_deployment.command_sha256=sha256(apply_deployment.command_bytes)
                      AND apply_outbox.deployment_id=apply_deployment.id
                      AND apply_outbox.deployment_attempt=apply_deployment.attempt
                      AND apply_outbox.node_id=apply_deployment.node_id
                      AND apply_outbox.subject='cdnca.agent.commands.'||apply_deployment.node_id::text
                      AND apply_outbox.payload=apply_deployment.command_bytes
                      AND apply_outbox.payload_sha256=apply_deployment.command_sha256
                      AND apply_outbox.payload_sha256=sha256(apply_outbox.payload)
                      AND node_state.current_config_identity_schema=1
                      AND node_state.current_config_version_id=candidate.candidate_config_version_id
                      AND node_state.current_config_artifact_sha256=candidate.candidate_artifact_sha256
                      AND node_state.previous_config_identity_schema=1
                      AND node_state.previous_config_version_id=NEW.recovery_config_version_id
                      AND node_state.previous_config_artifact_sha256=NEW.recovery_artifact_sha256
                )
            )
        );
    IF NOT proven_mode AND NOT queued_mode THEN
        RAISE EXCEPTION 'invalid security policy activation recovery rollout identity' USING ERRCODE = 'P8802';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_security_policy_activation_recovery_pending_095()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    candidate security_policy_activation_candidates%ROWTYPE;
    rollout_record rollouts%ROWTYPE;
    deployment node_deployments%ROWTYPE;
    outbox edge_command_outbox%ROWTYPE;
    node_state node_config_state%ROWTYPE;
    expected_nodes uuid[];
    expected_recovery_target bytea;
BEGIN
    SELECT * INTO candidate FROM security_policy_activation_candidates
    WHERE id=NEW.candidate_id AND tenant_scope_id=NEW.tenant_scope_id
    FOR UPDATE;
    SELECT * INTO rollout_record FROM rollouts
    WHERE id=NEW.rollout_id AND configuration_scope_id=NEW.tenant_scope_id;
    SELECT * INTO deployment FROM node_deployments
    WHERE id=NEW.deployment_id AND attempt=NEW.deployment_attempt;
    SELECT * INTO outbox FROM edge_command_outbox WHERE id=NEW.outbox_id;
    SELECT * INTO node_state FROM node_config_state
    WHERE node_id=NEW.node_id AND configuration_scope_id=NEW.tenant_scope_id;

    IF candidate.id IS NULL OR candidate.recovered_at IS NOT NULL OR
       rollout_record.id IS NULL OR deployment.id IS NULL OR
       outbox.id IS NULL OR node_state.node_id IS NULL OR NEW.generation <> COALESCE((
           SELECT max(prior.generation)
           FROM security_policy_activation_recovery_pending_095 prior
           WHERE prior.candidate_id=NEW.candidate_id AND prior.node_id=NEW.node_id
       ),0)+1 OR
       NEW.candidate_config_version_id <> candidate.candidate_config_version_id OR
       NEW.candidate_artifact_sha256 <> candidate.candidate_artifact_sha256 OR
       NEW.candidate_target_snapshot_sha256 <> candidate.target_snapshot_sha256 OR
       rollout_record.contract_version <> 1 OR rollout_record.status NOT IN ('queued','completed') OR
       rollout_record.request_id <> NEW.request_id OR rollout_record.created_at <> NEW.created_at OR
       deployment.rollout_id <> NEW.rollout_id OR deployment.node_id <> NEW.node_id OR
       deployment.action <> NEW.action OR deployment.attempt <> NEW.deployment_attempt OR
       deployment.attempt IS DISTINCT FROM (
           SELECT max(other.attempt) FROM node_deployments other
           WHERE other.rollout_id=NEW.rollout_id AND other.node_id=NEW.node_id
       ) OR
       deployment.command_sha256 <> sha256(deployment.command_bytes) OR
       outbox.deployment_id <> NEW.deployment_id OR
       outbox.deployment_attempt <> NEW.deployment_attempt OR outbox.node_id <> NEW.node_id OR
       outbox.payload <> deployment.command_bytes OR
       outbox.payload_sha256 <> deployment.command_sha256 OR
       outbox.payload_sha256 <> sha256(outbox.payload) THEN
        RAISE EXCEPTION 'invalid security activation recovery pending identity'
            USING ERRCODE = 'P9502';
    END IF;

    IF NEW.action = 'apply' THEN
        SELECT array_agg(other.node_id ORDER BY other.node_id::text COLLATE "C")
          INTO expected_nodes
        FROM node_deployments other
        JOIN node_config_state other_state
          ON other_state.node_id=other.node_id
         AND other_state.configuration_scope_id=NEW.tenant_scope_id
        WHERE other.rollout_id=NEW.rollout_id
          AND other.attempt=NEW.deployment_attempt
          AND other.action='apply'
          AND other.previous_config_version_id=NEW.recovery_config_version_id
          AND other_state.current_config_identity_schema=1
          AND other_state.current_config_version_id=NEW.recovery_config_version_id
          AND other_state.current_config_artifact_sha256=NEW.recovery_artifact_sha256;
        expected_recovery_target := security_policy_activation_recovery_target_sha256_095(
            NEW.tenant_scope_id, candidate.site_id, NEW.recovery_config_version_id,
            NEW.recovery_artifact_sha256, expected_nodes);
        IF rollout_record.action <> 'apply' OR
           deployment.config_version_id <> NEW.candidate_config_version_id OR
           deployment.previous_config_version_id IS DISTINCT FROM NEW.recovery_config_version_id OR
           NEW.recovery_config_version_id IS NULL OR NEW.recovery_artifact_sha256 IS NULL OR
           node_state.current_config_identity_schema <> 1 OR
           node_state.current_config_version_id <> NEW.recovery_config_version_id OR
           node_state.current_config_artifact_sha256 <> NEW.recovery_artifact_sha256 OR
           expected_recovery_target IS NULL OR
           NEW.recovery_target_snapshot_sha256 <> expected_recovery_target OR (
               NOT EXISTS (
                   SELECT 1 FROM security_policy_activation_rollouts activation
                   WHERE activation.candidate_id=NEW.candidate_id
                     AND activation.tenant_scope_id=NEW.tenant_scope_id
                     AND activation.rollout_id=NEW.rollout_id
                     AND activation.candidate_config_version_id=NEW.candidate_config_version_id
                     AND activation.candidate_artifact_sha256=NEW.candidate_artifact_sha256
                     AND activation.target_snapshot_sha256=NEW.candidate_target_snapshot_sha256
                     AND NEW.node_id=ANY(activation.node_ids)
               ) AND NOT (
                   rollout_record.config_version_id=candidate.candidate_config_version_id AND
                   ((rollout_record.idempotency_key=
                       'canary.'||encode(sha256(convert_to('canary:'||candidate.id::text,'UTF8')),'hex') AND
                     NEW.node_id=ANY(candidate.canary_node_ids) AND
                     (SELECT count(*) FROM node_deployments phase_deployment
                      WHERE phase_deployment.rollout_id=NEW.rollout_id AND phase_deployment.attempt=1)
                     =cardinality(candidate.canary_node_ids)) OR
                    (rollout_record.idempotency_key=
                       'expand.'||encode(sha256(convert_to('expand:'||candidate.id::text,'UTF8')),'hex') AND
                     NEW.node_id=ANY(candidate.expand_node_ids) AND
                     (SELECT count(*) FROM node_deployments phase_deployment
                      WHERE phase_deployment.rollout_id=NEW.rollout_id AND phase_deployment.attempt=1)
                     =cardinality(candidate.expand_node_ids)))
               )
           ) THEN
            RAISE EXCEPTION 'invalid security activation apply recovery pending identity'
                USING ERRCODE = 'P9502';
        END IF;
    ELSE
        SELECT recovery.node_ids INTO expected_nodes
        FROM security_policy_activation_recovery_rollouts recovery
        WHERE recovery.candidate_id=NEW.candidate_id
          AND recovery.tenant_scope_id=NEW.tenant_scope_id
          AND recovery.rollout_id=NEW.rollout_id
          AND recovery.recovery_config_version_id=NEW.recovery_config_version_id
          AND recovery.recovery_artifact_sha256=NEW.recovery_artifact_sha256
          AND NEW.node_id=ANY(recovery.node_ids)
          AND recovery.request_id=NEW.request_id;
        expected_recovery_target := security_policy_activation_recovery_target_sha256_095(
            NEW.tenant_scope_id, candidate.site_id, NEW.recovery_config_version_id,
            NEW.recovery_artifact_sha256, expected_nodes);
        IF rollout_record.action <> 'rollback' OR
           rollout_record.config_version_id <> NEW.recovery_config_version_id OR
           deployment.config_version_id <> NEW.recovery_config_version_id OR
           deployment.previous_config_version_id <> NEW.candidate_config_version_id OR
           expected_recovery_target IS NULL OR
           NEW.recovery_target_snapshot_sha256 <> expected_recovery_target THEN
            RAISE EXCEPTION 'invalid security activation rollback recovery pending identity'
                USING ERRCODE = 'P9502';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_security_policy_activation_recovery_proof_095()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    pending security_policy_activation_recovery_pending_095%ROWTYPE;
    deployment node_deployments%ROWTYPE;
    latest deployment_status_events%ROWTYPE;
    node_state node_config_state%ROWTYPE;
BEGIN
    SELECT * INTO pending FROM security_policy_activation_recovery_pending_095
    WHERE candidate_id=NEW.candidate_id AND node_id=NEW.node_id AND generation=NEW.generation;
    SELECT * INTO deployment FROM node_deployments
    WHERE id=NEW.deployment_id AND attempt=NEW.deployment_attempt;
    SELECT * INTO latest FROM deployment_status_events
    WHERE deployment_id=NEW.deployment_id AND attempt=NEW.deployment_attempt
    ORDER BY transition_sequence DESC LIMIT 1;
    SELECT * INTO node_state FROM node_config_state
    WHERE node_id=NEW.node_id AND configuration_scope_id=NEW.tenant_scope_id;

    IF pending.candidate_id IS NULL OR deployment.id IS NULL OR latest.id IS NULL OR
       node_state.node_id IS NULL OR
       ROW(NEW.candidate_id,NEW.tenant_scope_id,NEW.rollout_id,NEW.deployment_id,
           NEW.deployment_attempt,NEW.node_id,NEW.generation,NEW.action,
           NEW.candidate_config_version_id,NEW.candidate_artifact_sha256,
           NEW.recovery_config_version_id,NEW.recovery_artifact_sha256,
           NEW.candidate_target_snapshot_sha256,NEW.recovery_target_snapshot_sha256,NEW.outbox_id)
       IS DISTINCT FROM
       ROW(pending.candidate_id,pending.tenant_scope_id,pending.rollout_id,pending.deployment_id,
           pending.deployment_attempt,pending.node_id,pending.generation,pending.action,
           pending.candidate_config_version_id,pending.candidate_artifact_sha256,
           pending.recovery_config_version_id,pending.recovery_artifact_sha256,
           pending.candidate_target_snapshot_sha256,pending.recovery_target_snapshot_sha256,pending.outbox_id) OR
       NEW.action IS DISTINCT FROM 'rollback' OR
       NEW.deployment_attempt IS DISTINCT FROM (
           SELECT max(other.attempt) FROM node_deployments other
           WHERE other.rollout_id=NEW.rollout_id AND other.node_id=NEW.node_id
       ) OR deployment.action IS DISTINCT FROM 'rollback' OR deployment.state IS DISTINCT FROM 'reverted' OR
       latest.id IS DISTINCT FROM NEW.status_event_id OR
       latest.transition_sequence IS DISTINCT FROM NEW.transition_sequence OR
       latest.state IS DISTINCT FROM 'reverted' OR
       latest.active_config_identity_api_version IS DISTINCT FROM 1 OR
       latest.active_config_identity_schema IS DISTINCT FROM 1 OR
       latest.active_config_version_id IS DISTINCT FROM NEW.recovery_config_version_id OR
       latest.active_config_artifact_sha256 IS DISTINCT FROM NEW.recovery_artifact_sha256 OR
       node_state.current_config_identity_schema IS DISTINCT FROM 1 OR
       node_state.current_config_version_id IS DISTINCT FROM NEW.recovery_config_version_id OR
       node_state.current_config_artifact_sha256 IS DISTINCT FROM NEW.recovery_artifact_sha256 OR
       NEW.proved_at IS DISTINCT FROM latest.received_at OR active_config_identity_artifact_valid_087(
           NEW.node_id, NEW.recovery_config_version_id, NEW.recovery_artifact_sha256,
           NEW.deployment_id, NEW.deployment_attempt, latest.state
       ) IS NOT TRUE THEN
        RAISE EXCEPTION 'invalid security activation recovery proof identity'
            USING ERRCODE = 'P9502';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER security_policy_activation_recovery_pending_validate_095
BEFORE INSERT ON security_policy_activation_recovery_pending_095
FOR EACH ROW EXECUTE FUNCTION validate_security_policy_activation_recovery_pending_095();

CREATE TRIGGER security_policy_activation_recovery_proofs_validate_095
BEFORE INSERT ON security_policy_activation_recovery_proofs_095
FOR EACH ROW EXECUTE FUNCTION validate_security_policy_activation_recovery_proof_095();

CREATE FUNCTION prevent_security_policy_activation_recovery_fact_mutation_095()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'security activation recovery facts are append-only'
        USING ERRCODE = 'P9502';
END;
$$;

CREATE TRIGGER security_policy_activation_recovery_pending_immutable_095
BEFORE UPDATE OR DELETE ON security_policy_activation_recovery_pending_095
FOR EACH ROW EXECUTE FUNCTION prevent_security_policy_activation_recovery_fact_mutation_095();
CREATE TRIGGER security_policy_activation_recovery_pending_no_truncate_095
BEFORE TRUNCATE ON security_policy_activation_recovery_pending_095
FOR EACH STATEMENT EXECUTE FUNCTION prevent_security_policy_activation_recovery_fact_mutation_095();
CREATE TRIGGER security_policy_activation_recovery_proofs_immutable_095
BEFORE UPDATE OR DELETE ON security_policy_activation_recovery_proofs_095
FOR EACH ROW EXECUTE FUNCTION prevent_security_policy_activation_recovery_fact_mutation_095();
CREATE TRIGGER security_policy_activation_recovery_proofs_no_truncate_095
BEFORE TRUNCATE ON security_policy_activation_recovery_proofs_095
FOR EACH STATEMENT EXECUTE FUNCTION prevent_security_policy_activation_recovery_fact_mutation_095();

CREATE FUNCTION lock_security_policy_activation_retry_candidates_095()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.operation <> 'edge_rollout.retry' OR EXISTS (
        SELECT 1
        FROM edge_rollout_write_requests existing
        WHERE existing.actor_user_id=NEW.actor_user_id
          AND existing.operation=NEW.operation
          AND existing.idempotency_key=NEW.idempotency_key
    ) THEN
        RETURN NEW;
    END IF;
    PERFORM candidate.id
    FROM security_policy_activation_candidates candidate
    WHERE candidate.tenant_scope_id=NEW.configuration_scope_id
      AND EXISTS (
          SELECT 1
          FROM security_policy_activation_recovery_pending_095 pending
          WHERE pending.candidate_id=candidate.id
            AND pending.tenant_scope_id=NEW.configuration_scope_id
            AND pending.tenant_scope_id=candidate.tenant_scope_id
            AND pending.rollout_id=NEW.rollout_id
      )
    ORDER BY candidate.id
    FOR UPDATE;
    RETURN NEW;
END;
$$;

CREATE TRIGGER edge_rollout_write_request_security_activation_lock_095
BEFORE INSERT ON edge_rollout_write_requests
FOR EACH ROW EXECUTE FUNCTION lock_security_policy_activation_retry_candidates_095();

CREATE FUNCTION record_security_policy_activation_recovery_pending_095(checked_rollout_id uuid)
RETURNS bigint
LANGUAGE plpgsql
AS $$
DECLARE
    inserted_count bigint := 0;
    action_count bigint := 0;
BEGIN
    WITH inserted AS (
        INSERT INTO security_policy_activation_recovery_pending_095(
            candidate_id,tenant_scope_id,rollout_id,deployment_id,deployment_attempt,node_id,generation,
            action,candidate_config_version_id,candidate_artifact_sha256,recovery_config_version_id,
            recovery_artifact_sha256,candidate_target_snapshot_sha256,recovery_target_snapshot_sha256,
            outbox_id,request_id,created_at)
        SELECT candidate.id,candidate.tenant_scope_id,rollout.id,deployment.id,deployment.attempt,
               deployment.node_id,COALESCE((
                   SELECT max(prior.generation)
                   FROM security_policy_activation_recovery_pending_095 prior
                   WHERE prior.candidate_id=candidate.id AND prior.node_id=deployment.node_id
               ),0)+1,'apply',candidate.candidate_config_version_id,
               candidate.candidate_artifact_sha256,deployment.previous_config_version_id,
               node_state.current_config_artifact_sha256,candidate.target_snapshot_sha256,
               security_policy_activation_recovery_target_sha256_095(
                   candidate.tenant_scope_id,candidate.site_id,deployment.previous_config_version_id,
                   node_state.current_config_artifact_sha256,
                   ARRAY(
                       SELECT other.node_id
                       FROM node_deployments other
                       JOIN node_config_state other_state
                         ON other_state.node_id=other.node_id
                        AND other_state.configuration_scope_id=candidate.tenant_scope_id
                       WHERE other.rollout_id=rollout.id
                         AND other.attempt=deployment.attempt
                         AND other.action='apply'
                         AND other.previous_config_version_id=deployment.previous_config_version_id
                         AND other_state.current_config_identity_schema=1
                         AND other_state.current_config_version_id=deployment.previous_config_version_id
                         AND other_state.current_config_artifact_sha256=node_state.current_config_artifact_sha256
                       ORDER BY other.node_id::text COLLATE "C"
                   )
               ),outbox.id,rollout.request_id,rollout.created_at
        FROM rollouts rollout
        JOIN security_policy_activation_candidates candidate
          ON candidate.tenant_scope_id=rollout.configuration_scope_id
         AND candidate.candidate_config_version_id=rollout.config_version_id
        JOIN node_deployments deployment ON deployment.rollout_id=rollout.id
        JOIN edge_command_outbox outbox
          ON outbox.deployment_id=deployment.id AND outbox.deployment_attempt=deployment.attempt
        JOIN node_config_state node_state
          ON node_state.node_id=deployment.node_id
         AND node_state.configuration_scope_id=candidate.tenant_scope_id
        WHERE rollout.id=checked_rollout_id
          AND rollout.action='apply' AND deployment.action='apply'
          AND deployment.attempt=(
              SELECT max(latest.attempt) FROM node_deployments latest
              WHERE latest.rollout_id=deployment.rollout_id AND latest.node_id=deployment.node_id
          )
          AND (
              EXISTS (
                  SELECT 1 FROM security_policy_activation_rollouts activation
                  WHERE activation.candidate_id=candidate.id
                    AND activation.tenant_scope_id=candidate.tenant_scope_id
                    AND activation.rollout_id=rollout.id
                    AND activation.candidate_config_version_id=candidate.candidate_config_version_id
                    AND activation.candidate_artifact_sha256=candidate.candidate_artifact_sha256
                    AND activation.target_snapshot_sha256=candidate.target_snapshot_sha256
                    AND deployment.node_id=ANY(activation.node_ids)
              ) OR
              (rollout.idempotency_key=
                   'canary.'||encode(sha256(convert_to('canary:'||candidate.id::text,'UTF8')),'hex') AND
               deployment.node_id=ANY(candidate.canary_node_ids) AND
               (SELECT count(*) FROM node_deployments phase_deployment
                WHERE phase_deployment.rollout_id=rollout.id AND phase_deployment.attempt=1)
               =cardinality(candidate.canary_node_ids)) OR
              (rollout.idempotency_key=
                   'expand.'||encode(sha256(convert_to('expand:'||candidate.id::text,'UTF8')),'hex') AND
               deployment.node_id=ANY(candidate.expand_node_ids) AND
               (SELECT count(*) FROM node_deployments phase_deployment
                WHERE phase_deployment.rollout_id=rollout.id AND phase_deployment.attempt=1)
               =cardinality(candidate.expand_node_ids))
          )
          AND deployment.previous_config_version_id IS NOT NULL
          AND node_state.current_config_identity_schema=1
          AND node_state.current_config_version_id=deployment.previous_config_version_id
          AND octet_length(node_state.current_config_artifact_sha256)=32
          AND NOT EXISTS (
              SELECT 1 FROM security_policy_activation_recovery_pending_095 existing
              WHERE existing.deployment_id=deployment.id
                AND existing.deployment_attempt=deployment.attempt
          )
        FOR UPDATE OF candidate
        ON CONFLICT (deployment_id,deployment_attempt) DO NOTHING
        RETURNING 1
    ) SELECT count(*) INTO inserted_count FROM inserted;

    WITH inserted AS (
        INSERT INTO security_policy_activation_recovery_pending_095(
            candidate_id,tenant_scope_id,rollout_id,deployment_id,deployment_attempt,node_id,generation,
            action,candidate_config_version_id,candidate_artifact_sha256,recovery_config_version_id,
            recovery_artifact_sha256,candidate_target_snapshot_sha256,recovery_target_snapshot_sha256,
            outbox_id,request_id,created_at)
        SELECT candidate.id,candidate.tenant_scope_id,rollout.id,deployment.id,deployment.attempt,
               deployment.node_id,COALESCE((
                   SELECT max(prior.generation)
                   FROM security_policy_activation_recovery_pending_095 prior
                   WHERE prior.candidate_id=candidate.id AND prior.node_id=deployment.node_id
               ),0)+1,'rollback',candidate.candidate_config_version_id,
               candidate.candidate_artifact_sha256,recovery.recovery_config_version_id,
               recovery.recovery_artifact_sha256,candidate.target_snapshot_sha256,
               security_policy_activation_recovery_target_sha256_095(
                   candidate.tenant_scope_id,candidate.site_id,recovery.recovery_config_version_id,
                   recovery.recovery_artifact_sha256,recovery.node_ids
               ),outbox.id,recovery.request_id,rollout.created_at
        FROM security_policy_activation_recovery_rollouts recovery
        JOIN security_policy_activation_candidates candidate ON candidate.id=recovery.candidate_id
        JOIN rollouts rollout ON rollout.id=recovery.rollout_id
        JOIN node_deployments deployment ON deployment.rollout_id=rollout.id
        JOIN edge_command_outbox outbox
          ON outbox.deployment_id=deployment.id AND outbox.deployment_attempt=deployment.attempt
        WHERE recovery.rollout_id=checked_rollout_id
          AND rollout.action='rollback' AND deployment.action='rollback'
          AND deployment.attempt=(
              SELECT max(latest.attempt) FROM node_deployments latest
              WHERE latest.rollout_id=deployment.rollout_id AND latest.node_id=deployment.node_id
          )
          AND deployment.node_id=ANY(recovery.node_ids)
          AND NOT EXISTS (
              SELECT 1 FROM security_policy_activation_recovery_pending_095 existing
              WHERE existing.deployment_id=deployment.id
                AND existing.deployment_attempt=deployment.attempt
          )
        FOR UPDATE OF candidate
        ON CONFLICT (deployment_id,deployment_attempt) DO NOTHING
        RETURNING 1
    ) SELECT count(*) INTO action_count FROM inserted;
    RETURN inserted_count + action_count;
END;
$$;

CREATE FUNCTION record_security_policy_activation_recovery_pending_outbox_095()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_rollout_id uuid;
BEGIN
    SELECT rollout_id INTO target_rollout_id FROM node_deployments
    WHERE id=NEW.deployment_id AND attempt=NEW.deployment_attempt;
    PERFORM record_security_policy_activation_recovery_pending_095(target_rollout_id);
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER edge_command_outbox_security_activation_pending_095
AFTER INSERT ON edge_command_outbox
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION record_security_policy_activation_recovery_pending_outbox_095();

CREATE FUNCTION record_security_policy_activation_recovery_proofs_095()
RETURNS bigint
LANGUAGE plpgsql
AS $$
DECLARE
    inserted_count bigint;
BEGIN
    WITH inserted AS (
        INSERT INTO security_policy_activation_recovery_proofs_095(
            candidate_id,tenant_scope_id,rollout_id,deployment_id,deployment_attempt,node_id,generation,
            action,candidate_config_version_id,candidate_artifact_sha256,recovery_config_version_id,
            recovery_artifact_sha256,candidate_target_snapshot_sha256,recovery_target_snapshot_sha256,
            outbox_id,status_event_id,transition_sequence,proved_at)
        SELECT pending.candidate_id,pending.tenant_scope_id,pending.rollout_id,pending.deployment_id,
               pending.deployment_attempt,pending.node_id,pending.generation,pending.action,
               pending.candidate_config_version_id,pending.candidate_artifact_sha256,
               pending.recovery_config_version_id,pending.recovery_artifact_sha256,
               pending.candidate_target_snapshot_sha256,pending.recovery_target_snapshot_sha256,
               pending.outbox_id,latest.id,latest.transition_sequence,latest.received_at
        FROM security_policy_activation_recovery_pending_095 pending
        JOIN node_deployments deployment
          ON deployment.id=pending.deployment_id AND deployment.attempt=pending.deployment_attempt
        JOIN LATERAL (
            SELECT event.* FROM deployment_status_events event
            WHERE event.deployment_id=pending.deployment_id
              AND event.attempt=pending.deployment_attempt
            ORDER BY event.transition_sequence DESC LIMIT 1
        ) latest ON true
        JOIN node_config_state node_state
          ON node_state.node_id=pending.node_id
         AND node_state.configuration_scope_id=pending.tenant_scope_id
        WHERE pending.action='rollback'
          AND pending.deployment_attempt=(
              SELECT max(other.attempt) FROM node_deployments other
              WHERE other.rollout_id=pending.rollout_id AND other.node_id=pending.node_id
          )
          AND deployment.action='rollback' AND deployment.state='reverted'
          AND latest.state='reverted' AND latest.active_config_identity_api_version=1
          AND latest.active_config_identity_schema=1
          AND latest.active_config_version_id=pending.recovery_config_version_id
          AND latest.active_config_artifact_sha256=pending.recovery_artifact_sha256
          AND node_state.current_config_identity_schema=1
          AND node_state.current_config_version_id=pending.recovery_config_version_id
          AND node_state.current_config_artifact_sha256=pending.recovery_artifact_sha256
          AND active_config_identity_artifact_valid_087(
              pending.node_id,pending.recovery_config_version_id,pending.recovery_artifact_sha256,
              pending.deployment_id,pending.deployment_attempt,latest.state
          )
        ON CONFLICT (candidate_id,node_id,generation) DO NOTHING
        RETURNING 1
    ) SELECT count(*) INTO inserted_count FROM inserted;
    RETURN inserted_count;
END;
$$;

CREATE FUNCTION record_security_policy_activation_recovery_proof_event_095()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM record_security_policy_activation_recovery_proofs_095();
    RETURN NULL;
END;
$$;

CREATE FUNCTION record_security_policy_activation_recovery_proof_state_095()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM record_security_policy_activation_recovery_proofs_095();
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER deployment_status_security_activation_proof_095
AFTER INSERT ON deployment_status_events
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION record_security_policy_activation_recovery_proof_event_095();

CREATE CONSTRAINT TRIGGER node_config_state_security_activation_proof_095
AFTER INSERT OR UPDATE ON node_config_state
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION record_security_policy_activation_recovery_proof_state_095();

CREATE FUNCTION security_policy_activation_recovered_095(checked_candidate_id uuid)
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
           NOT security_policy_activation_recovered_095(NEW.id)
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
        IF EXISTS (
            SELECT 1 FROM edge_config_publications publication
            WHERE publication.rollout_id = NEW.id AND publication.contract_version = 1
        ) THEN
            RETURN NULL;
        END IF;
        IF NEW.action='apply' AND EXISTS (
            SELECT 1 FROM security_policy_activation_candidates candidate
            WHERE candidate.tenant_scope_id=NEW.configuration_scope_id
              AND candidate.candidate_config_version_id=NEW.config_version_id
              AND ((NEW.idempotency_key=
                    'canary.'||encode(sha256(convert_to('canary:'||candidate.id::text,'UTF8')),'hex') AND
                    (SELECT count(*) FROM node_deployments deployment
                     WHERE deployment.rollout_id=NEW.id AND deployment.attempt=1)
                    =cardinality(candidate.canary_node_ids) AND NOT EXISTS (
                        SELECT 1 FROM node_deployments deployment
                        WHERE deployment.rollout_id=NEW.id
                          AND NOT deployment.node_id=ANY(candidate.canary_node_ids)
                    )) OR
                   (NEW.idempotency_key=
                    'expand.'||encode(sha256(convert_to('expand:'||candidate.id::text,'UTF8')),'hex') AND
                    cardinality(candidate.expand_node_ids)>0 AND
                    (SELECT count(*) FROM node_deployments deployment
                     WHERE deployment.rollout_id=NEW.id AND deployment.attempt=1)
                    =cardinality(candidate.expand_node_ids) AND NOT EXISTS (
                        SELECT 1 FROM node_deployments deployment
                        WHERE deployment.rollout_id=NEW.id
                          AND NOT deployment.node_id=ANY(candidate.expand_node_ids)
                    )))
        ) THEN
            PERFORM record_security_policy_activation_recovery_pending_095(NEW.id);
            IF EXISTS (
                SELECT 1 FROM node_deployments deployment
                WHERE deployment.rollout_id=NEW.id AND NOT EXISTS (
                    SELECT 1 FROM security_policy_activation_recovery_pending_095 pending
                    JOIN edge_command_outbox outbox ON outbox.id=pending.outbox_id
                    WHERE pending.rollout_id=NEW.id AND pending.deployment_id=deployment.id
                      AND pending.deployment_attempt=deployment.attempt
                      AND pending.node_id=deployment.node_id AND pending.action='apply'
                      AND outbox.deployment_id=deployment.id
                      AND outbox.deployment_attempt=deployment.attempt
                )
            ) THEN
                RAISE EXCEPTION 'security activation derived apply rollout lacks exact recovery pending facts'
                    USING ERRCODE = 'P9502';
            END IF;
            RETURN NULL;
        END IF;
        IF EXISTS (
            SELECT 1 FROM security_policy_activation_rollouts activation
            JOIN security_policy_activation_candidates candidate ON candidate.id=activation.candidate_id
            WHERE activation.rollout_id=NEW.id
              AND activation.tenant_scope_id=NEW.configuration_scope_id
              AND activation.candidate_config_version_id=NEW.config_version_id
              AND candidate.candidate_artifact_sha256=activation.candidate_artifact_sha256
              AND candidate.target_snapshot_sha256=activation.target_snapshot_sha256
              AND NEW.action='apply'
        ) THEN
            PERFORM record_security_policy_activation_recovery_pending_095(NEW.id);
            IF EXISTS (
                SELECT 1 FROM node_deployments deployment
                WHERE deployment.rollout_id=NEW.id AND NOT EXISTS (
                    SELECT 1 FROM security_policy_activation_recovery_pending_095 pending
                    JOIN edge_command_outbox outbox ON outbox.id=pending.outbox_id
                    WHERE pending.rollout_id=NEW.id AND pending.deployment_id=deployment.id
                      AND pending.deployment_attempt=deployment.attempt
                      AND pending.node_id=deployment.node_id AND pending.action='apply'
                      AND outbox.deployment_id=deployment.id
                      AND outbox.deployment_attempt=deployment.attempt
                )
            ) THEN
                RAISE EXCEPTION 'security activation apply rollout lacks exact recovery pending facts'
                    USING ERRCODE = 'P9502';
            END IF;
            RETURN NULL;
        END IF;
        IF EXISTS (
            SELECT 1 FROM security_policy_activation_recovery_rollouts recovery
            WHERE recovery.rollout_id=NEW.id
              AND recovery.tenant_scope_id=NEW.configuration_scope_id
              AND recovery.recovery_config_version_id=NEW.config_version_id
              AND NEW.action='rollback'
        ) THEN
            PERFORM record_security_policy_activation_recovery_pending_095(NEW.id);
            IF EXISTS (
                SELECT 1 FROM node_deployments deployment
                WHERE deployment.rollout_id=NEW.id AND NOT EXISTS (
                    SELECT 1 FROM security_policy_activation_recovery_pending_095 pending
                    JOIN edge_command_outbox outbox ON outbox.id=pending.outbox_id
                    WHERE pending.rollout_id=NEW.id AND pending.deployment_id=deployment.id
                      AND pending.deployment_attempt=deployment.attempt
                      AND pending.node_id=deployment.node_id AND pending.action='rollback'
                      AND outbox.deployment_id=deployment.id
                      AND outbox.deployment_attempt=deployment.attempt
                )
            ) THEN
                RAISE EXCEPTION 'security activation rollback rollout lacks exact recovery pending facts'
                    USING ERRCODE = 'P9502';
            END IF;
            RETURN NULL;
        END IF;
        RAISE EXCEPTION 'contract rollout requires an audited publication or security activation fact'
            USING ERRCODE = 'P0001';
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

DO $$
DECLARE
    rollout_record record;
BEGIN
    FOR rollout_record IN
        SELECT activation.rollout_id
        FROM security_policy_activation_rollouts activation
        JOIN rollouts rollout ON rollout.id=activation.rollout_id
        ORDER BY rollout.created_at,activation.rollout_id
    LOOP
        PERFORM record_security_policy_activation_recovery_pending_095(rollout_record.rollout_id);
    END LOOP;
    FOR rollout_record IN
        SELECT recovery.rollout_id
        FROM security_policy_activation_recovery_rollouts recovery
        JOIN rollouts rollout ON rollout.id=recovery.rollout_id
        ORDER BY rollout.created_at,recovery.rollout_id
    LOOP
        PERFORM record_security_policy_activation_recovery_pending_095(rollout_record.rollout_id);
    END LOOP;
    PERFORM record_security_policy_activation_recovery_proofs_095();

    IF EXISTS (
        SELECT 1 FROM node_deployments deployment
        WHERE deployment.rollout_id IN (
            SELECT rollout_id FROM security_policy_activation_rollouts
            UNION
            SELECT rollout_id FROM security_policy_activation_recovery_rollouts
        ) AND deployment.attempt=(
            SELECT max(latest.attempt) FROM node_deployments latest
            WHERE latest.rollout_id=deployment.rollout_id AND latest.node_id=deployment.node_id
        ) AND NOT EXISTS (
            SELECT 1 FROM security_policy_activation_recovery_pending_095 pending
            WHERE pending.deployment_id=deployment.id
              AND pending.deployment_attempt=deployment.attempt
              AND pending.rollout_id=deployment.rollout_id
              AND pending.node_id=deployment.node_id
        )
    ) OR EXISTS (
        SELECT 1 FROM security_policy_activation_candidates candidate
        WHERE candidate.recovered_at IS NOT NULL
          AND NOT security_policy_activation_recovered_095(candidate.id)
    ) OR EXISTS (
        SELECT 1
        FROM security_policy_activation_candidates candidate
        JOIN security_policy_activation_recovery_pending_095 pending
          ON pending.candidate_id=candidate.id AND pending.action='apply'
        JOIN node_config_state state
          ON state.node_id=pending.node_id AND state.configuration_scope_id=pending.tenant_scope_id
        WHERE candidate.candidate_status IN ('failed','cancelled','expired')
          AND state.current_config_identity_schema=1
          AND state.current_config_version_id=pending.candidate_config_version_id
          AND state.current_config_artifact_sha256=pending.candidate_artifact_sha256
          AND NOT EXISTS (
              SELECT 1 FROM security_policy_activation_recovery_pending_095 recovery
              WHERE recovery.candidate_id=pending.candidate_id
                AND recovery.node_id=pending.node_id AND recovery.action='rollback'
          )
    ) THEN
        RAISE EXCEPTION 'migration 095 cannot prove pre-existing security activation recovery facts'
            USING ERRCODE = 'P9502';
    END IF;
END;
$$;

REVOKE ALL ON TABLE security_policy_activation_recovery_pending_095 FROM PUBLIC;
REVOKE ALL ON TABLE security_policy_activation_recovery_proofs_095 FROM PUBLIC;
REVOKE ALL ON FUNCTION security_policy_activation_recovery_target_sha256_095(uuid,uuid,uuid,bytea,uuid[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_security_policy_activation_recovery_pending_095() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_security_policy_activation_recovery_proof_095() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_security_policy_activation_recovery_fact_mutation_095() FROM PUBLIC;
REVOKE ALL ON FUNCTION lock_security_policy_activation_retry_candidates_095() FROM PUBLIC;
REVOKE ALL ON FUNCTION record_security_policy_activation_recovery_pending_095(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION record_security_policy_activation_recovery_pending_outbox_095() FROM PUBLIC;
REVOKE ALL ON FUNCTION record_security_policy_activation_recovery_proofs_095() FROM PUBLIC;
REVOKE ALL ON FUNCTION record_security_policy_activation_recovery_proof_event_095() FROM PUBLIC;
REVOKE ALL ON FUNCTION record_security_policy_activation_recovery_proof_state_095() FROM PUBLIC;
REVOKE ALL ON FUNCTION security_policy_activation_recovered_095(uuid) FROM PUBLIC;
