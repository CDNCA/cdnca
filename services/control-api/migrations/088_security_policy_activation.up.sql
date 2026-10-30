LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE security_policy_site_bindings,
    security_policy_publications,
    security_policy_publication_targets,
    edge_configuration_scopes,
    config_versions,
    configuration_artifacts,
    rollouts,
    node_deployments,
    deployment_status_events,
    node_config_state
IN SHARE ROW EXCLUSIVE MODE;

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
        WHERE version = 87
          AND migration_id = '087_active_config_identity_control'
          AND checksum_sha256 = 'bf9388d78ed42d1d4faba324863b4efd47fa0e7aefff5e37c48bc0e8da66383b'
          AND down_checksum_sha256 = 'd6e9ddd6e856b228733c3615422acfe8567d65246d941ffc338ec76e6eb7997b'
          AND integrity_state = 'verified'
    ) THEN
        RAISE EXCEPTION 'migration 088 requires the exact verified 087 release head'
            USING ERRCODE = 'P8800';
    END IF;
END;
$$;

CREATE FUNCTION valid_security_activation_nodes_088(node_ids uuid[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT node_ids IS NOT NULL AND cardinality(node_ids) <= 10000 AND
           NOT EXISTS (SELECT 1 FROM unnest(node_ids) node_id WHERE node_id IS NULL) AND
           cardinality(node_ids) = (SELECT count(DISTINCT node_id) FROM unnest(node_ids) node_id)
$$;

CREATE TABLE security_policy_activation_config_facts (
    tenant_scope_id uuid NOT NULL,
    config_version_id uuid NOT NULL,
    artifact_sha256 bytea NOT NULL CHECK (octet_length(artifact_sha256) = 32),
    policy_kind text NOT NULL CHECK (policy_kind IN ('waf','acl','cc')),
    required_capabilities jsonb NOT NULL CHECK (
        jsonb_typeof(required_capabilities) = 'array' AND jsonb_array_length(required_capabilities) > 0
    ),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, config_version_id),
    UNIQUE (tenant_scope_id, config_version_id, artifact_sha256),
    FOREIGN KEY (tenant_scope_id, config_version_id)
        REFERENCES config_versions(configuration_scope_id, id) ON DELETE RESTRICT
);

CREATE TABLE security_policy_activation_candidates (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    binding_revision bigint NOT NULL CHECK (binding_revision > 0),
    last_bundle_id uuid NOT NULL,
    last_claimed_policy_version bigint NOT NULL CHECK (last_claimed_policy_version > 0),
    expected_active_policy_version bigint NOT NULL CHECK (expected_active_policy_version >= 0),
    candidate_source_revision bigint NOT NULL CHECK (candidate_source_revision > 1),
    candidate_config_version_id uuid NOT NULL,
    candidate_artifact_sha256 bytea NOT NULL CHECK (octet_length(candidate_artifact_sha256) = 32),
    target_snapshot_sha256 bytea NOT NULL CHECK (octet_length(target_snapshot_sha256) = 32),
    required_capabilities jsonb NOT NULL CHECK (jsonb_typeof(required_capabilities) = 'array'),
    candidate_status text NOT NULL CHECK (
        candidate_status IN ('claimed','canary','expanding','healthy','failed','cancelled','expired','promoted')
    ),
    canary_node_ids uuid[] NOT NULL CHECK (
        cardinality(canary_node_ids) > 0 AND valid_security_activation_nodes_088(canary_node_ids)
    ),
    expand_node_ids uuid[] NOT NULL DEFAULT '{}'::uuid[] CHECK (
        valid_security_activation_nodes_088(expand_node_ids)
    ),
    idempotency_key text NOT NULL CHECK (
        char_length(idempotency_key) BETWEEN 1 AND 128 AND
        idempotency_key ~ '^[A-Za-z0-9._-]+$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    request_id text NOT NULL CHECK (
        request_id = btrim(request_id) AND char_length(request_id) BETWEEN 1 AND 128 AND
        request_id !~ '[[:cntrl:]]' AND
        position(U&'\2028' in request_id) = 0 AND position(U&'\2029' in request_id) = 0
    ),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    promoted_at timestamptz,
    recovered_at timestamptz,
    UNIQUE (tenant_scope_id, idempotency_key),
    UNIQUE (tenant_scope_id, id),
    UNIQUE (tenant_scope_id, id, candidate_config_version_id, candidate_artifact_sha256, target_snapshot_sha256),
    FOREIGN KEY (tenant_scope_id, binding_id)
        REFERENCES security_policy_site_bindings(tenant_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, last_bundle_id, binding_id)
        REFERENCES security_policy_publications(tenant_scope_id, id, binding_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, site_id)
        REFERENCES sites(scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, candidate_config_version_id)
        REFERENCES config_versions(configuration_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, candidate_config_version_id, candidate_artifact_sha256)
        REFERENCES security_policy_activation_config_facts(
            tenant_scope_id, config_version_id, artifact_sha256
        ) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (NOT (canary_node_ids && expand_node_ids)),
    CHECK (expires_at > created_at),
    CHECK (
        (candidate_status = 'promoted' AND promoted_at IS NOT NULL AND promoted_at >= created_at) OR
        (candidate_status <> 'promoted' AND promoted_at IS NULL)
    ),
    CHECK (
        recovered_at IS NULL OR
        (candidate_status IN ('failed','cancelled','expired') AND recovered_at >= updated_at)
    )
);

CREATE INDEX security_policy_activation_candidates_status_idx
    ON security_policy_activation_candidates (candidate_status, expires_at, created_at);
CREATE INDEX security_policy_activation_candidates_binding_idx
    ON security_policy_activation_candidates (tenant_scope_id, binding_id, created_at DESC);
CREATE UNIQUE INDEX security_policy_activation_candidates_open_binding_idx
    ON security_policy_activation_candidates (tenant_scope_id, binding_id)
    WHERE candidate_status IN ('claimed','canary','expanding','healthy') OR
          (candidate_status IN ('failed','cancelled','expired') AND recovered_at IS NULL);

CREATE TABLE security_policy_activation_rollouts (
    candidate_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    phase text NOT NULL CHECK (phase IN ('canary','expand')),
    rollout_id uuid NOT NULL,
    candidate_config_version_id uuid NOT NULL,
    candidate_artifact_sha256 bytea NOT NULL CHECK (octet_length(candidate_artifact_sha256) = 32),
    target_snapshot_sha256 bytea NOT NULL CHECK (octet_length(target_snapshot_sha256) = 32),
    node_ids uuid[] NOT NULL CHECK (
        cardinality(node_ids) > 0 AND valid_security_activation_nodes_088(node_ids)
    ),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (candidate_id, phase),
    UNIQUE (rollout_id),
    FOREIGN KEY (tenant_scope_id, candidate_id, candidate_config_version_id,
                 candidate_artifact_sha256, target_snapshot_sha256)
        REFERENCES security_policy_activation_candidates(
            tenant_scope_id, id, candidate_config_version_id,
            candidate_artifact_sha256, target_snapshot_sha256
        ) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, rollout_id)
        REFERENCES rollouts(configuration_scope_id, id) ON DELETE RESTRICT
);

CREATE TABLE security_policy_activation_events (
    id uuid PRIMARY KEY,
    candidate_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    event_key text NOT NULL CHECK (
        char_length(event_key) BETWEEN 1 AND 128 AND event_key ~ '^[A-Za-z0-9._:-]+$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    action text NOT NULL CHECK (action IN ('claim','canary','wait','expand','promote','fail','cancel','expire','rollback','recover')),
    from_status text,
    to_status text NOT NULL CHECK (
        to_status IN ('claimed','canary','expanding','healthy','failed','cancelled','expired','promoted')
    ),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    request_id text NOT NULL CHECK (
        request_id = btrim(request_id) AND char_length(request_id) BETWEEN 1 AND 128 AND
        request_id !~ '[[:cntrl:]]'
    ),
    created_at timestamptz NOT NULL,
    UNIQUE (candidate_id, event_key),
    FOREIGN KEY (tenant_scope_id, candidate_id)
        REFERENCES security_policy_activation_candidates(tenant_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

CREATE TABLE security_policy_activation_recovery_rollouts (
    candidate_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    rollout_id uuid NOT NULL,
    recovery_config_version_id uuid NOT NULL,
    recovery_artifact_sha256 bytea NOT NULL CHECK (octet_length(recovery_artifact_sha256) = 32),
    target_snapshot_sha256 bytea NOT NULL CHECK (octet_length(target_snapshot_sha256) = 32),
    node_ids uuid[] NOT NULL CHECK (
        cardinality(node_ids) > 0 AND valid_security_activation_nodes_088(node_ids)
    ),
    request_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (candidate_id, rollout_id),
    UNIQUE (rollout_id),
    FOREIGN KEY (tenant_scope_id, candidate_id)
        REFERENCES security_policy_activation_candidates(tenant_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, rollout_id)
        REFERENCES rollouts(configuration_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, recovery_config_version_id)
        REFERENCES config_versions(configuration_scope_id, id) ON DELETE RESTRICT
);

CREATE FUNCTION validate_security_policy_activation_rollout_088()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    candidate security_policy_activation_candidates%ROWTYPE;
    rollout_record rollouts%ROWTYPE;
    expected_nodes uuid[];
BEGIN
    SELECT * INTO candidate FROM security_policy_activation_candidates
    WHERE id=NEW.candidate_id AND tenant_scope_id=NEW.tenant_scope_id;
    SELECT * INTO rollout_record FROM rollouts
    WHERE id=NEW.rollout_id AND configuration_scope_id=NEW.tenant_scope_id;
    expected_nodes := CASE WHEN NEW.phase='canary' THEN candidate.canary_node_ids ELSE candidate.expand_node_ids END;
    IF candidate.id IS NULL OR rollout_record.id IS NULL OR cardinality(expected_nodes)=0 OR
       NEW.node_ids <> expected_nodes OR rollout_record.contract_version <> 1 OR
       rollout_record.status NOT IN ('queued','completed') OR rollout_record.action <> 'apply' OR
       rollout_record.config_version_id <> candidate.candidate_config_version_id OR
       NEW.candidate_config_version_id <> candidate.candidate_config_version_id OR
       NEW.candidate_artifact_sha256 <> candidate.candidate_artifact_sha256 OR
       NEW.target_snapshot_sha256 <> candidate.target_snapshot_sha256 OR
       (SELECT count(*) FROM node_deployments deployment
        WHERE deployment.rollout_id=NEW.rollout_id AND deployment.attempt=1) <> cardinality(expected_nodes) OR
       EXISTS (
           SELECT 1 FROM node_deployments deployment
           WHERE deployment.rollout_id=NEW.rollout_id AND deployment.attempt=1 AND
                 (NOT deployment.node_id=ANY(expected_nodes) OR deployment.action <> 'apply' OR
                  deployment.config_version_id <> candidate.candidate_config_version_id OR
                  NOT active_config_identity_artifact_valid_087(
                      deployment.node_id, candidate.candidate_config_version_id,
                      candidate.candidate_artifact_sha256, deployment.id, deployment.attempt,
                      (SELECT event.state FROM deployment_status_events event
                       WHERE event.deployment_id=deployment.id AND event.attempt=deployment.attempt
                       ORDER BY event.transition_sequence DESC LIMIT 1)
                  ))
       ) THEN
        RAISE EXCEPTION 'invalid security policy activation rollout identity' USING ERRCODE = 'P8802';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER security_policy_activation_rollouts_validate
BEFORE INSERT ON security_policy_activation_rollouts
FOR EACH ROW EXECUTE FUNCTION validate_security_policy_activation_rollout_088();

CREATE FUNCTION validate_security_policy_activation_recovery_rollout_088()
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

CREATE FUNCTION security_policy_activation_recovered_088(checked_candidate_id uuid)
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

CREATE TRIGGER security_policy_activation_recovery_rollouts_validate
BEFORE INSERT ON security_policy_activation_recovery_rollouts
FOR EACH ROW EXECUTE FUNCTION validate_security_policy_activation_recovery_rollout_088();

CREATE FUNCTION security_policy_activation_phase_healthy_088(checked_candidate_id uuid, checked_phase text)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM security_policy_activation_rollouts activation_rollout
        JOIN security_policy_activation_candidates candidate ON candidate.id=activation_rollout.candidate_id
        JOIN rollouts rollout ON rollout.id=activation_rollout.rollout_id
        WHERE activation_rollout.candidate_id=checked_candidate_id AND activation_rollout.phase=checked_phase
          AND rollout.configuration_scope_id=candidate.tenant_scope_id
          AND rollout.config_version_id=candidate.candidate_config_version_id
          AND rollout.contract_version=1 AND rollout.action='apply' AND rollout.status IN ('queued','completed')
          AND (SELECT count(*) FROM node_deployments deployment
               WHERE deployment.rollout_id=activation_rollout.rollout_id AND deployment.attempt=1) =
              cardinality(activation_rollout.node_ids)
          AND NOT EXISTS (
              SELECT 1
              FROM unnest(activation_rollout.node_ids) expected_node_id
              WHERE NOT EXISTS (
                  SELECT 1
                  FROM node_deployments deployment
                  JOIN LATERAL (
                      SELECT event.state,event.active_config_identity_api_version,
                             event.active_config_identity_schema,event.active_config_version_id,
                             event.active_config_artifact_sha256
                      FROM deployment_status_events event
                      WHERE event.deployment_id=deployment.id AND event.attempt=deployment.attempt
                      ORDER BY event.transition_sequence DESC
                      LIMIT 1
                  ) latest ON true
                  WHERE deployment.rollout_id=activation_rollout.rollout_id
                    AND deployment.node_id=expected_node_id
                    AND deployment.attempt=(
                        SELECT max(attempt) FROM node_deployments retry
                        WHERE retry.rollout_id=activation_rollout.rollout_id
                          AND retry.node_id=expected_node_id
                    )
                    AND deployment.action='apply'
                    AND deployment.config_version_id=candidate.candidate_config_version_id
                    AND latest.state='healthy'
                    AND latest.active_config_identity_api_version=1
                    AND latest.active_config_identity_schema=1
                    AND latest.active_config_version_id=candidate.candidate_config_version_id
                    AND latest.active_config_artifact_sha256=candidate.candidate_artifact_sha256
                    AND active_config_identity_artifact_valid_087(
                        deployment.node_id, latest.active_config_version_id,
                        latest.active_config_artifact_sha256, deployment.id, deployment.attempt,
                        latest.state
                    )
              )
          )
    )
$$;

CREATE FUNCTION protect_security_policy_activation_candidate()
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

CREATE TRIGGER security_policy_activation_candidates_protected
BEFORE UPDATE OR DELETE ON security_policy_activation_candidates
FOR EACH ROW EXECUTE FUNCTION protect_security_policy_activation_candidate();
CREATE TRIGGER security_policy_activation_candidates_no_truncate
BEFORE TRUNCATE ON security_policy_activation_candidates
FOR EACH STATEMENT EXECUTE FUNCTION protect_security_policy_activation_candidate();

CREATE FUNCTION prevent_security_policy_activation_fact_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'security policy activation facts are append-only' USING ERRCODE = 'P8802';
END;
$$;

CREATE TRIGGER security_policy_activation_rollouts_append_only
BEFORE UPDATE OR DELETE ON security_policy_activation_rollouts
FOR EACH ROW EXECUTE FUNCTION prevent_security_policy_activation_fact_mutation();
CREATE TRIGGER security_policy_activation_rollouts_no_truncate
BEFORE TRUNCATE ON security_policy_activation_rollouts
FOR EACH STATEMENT EXECUTE FUNCTION prevent_security_policy_activation_fact_mutation();
CREATE TRIGGER security_policy_activation_config_facts_append_only
BEFORE UPDATE OR DELETE ON security_policy_activation_config_facts
FOR EACH ROW EXECUTE FUNCTION prevent_security_policy_activation_fact_mutation();
CREATE TRIGGER security_policy_activation_config_facts_no_truncate
BEFORE TRUNCATE ON security_policy_activation_config_facts
FOR EACH STATEMENT EXECUTE FUNCTION prevent_security_policy_activation_fact_mutation();
CREATE TRIGGER security_policy_activation_recovery_rollouts_append_only
BEFORE UPDATE OR DELETE ON security_policy_activation_recovery_rollouts
FOR EACH ROW EXECUTE FUNCTION prevent_security_policy_activation_fact_mutation();
CREATE TRIGGER security_policy_activation_recovery_rollouts_no_truncate
BEFORE TRUNCATE ON security_policy_activation_recovery_rollouts
FOR EACH STATEMENT EXECUTE FUNCTION prevent_security_policy_activation_fact_mutation();
CREATE TRIGGER security_policy_activation_events_append_only
BEFORE UPDATE OR DELETE ON security_policy_activation_events
FOR EACH ROW EXECUTE FUNCTION prevent_security_policy_activation_fact_mutation();
CREATE TRIGGER security_policy_activation_events_no_truncate
BEFORE TRUNCATE ON security_policy_activation_events
FOR EACH STATEMENT EXECUTE FUNCTION prevent_security_policy_activation_fact_mutation();

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
