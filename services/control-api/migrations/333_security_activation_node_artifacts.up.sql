LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE security_policy_activation_config_facts,
    security_policy_activation_candidates,
    security_policy_activation_rollouts,
    security_policy_activation_recovery_rollouts,
    security_activation_capability_waits,
    configuration_artifacts
IN SHARE ROW EXCLUSIVE MODE;

DO $migration_333_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 332 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 332 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=332 AND
        migration_id='332_node_traffic_history_retention' AND
        checksum_sha256='978cd44a59362d5622eddfbe0753475169ef9c9d8730217284ff42d830035b93' AND
        down_checksum_sha256='029c9d24d1fa9fce2c1fbb998230c3e3d9cbfb184e2c5fc00eebfcb97ab840cf' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 333 requires the exact verified 332 release head' USING ERRCODE='P3330';
    END IF;
END;
$migration_333_up$;

-- r136 g11 gap 8: security activation on site runtime v2. A v2 candidate's
-- identity (candidate_artifact_sha256, config_facts.artifact_sha256) is the
-- digest of its plaintext bundle; each target node gets its own HPKE artifact
-- (bound to a pre-assigned deployment_id/event_id, attempt 1), recorded here.
-- A v1 candidate has no rows and keeps comparing nodes with its one artifact.
CREATE TABLE security_policy_activation_node_artifacts_333 (
    tenant_scope_id uuid NOT NULL,
    config_version_id uuid NOT NULL,
    node_id uuid NOT NULL,
    deployment_id uuid NOT NULL UNIQUE,
    event_id uuid NOT NULL UNIQUE,
    artifact_id uuid NOT NULL UNIQUE,
    artifact_sha256 bytea NOT NULL CHECK (octet_length(artifact_sha256) = 32),
    recipient_key_id text NOT NULL CHECK (recipient_key_id ~ '^x25519:[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, config_version_id, node_id),
    UNIQUE (config_version_id, recipient_key_id),
    FOREIGN KEY (tenant_scope_id, config_version_id)
        REFERENCES security_policy_activation_config_facts(tenant_scope_id, config_version_id) ON DELETE RESTRICT,
    FOREIGN KEY (artifact_id) REFERENCES configuration_artifacts(id) ON DELETE RESTRICT
);

CREATE FUNCTION validate_security_policy_activation_node_artifact_333()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM configuration_artifacts artifact
        JOIN config_versions version ON version.id=artifact.config_version_id
        WHERE artifact.id=NEW.artifact_id AND artifact.config_version_id=NEW.config_version_id
          AND version.configuration_scope_id=NEW.tenant_scope_id
          AND artifact.kind='configuration'
          AND artifact.encryption_algorithm='hpke_x25519_hkdf_sha256_aes_256_gcm'
          AND artifact.recipient_key_id=NEW.recipient_key_id
          AND artifact.sha256=NEW.artifact_sha256 AND artifact.sha256=sha256(artifact.wire_bytes)
    ) THEN
        RAISE EXCEPTION 'invalid security activation node artifact' USING ERRCODE='P3332';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER security_policy_activation_node_artifacts_validate_333
BEFORE INSERT ON security_policy_activation_node_artifacts_333
FOR EACH ROW EXECUTE FUNCTION validate_security_policy_activation_node_artifact_333();
CREATE TRIGGER security_policy_activation_node_artifacts_append_only_333
BEFORE UPDATE OR DELETE ON security_policy_activation_node_artifacts_333
FOR EACH ROW EXECUTE FUNCTION prevent_security_policy_activation_fact_mutation();
CREATE TRIGGER security_policy_activation_node_artifacts_no_truncate_333
BEFORE TRUNCATE ON security_policy_activation_node_artifacts_333
FOR EACH STATEMENT EXECUTE FUNCTION prevent_security_policy_activation_fact_mutation();

-- The artifact digest a node runs when it runs the candidate: its own v2
-- artifact, or (v1, no rows for the config) the candidate's one artifact.
-- A v2 config without a row for the node yields NULL: never healthy.
CREATE FUNCTION security_policy_activation_node_artifact_sha256_333(
    checked_tenant_scope_id uuid,
    checked_config_version_id uuid,
    checked_node_id uuid,
    candidate_artifact_sha256 bytea
)
RETURNS bytea
LANGUAGE sql
STABLE
AS $$
    SELECT CASE
        WHEN NOT EXISTS (
            SELECT 1 FROM security_policy_activation_node_artifacts_333 any_node
            WHERE any_node.tenant_scope_id=checked_tenant_scope_id
              AND any_node.config_version_id=checked_config_version_id
        ) THEN candidate_artifact_sha256
        ELSE (
            SELECT node_artifact.artifact_sha256 FROM security_policy_activation_node_artifacts_333 node_artifact
            WHERE node_artifact.tenant_scope_id=checked_tenant_scope_id
              AND node_artifact.config_version_id=checked_config_version_id
              AND node_artifact.node_id=checked_node_id
        )
    END
$$;

-- Each comparison of a node-reported digest with the candidate digest asks
-- for that node's expected digest instead. Replace exactly one occurrence.
DO $migration_333_functions$
DECLARE
    replacement record;
    definition text;
    occurrences integer;
BEGIN
    FOR replacement IN SELECT * FROM (VALUES
        ('validate_security_policy_activation_rollout_088()',
         E'candidate.candidate_artifact_sha256, deployment.id, deployment.attempt,',
         E'security_policy_activation_node_artifact_sha256_333(candidate.tenant_scope_id, candidate.candidate_config_version_id, deployment.node_id, candidate.candidate_artifact_sha256), deployment.id, deployment.attempt,'),
        ('security_policy_activation_phase_healthy_088(uuid,text)',
         E'AND latest.active_config_artifact_sha256=candidate.candidate_artifact_sha256',
         E'AND latest.active_config_artifact_sha256=security_policy_activation_node_artifact_sha256_333(candidate.tenant_scope_id, candidate.candidate_config_version_id, deployment.node_id, candidate.candidate_artifact_sha256)'),
        ('validate_security_policy_activation_recovery_rollout_088()',
         E'AND node_state.current_config_artifact_sha256=candidate.candidate_artifact_sha256',
         E'AND node_state.current_config_artifact_sha256=security_policy_activation_node_artifact_sha256_333(candidate.tenant_scope_id, candidate.candidate_config_version_id, pending.node_id, candidate.candidate_artifact_sha256)')
    ) AS item(signature, needle, value) LOOP
        SELECT pg_get_functiondef(replacement.signature::regprocedure) INTO definition;
        occurrences := (length(definition) - length(replace(definition, replacement.needle, ''))) / length(replacement.needle);
        IF occurrences <> 1 OR strpos(definition, 'security_policy_activation_node_artifact_sha256_333') <> 0 THEN
            RAISE EXCEPTION 'migration 333 cannot find the node digest comparison in %', replacement.signature
                USING ERRCODE='P3330';
        END IF;
        EXECUTE replace(definition, replacement.needle, replacement.value);
    END LOOP;
END;
$migration_333_functions$;

-- A capability wait resumes on the site runtime it was requested for.
ALTER TABLE security_activation_capability_waits
    ADD COLUMN site_runtime_schema text NOT NULL DEFAULT 'cdnca.edge.site-runtime/v1'
        CHECK (site_runtime_schema IN ('cdnca.edge.site-runtime/v1','cdnca.edge.site-runtime/v2'));

REVOKE ALL ON security_policy_activation_node_artifacts_333 FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_security_policy_activation_node_artifact_333() FROM PUBLIC;
GRANT SELECT, INSERT ON security_policy_activation_node_artifacts_333 TO cdnca_control_app, cdnca_control_runtime;
