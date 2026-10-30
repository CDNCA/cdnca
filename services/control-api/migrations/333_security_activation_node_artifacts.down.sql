LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE security_policy_activation_node_artifacts_333,
    security_policy_activation_candidates,
    security_activation_capability_waits
IN SHARE ROW EXCLUSIVE MODE;

DO $migration_333_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 333 OR
       (SELECT max(version) FROM schema_migrations) <> 333 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=333 AND
        migration_id='333_security_activation_node_artifacts' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 333 down requires the exact verified migration head' USING ERRCODE='P3331';
    END IF;
    IF EXISTS (SELECT 1 FROM security_policy_activation_node_artifacts_333) OR
       EXISTS (SELECT 1 FROM security_activation_capability_waits
               WHERE site_runtime_schema <> 'cdnca.edge.site-runtime/v1') THEN
        RAISE EXCEPTION 'migration 333 rollback would drop site runtime v2 security activation facts'
            USING ERRCODE='P3331';
    END IF;
END;
$migration_333_down$;

DO $migration_333_down_functions$
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
        occurrences := (length(definition) - length(replace(definition, replacement.value, ''))) / length(replacement.value);
        IF occurrences <> 1 THEN
            RAISE EXCEPTION 'migration 333 down cannot find the node digest comparison in %', replacement.signature
                USING ERRCODE='P3331';
        END IF;
        EXECUTE replace(definition, replacement.value, replacement.needle);
    END LOOP;
END;
$migration_333_down_functions$;

ALTER TABLE security_activation_capability_waits DROP COLUMN site_runtime_schema;
DROP FUNCTION security_policy_activation_node_artifact_sha256_333(uuid,uuid,uuid,bytea);
DROP TABLE security_policy_activation_node_artifacts_333;
DROP FUNCTION validate_security_policy_activation_node_artifact_333();
