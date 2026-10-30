LOCK TABLE schema_migrations, dns_reconcile_propagation_attempts
IN ACCESS EXCLUSIVE MODE;

DO $migration_129$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 129 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 129 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=129 AND migration_id='129_dns_reconcile_observation_integrity'
          AND checksum_sha256='2e50d159f91bf76ffba9f0e918260c07e79c8eb1089229736200fb33a17b3366'
          AND down_checksum_sha256 ~ '^[0-9a-f]{64}$'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) OR to_regprocedure('dns_reconcile_check_result_valid_129(jsonb,uuid,text)') IS NULL OR
       NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid='dns_reconcile_propagation_attempts'::regclass
          AND conname='dns_reconcile_observation_integrity_129' AND NOT convalidated
    ) THEN
        RAISE EXCEPTION 'migration 129 rollback requires the exact verified 129 head'
            USING ERRCODE='P1290';
    END IF;
    IF EXISTS (
        SELECT 1 FROM dns_reconcile_propagation_attempts WHERE classification='nodata'
    ) THEN
        RAISE EXCEPTION 'migration 129 rollback would discard NODATA propagation facts'
            USING ERRCODE='P1291';
    END IF;
END;
$migration_129$;

ALTER TABLE dns_reconcile_propagation_attempts
    DROP CONSTRAINT dns_reconcile_observation_integrity_129,
    DROP CONSTRAINT dns_reconcile_propagation_attempts_classification_check,
    ADD CONSTRAINT dns_reconcile_propagation_attempts_classification_check CHECK (classification IN (
        'healthy', 'missing_record', 'wrong_value', 'cname_chain', 'cname_loop',
        'cname_depth_exceeded', 'nxdomain', 'servfail', 'timeout',
        'authority_inconsistent', 'public_propagating', 'public_propagation_failed',
        'resolver_failure', 'malformed_response'
    ));

DROP FUNCTION dns_reconcile_check_result_valid_129(jsonb,uuid,text);
