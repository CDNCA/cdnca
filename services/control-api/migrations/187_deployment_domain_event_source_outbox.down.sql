LOCK TABLE schema_migrations, deployment_domain_event_source_outbox IN ACCESS EXCLUSIVE MODE;

DO $migration_187_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 187 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 187 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=187 AND migration_id='187_deployment_domain_event_source_outbox' AND
              checksum_sha256='1d7132c342f82b1445ef0be83968704465fd26659915ecb24d2c566e082e2be4' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=186 AND migration_id='186_site_domain_export_rbac' AND
              checksum_sha256='fa30f9adc3f68d6bddca97311f1345fb39327cb06cb28e8d640ee824e4466203' AND
              down_checksum_sha256='a10c012d16f9bf4e00789b8ba5a96ee59607509cd557e2051e6de3b4a0049fef' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 187 rollback requires the exact verified 187 and 186 release heads'
            USING ERRCODE='P1870';
    END IF;
    IF EXISTS (SELECT 1 FROM deployment_domain_event_source_outbox) THEN
        RAISE EXCEPTION 'deployment domain event source outbox contains durable events'
            USING ERRCODE='P1871';
    END IF;
END;
$migration_187_down$;

DROP TRIGGER deployment_domain_event_source_outbox_append_only ON deployment_domain_event_source_outbox;
DROP FUNCTION validate_deployment_domain_event_source_outbox();
DROP TABLE deployment_domain_event_source_outbox;
