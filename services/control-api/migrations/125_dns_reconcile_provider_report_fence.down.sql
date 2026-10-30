LOCK TABLE schema_migrations,
    dns_reconcile_provider_reports,
    dns_reconcile_provider_report_fence_125_backup
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 125 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 125 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 125
          AND migration_id = '125_dns_reconcile_provider_report_fence'
          AND integrity_state = 'verified'
          AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 125 rollback requires the exact verified release head'
            USING ERRCODE = 'P1250';
    END IF;
END;
$$;

DO $$
DECLARE
    backup_count integer;
    legacy_name text;
    legacy_definition text;
BEGIN
    IF EXISTS (
        SELECT 1 FROM dns_reconcile_provider_reports
        WHERE source = 'workload' AND job_attempt IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 125 rollback would discard fenced provider report facts'
            USING ERRCODE = 'P1252';
    END IF;

    SELECT count(*), min(constraint_name), min(constraint_definition)
      INTO backup_count, legacy_name, legacy_definition
    FROM dns_reconcile_provider_report_fence_125_backup;
    IF backup_count <> 1 OR legacy_name IS NULL OR legacy_definition IS NULL THEN
        RAISE EXCEPTION 'migration 125 rollback metadata is missing or ambiguous'
            USING ERRCODE = 'P1251';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'dns_reconcile_provider_reports'::regclass
          AND conname = 'dns_reconcile_provider_reports_source_shape_125'
          AND contype = 'c'
    ) THEN
        RAISE EXCEPTION 'migration 125 rollback source-shape constraint is missing'
            USING ERRCODE = 'P1251';
    END IF;

    ALTER TABLE dns_reconcile_provider_reports
        DROP CONSTRAINT dns_reconcile_provider_reports_source_shape_125;
    EXECUTE format(
        'ALTER TABLE %I ADD CONSTRAINT %I %s',
        'dns_reconcile_provider_reports', legacy_name, legacy_definition
    );
END;
$$;

CREATE OR REPLACE FUNCTION validate_dns_reconcile_provider_report_076()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    latest_sequence bigint;
    latest_revision bigint;
BEGIN
    PERFORM 1 FROM dns_reconcile_operations
    WHERE tenant_id=NEW.tenant_id AND job_id=NEW.job_id
      AND phase=NEW.phase AND ordinal=NEW.operation_ordinal
    FOR UPDATE;
    IF NEW.source = 'worker' THEN
        PERFORM assert_dns_reconcile_live_claim_076(
            NEW.tenant_id, NEW.job_id, NEW.job_attempt, NEW.lease_id,
            NEW.worker_id, NEW.received_at
        );
    END IF;
    IF NEW.accepted THEN
        SELECT max(report_sequence), max(provider_revision)
        INTO latest_sequence, latest_revision
        FROM dns_reconcile_provider_reports
        WHERE job_id=NEW.job_id AND phase=NEW.phase
          AND operation_ordinal=NEW.operation_ordinal AND accepted;
        IF latest_sequence IS NOT NULL AND NEW.report_sequence <= latest_sequence THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'accepted DNS provider report sequence is not increasing';
        END IF;
        IF latest_revision IS NOT NULL AND NEW.provider_revision IS NOT NULL AND
           NEW.provider_revision < latest_revision THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'accepted DNS provider revision is not increasing';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DROP TABLE dns_reconcile_provider_report_fence_125_backup;
