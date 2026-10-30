LOCK TABLE schema_migrations,
    dns_reconcile_provider_reports
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 124 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 124 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 124
          AND migration_id = '124_plugin_webhook_event_clock'
          AND checksum_sha256 = 'd53d6c1fc04d4d09c227989e507b2b35de5855a4a524081290984921fce97afb'
          AND down_checksum_sha256 = '3ecbc3b06be8ad64cac9ea4ba5e7eb9a8fea9710e4957cf89c6ff868c03477cb'
          AND integrity_state = 'verified'
          AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 125 requires the exact verified 124 release head'
            USING ERRCODE = 'P1250';
    END IF;
END;
$$;

CREATE TABLE dns_reconcile_provider_report_fence_125_backup (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    constraint_name text NOT NULL,
    constraint_definition text NOT NULL
);

DO $$
DECLARE
    legacy_count integer;
    legacy_name text;
    legacy_definition text;
BEGIN
    SELECT count(*), min(conname::text)
      INTO legacy_count, legacy_name
    FROM pg_constraint
    WHERE conrelid = 'dns_reconcile_provider_reports'::regclass
      AND contype = 'c'
      AND pg_get_expr(conbin, conrelid) LIKE '%source%workload%'
      AND pg_get_expr(conbin, conrelid) LIKE '%command_idempotency_key%'
      AND pg_get_expr(conbin, conrelid) LIKE '%job_attempt%'
      AND pg_get_expr(conbin, conrelid) LIKE '%lease_id%'
      AND pg_get_expr(conbin, conrelid) LIKE '%worker_id%';

    IF legacy_count <> 1 OR legacy_name IS NULL THEN
        RAISE EXCEPTION 'migration 125 requires exactly one legacy provider report source-shape check'
            USING ERRCODE = 'P1251';
    END IF;

    SELECT pg_get_constraintdef(oid, false)
      INTO legacy_definition
    FROM pg_constraint
    WHERE conrelid = 'dns_reconcile_provider_reports'::regclass
      AND conname::text = legacy_name;

    INSERT INTO dns_reconcile_provider_report_fence_125_backup(constraint_name, constraint_definition)
    VALUES (legacy_name, legacy_definition);

    EXECUTE format(
        'ALTER TABLE %I DROP CONSTRAINT %I',
        'dns_reconcile_provider_reports', legacy_name
    );
END;
$$;

ALTER TABLE dns_reconcile_provider_reports
ADD CONSTRAINT dns_reconcile_provider_reports_source_shape_125 CHECK (
    (source = 'worker' AND command_idempotency_key IS NULL AND command_digest IS NULL AND
     request_id IS NULL AND traceparent IS NULL AND expected_task_revision IS NULL AND
     job_attempt IS NOT NULL AND lease_id IS NOT NULL AND worker_id IS NOT NULL) OR
    (source = 'workload' AND command_idempotency_key IS NOT NULL AND command_digest IS NOT NULL AND
     request_id IS NOT NULL AND traceparent IS NOT NULL AND expected_task_revision IS NOT NULL AND (
        (job_attempt IS NULL AND lease_id IS NULL AND worker_id IS NULL) OR
        (job_attempt IS NOT NULL AND lease_id IS NOT NULL AND worker_id IS NOT NULL)
     ))
);

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
    IF NEW.source = 'worker' OR NEW.job_attempt IS NOT NULL THEN
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
