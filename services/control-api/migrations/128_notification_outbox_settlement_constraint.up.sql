LOCK TABLE schema_migrations, notification_outbox IN ACCESS EXCLUSIVE MODE;

DO $migration_128$
DECLARE
    legacy_exact boolean;
    state_exact boolean;
    failure_exact boolean;
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 127 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 127 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) THEN
        RAISE EXCEPTION 'migration 128 requires the exact verified 127 release head'
            USING ERRCODE='P1280';
    END IF;

    CREATE TEMPORARY TABLE notification_outbox_constraints_expected_128 (
        status text NOT NULL,
        lease_token uuid,
        lease_expires_at timestamptz,
        last_failure_code text,
        completed_at timestamptz,
        CONSTRAINT legacy_failure_shape_128 CHECK (
            (status = 'succeeded' AND last_failure_code IS NULL) OR
            (status IN ('permanent_failed', 'exhausted') AND last_failure_code IS NOT NULL) OR
            status IN ('pending', 'leased')
        ),
        CONSTRAINT state_shape_128 CHECK (
            (status='pending' AND lease_token IS NULL AND lease_expires_at IS NULL AND completed_at IS NULL) OR
            (status='leased' AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL AND completed_at IS NULL) OR
            (status IN ('accepted','unknown') AND lease_token IS NULL AND lease_expires_at IS NULL AND completed_at IS NULL) OR
            (status IN ('succeeded','permanent_failed','exhausted','cancelled') AND
             lease_token IS NULL AND lease_expires_at IS NULL AND completed_at IS NOT NULL)
        ),
        CONSTRAINT failure_shape_128 CHECK (
            (status IN ('succeeded','accepted') AND last_failure_code IS NULL) OR
            (status='unknown' AND last_failure_code='provider_outcome_unknown') OR
            (status IN ('permanent_failed','exhausted','cancelled') AND last_failure_code IS NOT NULL) OR
            status IN ('pending','leased')
        )
    ) ON COMMIT DROP;

    SELECT count(*) = 1 AND bool_and(
        constraint_row.contype = 'c' AND constraint_row.convalidated AND
        NOT constraint_row.connoinherit AND
        pg_get_expr(constraint_row.conbin, constraint_row.conrelid, false) = (
            SELECT pg_get_expr(expected.conbin, expected.conrelid, false)
            FROM pg_constraint expected
            WHERE expected.conrelid = 'pg_temp.notification_outbox_constraints_expected_128'::regclass
              AND expected.conname = 'legacy_failure_shape_128'
        )
    ) INTO legacy_exact
    FROM pg_constraint constraint_row
    WHERE constraint_row.conrelid = 'notification_outbox'::regclass
      AND constraint_row.conname = 'notification_outbox_check2';

    SELECT count(*) = 1 AND bool_and(
        constraint_row.contype = 'c' AND constraint_row.convalidated AND
        NOT constraint_row.connoinherit AND
        pg_get_expr(constraint_row.conbin, constraint_row.conrelid, false) = (
            SELECT pg_get_expr(expected.conbin, expected.conrelid, false)
            FROM pg_constraint expected
            WHERE expected.conrelid = 'pg_temp.notification_outbox_constraints_expected_128'::regclass
              AND expected.conname = 'state_shape_128'
        )
    ) INTO state_exact
    FROM pg_constraint constraint_row
    WHERE constraint_row.conrelid = 'notification_outbox'::regclass
      AND constraint_row.conname = 'notification_outbox_state_shape_108';

    SELECT count(*) = 1 AND bool_and(
        constraint_row.contype = 'c' AND constraint_row.convalidated AND
        NOT constraint_row.connoinherit AND
        pg_get_expr(constraint_row.conbin, constraint_row.conrelid, false) = (
            SELECT pg_get_expr(expected.conbin, expected.conrelid, false)
            FROM pg_constraint expected
            WHERE expected.conrelid = 'pg_temp.notification_outbox_constraints_expected_128'::regclass
              AND expected.conname = 'failure_shape_128'
        )
    ) INTO failure_exact
    FROM pg_constraint constraint_row
    WHERE constraint_row.conrelid = 'notification_outbox'::regclass
      AND constraint_row.conname = 'notification_outbox_failure_shape_108';

    DROP TABLE pg_temp.notification_outbox_constraints_expected_128;
    IF legacy_exact IS DISTINCT FROM true OR state_exact IS DISTINCT FROM true OR
       failure_exact IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'migration 128 notification outbox constraint baseline is unexpected'
            USING ERRCODE='P1280';
    END IF;
END;
$migration_128$;

ALTER TABLE notification_outbox
    DROP CONSTRAINT notification_outbox_check2;
