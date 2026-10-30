LOCK TABLE schema_migrations, notification_outbox,
    notification_delivery_settlements_108, notification_delivery_facts_108,
    notification_delivery_command_receipts_108
IN ACCESS EXCLUSIVE MODE;

DO $migration_128$
DECLARE
    stale_constraint_count integer;
    state_exact boolean;
    failure_exact boolean;
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 128 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 128 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 128 AND migration_id = '128_notification_outbox_settlement_constraint'
          AND checksum_sha256 = '7a6e8595c4487e733b1033c308878f1a8a4c413a6b05c998960c87638434622d'
          AND integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 128 rollback requires the exact verified 128 head'
            USING ERRCODE='P1280';
    END IF;

    CREATE TEMPORARY TABLE notification_outbox_constraints_expected_128 (
        status text NOT NULL,
        lease_token uuid,
        lease_expires_at timestamptz,
        last_failure_code text,
        completed_at timestamptz,
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

    SELECT count(*) INTO stale_constraint_count
    FROM pg_constraint
    WHERE conrelid = 'notification_outbox'::regclass
      AND conname = 'notification_outbox_check2';

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
    IF stale_constraint_count <> 0 OR state_exact IS DISTINCT FROM true OR
       failure_exact IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'migration 128 rollback notification outbox constraint baseline is unexpected'
            USING ERRCODE='P1280';
    END IF;

    IF EXISTS (
        SELECT 1 FROM notification_outbox
        WHERE status IN ('accepted','unknown','cancelled') OR generation <> 1 OR
              replay_of_outbox_id IS NOT NULL
    ) OR EXISTS (SELECT 1 FROM notification_delivery_settlements_108) OR
       EXISTS (SELECT 1 FROM notification_delivery_facts_108) OR
       EXISTS (SELECT 1 FROM notification_delivery_command_receipts_108) THEN
        RAISE EXCEPTION 'migration 128 rollback would discard notification settlement facts'
            USING ERRCODE='P1281';
    END IF;
END;
$migration_128$;

ALTER TABLE notification_outbox
    ADD CONSTRAINT notification_outbox_check2 CHECK (
        (status = 'succeeded' AND last_failure_code IS NULL) OR
        (status IN ('permanent_failed', 'exhausted') AND last_failure_code IS NOT NULL) OR
        status IN ('pending', 'leased')
    );
