LOCK TABLE schema_migrations,
    plugin_webhook_events
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 123 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 123 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 123
          AND migration_id = '123_plugin_webhook_domain_event_producer'
          AND checksum_sha256 = '1571676e83b10966f0490b7f4ef8064e9e3e19593e8577a726c160dcaff64e0f'
          AND down_checksum_sha256 = '6dc511cc3321279a5434d8d345d8da9ea85ea8432b6cb727b33778ac0c243690'
          AND integrity_state = 'verified'
          AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 124 requires the exact verified 123 release head'
            USING ERRCODE = 'P1240';
    END IF;
END;
$$;

-- The 084 check was anonymous. Keep its identity so rollback can restore the
-- predecessor shape without guessing a generated PostgreSQL constraint name.
CREATE TABLE plugin_webhook_event_clock_124_backup (
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
    WHERE conrelid = 'plugin_webhook_events'::regclass
      AND contype = 'c'
      AND regexp_replace(lower(pg_get_constraintdef(oid, false)), '[[:space:]]+', '', 'g') =
          'check((created_at=event_time))';

    IF legacy_count <> 1 OR legacy_name IS NULL THEN
        RAISE EXCEPTION 'migration 124 requires exactly one legacy created_at/event_time check'
            USING ERRCODE = 'P1241';
    END IF;

    SELECT pg_get_constraintdef(oid, false)
      INTO legacy_definition
    FROM pg_constraint
    WHERE conrelid = 'plugin_webhook_events'::regclass
      AND conname::text = legacy_name;

    IF regexp_replace(lower(legacy_definition), '[[:space:]]+', '', 'g') <>
       'check((created_at=event_time))' THEN
        RAISE EXCEPTION 'migration 124 found an unexpected legacy clock constraint definition'
            USING ERRCODE = 'P1241';
    END IF;

    INSERT INTO plugin_webhook_event_clock_124_backup(constraint_name, constraint_definition)
    VALUES (legacy_name, legacy_definition);

    EXECUTE format(
        'ALTER TABLE %I DROP CONSTRAINT %I',
        'plugin_webhook_events', legacy_name
    );
END;
$$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM plugin_webhook_events
        WHERE event_time IS DISTINCT FROM created_at
    ) THEN
        RAISE EXCEPTION 'migration 124 found event facts incompatible with the forward clock relation'
            USING ERRCODE = 'P1242';
    END IF;
END;
$$;

ALTER TABLE plugin_webhook_events
    ADD CONSTRAINT plugin_webhook_events_event_clock_124 CHECK (
        isfinite(event_time) AND
        isfinite(created_at) AND
        date_trunc('microseconds', event_time) = event_time AND
        event_time <= created_at
    );
