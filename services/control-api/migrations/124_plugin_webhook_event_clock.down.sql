LOCK TABLE schema_migrations,
    plugin_webhook_events,
    plugin_webhook_event_clock_124_backup
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
          AND integrity_state = 'verified'
          AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 124 rollback requires the exact verified release head'
            USING ERRCODE = 'P1240';
    END IF;
END;
$$;

DO $$
DECLARE
    backup_count integer;
    legacy_name text;
BEGIN
    SELECT count(*), min(constraint_name)
      INTO backup_count, legacy_name
    FROM plugin_webhook_event_clock_124_backup;
    IF backup_count <> 1 OR legacy_name IS NULL THEN
        RAISE EXCEPTION 'migration 124 rollback metadata is missing or ambiguous'
            USING ERRCODE = 'P1241';
    END IF;

    IF EXISTS (
        SELECT 1 FROM plugin_webhook_events
        WHERE event_time IS DISTINCT FROM created_at
    ) THEN
        RAISE EXCEPTION 'migration 124 rollback would discard domain event clock facts'
            USING ERRCODE = 'P1242';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'plugin_webhook_events'::regclass
          AND conname = 'plugin_webhook_events_event_clock_124'
          AND contype = 'c'
    ) THEN
        RAISE EXCEPTION 'migration 124 rollback clock constraint is missing'
            USING ERRCODE = 'P1241';
    END IF;

    EXECUTE 'ALTER TABLE plugin_webhook_events DROP CONSTRAINT plugin_webhook_events_event_clock_124';
    EXECUTE format(
        'ALTER TABLE %I ADD CONSTRAINT %I CHECK (created_at = event_time)',
        'plugin_webhook_events', legacy_name
    );
END;
$$;

DROP TABLE plugin_webhook_event_clock_124_backup;
