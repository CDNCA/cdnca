LOCK TABLE schema_migrations, sites, site_display_id_sequences IN ACCESS EXCLUSIVE MODE;

DO $migration_210_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>210 OR
       (SELECT max(version) FROM schema_migrations)<>210 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=210 AND migration_id='210_site_display_ids' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 210 rollback requires the exact verified 210 release head'
            USING ERRCODE='P2100';
    END IF;
END;
$migration_210_down$;

ALTER TABLE sites
    DROP CONSTRAINT sites_scope_display_id_unique,
    DROP CONSTRAINT sites_display_id_positive,
    DROP COLUMN display_id;

DROP TABLE site_display_id_sequences;

