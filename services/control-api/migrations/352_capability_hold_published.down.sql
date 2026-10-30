LOCK TABLE schema_migrations, edge_capability_publication_holds IN ACCESS EXCLUSIVE MODE;

DO $migration_352_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 352 OR
       (SELECT max(version) FROM schema_migrations) <> 352 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=352 AND
        migration_id='352_capability_hold_published' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 352 down requires the exact verified migration head' USING ERRCODE='P3521';
    END IF;
END;
$migration_352_down$;

-- 351 ignores a hold at its publication's revision: the deferred nodes stay
-- challenge redelivery targets, and a line group still brings them back.
ALTER TABLE edge_capability_publication_holds DROP COLUMN published;
