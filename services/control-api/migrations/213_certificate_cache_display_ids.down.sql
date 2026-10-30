LOCK TABLE schema_migrations, certificate_assets, cache_operations,
    certificate_asset_display_id_sequences, cache_operation_display_id_sequences
IN ACCESS EXCLUSIVE MODE;

DO $migration_213_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>213 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>213 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=213 AND migration_id='213_certificate_cache_display_ids' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 213 rollback requires the exact verified 213 release head'
            USING ERRCODE='P2130';
    END IF;
END;
$migration_213_down$;

DROP TRIGGER certificate_assets_display_id_213 ON certificate_assets;
DROP TRIGGER cache_operations_display_id_213 ON cache_operations;
DROP TRIGGER certificate_assets_display_id_immutable_213 ON certificate_assets;
DROP TRIGGER cache_operations_display_id_immutable_213 ON cache_operations;
DROP FUNCTION allocate_certificate_asset_display_id_213();
DROP FUNCTION allocate_cache_operation_display_id_213();
DROP FUNCTION protect_display_id_213();

ALTER TABLE certificate_assets
    DROP CONSTRAINT certificate_assets_scope_display_id_unique,
    DROP CONSTRAINT certificate_assets_display_id_positive,
    DROP COLUMN display_id;
ALTER TABLE cache_operations
    DROP CONSTRAINT cache_operations_scope_display_id_unique,
    DROP CONSTRAINT cache_operations_display_id_positive,
    DROP COLUMN display_id;

DROP TABLE certificate_asset_display_id_sequences;
DROP TABLE cache_operation_display_id_sequences;
