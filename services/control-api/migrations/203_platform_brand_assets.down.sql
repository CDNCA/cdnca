LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_203_down$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=203 AND migration_id='203_platform_brand_assets' AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 203 rollback requires a verified 203 release head' USING ERRCODE='P2032';
    END IF;
END;
$migration_203_down$;

DROP TABLE platform_brand_asset_write_requests;
DROP TRIGGER platform_brand_assets_scope_203 ON platform_brand_assets;
DROP FUNCTION validate_platform_brand_assets_scope_203();
DROP TABLE platform_brand_assets;

