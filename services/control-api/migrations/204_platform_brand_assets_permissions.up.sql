LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_204$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=203
          AND migration_id='203_platform_brand_assets'
          AND integrity_state='verified'
          AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 204 requires a verified 203 brand-assets head' USING ERRCODE='P2040';
    END IF;
END;
$migration_204$;

GRANT USAGE ON SCHEMA public TO cdnca_control_app;
GRANT SELECT, INSERT, UPDATE, DELETE
    ON TABLE platform_brand_assets, platform_brand_asset_write_requests
    TO cdnca_control_app;

LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

