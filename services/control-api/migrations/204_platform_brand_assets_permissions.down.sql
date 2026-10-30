LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_204_down$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=204
          AND migration_id='204_platform_brand_assets_permissions'
          AND integrity_state='verified'
          AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 204 rollback requires a verified 204 brand-assets permissions head' USING ERRCODE='P2041';
    END IF;
END;
$migration_204_down$;

REVOKE SELECT, INSERT, UPDATE, DELETE
    ON TABLE platform_brand_assets, platform_brand_asset_write_requests
    FROM cdnca_control_app;

