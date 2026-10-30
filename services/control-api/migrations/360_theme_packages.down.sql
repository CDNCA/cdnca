LOCK TABLE schema_migrations, platform_brand_assets, platform_brand_asset_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_360_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 360 OR
       (SELECT max(version) FROM schema_migrations) <> 360 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=360 AND
        migration_id='360_theme_packages' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 360 down requires the exact verified migration head' USING ERRCODE='P3604';
    END IF;
    -- 203's slot set cannot hold the theme slots, and error page publications
    -- made after an activation pin a theme package: refuse rather than orphan.
    IF EXISTS (SELECT 1 FROM platform_brand_assets WHERE slot NOT IN ('favicon', 'logo', 'login_ad')) OR
       EXISTS (SELECT 1 FROM platform_brand_asset_write_requests WHERE slot NOT IN ('favicon', 'logo', 'login_ad')) OR
       EXISTS (SELECT 1 FROM theme_activations) THEN
        RAISE EXCEPTION 'migration 360 down refuses to drop theme slots or activations in use' USING ERRCODE='P3605';
    END IF;
END;
$migration_360_down$;

ALTER TABLE platform_brand_asset_write_requests
    DROP CONSTRAINT platform_brand_asset_write_requests_slot_check_360,
    ADD CONSTRAINT platform_brand_asset_write_requests_slot_check CHECK (slot IN ('favicon','logo','login_ad'));
ALTER TABLE platform_brand_assets
    DROP CONSTRAINT platform_brand_assets_media_check_360,
    DROP CONSTRAINT platform_brand_assets_reference_check_360,
    DROP CONSTRAINT platform_brand_assets_slot_check_360,
    ADD CONSTRAINT platform_brand_assets_slot_check CHECK (slot IN ('favicon','logo','login_ad')),
    ADD CONSTRAINT platform_brand_assets_reference_check CHECK (reference ~ '^asset://brand/(favicon|logo|login_ad)/[0-9a-f]{64}$'),
    ADD CONSTRAINT platform_brand_assets_check CHECK ((slot='logo' AND mime_type='image/png') OR
           (slot='login_ad' AND mime_type='image/jpeg') OR
           (slot='favicon' AND mime_type IN ('image/x-icon','image/vnd.microsoft.icon','image/png')));

DROP TABLE theme_activations;
DROP TABLE theme_error_pages;
DROP TABLE theme_package_assets;
DROP TABLE theme_assets;
DROP TABLE theme_packages;
DROP FUNCTION protect_theme_facts_360();
DROP FUNCTION validate_theme_activation_360();
