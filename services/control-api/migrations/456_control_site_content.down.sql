LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_456_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 456 OR
       (SELECT max(version) FROM schema_migrations) <> 456 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=456 AND
        migration_id='456_control_site_content' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 456 down requires the exact verified migration head' USING ERRCODE='P4561';
    END IF;
    -- A published website, uploaded images or a plugin that is not built in
    -- would be lost; built-in plugins come back from the binary.
    IF EXISTS (SELECT 1 FROM control_site_content WHERE published IS NOT NULL) OR
       EXISTS (SELECT 1 FROM control_site_assets) OR
       EXISTS (SELECT 1 FROM site_theme_packages WHERE source <> 'builtin') THEN
        RAISE EXCEPTION 'migration 456 rollback would drop the published website, its images or website theme plugins' USING ERRCODE='P4562';
    END IF;
END;
$migration_456_down$;

DROP TABLE site_theme_activations;
DROP TABLE site_theme_customizations;
DROP TABLE site_theme_images;
DROP TABLE site_theme_packages;
DROP TABLE control_site_write_requests;
DROP TABLE control_site_assets;
DROP TABLE control_site_content;
