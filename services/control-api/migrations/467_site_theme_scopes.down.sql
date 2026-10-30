LOCK TABLE schema_migrations, theme_activations, site_theme_packages, site_theme_activations IN ACCESS EXCLUSIVE MODE;

DO $migration_467_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 467 OR
       (SELECT max(version) FROM schema_migrations) <> 467 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=467 AND
        migration_id='467_site_theme_scopes' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 467 down requires the exact verified migration head' USING ERRCODE='P4673';
    END IF;
    -- Rolling back would lose what only 467 can hold: a console theme active
    -- on one console only, or a v2 website theme plugin (page bundle, console
    -- theme, sign-in style, content schema). Website content entered for a v2
    -- plugin lives in the 456 document (plugin_content) and survives; v1
    -- plugins and 'all' activations survive unchanged.
    IF EXISTS (SELECT 1 FROM theme_activations WHERE slot <> 'all') OR
       EXISTS (SELECT 1 FROM site_theme_packages WHERE schema <> 'cdnca.site-theme/v1') THEN
        RAISE EXCEPTION 'migration 467 rollback would drop per-console theme activations or v2 website theme plugins' USING ERRCODE='P4674';
    END IF;
END;
$migration_467_down$;

DROP TRIGGER site_theme_activations_scope_467 ON site_theme_activations;
DROP FUNCTION validate_site_theme_activation_467();
ALTER TABLE site_theme_packages DROP CONSTRAINT site_theme_packages_shape_467,
    DROP CONSTRAINT site_theme_packages_scopes_467;
ALTER TABLE site_theme_packages ALTER COLUMN layout SET NOT NULL;
ALTER TABLE site_theme_packages DROP COLUMN content_schema, DROP COLUMN auth_css, DROP COLUMN console_package_sha256,
    DROP COLUMN bundle_sha256, DROP COLUMN bundle_entry, DROP COLUMN applies_to, DROP COLUMN publisher, DROP COLUMN schema;
DROP TRIGGER theme_activations_slot_467 ON theme_activations;
DROP FUNCTION validate_theme_activation_slot_467();
DROP INDEX theme_activations_slot_467;
ALTER TABLE theme_activations DROP COLUMN slot;
