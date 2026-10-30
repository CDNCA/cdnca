LOCK TABLE schema_migrations, rule_pack_artifacts, theme_packages IN ACCESS EXCLUSIVE MODE;

DO $migration_372_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 372 OR
       (SELECT max(version) FROM schema_migrations) <> 372 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=372 AND
        migration_id='372_market_data_packs' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 372 down requires the exact verified migration head' USING ERRCODE='P3721';
    END IF;
    -- Market packs and themes cannot be expressed by 371: refuse rather than drop them.
    IF EXISTS (SELECT 1 FROM rule_pack_artifacts WHERE source = 'market') OR
       EXISTS (SELECT 1 FROM theme_packages WHERE source = 'market') OR
       EXISTS (SELECT 1 FROM market_data_pack_sources) THEN
        RAISE EXCEPTION 'migration 372 down refuses to drop market rule packs or themes' USING ERRCODE='P3722';
    END IF;
END;
$migration_372_down$;

DROP TABLE market_data_pack_sources;

ALTER TABLE theme_packages DROP CONSTRAINT theme_packages_feature_372;
ALTER TABLE theme_packages DROP CONSTRAINT theme_packages_source_id_372;
ALTER TABLE theme_packages DROP CONSTRAINT theme_packages_source_372;
ALTER TABLE theme_packages DROP CONSTRAINT theme_packages_theme_id_372;
ALTER TABLE theme_packages
    ADD CHECK (theme_id ~ '^(default|official\.[a-z][a-z0-9-]{0,31}|custom\.[a-z][a-z0-9-]{0,31})$'),
    ADD CHECK (source IN ('builtin', 'upload')),
    ADD CHECK ((source = 'builtin') = (theme_id !~ '^custom\.')),
    ADD CHECK (source = 'builtin' OR requires_feature = '');

ALTER TABLE rule_pack_artifacts DROP CONSTRAINT rule_pack_artifacts_market_layer_372;
ALTER TABLE rule_pack_artifacts DROP CONSTRAINT rule_pack_artifacts_source_372;
ALTER TABLE rule_pack_artifacts ADD CONSTRAINT rule_pack_artifacts_source_359
    CHECK (source IN ('catalog', 'import', 'tenant', 'subscription'));
