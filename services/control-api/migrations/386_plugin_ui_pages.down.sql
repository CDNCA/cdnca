LOCK TABLE schema_migrations, market_data_pack_sources, plugin_ui_pages IN ACCESS EXCLUSIVE MODE;

DO $migration_386_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 386 OR
       (SELECT max(version) FROM schema_migrations) <> 386 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=386 AND
        migration_id='386_plugin_ui_pages' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 386 down requires the exact verified migration head' USING ERRCODE='P3861';
    END IF;
    -- plugin_ui sources cannot be expressed by the 372 constraints.
    IF EXISTS (SELECT 1 FROM market_data_pack_sources WHERE kind = 'plugin_ui') THEN
        RAISE EXCEPTION 'migration 386 rollback would drop materialized plugin pages' USING ERRCODE='P3862';
    END IF;
END;
$migration_386_down$;

DROP TABLE plugin_ui_pages;
ALTER TABLE market_data_pack_sources DROP CONSTRAINT market_data_pack_sources_plugin_ui_386;
ALTER TABLE market_data_pack_sources DROP CONSTRAINT market_data_pack_sources_kind_386;
ALTER TABLE market_data_pack_sources ADD CONSTRAINT market_data_pack_sources_kind_check
    CHECK (kind IN ('market_rule_pack', 'market_theme'));
ALTER TABLE market_data_pack_sources DROP CONSTRAINT market_data_pack_sources_artifact_id_386;
ALTER TABLE market_data_pack_sources ADD CONSTRAINT market_data_pack_sources_artifact_id_check
    CHECK (artifact_id ~ '^(market_rule_pack|market_theme)/[a-z0-9]+([.-][a-z0-9]+)+$');
