LOCK TABLE schema_migrations, market_data_pack_sources, plugin_providers, dns_providers IN ACCESS EXCLUSIVE MODE;

DO $migration_397_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 397 OR
       (SELECT max(version) FROM schema_migrations) <> 397 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=397 AND
        migration_id='397_plugin_providers' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 397 down requires the exact verified migration head' USING ERRCODE='P3972';
    END IF;
    IF EXISTS (SELECT 1 FROM market_data_pack_sources WHERE kind = 'plugin_provider') OR
       EXISTS (SELECT 1 FROM dns_providers WHERE provider_type = 'plugin') THEN
        RAISE EXCEPTION 'migration 397 rollback would drop provider plugins in use' USING ERRCODE='P3973';
    END IF;
END;
$migration_397_down$;

ALTER TABLE dns_providers DROP CONSTRAINT dns_providers_provider_type_check;
ALTER TABLE dns_providers ADD CONSTRAINT dns_providers_provider_type_check CHECK (
    provider_type IN ('aliyun', 'cloudflare', 'huawei', 'dnspod_cn', 'dns_com', 'dnsdun', 'dns_la', 'custom_http')
);
DROP TABLE plugin_providers;
DROP FUNCTION plugin_providers_enable_gate_397();
ALTER TABLE market_data_pack_sources DROP CONSTRAINT market_data_pack_sources_plugin_provider_397;
ALTER TABLE market_data_pack_sources DROP CONSTRAINT market_data_pack_sources_kind_397;
ALTER TABLE market_data_pack_sources ADD CONSTRAINT market_data_pack_sources_kind_386
    CHECK (kind IN ('market_rule_pack', 'market_theme', 'plugin_ui'));
ALTER TABLE market_data_pack_sources DROP CONSTRAINT market_data_pack_sources_artifact_id_397;
ALTER TABLE market_data_pack_sources ADD CONSTRAINT market_data_pack_sources_artifact_id_386
    CHECK (artifact_id ~ '^(market_rule_pack|market_theme|plugin_ui)/[a-z0-9]+([.-][a-z0-9]+)+$');
