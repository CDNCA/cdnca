LOCK TABLE schema_migrations, cdn_provider_accounts, site_supply_cdn_configs, site_supply_cdn_sites,
    site_supply_cdn_resources, site_supply_cdn_validation_records, cdn_provider_usage IN ACCESS EXCLUSIVE MODE;

DO $migration_375_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 375 OR
       (SELECT max(version) FROM schema_migrations) <> 375 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=375 AND
        migration_id='375_aggregated_edge_sync' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 375 down requires the exact verified migration head' USING ERRCODE='P3751';
    END IF;
    -- Validation records the controller wrote into the member's DNS and WAF
    -- rules in the member's vendor account are the only record of those
    -- objects: dropping them would leave them behind. Remove them first.
    IF EXISTS (SELECT 1 FROM site_supply_cdn_validation_records WHERE dns_ref <> '') OR
       EXISTS (SELECT 1 FROM site_supply_cdn_resources WHERE kind = 'waf_rule') THEN
        RAISE EXCEPTION 'migration 375 rollback would orphan published DNS records or vendor WAF rules'
            USING ERRCODE='P3752';
    END IF;
END;
$migration_375_down$;

DROP TRIGGER aggregated_edge_supply_changed_375 ON cdn_provider_accounts;
DROP TRIGGER aggregated_edge_supply_changed_375 ON site_supply_cdn_configs;
DROP TRIGGER aggregated_edge_site_changed_375 ON site_quick_block_overrides;
DROP TRIGGER aggregated_edge_site_changed_375 ON site_security_mounts;
DROP TRIGGER aggregated_edge_site_activated_375 ON challenge_site_bindings_138;
DROP TRIGGER aggregated_edge_site_changed_375 ON challenge_site_bindings_138;
DROP TRIGGER aggregated_edge_site_activated_375 ON security_policy_site_bindings;
DROP TRIGGER aggregated_edge_site_changed_375 ON security_policy_site_bindings;
DROP TRIGGER aggregated_edge_site_changed_375 ON cache_policy_heads;
DROP TRIGGER aggregated_edge_site_changed_375 ON site_domain_facts;
DROP TRIGGER aggregated_edge_site_changed_375 ON site_origins;
DROP TRIGGER aggregated_edge_site_changed_375 ON sites;
DROP FUNCTION aggregated_edge_supply_changed_375();
DROP FUNCTION aggregated_edge_site_changed_375();

DROP TABLE cdn_provider_usage;
DROP TABLE site_supply_cdn_validation_records;

DROP INDEX site_supply_cdn_sites_dirty_375_idx;
ALTER TABLE site_supply_cdn_sites DROP COLUMN projected_generation, DROP COLUMN source_generation;

ALTER TABLE site_supply_cdn_resources
    DROP CONSTRAINT site_supply_cdn_resources_kind_check,
    ADD CONSTRAINT site_supply_cdn_resources_kind_check
        CHECK (kind IN ('hostname', 'origin_rule', 'https_redirect', 'cache_rule'));

ALTER TABLE cdn_provider_accounts
    DROP COLUMN usage_error_code, DROP COLUMN usage_next_pull_at, DROP COLUMN usage_pulled_through,
    DROP COLUMN waf_rule_limit, DROP COLUMN fallback_origin_checked_at, DROP COLUMN fallback_origin_status,
    DROP COLUMN fallback_origin;
