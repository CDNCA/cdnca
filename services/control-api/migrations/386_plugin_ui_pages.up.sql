LOCK TABLE schema_migrations, market_data_pack_sources IN ACCESS EXCLUSIVE MODE;

DO $migration_386_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 385 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 385 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=385 AND
        migration_id='385_site_traffic_limits' AND
        checksum_sha256='6f341a154adc549a92d4ad631dcd95549ada31a5f34d522bb4b2c049ac898529' AND
        down_checksum_sha256='93329a6b93bf825da3a03317fa0b7a614294f0c65217abec5dad8b55e8e13137' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.plugin_ui_pages') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 386 requires the exact verified 385 release head' USING ERRCODE='P3860';
    END IF;
END;
$migration_386_up$;

-- 386（r136 pa19-uipage 占位：接在 385 之后；合入时主会话改号）。
-- PA-19 (ADR 0007 §8.3): a ui_page plugin's page declaration reaches this
-- control plane as artifact catalog entry plugin_ui/<plugin id> of an
-- authorized plugin installation (libs/entitlement/pluginui). artifactsync
-- materializes it here once the installation is enabled on this control
-- plane; a page origin is in the web CSP frame-src and its pages are in the
-- menu only while the row is active. An entry no longer served
-- (authorization disabled or uninstalled) or an installation no longer
-- enabled here withdraws it at the next sync: the origin leaves frame-src
-- and the control plane proxy refuses its backend.
ALTER TABLE market_data_pack_sources DROP CONSTRAINT market_data_pack_sources_artifact_id_check;
ALTER TABLE market_data_pack_sources ADD CONSTRAINT market_data_pack_sources_artifact_id_386
    CHECK (artifact_id ~ '^(market_rule_pack|market_theme|plugin_ui)/[a-z0-9]+([.-][a-z0-9]+)+$');
ALTER TABLE market_data_pack_sources DROP CONSTRAINT market_data_pack_sources_kind_check;
ALTER TABLE market_data_pack_sources ADD CONSTRAINT market_data_pack_sources_kind_386
    CHECK (kind IN ('market_rule_pack', 'market_theme', 'plugin_ui'));
ALTER TABLE market_data_pack_sources ADD CONSTRAINT market_data_pack_sources_plugin_ui_386
    CHECK (kind <> 'plugin_ui' OR local_name = plugin_id);

CREATE TABLE plugin_ui_pages (
    plugin_id text PRIMARY KEY CHECK (plugin_id ~ '^[a-z0-9]+([.-][a-z0-9]+)+$' AND char_length(plugin_id) BETWEEN 3 AND 128),
    version text NOT NULL CHECK (char_length(version) BETWEEN 5 AND 64),
    -- https://<dns host>: the iframe origin and the CSP frame-src source.
    -- (a DNS name: the last label is never all digits, so no IPv4 literal).
    origin text NOT NULL CHECK (origin ~ '^https://[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$' AND
        origin !~ '\.[0-9]+$'),
    -- The plugin backend the control plane proxies page API calls to ('' = none).
    api_base_url text NOT NULL CHECK (api_base_url = '' OR
        api_base_url ~ '^https://[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+(/[^?#]*)?$'),
    -- The canonical cdnca.plugin-ui/v1 declaration (pages, mounts, gates).
    declaration jsonb NOT NULL CHECK (jsonb_typeof(declaration) = 'object' AND declaration->>'plugin_id' = plugin_id AND
        declaration->>'origin' = origin),
    declaration_sha256 text NOT NULL CHECK (declaration_sha256 ~ '^[0-9a-f]{64}$'),
    status text NOT NULL CHECK (status IN ('active', 'withdrawn')),
    -- The plugin installation this control plane confirmed (proxy identity).
    tenant_scope_id uuid NOT NULL,
    authorization_id uuid NOT NULL,
    materialized_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);
-- Two enabled plugins cannot claim the same page origin (the CSP and the
-- postMessage origin check identify a plugin by it).
CREATE UNIQUE INDEX plugin_ui_pages_active_origin_386 ON plugin_ui_pages (origin) WHERE status = 'active';

REVOKE ALL ON plugin_ui_pages FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON plugin_ui_pages TO cdnca_control_app;
GRANT SELECT ON plugin_ui_pages TO cdnca_control_runtime;
