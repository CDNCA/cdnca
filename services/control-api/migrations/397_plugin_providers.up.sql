LOCK TABLE schema_migrations, market_data_pack_sources, dns_providers IN ACCESS EXCLUSIVE MODE;

DO $migration_397_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 396 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 396 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=396 AND
        migration_id='396_ge_cache' AND
        checksum_sha256='1ad8fba779a1a603581b1074c5f48f90ca35d0e03ee2f6ec0cac864764878d90' AND
        down_checksum_sha256='03e4886921448fd0c46dfbcafbb0fd723c53649a67ed672c7f271cd34b4225ce' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.plugin_providers') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 397 requires the exact verified 396 release head' USING ERRCODE='P3970';
    END IF;
END;
$migration_397_up$;

-- 397（r136 pa22-provider，合入时接在 396_ge_cache 之后）。
-- PA-22 (ADR 0007 §8.2): a third-party DNS / SMS / ICP provider plugin's
-- declaration (libs/entitlement/pluginprovider) reaches this control plane
-- as artifact plugin_provider/<plugin id> of an authorized installation.
-- artifactsync materializes it here once the installation is enabled on
-- this control plane, with contract_status pending: the installation
-- contract runner calls the plugin's sandbox and records the report. Only a
-- declaration whose contract passed (for exactly these bytes) can be enabled
-- by an administrator, and only an enabled, passed, active provider is ever
-- called (DNS provider type plugin, SMS transport, ICP query). An upgrade
-- (new declaration bytes) resets the contract; the provider is unusable
-- until the new version passes again.
ALTER TABLE market_data_pack_sources DROP CONSTRAINT market_data_pack_sources_artifact_id_386;
ALTER TABLE market_data_pack_sources ADD CONSTRAINT market_data_pack_sources_artifact_id_397
    CHECK (artifact_id ~ '^(market_rule_pack|market_theme|plugin_ui|plugin_provider)/[a-z0-9]+([.-][a-z0-9]+)+$');
ALTER TABLE market_data_pack_sources DROP CONSTRAINT market_data_pack_sources_kind_386;
ALTER TABLE market_data_pack_sources ADD CONSTRAINT market_data_pack_sources_kind_397
    CHECK (kind IN ('market_rule_pack', 'market_theme', 'plugin_ui', 'plugin_provider'));
ALTER TABLE market_data_pack_sources ADD CONSTRAINT market_data_pack_sources_plugin_provider_397
    CHECK (kind <> 'plugin_provider' OR local_name = plugin_id);

CREATE TABLE plugin_providers (
    plugin_id text PRIMARY KEY CHECK (plugin_id ~ '^[a-z0-9]+([.-][a-z0-9]+)+$' AND char_length(plugin_id) BETWEEN 3 AND 128),
    version text NOT NULL CHECK (char_length(version) BETWEEN 5 AND 64),
    base_url text NOT NULL CHECK (base_url ~ '^https://[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+(/[^?#]*)?$' AND
        base_url !~ '^https://[^/]*\.[0-9]+(/|$)'),
    kinds text[] NOT NULL CHECK (cardinality(kinds) BETWEEN 1 AND 3 AND kinds <@ ARRAY['dns', 'icp', 'sms']::text[]),
    -- The canonical cdnca.plugin-provider/v1 declaration.
    declaration jsonb NOT NULL CHECK (jsonb_typeof(declaration) = 'object' AND declaration->>'plugin_id' = plugin_id AND
        declaration->>'base_url' = base_url),
    declaration_sha256 text NOT NULL CHECK (declaration_sha256 ~ '^[0-9a-f]{64}$'),
    status text NOT NULL CHECK (status IN ('active', 'withdrawn')),
    -- The plugin installation this control plane confirmed.
    tenant_scope_id uuid NOT NULL,
    authorization_id uuid NOT NULL,
    -- Installation contract: pending until the runner checked these bytes.
    contract_status text NOT NULL CHECK (contract_status IN ('pending', 'passed', 'failed')),
    contract_version text CHECK (contract_version IS NULL OR char_length(contract_version) BETWEEN 1 AND 64),
    contract_declaration_sha256 text CHECK (contract_declaration_sha256 IS NULL OR contract_declaration_sha256 ~ '^[0-9a-f]{64}$'),
    contract_report jsonb CHECK (contract_report IS NULL OR jsonb_typeof(contract_report) = 'object'),
    contract_checked_at timestamptz,
    -- The administrator's choice; a provider is used only while enabled AND
    -- its current declaration passed the contract (plugin_provider_usable).
    enabled boolean NOT NULL DEFAULT false,
    enabled_by_user_id uuid,
    enabled_at timestamptz,
    materialized_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (contract_status = 'pending' OR (contract_version IS NOT NULL AND contract_declaration_sha256 IS NOT NULL AND
        contract_report IS NOT NULL AND contract_checked_at IS NOT NULL)),
    CHECK (NOT enabled OR (enabled_by_user_id IS NOT NULL AND enabled_at IS NOT NULL))
);

-- Turning a provider on requires a passed contract for the current bytes.
CREATE FUNCTION plugin_providers_enable_gate_397() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.enabled AND (TG_OP = 'INSERT' OR NOT OLD.enabled) AND NOT (NEW.status = 'active' AND
        NEW.contract_status = 'passed' AND NEW.contract_declaration_sha256 = NEW.declaration_sha256) THEN
        RAISE EXCEPTION 'provider plugin % cannot be enabled before its contract passed', NEW.plugin_id
            USING ERRCODE = 'P3971';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER plugin_providers_enable_gate_397 BEFORE INSERT OR UPDATE ON plugin_providers
    FOR EACH ROW EXECUTE FUNCTION plugin_providers_enable_gate_397();

-- The DNS provider type of a third-party plugin: credentials {plugin_id}.
ALTER TABLE dns_providers DROP CONSTRAINT dns_providers_provider_type_check;
ALTER TABLE dns_providers ADD CONSTRAINT dns_providers_provider_type_check CHECK (
    provider_type IN ('aliyun', 'cloudflare', 'huawei', 'dnspod_cn', 'dns_com', 'dnsdun', 'dns_la', 'custom_http', 'plugin')
);

REVOKE ALL ON plugin_providers FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON plugin_providers TO cdnca_control_app;
GRANT SELECT ON plugin_providers TO cdnca_control_runtime;
