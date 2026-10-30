LOCK TABLE schema_migrations, cdn_provider_accounts, site_supply_cdn_configs, site_supply_cdn_sites,
    site_supply_cdn_resources IN ACCESS EXCLUSIVE MODE;

DO $migration_375_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 374 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 374 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=374 AND
        migration_id='374_site_crs_overrides' AND
        checksum_sha256='80d17aff7fb59880ff3c248240f661c68725cf647801616e714f3d3353812acd' AND
        down_checksum_sha256='62a77bf305f3436aba44ad97c75863d97a446b82f622ac1bf4d7fa0d5db7e842' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.site_supply_cdn_validation_records') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 375 requires the exact verified 374 release head' USING ERRCODE='P3750';
    END IF;
END;
$migration_375_up$;

-- Cloudflare for SaaS configuration sync, the rest of P1-c
-- (docs/adr/0008-aggregated-edge.md §4.1, §7.2, §10): the account's fallback
-- origin, DCV TXT records published through the site's DNS provider, the
-- basic WAF rule, usage, and an incremental projection queue.

-- The SaaS zone's fallback origin (account-wide: every custom hostname
-- without its own origin goes there). '' = not set by the controller.
ALTER TABLE cdn_provider_accounts
    ADD COLUMN fallback_origin text NOT NULL DEFAULT '' CHECK (
        fallback_origin = '' OR (fallback_origin = lower(fallback_origin) AND char_length(fallback_origin) <= 253 AND
        fallback_origin ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')),
    ADD COLUMN fallback_origin_status text NOT NULL DEFAULT '' CHECK (
        char_length(fallback_origin_status) <= 64 AND fallback_origin_status !~ '[[:cntrl:]]'),
    ADD COLUMN fallback_origin_checked_at timestamptz CHECK (
        fallback_origin_checked_at IS NULL OR isfinite(fallback_origin_checked_at)),
    -- The controller never goes past this many custom WAF rules in the zone
    -- (each synced site with a basic WAF projection is one rule; the zone
    -- plan caps them). The member raises it after upgrading the plan.
    ADD COLUMN waf_rule_limit integer NOT NULL DEFAULT 5 CHECK (waf_rule_limit BETWEEN 0 AND 10000),
    -- Usage pull (ADR 0008 §3.1 usage): hours up to usage_pulled_through are
    -- stored; the next pull is due at usage_next_pull_at.
    ADD COLUMN usage_pulled_through timestamptz CHECK (usage_pulled_through IS NULL OR isfinite(usage_pulled_through)),
    ADD COLUMN usage_next_pull_at timestamptz CHECK (usage_next_pull_at IS NULL OR isfinite(usage_next_pull_at)),
    ADD COLUMN usage_error_code text NOT NULL DEFAULT '' CHECK (char_length(usage_error_code) <= 64);

-- The basic WAF projection is one owned custom rule per site.
ALTER TABLE site_supply_cdn_resources
    DROP CONSTRAINT site_supply_cdn_resources_kind_check,
    ADD CONSTRAINT site_supply_cdn_resources_kind_check
        CHECK (kind IN ('hostname', 'origin_rule', 'https_redirect', 'cache_rule', 'waf_rule'));

-- Incremental projection: every change to what the projection reads bumps
-- source_generation (triggers below); the worker re-projects only rows whose
-- projected_generation is behind, instead of every synced site every tick.
ALTER TABLE site_supply_cdn_sites
    ADD COLUMN source_generation bigint NOT NULL DEFAULT 1 CHECK (source_generation > 0),
    ADD COLUMN projected_generation bigint NOT NULL DEFAULT 0 CHECK (projected_generation >= 0);
CREATE INDEX site_supply_cdn_sites_dirty_375_idx ON site_supply_cdn_sites (next_observe_at)
    WHERE state <> 'removed' AND source_generation <> projected_generation;

-- DCV / ownership TXT records the vendor asks for (ADR 0008 §4.1): written
-- through the site tenant's DNS provider when one manages the name (auto),
-- otherwise listed for the member to add (manual). wanted=false rows are
-- records the vendor no longer lists; an auto record is deleted from DNS
-- before its row goes, so nothing is left behind in the member's zone.
CREATE TABLE site_supply_cdn_validation_records (
    site_id uuid NOT NULL,
    supply_id uuid NOT NULL,
    purpose text NOT NULL CHECK (purpose IN ('certificate', 'ownership')),
    record_name text NOT NULL CHECK (
        record_name = lower(record_name) AND char_length(record_name) <= 253 AND
        record_name ~ '^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'),
    record_value text NOT NULL CHECK (char_length(record_value) BETWEEN 1 AND 1024 AND record_value !~ '[[:cntrl:]]'),
    wanted boolean NOT NULL DEFAULT true,
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'published', 'manual', 'failed')),
    -- Opaque reference of the record the controller wrote ('' = none).
    dns_ref text NOT NULL DEFAULT '' CHECK (char_length(dns_ref) <= 2048 AND dns_ref !~ '[[:cntrl:]]'),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error_code text NOT NULL DEFAULT '' CHECK (char_length(last_error_code) <= 64),
    next_attempt_at timestamptz NOT NULL CHECK (isfinite(next_attempt_at)),
    published_at timestamptz CHECK (published_at IS NULL OR isfinite(published_at)),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    PRIMARY KEY (site_id, supply_id, record_name, record_value),
    FOREIGN KEY (site_id, supply_id) REFERENCES site_supply_cdn_sites(site_id, supply_id) ON DELETE RESTRICT,
    CHECK (state <> 'published' OR dns_ref <> '')
);
CREATE INDEX site_supply_cdn_validation_records_due_375_idx ON site_supply_cdn_validation_records (next_attempt_at);

-- Hourly usage per custom hostname of an account (requests, edge bytes).
CREATE TABLE cdn_provider_usage (
    account_id uuid NOT NULL REFERENCES cdn_provider_accounts(id) ON DELETE CASCADE,
    hostname text NOT NULL CHECK (hostname = lower(hostname) AND char_length(hostname) BETWEEN 1 AND 253 AND
        hostname !~ '[[:cntrl:][:space:]]'),
    bucket_start timestamptz NOT NULL CHECK (isfinite(bucket_start) AND date_trunc('hour', bucket_start) = bucket_start),
    requests bigint NOT NULL CHECK (requests >= 0),
    bytes bigint NOT NULL CHECK (bytes >= 0),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (account_id, hostname, bucket_start)
);
CREATE INDEX cdn_provider_usage_bucket_375_idx ON cdn_provider_usage (bucket_start);

-- Projection source triggers. SECURITY DEFINER: whichever role writes a
-- site, its origins, cache policy or security bindings, the queue row is
-- bumped (no extra grants on site_supply_cdn_sites for those roles).
DO $migration_375_functions$
BEGIN
    EXECUTE format($ddl$
        CREATE FUNCTION %I.aggregated_edge_site_changed_375() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $body$
        DECLARE
            changed uuid;
        BEGIN
            IF TG_OP = 'DELETE' THEN
                changed := OLD.site_id;
            ELSIF TG_TABLE_NAME = 'sites' THEN
                changed := NEW.id;
            ELSE
                changed := NEW.site_id;
            END IF;
            UPDATE %I.site_supply_cdn_sites SET source_generation = source_generation + 1
                WHERE site_id = changed AND state <> 'removed';
            RETURN NULL;
        END;
        $body$;
    $ddl$, current_schema(), current_schema());
    EXECUTE format($ddl$
        CREATE FUNCTION %I.aggregated_edge_supply_changed_375() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $body$
        BEGIN
            IF TG_TABLE_NAME = 'cdn_provider_accounts' THEN
                UPDATE %I.site_supply_cdn_sites cdn SET source_generation = cdn.source_generation + 1
                    FROM %I.site_supply_cdn_configs config
                    WHERE config.supply_id = cdn.supply_id AND config.account_id = NEW.id AND cdn.state <> 'removed';
            ELSE
                UPDATE %I.site_supply_cdn_sites SET source_generation = source_generation + 1
                    WHERE supply_id = NEW.supply_id AND state <> 'removed';
            END IF;
            RETURN NULL;
        END;
        $body$;
    $ddl$, current_schema(), current_schema(), current_schema(), current_schema());
END;
$migration_375_functions$;
REVOKE ALL ON FUNCTION aggregated_edge_site_changed_375(), aggregated_edge_supply_changed_375() FROM PUBLIC;

CREATE TRIGGER aggregated_edge_site_changed_375 AFTER UPDATE ON sites FOR EACH ROW
    WHEN (OLD.revision IS DISTINCT FROM NEW.revision OR OLD.deleted_at IS DISTINCT FROM NEW.deleted_at OR
          OLD.domain IS DISTINCT FROM NEW.domain OR OLD.https_enabled IS DISTINCT FROM NEW.https_enabled OR
          OLD.force_https IS DISTINCT FROM NEW.force_https OR OLD.tls_protocols IS DISTINCT FROM NEW.tls_protocols)
    EXECUTE FUNCTION aggregated_edge_site_changed_375();
CREATE TRIGGER aggregated_edge_site_changed_375 AFTER INSERT OR UPDATE OR DELETE ON site_origins
    FOR EACH ROW EXECUTE FUNCTION aggregated_edge_site_changed_375();
CREATE TRIGGER aggregated_edge_site_changed_375 AFTER INSERT ON site_domain_facts
    FOR EACH ROW EXECUTE FUNCTION aggregated_edge_site_changed_375();
CREATE TRIGGER aggregated_edge_site_changed_375 AFTER INSERT OR UPDATE ON cache_policy_heads
    FOR EACH ROW EXECUTE FUNCTION aggregated_edge_site_changed_375();
CREATE TRIGGER aggregated_edge_site_changed_375 AFTER INSERT OR DELETE ON security_policy_site_bindings
    FOR EACH ROW EXECUTE FUNCTION aggregated_edge_site_changed_375();
CREATE TRIGGER aggregated_edge_site_activated_375 AFTER UPDATE OF active_policy_version ON security_policy_site_bindings
    FOR EACH ROW WHEN (OLD.active_policy_version IS DISTINCT FROM NEW.active_policy_version)
    EXECUTE FUNCTION aggregated_edge_site_changed_375();
CREATE TRIGGER aggregated_edge_site_changed_375 AFTER INSERT OR DELETE ON challenge_site_bindings_138
    FOR EACH ROW EXECUTE FUNCTION aggregated_edge_site_changed_375();
CREATE TRIGGER aggregated_edge_site_activated_375 AFTER UPDATE OF active_binding_revision ON challenge_site_bindings_138
    FOR EACH ROW WHEN (OLD.active_binding_revision IS DISTINCT FROM NEW.active_binding_revision)
    EXECUTE FUNCTION aggregated_edge_site_changed_375();
CREATE TRIGGER aggregated_edge_site_changed_375 AFTER INSERT OR UPDATE OR DELETE ON site_security_mounts
    FOR EACH ROW EXECUTE FUNCTION aggregated_edge_site_changed_375();
CREATE TRIGGER aggregated_edge_site_changed_375 AFTER INSERT OR UPDATE OR DELETE ON site_quick_block_overrides
    FOR EACH ROW EXECUTE FUNCTION aggregated_edge_site_changed_375();
CREATE TRIGGER aggregated_edge_supply_changed_375 AFTER UPDATE OF origin_server ON site_supply_cdn_configs
    FOR EACH ROW WHEN (OLD.origin_server IS DISTINCT FROM NEW.origin_server)
    EXECUTE FUNCTION aggregated_edge_supply_changed_375();
CREATE TRIGGER aggregated_edge_supply_changed_375 AFTER UPDATE OF fallback_origin ON cdn_provider_accounts
    FOR EACH ROW WHEN (OLD.fallback_origin IS DISTINCT FROM NEW.fallback_origin)
    EXECUTE FUNCTION aggregated_edge_supply_changed_375();

REVOKE ALL ON site_supply_cdn_validation_records, cdn_provider_usage FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON site_supply_cdn_validation_records, cdn_provider_usage
    TO cdnca_control_app, cdnca_control_runtime;
