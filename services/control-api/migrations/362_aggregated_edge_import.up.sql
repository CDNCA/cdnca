LOCK TABLE schema_migrations, cdn_provider_accounts, site_supply_cdn_configs, site_supply_bindings IN ACCESS EXCLUSIVE MODE;

DO $migration_362_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 361 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 361 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=361 AND
        migration_id='361_audit_unified_fields' AND
        checksum_sha256='328119e6a5097148319fee0638682cf86e98c3ab57a8e3253a47c16ef6f9ec21' AND
        down_checksum_sha256='f5a6d342b089da22c413305dcd863bdc893548713c53b361b016f9f32afffc24' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.cdn_zone_imports') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 362 requires the exact verified 361 release head' USING ERRCODE='P3620';
    END IF;
END;
$migration_362_up$;

-- One-click import of an existing Cloudflare zone (docs/adr/0008-aggregated-edge.md
-- §5): a read-only token, a mapping report and a refreshed site view. The
-- imported sites never take part in cross-CDN scheduling (§5.3, §11.1); the
-- migrate wizard changes the listed DNS records only after the member confirms.

-- access: 'manage' accounts drive config sync and the migrate wizard's DNS
-- writes; 'read_only' accounts hold an import token and are never attached
-- to a supply. Fixed at creation.
ALTER TABLE cdn_provider_accounts
    ADD COLUMN access text NOT NULL DEFAULT 'manage' CHECK (access IN ('manage', 'read_only'));

CREATE FUNCTION cdn_provider_account_access_362()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.access IS DISTINCT FROM OLD.access THEN
        RAISE EXCEPTION 'a cdn provider account access level is fixed at creation' USING ERRCODE='P3621';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER cdn_provider_account_access_362
BEFORE UPDATE OF access ON cdn_provider_accounts
FOR EACH ROW EXECUTE FUNCTION cdn_provider_account_access_362();

CREATE FUNCTION site_supply_cdn_config_account_362()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.account_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM cdn_provider_accounts WHERE id = NEW.account_id AND access = 'read_only') THEN
        RAISE EXCEPTION 'a read-only import account cannot back a supply' USING ERRCODE='P3623';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER site_supply_cdn_config_account_362
BEFORE INSERT OR UPDATE OF account_id ON site_supply_cdn_configs
FOR EACH ROW EXECUTE FUNCTION site_supply_cdn_config_account_362();

-- One imported zone. account_id is the read-only account holding the token;
-- deleting the import deletes that account with it (the service does both).
CREATE TABLE cdn_zone_imports (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    platform_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    account_id uuid NOT NULL UNIQUE REFERENCES cdn_provider_accounts(id) ON DELETE RESTRICT,
    provider text NOT NULL CHECK (provider ~ '^[a-z][a-z0-9_]{0,31}$'),
    zone_ref text NOT NULL CHECK (char_length(zone_ref) BETWEEN 1 AND 64 AND zone_ref ~ '^[A-Za-z0-9._-]+$'),
    zone_name text NOT NULL DEFAULT '' CHECK (char_length(zone_name) <= 253 AND zone_name !~ '[[:cntrl:][:space:]]'),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'ready', 'failed')),
    -- Whether the vendor told us the token is read-only (false = unverified).
    read_only_verified boolean NOT NULL DEFAULT false,
    -- sha256 of the last import snapshot; a refresh that reads the same
    -- snapshot changes nothing but the times.
    snapshot_sha256 text NOT NULL DEFAULT '' CHECK (snapshot_sha256 = '' OR snapshot_sha256 ~ '^[0-9a-f]{64}$'),
    -- The mapping report (ADR 0008 §5.2): counts, zone settings and items.
    report jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(report) = 'object' AND octet_length(report::text) <= 1048576),
    missing_permissions text[] NOT NULL DEFAULT ARRAY[]::text[] CHECK (cardinality(missing_permissions) <= 64),
    refresh_interval_seconds integer NOT NULL DEFAULT 3600 CHECK (refresh_interval_seconds BETWEEN 300 AND 604800),
    next_refresh_at timestamptz NOT NULL CHECK (isfinite(next_refresh_at)),
    refreshed_at timestamptz CHECK (refreshed_at IS NULL OR isfinite(refreshed_at)),
    lease_until timestamptz CHECK (lease_until IS NULL OR isfinite(lease_until)),
    last_error_code text NOT NULL DEFAULT '' CHECK (char_length(last_error_code) <= 64),
    -- Bumped by every refresh that changes the snapshot; a migrate plan is
    -- only confirmed against the revision it was made from.
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    UNIQUE (provider, zone_ref),
    FOREIGN KEY (account_id, provider) REFERENCES cdn_provider_accounts(id, provider) ON DELETE RESTRICT
);
CREATE INDEX cdn_zone_imports_due_362_idx ON cdn_zone_imports (next_refresh_at);

-- The read-only site view of one proxied hostname of an imported zone. It
-- is not a sites row and can never be bound to a supply; while it is
-- read_only, a platform site serving the same hostname cannot be bound to
-- any supply either (cross-CDN scheduling would fight the vendor-held DNS).
-- The migrate wizard moves it to migrated once the listed records changed.
CREATE TABLE cdn_import_sites (
    import_id uuid NOT NULL REFERENCES cdn_zone_imports(id) ON DELETE CASCADE,
    hostname text NOT NULL CHECK (
        hostname = lower(hostname) AND char_length(hostname) <= 253 AND
        hostname ~ '^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    state text NOT NULL DEFAULT 'read_only' CHECK (state IN ('read_only', 'migrated')),
    -- Still proxied by the vendor in the last refresh.
    present boolean NOT NULL DEFAULT true,
    view jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(view) = 'object' AND octet_length(view::text) <= 65536),
    mapped_count integer NOT NULL DEFAULT 0 CHECK (mapped_count >= 0),
    vendor_only_count integer NOT NULL DEFAULT 0 CHECK (vendor_only_count >= 0),
    -- The platform site the hostname was migrated to (no FK: the record
    -- outlives a later deletion of that site).
    migrated_site_id uuid,
    migrated_at timestamptz CHECK (migrated_at IS NULL OR isfinite(migrated_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (import_id, hostname),
    CHECK ((state = 'migrated') = (migrated_site_id IS NOT NULL AND migrated_at IS NOT NULL))
);
CREATE INDEX cdn_import_sites_hostname_362_idx ON cdn_import_sites (hostname) WHERE state = 'read_only';

-- Migrate wizard plans (ADR 0008 §11.1). plan lists every DNS record that
-- will change, before and after; plan_sha256 and import_revision are what
-- the member confirms. Only one open plan per hostname.
CREATE TABLE cdn_import_migrations (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    import_id uuid NOT NULL REFERENCES cdn_zone_imports(id) ON DELETE CASCADE,
    hostname text NOT NULL CHECK (hostname = lower(hostname) AND char_length(hostname) BETWEEN 1 AND 253),
    target_site_id uuid NOT NULL,
    target_cname text NOT NULL CHECK (char_length(target_cname) BETWEEN 1 AND 253 AND target_cname = lower(target_cname)),
    writer_account_id uuid NOT NULL REFERENCES cdn_provider_accounts(id) ON DELETE RESTRICT,
    state text NOT NULL CHECK (state IN ('planned', 'applied', 'failed', 'cancelled', 'superseded')),
    import_revision bigint NOT NULL CHECK (import_revision > 0),
    plan jsonb NOT NULL CHECK (jsonb_typeof(plan) = 'array' AND jsonb_array_length(plan) BETWEEN 1 AND 32 AND
        octet_length(plan::text) <= 65536),
    plan_sha256 text NOT NULL CHECK (plan_sha256 ~ '^[0-9a-f]{64}$'),
    expires_at timestamptz NOT NULL CHECK (isfinite(expires_at)),
    -- Per-record outcome of the apply (what was written before a failure).
    result jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(result) = 'array' AND octet_length(result::text) <= 65536),
    error_code text NOT NULL DEFAULT '' CHECK (char_length(error_code) <= 64),
    created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    confirmed_by uuid REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    finished_at timestamptz CHECK (finished_at IS NULL OR isfinite(finished_at)),
    CHECK ((state = 'planned') = (finished_at IS NULL))
);
CREATE UNIQUE INDEX cdn_import_migrations_open_362_uidx ON cdn_import_migrations (import_id, hostname) WHERE state = 'planned';
CREATE INDEX cdn_import_migrations_import_362_idx ON cdn_import_migrations (import_id, created_at);

-- A platform site whose hostname is still a read-only imported view cannot
-- enter a scheduling binding (ADR 0008 §5.3, §11.1): its traffic is
-- resolved by the vendor until the migrate wizard changes the records.
CREATE FUNCTION site_supply_binding_import_guard_362()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    blocked text;
BEGIN
    SELECT imported.hostname INTO blocked
    FROM cdn_import_sites imported
    WHERE imported.state = 'read_only' AND imported.hostname IN (
        SELECT site.domain FROM sites site WHERE site.id = NEW.site_id
        UNION
        SELECT current.canonical_domain FROM (
            SELECT DISTINCT ON (fact.canonical_domain) fact.canonical_domain, fact.action
            FROM site_domain_facts fact WHERE fact.site_id = NEW.site_id
            ORDER BY fact.canonical_domain, fact.global_sequence DESC) current
        WHERE current.action = 'activate')
    ORDER BY imported.hostname LIMIT 1;
    IF blocked IS NOT NULL THEN
        RAISE EXCEPTION 'hostname % is a read-only imported site; migrate it before scheduling', blocked
            USING ERRCODE='P3622';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER site_supply_binding_import_guard_362
BEFORE INSERT OR UPDATE OF site_id ON site_supply_bindings
FOR EACH ROW EXECUTE FUNCTION site_supply_binding_import_guard_362();

REVOKE ALL ON cdn_zone_imports, cdn_import_sites, cdn_import_migrations FROM PUBLIC;
REVOKE ALL ON FUNCTION cdn_provider_account_access_362(), site_supply_cdn_config_account_362(),
    site_supply_binding_import_guard_362() FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON cdn_zone_imports, cdn_import_sites, cdn_import_migrations
    TO cdnca_control_app, cdnca_control_runtime;
