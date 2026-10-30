LOCK TABLE schema_migrations, permissions, access_scopes, roles, role_permissions, site_supplies IN ACCESS EXCLUSIVE MODE;

DO $migration_350_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 349 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 349 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=349 AND
        migration_id='349_rule_packs' AND
        checksum_sha256='ba2acf69a0296766ac6d7538824677d784bf39c536abcca884b041e4a5aab0a8' AND
        down_checksum_sha256='cae1167cd408935a65269841290108990acb984ee6e428bb368147ab82fadb75' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.cdn_provider_accounts') IS NOT NULL OR
            EXISTS (SELECT 1 FROM permissions WHERE name = 'edge.aggregated.manage') THEN
        RAISE EXCEPTION 'migration 350 requires the exact verified 349 release head' USING ERRCODE='P3500';
    END IF;
END;
$migration_350_up$;

-- Aggregated edge (docs/adr/0008-aggregated-edge.md §9): the member's own
-- third-party CDN accounts and the third_party_cdn site supplies of 285.
-- Platform scope only: a member reselling sites shows its customers the
-- supply CNAME, never its CDN account (ADR 0008 §7.1).
INSERT INTO permissions(name, description)
VALUES ('edge.aggregated.manage', 'Bind third-party CDN accounts and manage aggregated edge supplies');

INSERT INTO role_permissions(role_id, permission_name)
SELECT role.id, 'edge.aggregated.manage'
FROM roles role
JOIN access_scopes scope ON scope.id = role.scope_id AND scope.kind = 'platform'
WHERE role.system_role AND role.name = 'platform_owner'
ON CONFLICT DO NOTHING;

-- A member's account at a CDN vendor. The credential is one AES-GCM envelope
-- under the DNS credential keyring, bound (AAD) to this row (ADR 0008 §3.5).
-- credential_version is the fence an in-flight vendor call is leased on:
-- every credential change or revocation bumps it, so a call started with
-- the old credential cannot finish under the new one.
CREATE TABLE cdn_provider_accounts (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    platform_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    provider text NOT NULL CHECK (provider ~ '^[a-z][a-z0-9_]{0,31}$'),
    name text NOT NULL CHECK (name = btrim(name) AND char_length(name) BETWEEN 1 AND 128 AND name !~ '[[:cntrl:]]'),
    -- Non-secret adapter settings (e.g. the Cloudflare SaaS zone id).
    settings jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(settings) = 'object' AND octet_length(settings::text) <= 8192),
    credential_key_id text NOT NULL CHECK (char_length(credential_key_id) BETWEEN 1 AND 255),
    credential_ciphertext bytea NOT NULL CHECK (octet_length(credential_ciphertext) BETWEEN 29 AND 65536),
    -- {"field": "16 hex fingerprint"} of each secret field, for the masked view.
    credential_fingerprints jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(credential_fingerprints) = 'object'),
    credential_version bigint NOT NULL DEFAULT 1 CHECK (credential_version > 0),
    credential_revoked boolean NOT NULL DEFAULT false,
    status text NOT NULL DEFAULT 'unverified' CHECK (status IN ('unverified', 'verified', 'disabled')),
    -- Last Verify: account identity, plan and the permissions the token lacks.
    account_ref text NOT NULL DEFAULT '' CHECK (char_length(account_ref) <= 255 AND account_ref !~ '[[:cntrl:]]'),
    plan text NOT NULL DEFAULT '' CHECK (char_length(plan) <= 128 AND plan !~ '[[:cntrl:]]'),
    capabilities text[] NOT NULL DEFAULT ARRAY[]::text[] CHECK (cardinality(capabilities) <= 32),
    missing_permissions text[] NOT NULL DEFAULT ARRAY[]::text[] CHECK (cardinality(missing_permissions) <= 32),
    verified_at timestamptz CHECK (verified_at IS NULL OR isfinite(verified_at)),
    -- The controller never goes past this many hostnames on the account
    -- (ADR 0008 §3.4): the vendor free allowance unless the member raised it.
    hostname_limit integer NOT NULL CHECK (hostname_limit BETWEEN 0 AND 1000000),
    -- Writes pause until this time after the vendor answered 429.
    write_paused_until timestamptz CHECK (write_paused_until IS NULL OR isfinite(write_paused_until)),
    last_error_code text NOT NULL DEFAULT '' CHECK (char_length(last_error_code) <= 64),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    UNIQUE (platform_scope_id, name),
    UNIQUE (id, provider),
    CHECK (status <> 'verified' OR NOT credential_revoked)
);

CREATE FUNCTION cdn_provider_account_credential_fence_350()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.credential_version := OLD.credential_version;
    NEW.credential_revoked := OLD.credential_revoked;
    IF NEW.credential_key_id IS DISTINCT FROM OLD.credential_key_id OR
       NEW.credential_ciphertext IS DISTINCT FROM OLD.credential_ciphertext THEN
        -- A new credential (or a KEK rewrap) is a new version; it starts
        -- unrevoked unless the account is being disabled with it.
        NEW.credential_version := OLD.credential_version + 1;
        NEW.credential_revoked := NEW.status = 'disabled';
    ELSIF NEW.status = 'disabled' AND NOT OLD.credential_revoked THEN
        -- Disabling revokes the credential; only a new credential re-enables.
        NEW.credential_version := OLD.credential_version + 1;
        NEW.credential_revoked := true;
    END IF;
    IF NEW.credential_revoked AND NEW.status <> 'disabled' THEN
        RAISE EXCEPTION 'a revoked cdn provider credential must be replaced before the account is re-enabled'
            USING ERRCODE='P3502';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER cdn_provider_account_credential_fence_350
BEFORE UPDATE ON cdn_provider_accounts
FOR EACH ROW EXECUTE FUNCTION cdn_provider_account_credential_fence_350();

-- The configuration of a site_supplies row of kind third_party_cdn.
-- config_sync writes the vendor side from the site model through the
-- account; schedule_only only records the access CNAME the member built.
CREATE TABLE site_supply_cdn_configs (
    supply_id uuid PRIMARY KEY REFERENCES site_supplies(id) ON DELETE RESTRICT,
    provider text NOT NULL CHECK (provider ~ '^[a-z][a-z0-9_]{0,31}$'),
    mode text NOT NULL CHECK (mode IN ('config_sync', 'schedule_only')),
    account_id uuid,
    -- Vendor access name traffic is CNAMEd to (schedule_only: the member's;
    -- config_sync: the SaaS zone's CNAME target).
    endpoint text NOT NULL DEFAULT '' CHECK (
        endpoint = '' OR (endpoint = lower(endpoint) AND char_length(endpoint) <= 253 AND
        endpoint ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')),
    -- Vendor-side origin hostname; '' uses the account's fallback origin.
    origin_server text NOT NULL DEFAULT '' CHECK (
        origin_server = '' OR (origin_server = lower(origin_server) AND char_length(origin_server) <= 253 AND
        origin_server ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')),
    drift_policy text NOT NULL DEFAULT 'enforce' CHECK (drift_policy IN ('enforce', 'report')),
    health_path text NOT NULL DEFAULT '/' CHECK (health_path ~ '^/[A-Za-z0-9._~!$&''()*+,;=:@%/-]{0,255}$'),
    health_status integer NOT NULL DEFAULT 200 CHECK (health_status BETWEEN 100 AND 599),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    FOREIGN KEY (account_id, provider) REFERENCES cdn_provider_accounts(id, provider) ON DELETE RESTRICT,
    CHECK (mode <> 'config_sync' OR account_id IS NOT NULL),
    CHECK (mode <> 'schedule_only' OR endpoint <> '')
);
CREATE INDEX site_supply_cdn_configs_account_350_idx ON site_supply_cdn_configs (account_id) WHERE account_id IS NOT NULL;

-- Configuration sync state of one site on one config_sync supply. The row
-- outlives the site binding until every owned vendor resource is deleted
-- (ADR 0008 §3.3 删除: no orphans), so it has no foreign key to sites.
CREATE TABLE site_supply_cdn_sites (
    site_id uuid NOT NULL,
    supply_id uuid NOT NULL REFERENCES site_supply_cdn_configs(supply_id) ON DELETE RESTRICT,
    -- Site settings the member chose to leave out of this supply's
    -- projection (ADR 0008 §3.1); every other unsupported setting refuses.
    ignored_settings text[] NOT NULL DEFAULT ARRAY[]::text[] CHECK (cardinality(ignored_settings) <= 64),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'synced', 'refused', 'failed', 'removing', 'removed')),
    site_revision bigint NOT NULL DEFAULT 0 CHECK (site_revision >= 0),
    projection_sha256 text NOT NULL DEFAULT '' CHECK (projection_sha256 = '' OR projection_sha256 ~ '^[0-9a-f]{64}$'),
    -- Unsupported settings or missing vendor permissions that refused the sync.
    refusal jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(refusal) = 'array' AND octet_length(refusal::text) <= 16384),
    drift_state text NOT NULL DEFAULT 'none' CHECK (drift_state IN ('none', 'drifted')),
    drift jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(drift) = 'array' AND octet_length(drift::text) <= 16384),
    last_error_code text NOT NULL DEFAULT '' CHECK (char_length(last_error_code) <= 64),
    applied_at timestamptz CHECK (applied_at IS NULL OR isfinite(applied_at)),
    observed_at timestamptz CHECK (observed_at IS NULL OR isfinite(observed_at)),
    next_observe_at timestamptz NOT NULL CHECK (isfinite(next_observe_at)),
    lease_until timestamptz CHECK (lease_until IS NULL OR isfinite(lease_until)),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    PRIMARY KEY (site_id, supply_id)
);
CREATE INDEX site_supply_cdn_sites_due_350_idx ON site_supply_cdn_sites (next_observe_at) WHERE state <> 'removed';
CREATE INDEX site_supply_cdn_sites_supply_350_idx ON site_supply_cdn_sites (supply_id);

-- Vendor resources the controller created for a site on a supply: the
-- resource key, the vendor id and the fingerprint recorded after the last
-- successful write (drift compares the vendor's copy with it).
CREATE TABLE site_supply_cdn_resources (
    site_id uuid NOT NULL,
    supply_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('hostname', 'origin_rule', 'https_redirect', 'cache_rule')),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 253 AND name !~ '[[:cntrl:][:space:]]'),
    remote_id text NOT NULL CHECK (char_length(remote_id) BETWEEN 1 AND 512 AND remote_id !~ '[[:cntrl:]]'),
    applied_fingerprint text NOT NULL CHECK (applied_fingerprint ~ '^[0-9a-f]{64}$'),
    observed_fingerprint text NOT NULL DEFAULT '' CHECK (observed_fingerprint = '' OR observed_fingerprint ~ '^[0-9a-f]{64}$'),
    remote_state text NOT NULL DEFAULT '' CHECK (char_length(remote_state) <= 64),
    -- DNS records (ownership / certificate TXT) the member must publish.
    validation jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(validation) = 'array' AND octet_length(validation::text) <= 8192),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (site_id, supply_id, kind, name),
    FOREIGN KEY (site_id, supply_id) REFERENCES site_supply_cdn_sites(site_id, supply_id) ON DELETE RESTRICT
);
CREATE INDEX site_supply_cdn_resources_supply_350_idx ON site_supply_cdn_resources (supply_id, kind, name);

-- Whether the aggregated edge may act (ADR 0008 §8, §11.2). The worker
-- records here each time it evaluates module.aggregated_edge: frozen stops
-- sync, observation and automatic switching without deleting anything;
-- after the entitlement returns a full reconcile runs before switching
-- resumes (reconcile_required).
CREATE TABLE aggregated_edge_runtime (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    state text NOT NULL CHECK (state IN ('inactive', 'active', 'frozen')),
    reconcile_required boolean NOT NULL DEFAULT false,
    frozen_at timestamptz CHECK (frozen_at IS NULL OR isfinite(frozen_at)),
    resumed_at timestamptz CHECK (resumed_at IS NULL OR isfinite(resumed_at)),
    reconciled_at timestamptz CHECK (reconciled_at IS NULL OR isfinite(reconciled_at)),
    evaluated_at timestamptz NOT NULL CHECK (isfinite(evaluated_at)),
    denial text NOT NULL DEFAULT '' CHECK (char_length(denial) <= 64),
    CHECK (state <> 'frozen' OR frozen_at IS NOT NULL)
);
INSERT INTO aggregated_edge_runtime(singleton, state, evaluated_at) VALUES (true, 'inactive', now());

REVOKE ALL ON cdn_provider_accounts, site_supply_cdn_configs, site_supply_cdn_sites,
    site_supply_cdn_resources, aggregated_edge_runtime FROM PUBLIC;
REVOKE ALL ON FUNCTION cdn_provider_account_credential_fence_350() FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON cdn_provider_accounts, site_supply_cdn_configs, site_supply_cdn_sites,
    site_supply_cdn_resources TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, UPDATE ON aggregated_edge_runtime TO cdnca_control_app, cdnca_control_runtime;
