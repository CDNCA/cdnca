LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_285_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 284 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 284 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=284 AND
        migration_id='284_node_purge' AND
        checksum_sha256='0a0aff51ef85661bcaaa563a4618929fb76daab884515e33160163b1fb6057be' AND
        down_checksum_sha256='fe2bf9efbbc6713af9c792c2c40d828c8caacd13ed9e5062e3d82548463ca872' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.site_supplies') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 285 requires the exact verified 284 release head' USING ERRCODE='P2850';
    END IF;
END;
$migration_285_up$;

-- Site supply binding (docs/marketplace/02-supply-model.md §2).
--
-- Local node groups keep living on sites.node_group_id and the package
-- snapshot's backup_node_group_id: site_supply_bindings_effective derives
-- their bindings from those columns instead of copying them, so the two can
-- never drift and existing sites behave exactly as before. Only supplies that
-- have no column of their own (market subscriptions, third-party CDNs) get
-- stored rows.

-- A supply this controller can point a site at, other than its own node groups.
CREATE TABLE site_supplies (
    id uuid PRIMARY KEY,
    platform_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    kind text NOT NULL CHECK (kind IN ('market_subscription', 'third_party_cdn')),
    name text NOT NULL CHECK (name = btrim(name) AND char_length(name) BETWEEN 1 AND 128),
    -- market_subscription: the subscription id on the market.
    market_subscription_id uuid,
    -- Last supply CNAME the market assigned (GET /v1/supply-targets).
    target text NOT NULL DEFAULT '' CHECK (char_length(target) <= 253),
    target_synced_at timestamptz,
    -- Leaves behind the subscription with their current grant, as of the
    -- last sync: [{"leaf_member_id","node_pool_ref","grant_id"}].
    leaves jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(leaves) = 'array'),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'retired')),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK ((kind = 'market_subscription') = (market_subscription_id IS NOT NULL)),
    CHECK (updated_at >= created_at)
);
CREATE UNIQUE INDEX site_supplies_market_subscription_idx
    ON site_supplies (market_subscription_id) WHERE market_subscription_id IS NOT NULL;

CREATE TABLE site_supply_bindings (
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    supply_id uuid NOT NULL REFERENCES site_supplies(id) ON DELETE RESTRICT,
    role text NOT NULL CHECK (role IN ('primary', 'backup')),
    priority integer NOT NULL DEFAULT 100 CHECK (priority BETWEEN 0 AND 1000000),
    -- Region/line this binding serves; '' is the default line.
    line_scope text NOT NULL DEFAULT '' CHECK (char_length(line_scope) <= 64),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (site_id, supply_id, line_scope)
);
CREATE INDEX site_supply_bindings_supply_idx ON site_supply_bindings (supply_id);

-- What each leaf behind a market binding has applied. leaf_site_id is the
-- leaf's own site id returned by its first Commit (libs/marketproto/siteconf).
CREATE TABLE site_supply_leaf_sites (
    site_id uuid NOT NULL,
    supply_id uuid NOT NULL,
    leaf_member_id uuid NOT NULL,
    node_pool_ref text NOT NULL CHECK (char_length(node_pool_ref) BETWEEN 1 AND 128),
    leaf_site_id uuid,
    applied_revision bigint NOT NULL DEFAULT 0 CHECK (applied_revision >= 0),
    applied_digest text NOT NULL DEFAULT '' CHECK (applied_digest = '' OR applied_digest ~ '^[0-9a-f]{64}$'),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'applied', 'failed', 'inconsistent')),
    last_error text NOT NULL DEFAULT '' CHECK (char_length(last_error) <= 500),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (site_id, supply_id, leaf_member_id, node_pool_ref),
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE,
    FOREIGN KEY (supply_id) REFERENCES site_supplies(id) ON DELETE RESTRICT
);

-- Every revision the subscriber sent, so a failed Commit can roll the
-- already-committed leaves back to revision N-1.
CREATE TABLE site_supply_config_revisions (
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision > 0),
    config jsonb NOT NULL CHECK (jsonb_typeof(config) = 'object'),
    digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (site_id, revision)
);

CREATE VIEW site_supply_bindings_effective AS
SELECT s.id AS site_id, s.scope_id, 'local_node_group'::text AS kind, NULL::uuid AS supply_id,
       s.node_group_id AS node_group_id, 'primary'::text AS role, 0 AS priority, ''::text AS line_scope
FROM sites s
WHERE s.deleted_at IS NULL AND s.node_group_id IS NOT NULL
UNION ALL
SELECT s.id, s.scope_id, 'local_node_group', NULL,
       (sub.product_snapshot -> 'spec' ->> 'backup_node_group_id')::uuid, 'backup', 1000, ''
FROM sites s
JOIN package_subscriptions sub ON sub.id = s.package_subscription_id
WHERE s.deleted_at IS NULL
  AND sub.product_snapshot -> 'spec' ->> 'backup_node_group_id' ~ '^[0-9a-f-]{36}$'
UNION ALL
SELECT s.id, s.scope_id, supply.kind, supply.id, NULL, binding.role, binding.priority, binding.line_scope
FROM site_supply_bindings binding
JOIN sites s ON s.id = binding.site_id AND s.deleted_at IS NULL
JOIN site_supplies supply ON supply.id = binding.supply_id AND supply.status <> 'retired';

GRANT SELECT, INSERT, UPDATE ON site_supplies, site_supply_leaf_sites TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON site_supply_bindings TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT ON site_supply_config_revisions TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT ON site_supply_bindings_effective TO cdnca_control_app, cdnca_control_runtime;
