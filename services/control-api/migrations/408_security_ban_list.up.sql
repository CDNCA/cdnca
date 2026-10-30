LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_408_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 407 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 407 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=407 AND
        migration_id='407_attack_alert_notifications' AND
        checksum_sha256='3699dae3fad2bf7db849a25af7a3409855028d1523e290a82ece978c3bafb99c' AND
        down_checksum_sha256='9627a9f65b75eab8c8a5102b6ffd6559147473d1706bb12a440ca28334e2f18b' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('security_ban_entries') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 408 requires the exact verified 407 release head' USING ERRCODE='P4080';
    END IF;
END;
$migration_408_up$;

-- Placeholder number 408 (the merge renumbers it): the guard names the
-- integration head when written, 391_http_policy_regex_rules (count and max
-- 391), not version-1; the merge points it at the real previous version.
-- ge-waf S5 (GoEdge parity: IP list "record IP" / unban, missing 8; logic 3):
-- the security ban list library. One row per (site, client) ban:
--   source waf | cc: a node's automatic ban (WAF ban / auto block, CC
--     temporary ban), folded in from security_events temporary_ban by the
--     control plane (internal/securityban sync);
--   source manual: a ban an operator or the site owner added.
-- Every node serving the site receives the site's active bans (so one node's
-- automatic ban applies on all of them) and the releases of the last 7 days
-- (a release lifts the nodes' own automatic bans of the client that started
-- before it), as a signed per-node snapshot (agent ConnectResponse 25,
-- receipt ConnectRequest 22). A release is never deleted: it is the row's
-- released_at; a later ban of the same client is a new row.
CREATE TABLE security_ban_entries (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE CASCADE,
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    client_ip inet NOT NULL CHECK (masklen(client_ip) = CASE WHEN family(client_ip)=4 THEN 32 ELSE 128 END),
    source text NOT NULL CHECK (source IN ('waf', 'cc', 'manual')),
    rule_id text NOT NULL DEFAULT '' CHECK (rule_id = '' OR rule_id ~ '^[A-Za-z0-9:._-]{1,128}$'),
    reason text NOT NULL DEFAULT '' CHECK (char_length(reason) <= 256),
    banned_at timestamptz NOT NULL,
    banned_until timestamptz NOT NULL CHECK (banned_until > banned_at AND banned_until <= banned_at + interval '30 days'),
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    released_at timestamptz CHECK (released_at IS NULL OR released_at >= banned_at),
    released_by uuid REFERENCES users(id) ON DELETE SET NULL,
    -- The node event a waf / cc row came from (idempotent sync); NULL for manual.
    source_event_id text CHECK (source_event_id IS NULL OR char_length(source_event_id) BETWEEN 1 AND 128),
    CHECK ((source = 'manual') = (source_event_id IS NULL))
);
CREATE UNIQUE INDEX security_ban_entries_event ON security_ban_entries(source_event_id) WHERE source_event_id IS NOT NULL;
-- At most one active row (unreleased, not expired) per site and client: the
-- writers hold a transaction advisory lock per (site, client) and extend the
-- active row instead of adding one. An expired unreleased row stays as
-- history; it cannot be marked released (a release is sent to the nodes).
CREATE INDEX security_ban_entries_site_client ON security_ban_entries(site_id, client_ip, banned_at DESC);
CREATE INDEX security_ban_entries_scope ON security_ban_entries(tenant_scope_id, banned_at DESC);
CREATE INDEX security_ban_entries_released ON security_ban_entries(released_at) WHERE released_at IS NOT NULL;

-- Manual ban writes by Idempotency-Key (a retried create returns the same row).
CREATE TABLE security_ban_write_requests (
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE CASCADE,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9._-]{1,128}$'),
    entry_id uuid NOT NULL REFERENCES security_ban_entries(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (actor_scope_id, actor_user_id, idempotency_key)
);

-- The sync cursor over security_events (ClickHouse ingested_at, ms).
CREATE TABLE security_ban_sync_cursor (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    ingested_until_ms bigint NOT NULL CHECK (ingested_until_ms >= 0),
    updated_at timestamptz NOT NULL
);

-- Per node: the revision of its snapshot (grows on every change of what the
-- node should hold: content_sha256 is the digest of its bans and releases),
-- the digest of the published wire bytes, and the node's receipt of the last
-- one it answered.
CREATE TABLE security_ban_node_state (
    node_id uuid PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision >= 1),
    content_sha256 bytea NOT NULL CHECK (octet_length(content_sha256) = 32),
    list_sha256 bytea NOT NULL CHECK (octet_length(list_sha256) = 32),
    published_at timestamptz NOT NULL,
    applied_revision bigint NOT NULL DEFAULT 0 CHECK (applied_revision >= 0),
    applied_sha256 bytea CHECK (applied_sha256 IS NULL OR octet_length(applied_sha256) = 32),
    applied bool,
    applied_bans integer CHECK (applied_bans IS NULL OR applied_bans >= 0),
    applied_releases integer CHECK (applied_releases IS NULL OR applied_releases >= 0),
    error_code text NOT NULL DEFAULT '' CHECK (error_code = '' OR error_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    reported_at timestamptz
);

REVOKE ALL ON security_ban_entries, security_ban_write_requests, security_ban_sync_cursor, security_ban_node_state FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON security_ban_entries TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT ON security_ban_write_requests TO cdnca_control_app;
GRANT SELECT, INSERT, UPDATE ON security_ban_sync_cursor, security_ban_node_state TO cdnca_control_app, cdnca_control_runtime;
