LOCK TABLE schema_migrations, sites, nodes IN ACCESS EXCLUSIVE MODE;

DO $migration_403_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 402 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 402 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=402 AND
        migration_id='402_plugin_payment_providers' AND
        checksum_sha256='c0f5589b6ee9ecb90569081d861f8450546078555079ad75dd91a4d5bb175689' AND
        down_checksum_sha256='bef0eae462a2fbc0a8f3141fe1da268a9072d8f019a5d7a9d67825276e78df12' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.autodefense_sites') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 403 requires the exact verified 402 release head' USING ERRCODE='P4030';
    END IF;
END;
$migration_403_up$;

-- 403 (r136 ad-08-store, placeholder number: renumbered to 408 on merge).
-- Control-plane store of the official module.autodefense plugin (ADR 0010
-- section 4.5 as narrowed by node autonomy, user 10-19 06:20): no baseline,
-- baseline pointer, minute summary or sample is kept here; nodes learn on
-- their own. Individual verdicts (and the platform node security events,
-- F4) are ClickHouse autodefense_verdicts_v1; PostgreSQL keeps settings,
-- attack events, signatures, mitigations, releases, false positives and the
-- ingest receipts. A site without an autodefense_sites row is "off" with the
-- registry defaults. Deleting a site or a node deletes its rows.

CREATE TABLE autodefense_platform_settings (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    settings jsonb NOT NULL CHECK (jsonb_typeof(settings) = 'object'),
    revision bigint NOT NULL CHECK (revision > 0),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at))
);

CREATE TABLE autodefense_sites (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    mode text NOT NULL CHECK (mode IN ('off', 'learning', 'observe', 'protect')),
    sensitivity text NOT NULL CHECK (sensitivity IN ('low', 'medium', 'high')),
    maturity text NOT NULL CHECK (maturity IN ('prior', 'hour', 'day', 'week')),
    cross_site boolean NOT NULL,
    circuit_state text NOT NULL CHECK (circuit_state IN ('closed', 'open')),
    circuit_reason text CHECK (circuit_reason IS NULL OR circuit_reason ~ '^[a-z_]{1,64}$'),
    circuit_since timestamptz,
    circuit_manual_resume boolean NOT NULL,
    observe_until timestamptz,
    max_level jsonb NOT NULL CHECK (jsonb_typeof(max_level) = 'object' AND max_level->>'field' = 'site.max_level'),
    modules jsonb NOT NULL CHECK (jsonb_typeof(modules) = 'array'),
    last_event_at timestamptz,
    revision bigint NOT NULL CHECK (revision > 0),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (tenant_scope_id, site_id),
    FOREIGN KEY (tenant_scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE,
    CHECK ((circuit_state = 'open') = (circuit_reason IS NOT NULL AND circuit_since IS NOT NULL))
);

-- The layer 4 module of a node port group (platform only, section 7A.4).
CREATE TABLE autodefense_port_groups (
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    port_group_id text NOT NULL CHECK (port_group_id ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
    module jsonb NOT NULL CHECK (jsonb_typeof(module) = 'object' AND module->>'name' = 'l4'),
    state text NOT NULL CHECK (state ~ '^[a-z_]{1,32}$'),
    revision bigint NOT NULL CHECK (revision > 0),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (node_id, port_group_id)
);

-- The last state each node reported for a site: an attack event stays
-- active while any node of the site is in attack, protect_origin or cooldown.
CREATE TABLE autodefense_site_node_states (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    state text NOT NULL CHECK (state IN ('normal', 'surge', 'protect_origin', 'attack', 'cooldown', 'circuit_open', 'baseline_stale')),
    level smallint NOT NULL CHECK (level BETWEEN 0 AND 5),
    reported_at timestamptz NOT NULL CHECK (isfinite(reported_at)),
    PRIMARY KEY (tenant_scope_id, site_id, node_id),
    FOREIGN KEY (tenant_scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE
);

CREATE TABLE autodefense_events (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('active', 'ended')),
    started_at timestamptz NOT NULL CHECK (isfinite(started_at)),
    ended_at timestamptz,
    peak_level smallint NOT NULL CHECK (peak_level BETWEEN 0 AND 5),
    peak_request_milli bigint NOT NULL DEFAULT 0 CHECK (peak_request_milli >= 0),
    affected_requests bigint NOT NULL DEFAULT 0 CHECK (affected_requests >= 0),
    mitigated_requests bigint NOT NULL DEFAULT 0 CHECK (mitigated_requests >= 0),
    challenge_pass_permille bigint NOT NULL DEFAULT 0 CHECK (challenge_pass_permille BETWEEN 0 AND 1000),
    steps jsonb NOT NULL CHECK (jsonb_typeof(steps) = 'array' AND jsonb_array_length(steps) <= 256),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    FOREIGN KEY (tenant_scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE,
    CHECK ((status = 'ended') = (ended_at IS NOT NULL) AND (ended_at IS NULL OR ended_at >= started_at))
);
CREATE UNIQUE INDEX autodefense_events_active_idx ON autodefense_events (tenant_scope_id, site_id) WHERE status = 'active';
CREATE INDEX autodefense_events_list_idx ON autodefense_events (tenant_scope_id, started_at DESC, id);

CREATE TABLE autodefense_signatures (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    id text NOT NULL CHECK (id ~ '^[0-9a-f]{16}$'),
    conditions jsonb NOT NULL CHECK (jsonb_typeof(conditions) = 'array' AND jsonb_array_length(conditions) > 0),
    stage text NOT NULL CHECK (stage IN ('shadow', 'challenge', 'block', 'standby')),
    cover_permille bigint NOT NULL CHECK (cover_permille BETWEEN 0 AND 1000),
    fpr_ppm bigint NOT NULL CHECK (fpr_ppm BETWEEN 0 AND 1000000),
    hits bigint NOT NULL CHECK (hits >= 0),
    reason text NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 512),
    origin text NOT NULL CHECK (origin IN ('node', 'control')),
    origin_node_id uuid,
    managed boolean NOT NULL,
    solidified_kind text CHECK (solidified_kind IS NULL OR solidified_kind IN ('waf', 'cc')),
    solidified_rule_id uuid,
    revoked boolean NOT NULL,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (tenant_scope_id, site_id, id),
    FOREIGN KEY (tenant_scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE,
    CHECK ((origin = 'node') = (origin_node_id IS NOT NULL)),
    CHECK ((solidified_kind IS NULL) = (solidified_rule_id IS NULL) AND (solidified_kind IS NULL OR NOT managed))
);
CREATE INDEX autodefense_signatures_list_idx ON autodefense_signatures (tenant_scope_id, created_at DESC);

-- Mitigations in force (the autodefense ban list view, section 9.3 item 5):
-- one row per site target, extended by every L3+ verdict of any node.
CREATE TABLE autodefense_mitigations (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('ip', 'cidr', 'ja4')),
    target text NOT NULL CHECK (char_length(target) BETWEEN 1 AND 128),
    level smallint NOT NULL CHECK (level BETWEEN 1 AND 5),
    scope text NOT NULL CHECK (scope IN ('site', 'tenant')),
    offences bigint NOT NULL CHECK (offences > 0),
    score smallint NOT NULL CHECK (score BETWEEN 0 AND 100),
    reason text NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 512),
    last_node_id uuid NOT NULL,
    since timestamptz NOT NULL CHECK (isfinite(since)),
    until timestamptz NOT NULL CHECK (isfinite(until)),
    released_at timestamptz,
    released_by text CHECK (released_by IS NULL OR char_length(released_by) BETWEEN 1 AND 160),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    UNIQUE (tenant_scope_id, site_id, kind, target),
    FOREIGN KEY (tenant_scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE,
    CHECK (until > since AND (released_at IS NULL) = (released_by IS NULL))
);
CREATE INDEX autodefense_mitigations_list_idx ON autodefense_mitigations (tenant_scope_id, since DESC, id);

-- A released verdict (the verdict itself is ClickHouse history).
CREATE TABLE autodefense_verdict_releases (
    tenant_scope_id uuid NOT NULL,
    verdict_id uuid NOT NULL,
    site_id uuid NOT NULL,
    target text NOT NULL CHECK (char_length(target) BETWEEN 1 AND 128),
    released_by text NOT NULL CHECK (char_length(released_by) BETWEEN 1 AND 160),
    released_at timestamptz NOT NULL CHECK (isfinite(released_at)),
    PRIMARY KEY (tenant_scope_id, verdict_id),
    FOREIGN KEY (tenant_scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE
);

CREATE TABLE autodefense_false_positives (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    verdict_id uuid,
    block_id uuid REFERENCES autodefense_mitigations(id) ON DELETE SET NULL,
    signature_id text CHECK (signature_id IS NULL OR signature_id ~ '^[0-9a-f]{16}$'),
    target text CHECK (target IS NULL OR char_length(target) BETWEEN 1 AND 128),
    reason text NOT NULL CHECK (char_length(reason) <= 512),
    reported_by text NOT NULL CHECK (char_length(reported_by) BETWEEN 1 AND 160),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    FOREIGN KEY (tenant_scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE
);
CREATE INDEX autodefense_false_positives_list_idx ON autodefense_false_positives (tenant_scope_id, created_at DESC);

-- Ingest idempotency (contract section 5: node + site | port group + seq;
-- "node" for the F4 node_event reports).
-- The report stream keeps one day; rows older than two days are deleted.
CREATE TABLE autodefense_report_receipts (
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    report_scope text NOT NULL CHECK (report_scope ~ '^(site:[0-9a-f-]{36}|port_group:[a-z0-9][a-z0-9_-]{0,63}|node)$'),
    seq bigint NOT NULL CHECK (seq > 0),
    kind text NOT NULL CHECK (kind IN ('minute', 'state', 'candidate', 'verdicts', 'adjust', 'node_event')),
    outcome text NOT NULL CHECK (outcome IN ('applied', 'ignored', 'rejected_scope')),
    received_at timestamptz NOT NULL CHECK (isfinite(received_at)),
    PRIMARY KEY (node_id, report_scope, seq)
);
CREATE INDEX autodefense_report_receipts_age_idx ON autodefense_report_receipts (received_at);

REVOKE ALL ON autodefense_platform_settings, autodefense_sites, autodefense_port_groups, autodefense_site_node_states,
    autodefense_events, autodefense_signatures, autodefense_mitigations, autodefense_verdict_releases,
    autodefense_false_positives, autodefense_report_receipts FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON autodefense_platform_settings, autodefense_sites, autodefense_port_groups,
    autodefense_site_node_states, autodefense_events, autodefense_signatures, autodefense_mitigations,
    autodefense_verdict_releases, autodefense_false_positives TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, DELETE ON autodefense_report_receipts TO cdnca_control_app, cdnca_control_runtime;
