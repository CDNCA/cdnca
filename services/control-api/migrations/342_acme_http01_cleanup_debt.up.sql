LOCK TABLE schema_migrations, acme_http01_node_challenges, acme_http01_node_overlay_generations,
    acme_http01_node_overlay_states IN ACCESS EXCLUSIVE MODE;

DO $migration_342_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 341 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 341 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=341 AND
        migration_id='341_l4_guard_rules' AND
        checksum_sha256='986ce0399908def5abb7d0805c8c2f11767e1180a9d2957b7ee4c89db371d8cb' AND
        down_checksum_sha256='746551be8cc0506711a82f89053f715780f2667f5e921836943d31dc8e3f547c' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.acme_http01_site_overlay_states') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 342 requires the exact verified 341 release head' USING ERRCODE='P3420';
    END IF;
END;
$migration_342_up$;

-- ADR-0003 on top of 337: site desired versions, frozen required membership
-- (epochs), site coverage per node generation, the cleanup debt ledger, the
-- serving gate and the 063 backfill.
--
-- Concurrency: every HTTP-01 overlay writer first takes
-- pg_advisory_xact_lock(hashtextextended('acme-http01-overlay', 0)), then the
-- node state rows in UUID order (337). Writers are serialized, never lock site
-- and node rows in crossing orders, and a later writer re-reads the committed
-- union.

-- Nodes reachable through the site's CNAME before any HTTP-01 gate: active,
-- unheld nodes with an enabled endpoint in a current line group of the site
-- (its own, its package's primary and backup).
CREATE FUNCTION acme_http01_site_candidate_nodes(target_scope_id uuid, target_site_id uuid)
RETURNS SETOF uuid LANGUAGE sql STABLE AS $$
    SELECT DISTINCT endpoint.node_id FROM sites site
    LEFT JOIN package_subscriptions subscription ON subscription.tenant_scope_id=site.scope_id
     AND subscription.id=site.package_subscription_id AND subscription.deleted_at IS NULL
    JOIN node_line_groups line_group ON line_group.deleted_at IS NULL AND line_group.id IN (
         site.node_group_id,
         (subscription.product_snapshot->'spec'->>'node_group_id')::uuid,
         (subscription.product_snapshot->'spec'->>'backup_node_group_id')::uuid)
    JOIN node_line_endpoints endpoint ON endpoint.tenant_scope_id=line_group.tenant_scope_id
     AND endpoint.line_group_id=line_group.id AND endpoint.config_revision=line_group.current_revision
     AND endpoint.enabled AND endpoint.node_id IS NOT NULL
    JOIN nodes node ON node.id=endpoint.node_id AND node.admin_state='active'
    JOIN access_scopes node_scope ON node_scope.id=node.scope_id
    WHERE site.scope_id=target_scope_id AND site.id=target_site_id
      AND line_group.tenant_scope_id IN (site.scope_id, node.scope_id)
      AND (node.scope_id=site.scope_id OR node_scope.kind='platform')
      AND NOT EXISTS (SELECT 1 FROM node_serving_holds hold WHERE hold.node_id=node.id AND hold.held)
$$;

-- One row per site that ever had an HTTP-01 version.
CREATE TABLE acme_http01_site_overlay_states (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    current_version bigint NOT NULL CHECK (current_version >= 0),
    current_version_id uuid,
    open_epoch_id uuid,
    epoch_count bigint NOT NULL CHECK (epoch_count >= 0),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (updated_at >= created_at),
    PRIMARY KEY (tenant_scope_id, site_id),
    FOREIGN KEY (tenant_scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE RESTRICT,
    CHECK ((current_version = 0) = (current_version_id IS NULL)),
    CHECK (open_epoch_id IS NULL OR epoch_count > 0)
);

-- A non-empty token epoch of a site: required membership is frozen when it
-- opens and only the final empty version closes it.
CREATE TABLE acme_http01_site_overlay_epochs (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    sequence bigint NOT NULL CHECK (sequence >= 1),
    member_count integer NOT NULL CHECK (member_count BETWEEN 1 AND 10000),
    member_set_sha256 bytea NOT NULL CHECK (octet_length(member_set_sha256) = 32),
    opened_at timestamptz NOT NULL CHECK (isfinite(opened_at)),
    closed_at timestamptz CHECK (closed_at IS NULL OR (isfinite(closed_at) AND closed_at >= opened_at)),
    UNIQUE (tenant_scope_id, site_id, sequence),
    UNIQUE (id, tenant_scope_id, site_id),
    FOREIGN KEY (tenant_scope_id, site_id)
        REFERENCES acme_http01_site_overlay_states(tenant_scope_id, site_id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX acme_http01_site_overlay_epochs_open_342_idx
    ON acme_http01_site_overlay_epochs(tenant_scope_id, site_id) WHERE closed_at IS NULL;
ALTER TABLE acme_http01_site_overlay_states
    ADD FOREIGN KEY (open_epoch_id, tenant_scope_id, site_id)
        REFERENCES acme_http01_site_overlay_epochs(id, tenant_scope_id, site_id) ON DELETE RESTRICT;

CREATE TABLE acme_http01_site_overlay_epoch_members (
    epoch_id uuid NOT NULL REFERENCES acme_http01_site_overlay_epochs(id) ON DELETE RESTRICT,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    PRIMARY KEY (epoch_id, node_id)
);
CREATE INDEX acme_http01_site_overlay_epoch_members_node_342_idx
    ON acme_http01_site_overlay_epoch_members(node_id);

-- A site desired version: the site's live challenges of one epoch, deduplicated
-- by (domain, token) and ordered by (domain bytes, token digest). An empty
-- version closes its epoch. backfill_063 versions are evidence of a 063 site
-- version (no token rows, never served).
CREATE TABLE acme_http01_site_overlay_versions (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    version bigint NOT NULL CHECK (version >= 1),
    epoch_id uuid NOT NULL,
    token_count integer NOT NULL CHECK (token_count BETWEEN 0 AND 4096),
    token_set_sha256 bytea NOT NULL CHECK (octet_length(token_set_sha256) = 32),
    source text NOT NULL CHECK (source IN ('refresh', 'backfill_063')),
    legacy_version_id uuid REFERENCES acme_http01_overlay_versions(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    UNIQUE (tenant_scope_id, site_id, version),
    UNIQUE (id, tenant_scope_id, site_id),
    UNIQUE (id, tenant_scope_id, site_id, epoch_id),
    FOREIGN KEY (epoch_id, tenant_scope_id, site_id)
        REFERENCES acme_http01_site_overlay_epochs(id, tenant_scope_id, site_id) ON DELETE RESTRICT,
    CHECK ((source = 'backfill_063') = (legacy_version_id IS NOT NULL))
);
ALTER TABLE acme_http01_site_overlay_states
    ADD FOREIGN KEY (current_version_id, tenant_scope_id, site_id)
        REFERENCES acme_http01_site_overlay_versions(id, tenant_scope_id, site_id) ON DELETE RESTRICT;

CREATE TABLE acme_http01_site_overlay_version_tokens (
    version_id uuid NOT NULL REFERENCES acme_http01_site_overlay_versions(id) ON DELETE RESTRICT,
    ordinal integer NOT NULL CHECK (ordinal BETWEEN 1 AND 4096),
    tenant_scope_id uuid NOT NULL,
    operation_id text NOT NULL,
    attempt_id uuid NOT NULL,
    PRIMARY KEY (version_id, ordinal),
    UNIQUE (version_id, tenant_scope_id, operation_id, attempt_id),
    FOREIGN KEY (tenant_scope_id, operation_id, attempt_id)
        REFERENCES acme_http01_node_challenges(tenant_scope_id, operation_id, attempt_id) ON DELETE RESTRICT
);

-- The epoch a challenge was published in. Challenges recorded before 342 have
-- none and are withdrawn by this migration.
CREATE TABLE acme_http01_node_challenge_epochs (
    tenant_scope_id uuid NOT NULL,
    operation_id text NOT NULL,
    attempt_id uuid NOT NULL,
    epoch_id uuid NOT NULL REFERENCES acme_http01_site_overlay_epochs(id) ON DELETE RESTRICT,
    PRIMARY KEY (tenant_scope_id, operation_id, attempt_id),
    FOREIGN KEY (tenant_scope_id, operation_id, attempt_id)
        REFERENCES acme_http01_node_challenges(tenant_scope_id, operation_id, attempt_id) ON DELETE RESTRICT
);
CREATE INDEX acme_http01_node_challenge_epochs_epoch_342_idx ON acme_http01_node_challenge_epochs(epoch_id);
-- A node that may still serve tokens of a site it no longer has to serve them
-- for. One immutable debt per (node, site, epoch the node was required in);
-- while unresolved, a later release of the same (node, site) coalesces into
-- it, so the earliest uncovered source is kept.
CREATE TABLE acme_http01_node_overlay_cleanup_debts (
    id uuid PRIMARY KEY,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    required_epoch_id uuid NOT NULL,
    earliest_uncovered_site_version_id uuid NOT NULL,
    earliest_token_set_sha256 bytea NOT NULL CHECK (octet_length(earliest_token_set_sha256) = 32),
    earliest_token_count integer NOT NULL CHECK (earliest_token_count BETWEEN 1 AND 4096),
    opened_reason text NOT NULL CHECK (opened_reason IN (
        'member_removed', 'site_emptied', 'backfill_063_serving', 'backfill_063_removed')),
    opened_at timestamptz NOT NULL CHECK (isfinite(opened_at)),
    UNIQUE (node_id, tenant_scope_id, site_id, required_epoch_id),
    UNIQUE (id, node_id, tenant_scope_id, site_id),
    FOREIGN KEY (required_epoch_id, node_id)
        REFERENCES acme_http01_site_overlay_epoch_members(epoch_id, node_id) ON DELETE RESTRICT,
    FOREIGN KEY (required_epoch_id, tenant_scope_id, site_id)
        REFERENCES acme_http01_site_overlay_epochs(id, tenant_scope_id, site_id) ON DELETE RESTRICT,
    FOREIGN KEY (earliest_uncovered_site_version_id, tenant_scope_id, site_id, required_epoch_id)
        REFERENCES acme_http01_site_overlay_versions(id, tenant_scope_id, site_id, epoch_id) ON DELETE RESTRICT
);
CREATE INDEX acme_http01_node_overlay_cleanup_debts_site_342_idx
    ON acme_http01_node_overlay_cleanup_debts(tenant_scope_id, site_id, node_id);

-- Per-node generation coverage of one site: required (the full token set of
-- the site's current version) or cleanup_debt (zero tokens for a site the
-- node owes a cleanup).
CREATE TABLE acme_http01_node_overlay_generation_coverages (
    generation_id uuid NOT NULL REFERENCES acme_http01_node_overlay_generations(id) ON DELETE RESTRICT,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    coverage_kind text NOT NULL CHECK (coverage_kind IN ('required', 'cleanup_debt')),
    site_version_id uuid NOT NULL,
    site_token_set_sha256 bytea NOT NULL CHECK (octet_length(site_token_set_sha256) = 32),
    site_token_count integer NOT NULL CHECK (site_token_count BETWEEN 0 AND 4096),
    required_epoch_id uuid NOT NULL,
    cleanup_debt_id uuid,
    PRIMARY KEY (generation_id, site_id),
    FOREIGN KEY (site_version_id, tenant_scope_id, site_id)
        REFERENCES acme_http01_site_overlay_versions(id, tenant_scope_id, site_id) ON DELETE RESTRICT,
    FOREIGN KEY (required_epoch_id, tenant_scope_id, site_id)
        REFERENCES acme_http01_site_overlay_epochs(id, tenant_scope_id, site_id) ON DELETE RESTRICT,
    FOREIGN KEY (cleanup_debt_id, node_id, tenant_scope_id, site_id)
        REFERENCES acme_http01_node_overlay_cleanup_debts(id, node_id, tenant_scope_id, site_id) ON DELETE RESTRICT,
    CHECK ((coverage_kind = 'required') = (site_token_count > 0)),
    CHECK (coverage_kind = 'required' OR cleanup_debt_id IS NOT NULL)
);
CREATE INDEX acme_http01_node_overlay_generation_coverages_debt_342_idx
    ON acme_http01_node_overlay_generation_coverages(cleanup_debt_id) WHERE cleanup_debt_id IS NOT NULL;

-- Append-only debt ledger; the latest event is the debt's state.
CREATE TABLE acme_http01_node_overlay_cleanup_debt_events (
    debt_id uuid NOT NULL REFERENCES acme_http01_node_overlay_cleanup_debts(id) ON DELETE RESTRICT,
    sequence integer NOT NULL CHECK (sequence BETWEEN 1 AND 1000000),
    event text NOT NULL CHECK (event IN (
        'opened', 'coalesced', 'scheduled', 'resolved_cleanup', 'resolved_required')),
    reason text CHECK (reason IN (
        'member_removed', 'site_emptied', 'backfill_063_serving', 'backfill_063_removed')),
    epoch_id uuid REFERENCES acme_http01_site_overlay_epochs(id) ON DELETE RESTRICT,
    site_version_id uuid REFERENCES acme_http01_site_overlay_versions(id) ON DELETE RESTRICT,
    generation_id uuid REFERENCES acme_http01_node_overlay_generations(id) ON DELETE RESTRICT,
    occurred_at timestamptz NOT NULL CHECK (isfinite(occurred_at)),
    PRIMARY KEY (debt_id, sequence),
    CHECK ((event IN ('opened', 'coalesced')) = (reason IS NOT NULL AND epoch_id IS NOT NULL)),
    CHECK ((event IN ('opened', 'coalesced')) = (site_version_id IS NOT NULL)),
    CHECK ((event IN ('scheduled', 'resolved_cleanup', 'resolved_required')) = (generation_id IS NOT NULL))
);
CREATE INDEX acme_http01_node_overlay_cleanup_debt_events_resolved_342_idx
    ON acme_http01_node_overlay_cleanup_debt_events(debt_id) WHERE event IN ('resolved_cleanup', 'resolved_required');

-- A member leaving an open epoch's required set, with the debt it owes.
CREATE TABLE acme_http01_site_overlay_epoch_releases (
    epoch_id uuid NOT NULL,
    node_id uuid NOT NULL,
    reason text NOT NULL CHECK (reason IN (
        'member_removed', 'site_emptied', 'backfill_063_serving', 'backfill_063_removed')),
    debt_id uuid NOT NULL REFERENCES acme_http01_node_overlay_cleanup_debts(id) ON DELETE RESTRICT,
    released_at timestamptz NOT NULL CHECK (isfinite(released_at)),
    PRIMARY KEY (epoch_id, node_id),
    FOREIGN KEY (epoch_id, node_id)
        REFERENCES acme_http01_site_overlay_epoch_members(epoch_id, node_id) ON DELETE RESTRICT
);

-- Node generation purpose and coverage counts (ADR-0003). Generations written
-- before 342 are 'apply' without coverage.
ALTER TABLE acme_http01_node_overlay_generations
    ADD COLUMN purpose text NOT NULL DEFAULT 'apply',
    ADD COLUMN required_coverage_count integer NOT NULL DEFAULT 0,
    ADD COLUMN cleanup_debt_coverage_count integer NOT NULL DEFAULT 0,
    ADD COLUMN non_serving_proof_sha256 bytea,
    ADD CONSTRAINT acme_http01_node_overlay_generations_purpose_342 CHECK (
        purpose IN ('apply', 'cleanup_only') AND
        required_coverage_count BETWEEN 0 AND 100000 AND cleanup_debt_coverage_count BETWEEN 0 AND 100000 AND
        (purpose = 'cleanup_only') = (non_serving_proof_sha256 IS NOT NULL) AND
        (non_serving_proof_sha256 IS NULL OR octet_length(non_serving_proof_sha256) = 32) AND
        (purpose = 'apply' OR (token_count = 0 AND required_coverage_count = 0)));

-- 063 backfill marks (acme_http01_backfill_063). A site is bootstrapped (its
-- 063 version became a closed epoch whose targets owe a cleanup) or
-- quarantined. A node is pending until its first generation at or above the
-- floor (above every 063 site revision it saw) covers its debts.
CREATE TABLE acme_http01_overlay_backfill_sites (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    legacy_revision bigint NOT NULL CHECK (legacy_revision >= 1),
    state text NOT NULL CHECK (state IN ('bootstrapped', 'quarantined')),
    reason_code text NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    epoch_id uuid REFERENCES acme_http01_site_overlay_epochs(id) ON DELETE RESTRICT,
    legacy_version_id uuid REFERENCES acme_http01_overlay_versions(id) ON DELETE RESTRICT,
    recorded_at timestamptz NOT NULL CHECK (isfinite(recorded_at)),
    PRIMARY KEY (tenant_scope_id, site_id),
    FOREIGN KEY (tenant_scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE RESTRICT,
    CHECK ((state = 'bootstrapped') = (epoch_id IS NOT NULL))
);

CREATE TABLE acme_http01_overlay_backfill_nodes (
    node_id uuid PRIMARY KEY REFERENCES nodes(id) ON DELETE RESTRICT,
    state text NOT NULL CHECK (state IN ('pending', 'bootstrapped', 'quarantined')),
    reason_code text NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    generation_floor bigint NOT NULL CHECK (generation_floor BETWEEN 1 AND 9007199254740991),
    bootstrap_generation_id uuid REFERENCES acme_http01_node_overlay_generations(id) ON DELETE RESTRICT,
    recorded_at timestamptz NOT NULL CHECK (isfinite(recorded_at)),
    updated_at timestamptz NOT NULL CHECK (updated_at >= recorded_at),
    CHECK ((state = 'bootstrapped') = (bootstrap_generation_id IS NOT NULL))
);

-- (site, node) pairs a quarantined 063 bootstrap keeps out of serving.
CREATE TABLE acme_http01_overlay_backfill_quarantines (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    reason_code text NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    recorded_at timestamptz NOT NULL CHECK (isfinite(recorded_at)),
    PRIMARY KEY (tenant_scope_id, site_id, node_id),
    FOREIGN KEY (tenant_scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE RESTRICT
);
CREATE INDEX acme_http01_overlay_backfill_quarantines_node_342_idx
    ON acme_http01_overlay_backfill_quarantines(node_id);
-- Canonical digests; Go computes the same bytes (internal/acmehttp01).
CREATE FUNCTION acme_http01_site_token_set_digest(target_site_id uuid, token_keys text[])
RETURNS bytea LANGUAGE sql IMMUTABLE AS $$
    SELECT sha256(convert_to('cdnca.acme.http01-site-version/v1' || E'\n' || target_site_id::text || E'\n' ||
        COALESCE(array_to_string(token_keys, E'\n'), ''), 'UTF8'))
$$;

CREATE FUNCTION acme_http01_site_version_digest(target_version_id uuid)
RETURNS bytea LANGUAGE sql STABLE AS $$
    SELECT acme_http01_site_token_set_digest(version.site_id, ARRAY(
        SELECT token.tenant_scope_id::text || '/' || token.operation_id || '/' || token.attempt_id::text
        FROM acme_http01_site_overlay_version_tokens token WHERE token.version_id=version.id ORDER BY token.ordinal))
    FROM acme_http01_site_overlay_versions version WHERE version.id=target_version_id
$$;

-- nodescheduler.CanonicalNodeSetDigest.
CREATE FUNCTION acme_http01_node_set_digest(node_ids uuid[])
RETURNS bytea LANGUAGE sql IMMUTABLE AS $$
    SELECT sha256(convert_to('cdnca.edge.target-node-set/v1', 'UTF8') ||
        int4send((SELECT count(DISTINCT item) FROM unnest(node_ids) item)::integer) ||
        COALESCE((SELECT string_agg(uuid_send(item), ''::bytea ORDER BY item)
                  FROM (SELECT DISTINCT item FROM unnest(node_ids) item) distinct_nodes), ''::bytea))
$$;

-- The proof a cleanup_only generation binds: node, its non-serving admin
-- state and the generation, re-verified at commit.
CREATE FUNCTION acme_http01_non_serving_proof(target_node_id uuid, node_admin_state text, target_generation bigint)
RETURNS bytea LANGUAGE sql IMMUTABLE AS $$
    SELECT sha256(convert_to('cdnca.acme.http01-non-serving/v1' || E'\n' || target_node_id::text || E'\n' ||
        node_admin_state || E'\n' || target_generation::text, 'UTF8'))
$$;

-- 063 evidence digest of a legacy site version (same key format and order).
CREATE FUNCTION acme_http01_backfill_063_digest(target_site_id uuid, legacy_version_id uuid)
RETURNS bytea LANGUAGE sql STABLE AS $$
    SELECT acme_http01_site_token_set_digest(target_site_id, ARRAY(
        SELECT fact.tenant_scope_id::text || '/' || fact.operation_id || '/' || fact.challenge_attempt_id::text
        FROM acme_http01_overlay_token_facts fact WHERE fact.version_id=legacy_version_id
        ORDER BY convert_to(fact.domain, 'UTF8'), fact.token_sha256, fact.operation_id, fact.challenge_attempt_id))
$$;

-- Rebuildable projection: the latest event of every debt.
CREATE VIEW acme_http01_node_overlay_cleanup_debt_states AS
SELECT DISTINCT ON (event.debt_id)
       event.debt_id, debt.node_id, debt.tenant_scope_id, debt.site_id, debt.required_epoch_id,
       debt.earliest_uncovered_site_version_id, debt.opened_reason, debt.opened_at,
       event.sequence AS latest_sequence, event.event AS latest_event,
       event.generation_id AS latest_generation_id, event.occurred_at AS latest_event_at,
       event.event IN ('resolved_cleanup', 'resolved_required') AS resolved,
       EXISTS (SELECT 1 FROM acme_http01_node_overlay_cleanup_debt_events gating
               WHERE gating.debt_id=event.debt_id AND gating.event IN ('opened', 'coalesced')
                 AND gating.reason IN ('member_removed', 'backfill_063_removed')) AS gates_serving
FROM acme_http01_node_overlay_cleanup_debt_events event
JOIN acme_http01_node_overlay_cleanup_debts debt ON debt.id=event.debt_id
ORDER BY event.debt_id, event.sequence DESC;

-- Serving gate (ADR-0003 调度与恢复顺序 4): why the site must not resolve to
-- the node now, or NULL. A node that left the site's serving set owes a
-- cleanup it has not confirmed; while the site has an open epoch only its
-- active required members serve it (a node joining mid-epoch would serve
-- without the epoch's tokens); a quarantined 063 bootstrap fails closed.
CREATE FUNCTION acme_http01_site_node_serving_blocked(target_scope_id uuid, target_site_id uuid, target_node_id uuid)
RETURNS text LANGUAGE sql STABLE AS $$
    SELECT CASE
        WHEN EXISTS (SELECT 1 FROM acme_http01_overlay_backfill_quarantines quarantine
                     WHERE quarantine.tenant_scope_id=target_scope_id AND quarantine.site_id=target_site_id
                       AND quarantine.node_id=target_node_id) THEN 'backfill_quarantined'
        WHEN EXISTS (SELECT 1 FROM acme_http01_node_overlay_cleanup_debts debt
                     WHERE debt.tenant_scope_id=target_scope_id AND debt.site_id=target_site_id
                       AND debt.node_id=target_node_id
                       AND NOT EXISTS (SELECT 1 FROM acme_http01_node_overlay_cleanup_debt_events resolved
                                       WHERE resolved.debt_id=debt.id
                                         AND resolved.event IN ('resolved_cleanup', 'resolved_required'))
                       AND EXISTS (SELECT 1 FROM acme_http01_node_overlay_cleanup_debt_events gating
                                   WHERE gating.debt_id=debt.id AND gating.event IN ('opened', 'coalesced')
                                     AND gating.reason IN ('member_removed', 'backfill_063_removed')))
             THEN 'cleanup_debt'
        WHEN EXISTS (SELECT 1 FROM acme_http01_site_overlay_states state
                     WHERE state.tenant_scope_id=target_scope_id AND state.site_id=target_site_id
                       AND state.open_epoch_id IS NOT NULL
                       AND NOT EXISTS (SELECT 1 FROM acme_http01_site_overlay_epoch_members member
                                       WHERE member.epoch_id=state.open_epoch_id AND member.node_id=target_node_id
                                         AND NOT EXISTS (SELECT 1 FROM acme_http01_site_overlay_epoch_releases released
                                                         WHERE released.epoch_id=member.epoch_id
                                                           AND released.node_id=member.node_id)))
             THEN 'epoch_not_member'
    END
$$;

-- Sites the gate may affect at all (the fast path for DNS planners).
CREATE FUNCTION acme_http01_gated_sites()
RETURNS TABLE (tenant_scope_id uuid, site_id uuid) LANGUAGE sql STABLE AS $$
    SELECT quarantine.tenant_scope_id, quarantine.site_id FROM acme_http01_overlay_backfill_quarantines quarantine
    UNION
    SELECT state.tenant_scope_id, state.site_id FROM acme_http01_site_overlay_states state
    WHERE state.open_epoch_id IS NOT NULL
    UNION
    SELECT debt.tenant_scope_id, debt.site_id FROM acme_http01_node_overlay_cleanup_debts debt
    WHERE NOT EXISTS (SELECT 1 FROM acme_http01_node_overlay_cleanup_debt_events resolved
                      WHERE resolved.debt_id=debt.id AND resolved.event IN ('resolved_cleanup', 'resolved_required'))
$$;

-- Derived site version health (never a caller-written projection).
-- Non-empty: the epoch still has an active required member and every one of
-- them has a latest healthy generation whose required coverage is exactly
-- this version. Empty (final cleanup): the epoch is closed and every member
-- left it with a durable debt; never vacuous since an epoch has members.
CREATE FUNCTION acme_http01_site_version_healthy(target_version_id uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT CASE
        WHEN version.source = 'backfill_063' AND version.token_count > 0 THEN false
        WHEN version.token_count > 0 THEN
            EXISTS (SELECT 1 FROM acme_http01_site_overlay_epoch_members member
                    WHERE member.epoch_id=version.epoch_id AND NOT EXISTS (
                        SELECT 1 FROM acme_http01_site_overlay_epoch_releases released
                        WHERE released.epoch_id=member.epoch_id AND released.node_id=member.node_id))
            AND NOT EXISTS (
                SELECT 1 FROM acme_http01_site_overlay_epoch_members member
                WHERE member.epoch_id=version.epoch_id
                  AND NOT EXISTS (SELECT 1 FROM acme_http01_site_overlay_epoch_releases released
                                  WHERE released.epoch_id=member.epoch_id AND released.node_id=member.node_id)
                  AND NOT EXISTS (
                      SELECT 1 FROM acme_http01_node_overlay_states node_state
                      JOIN acme_http01_node_overlay_generation_coverages coverage
                        ON coverage.generation_id=node_state.latest_healthy_generation_id
                       AND coverage.tenant_scope_id=version.tenant_scope_id AND coverage.site_id=version.site_id
                      WHERE node_state.node_id=member.node_id AND coverage.coverage_kind='required'
                        AND coverage.site_version_id=version.id
                        AND coverage.site_token_set_sha256=version.token_set_sha256))
        ELSE
            EXISTS (SELECT 1 FROM acme_http01_site_overlay_epochs epoch
                    WHERE epoch.id=version.epoch_id AND epoch.closed_at IS NOT NULL)
            AND NOT EXISTS (
                SELECT 1 FROM acme_http01_site_overlay_epoch_members member
                WHERE member.epoch_id=version.epoch_id AND NOT EXISTS (
                    SELECT 1 FROM acme_http01_site_overlay_epoch_releases released
                    WHERE released.epoch_id=member.epoch_id AND released.node_id=member.node_id))
    END
    FROM acme_http01_site_overlay_versions version WHERE version.id=target_version_id
$$;
CREATE FUNCTION acme_http01_overlay_append_only_342()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'ACME HTTP-01 site overlay and cleanup debt facts are append-only' USING ERRCODE='P3421';
END;
$$;

-- Site state: starts empty; the version advances by one onto an existing
-- version; an epoch opens (count+1) only when none is open and closes only
-- onto NULL.
CREATE FUNCTION guard_acme_http01_site_overlay_state_342()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'ACME HTTP-01 site overlay state cannot be deleted' USING ERRCODE='P3422';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.current_version <> 0 OR NEW.open_epoch_id IS NOT NULL OR NEW.epoch_count <> 0 THEN
            RAISE EXCEPTION 'ACME HTTP-01 site overlay state must start empty' USING ERRCODE='P3422';
        END IF;
        RETURN NEW;
    END IF;
    IF (NEW.tenant_scope_id, NEW.site_id, NEW.created_at) IS DISTINCT FROM
       (OLD.tenant_scope_id, OLD.site_id, OLD.created_at) OR NEW.updated_at < OLD.updated_at OR
       NOT ((NEW.current_version = OLD.current_version AND NEW.current_version_id IS NOT DISTINCT FROM OLD.current_version_id) OR
            (NEW.current_version = OLD.current_version + 1 AND EXISTS (
                SELECT 1 FROM acme_http01_site_overlay_versions version
                WHERE version.id=NEW.current_version_id AND version.version=NEW.current_version))) OR
       NOT ((NEW.open_epoch_id IS NOT DISTINCT FROM OLD.open_epoch_id AND NEW.epoch_count = OLD.epoch_count) OR
            (OLD.open_epoch_id IS NULL AND NEW.open_epoch_id IS NOT NULL AND NEW.epoch_count = OLD.epoch_count + 1 AND
             EXISTS (SELECT 1 FROM acme_http01_site_overlay_epochs epoch
                     WHERE epoch.id=NEW.open_epoch_id AND epoch.sequence=NEW.epoch_count AND epoch.closed_at IS NULL)) OR
            (OLD.open_epoch_id IS NOT NULL AND NEW.open_epoch_id IS NULL AND NEW.epoch_count = OLD.epoch_count)) THEN
        RAISE EXCEPTION 'ACME HTTP-01 site overlay state may only advance' USING ERRCODE='P3422';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER acme_http01_site_overlay_states_guard_342
    BEFORE INSERT OR UPDATE OR DELETE ON acme_http01_site_overlay_states
    FOR EACH ROW EXECUTE FUNCTION guard_acme_http01_site_overlay_state_342();

-- Epochs: only closed_at changes, once.
CREATE FUNCTION guard_acme_http01_site_overlay_epoch_342()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' OR OLD.closed_at IS NOT NULL OR NEW.closed_at IS NULL OR
       (NEW.id, NEW.tenant_scope_id, NEW.site_id, NEW.sequence, NEW.member_count, NEW.member_set_sha256, NEW.opened_at)
       IS DISTINCT FROM
       (OLD.id, OLD.tenant_scope_id, OLD.site_id, OLD.sequence, OLD.member_count, OLD.member_set_sha256, OLD.opened_at) THEN
        RAISE EXCEPTION 'ACME HTTP-01 site overlay epoch may only be closed once' USING ERRCODE='P3423';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER acme_http01_site_overlay_epochs_guard_342
    BEFORE UPDATE OR DELETE ON acme_http01_site_overlay_epochs
    FOR EACH ROW EXECUTE FUNCTION guard_acme_http01_site_overlay_epoch_342();

-- Members are frozen before the epoch's first version.
CREATE FUNCTION guard_acme_http01_site_overlay_epoch_member_342()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' OR NOT EXISTS (
        SELECT 1 FROM acme_http01_site_overlay_epochs epoch WHERE epoch.id=NEW.epoch_id AND epoch.closed_at IS NULL
       ) OR EXISTS (SELECT 1 FROM acme_http01_site_overlay_versions version WHERE version.epoch_id=NEW.epoch_id) THEN
        RAISE EXCEPTION 'ACME HTTP-01 epoch membership is frozen' USING ERRCODE='P3423';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER acme_http01_site_overlay_epoch_members_guard_342
    BEFORE INSERT OR UPDATE OR DELETE ON acme_http01_site_overlay_epoch_members
    FOR EACH ROW EXECUTE FUNCTION guard_acme_http01_site_overlay_epoch_member_342();

-- A release leaves an open epoch with an unresolved debt of the same node and
-- site.
CREATE FUNCTION guard_acme_http01_site_overlay_epoch_release_342()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' OR NOT EXISTS (
        SELECT 1 FROM acme_http01_site_overlay_epochs epoch
        JOIN acme_http01_node_overlay_cleanup_debts debt ON debt.tenant_scope_id=epoch.tenant_scope_id
         AND debt.site_id=epoch.site_id AND debt.node_id=NEW.node_id AND debt.id=NEW.debt_id
        WHERE epoch.id=NEW.epoch_id AND epoch.closed_at IS NULL
       ) OR EXISTS (SELECT 1 FROM acme_http01_node_overlay_cleanup_debt_events resolved
                    WHERE resolved.debt_id=NEW.debt_id AND resolved.event IN ('resolved_cleanup', 'resolved_required')) THEN
        RAISE EXCEPTION 'ACME HTTP-01 epoch release needs an open epoch and an unresolved debt' USING ERRCODE='P3423';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER acme_http01_site_overlay_epoch_releases_guard_342
    BEFORE INSERT OR UPDATE OR DELETE ON acme_http01_site_overlay_epoch_releases
    FOR EACH ROW EXECUTE FUNCTION guard_acme_http01_site_overlay_epoch_release_342();

-- At commit: an epoch's members match its count and digest; an open epoch is
-- the site's open epoch; a closed one was released by every member and has
-- its empty version; every release has its opened/coalesced debt event.
CREATE FUNCTION validate_acme_http01_site_overlay_epoch_342()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    value acme_http01_site_overlay_epochs%ROWTYPE;
BEGIN
    IF TG_TABLE_NAME = 'acme_http01_site_overlay_epochs' THEN
        SELECT * INTO value FROM acme_http01_site_overlay_epochs WHERE id = NEW.id;
    ELSE
        SELECT * INTO value FROM acme_http01_site_overlay_epochs WHERE id = NEW.epoch_id;
    END IF;
    IF NOT FOUND OR value.member_count <> (SELECT count(*) FROM acme_http01_site_overlay_epoch_members WHERE epoch_id=value.id) OR
       value.member_set_sha256 IS DISTINCT FROM acme_http01_node_set_digest(ARRAY(
           SELECT node_id FROM acme_http01_site_overlay_epoch_members WHERE epoch_id=value.id)) OR
       (value.closed_at IS NULL) <> EXISTS (
           SELECT 1 FROM acme_http01_site_overlay_states state
           WHERE state.tenant_scope_id=value.tenant_scope_id AND state.site_id=value.site_id AND state.open_epoch_id=value.id) OR
       (value.closed_at IS NOT NULL AND (
           EXISTS (SELECT 1 FROM acme_http01_site_overlay_epoch_members member
                   WHERE member.epoch_id=value.id AND NOT EXISTS (
                       SELECT 1 FROM acme_http01_site_overlay_epoch_releases released
                       WHERE released.epoch_id=member.epoch_id AND released.node_id=member.node_id)) OR
           NOT EXISTS (SELECT 1 FROM acme_http01_site_overlay_versions version
                       WHERE version.epoch_id=value.id AND version.token_count=0 AND version.source='refresh'))) OR
       EXISTS (SELECT 1 FROM acme_http01_site_overlay_epoch_releases released
               WHERE released.epoch_id=value.id AND NOT EXISTS (
                   SELECT 1 FROM acme_http01_node_overlay_cleanup_debt_events event
                   WHERE event.debt_id=released.debt_id AND event.event IN ('opened', 'coalesced')
                     AND event.epoch_id=released.epoch_id AND event.reason=released.reason)) THEN
        RAISE EXCEPTION 'ACME HTTP-01 site overlay epoch is inconsistent' USING ERRCODE='P3423';
    END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER acme_http01_site_overlay_epochs_validate_342
    AFTER INSERT OR UPDATE ON acme_http01_site_overlay_epochs DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_acme_http01_site_overlay_epoch_342();
CREATE CONSTRAINT TRIGGER acme_http01_site_overlay_epoch_members_validate_342
    AFTER INSERT ON acme_http01_site_overlay_epoch_members DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_acme_http01_site_overlay_epoch_342();
CREATE CONSTRAINT TRIGGER acme_http01_site_overlay_epoch_releases_validate_342
    AFTER INSERT ON acme_http01_site_overlay_epoch_releases DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_acme_http01_site_overlay_epoch_342();
-- Versions are written into an open epoch.
CREATE FUNCTION guard_acme_http01_site_overlay_version_342()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' OR NOT EXISTS (
        SELECT 1 FROM acme_http01_site_overlay_epochs epoch WHERE epoch.id=NEW.epoch_id AND epoch.closed_at IS NULL) THEN
        RAISE EXCEPTION 'ACME HTTP-01 site version must be written into an open epoch' USING ERRCODE='P3424';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER acme_http01_site_overlay_versions_guard_342
    BEFORE INSERT OR UPDATE OR DELETE ON acme_http01_site_overlay_versions
    FOR EACH ROW EXECUTE FUNCTION guard_acme_http01_site_overlay_version_342();

-- At commit: a version's tokens are contiguous, strictly ordered by (domain
-- bytes, token digest), live challenges of its site and epoch when the version
-- was written; the digest and count match; the version is not ahead of the
-- site; a current version is non-empty exactly while its epoch is open;
-- backfill evidence carries no tokens and is never current.
CREATE FUNCTION validate_acme_http01_site_overlay_version_342()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    value acme_http01_site_overlay_versions%ROWTYPE;
    token_total integer;
    max_ordinal integer;
    is_current boolean;
    not_ahead boolean;
    epoch_open boolean;
    bad integer;
BEGIN
    IF TG_TABLE_NAME = 'acme_http01_site_overlay_versions' THEN
        SELECT * INTO value FROM acme_http01_site_overlay_versions WHERE id = NEW.id;
    ELSE
        SELECT * INTO value FROM acme_http01_site_overlay_versions WHERE id = NEW.version_id;
    END IF;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'ACME HTTP-01 site version is missing' USING ERRCODE='P3424';
    END IF;
    SELECT count(*), COALESCE(max(ordinal), 0) INTO token_total, max_ordinal
    FROM acme_http01_site_overlay_version_tokens WHERE version_id=value.id;
    SELECT state.current_version_id=value.id, value.version <= state.current_version INTO is_current, not_ahead
    FROM acme_http01_site_overlay_states state
    WHERE state.tenant_scope_id=value.tenant_scope_id AND state.site_id=value.site_id;
    IF NOT FOUND OR NOT not_ahead THEN
        RAISE EXCEPTION 'ACME HTTP-01 site version is ahead of its site' USING ERRCODE='P3424';
    END IF;
    SELECT epoch.closed_at IS NULL INTO epoch_open FROM acme_http01_site_overlay_epochs epoch WHERE epoch.id=value.epoch_id;
    IF value.source = 'backfill_063' THEN
        IF token_total <> 0 OR (is_current AND value.token_count > 0) THEN
            RAISE EXCEPTION 'ACME HTTP-01 backfill evidence cannot be served' USING ERRCODE='P3424';
        END IF;
        RETURN NULL;
    END IF;
    IF token_total <> value.token_count OR max_ordinal <> token_total OR
       acme_http01_site_version_digest(value.id) IS DISTINCT FROM value.token_set_sha256 OR
       (is_current AND (value.token_count > 0) <> epoch_open) THEN
        RAISE EXCEPTION 'ACME HTTP-01 site version tokens do not match its digest or epoch' USING ERRCODE='P3424';
    END IF;
    SELECT count(*) INTO bad
    FROM (
        SELECT challenge.*, link.epoch_id AS linked_epoch,
               lag(convert_to(challenge.domain, 'UTF8')) OVER ordered AS previous_domain,
               lag(challenge.token_sha256) OVER ordered AS previous_token
        FROM acme_http01_site_overlay_version_tokens token
        JOIN acme_http01_node_challenges challenge ON challenge.tenant_scope_id=token.tenant_scope_id
         AND challenge.operation_id=token.operation_id AND challenge.attempt_id=token.attempt_id
        LEFT JOIN acme_http01_node_challenge_epochs link ON link.tenant_scope_id=token.tenant_scope_id
         AND link.operation_id=token.operation_id AND link.attempt_id=token.attempt_id
        WHERE token.version_id=value.id
        WINDOW ordered AS (ORDER BY token.ordinal)
    ) checked
    WHERE checked.tenant_scope_id <> value.tenant_scope_id OR checked.site_id <> value.site_id OR
          checked.linked_epoch IS DISTINCT FROM value.epoch_id OR checked.created_at > value.created_at OR
          checked.expires_at <= value.created_at OR
          (checked.withdrawn_at IS NOT NULL AND checked.withdrawn_at <= value.created_at) OR
          (checked.previous_domain IS NOT NULL AND
           (checked.previous_domain, checked.previous_token) >= (convert_to(checked.domain, 'UTF8'), checked.token_sha256));
    IF bad <> 0 THEN
        RAISE EXCEPTION 'ACME HTTP-01 site version carries an ineligible or unordered challenge' USING ERRCODE='P3424';
    END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER acme_http01_site_overlay_versions_validate_342
    AFTER INSERT ON acme_http01_site_overlay_versions DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_acme_http01_site_overlay_version_342();
CREATE CONSTRAINT TRIGGER acme_http01_site_overlay_version_tokens_validate_342
    AFTER INSERT ON acme_http01_site_overlay_version_tokens DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_acme_http01_site_overlay_version_342();

-- A node's current generation must carry a required coverage of the current
-- version of every site it is an active member of, and a coverage of every
-- unresolved debt it owes (a node awaiting its 063 bootstrap generation is
-- exempt from the latter until regenerated).
CREATE FUNCTION assert_acme_http01_node_coverage_342(target_node_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    current_id uuid;
    exempt boolean;
BEGIN
    SELECT state.current_generation_id INTO current_id FROM acme_http01_node_overlay_states state
    WHERE state.node_id=target_node_id;
    SELECT EXISTS (SELECT 1 FROM acme_http01_overlay_backfill_nodes backfill
                   WHERE backfill.node_id=target_node_id AND backfill.state='pending') INTO exempt;
    IF EXISTS (
        SELECT 1 FROM acme_http01_site_overlay_epoch_members member
        JOIN acme_http01_site_overlay_epochs epoch ON epoch.id=member.epoch_id AND epoch.closed_at IS NULL
        JOIN acme_http01_site_overlay_states site ON site.tenant_scope_id=epoch.tenant_scope_id
         AND site.site_id=epoch.site_id AND site.open_epoch_id=epoch.id
        JOIN acme_http01_site_overlay_versions version ON version.id=site.current_version_id AND version.token_count > 0
        WHERE member.node_id=target_node_id
          AND NOT EXISTS (SELECT 1 FROM acme_http01_site_overlay_epoch_releases released
                          WHERE released.epoch_id=member.epoch_id AND released.node_id=member.node_id)
          AND NOT EXISTS (SELECT 1 FROM acme_http01_node_overlay_generation_coverages coverage
                          WHERE coverage.generation_id=current_id AND coverage.site_id=version.site_id
                            AND coverage.tenant_scope_id=version.tenant_scope_id
                            AND coverage.coverage_kind='required' AND coverage.site_version_id=version.id)
    ) OR (NOT exempt AND EXISTS (
        SELECT 1 FROM acme_http01_node_overlay_cleanup_debts debt
        WHERE debt.node_id=target_node_id
          AND NOT EXISTS (SELECT 1 FROM acme_http01_node_overlay_cleanup_debt_events resolved
                          WHERE resolved.debt_id=debt.id AND resolved.event IN ('resolved_cleanup', 'resolved_required'))
          AND NOT EXISTS (SELECT 1 FROM acme_http01_node_overlay_generation_coverages coverage
                          WHERE coverage.generation_id=current_id AND coverage.cleanup_debt_id=debt.id))) THEN
        RAISE EXCEPTION 'ACME HTTP-01 node % generation misses a required site or cleanup debt coverage', target_node_id
            USING ERRCODE='P3425';
    END IF;
END;
$$;

CREATE FUNCTION validate_acme_http01_node_coverage_342()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM assert_acme_http01_node_coverage_342(NEW.node_id);
    RETURN NULL;
END;
$$;
-- At commit: a 342 generation's coverage counts match; required coverage is
-- the exact token set of the site version (no missing or extra token, every
-- token of the generation is under one); cleanup_debt coverage has no token
-- and names an unresolved debt of the node; cleanup_only carries no token or
-- required coverage, covers every unresolved debt of the node and is bound to
-- a non-serving proof re-verified now.
CREATE FUNCTION validate_acme_http01_generation_coverage_342()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    value acme_http01_node_overlay_generations%ROWTYPE;
    required_total integer;
    debt_total integer;
    admin text;
BEGIN
    IF TG_TABLE_NAME = 'acme_http01_node_overlay_generations' THEN
        SELECT * INTO value FROM acme_http01_node_overlay_generations WHERE id = NEW.id;
    ELSE
        SELECT * INTO value FROM acme_http01_node_overlay_generations WHERE id = NEW.generation_id;
    END IF;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'ACME HTTP-01 node generation is missing' USING ERRCODE='P3425';
    END IF;
    SELECT count(*) FILTER (WHERE coverage_kind='required'), count(*) FILTER (WHERE coverage_kind='cleanup_debt')
    INTO required_total, debt_total
    FROM acme_http01_node_overlay_generation_coverages WHERE generation_id=value.id;
    IF required_total <> value.required_coverage_count OR debt_total <> value.cleanup_debt_coverage_count OR
       EXISTS (
        SELECT 1 FROM acme_http01_node_overlay_generation_coverages coverage
        JOIN acme_http01_site_overlay_versions version ON version.id=coverage.site_version_id
        WHERE coverage.generation_id=value.id AND (
            coverage.node_id <> value.node_id OR
            (coverage.coverage_kind = 'required' AND (
                version.source <> 'refresh' OR version.token_count <> coverage.site_token_count OR
                version.token_set_sha256 <> coverage.site_token_set_sha256 OR
                version.epoch_id <> coverage.required_epoch_id OR
                EXISTS (SELECT 1 FROM acme_http01_site_overlay_version_tokens wanted
                        WHERE wanted.version_id=version.id AND NOT EXISTS (
                            SELECT 1 FROM acme_http01_node_overlay_generation_tokens carried
                            WHERE carried.generation_id=value.id AND carried.tenant_scope_id=wanted.tenant_scope_id
                              AND carried.operation_id=wanted.operation_id AND carried.attempt_id=wanted.attempt_id)) OR
                EXISTS (SELECT 1 FROM acme_http01_node_overlay_generation_tokens carried
                        JOIN acme_http01_node_challenges challenge ON challenge.tenant_scope_id=carried.tenant_scope_id
                         AND challenge.operation_id=carried.operation_id AND challenge.attempt_id=carried.attempt_id
                        WHERE carried.generation_id=value.id AND challenge.tenant_scope_id=coverage.tenant_scope_id
                          AND challenge.site_id=coverage.site_id AND NOT EXISTS (
                              SELECT 1 FROM acme_http01_site_overlay_version_tokens wanted
                              WHERE wanted.version_id=version.id AND wanted.tenant_scope_id=carried.tenant_scope_id
                                AND wanted.operation_id=carried.operation_id AND wanted.attempt_id=carried.attempt_id)) OR
                (coverage.cleanup_debt_id IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM acme_http01_node_overlay_cleanup_debts debt
                    WHERE debt.id=coverage.cleanup_debt_id AND debt.node_id=value.node_id)))) OR
            (coverage.coverage_kind = 'cleanup_debt' AND (
                coverage.site_token_set_sha256 <> acme_http01_site_token_set_digest(coverage.site_id, ARRAY[]::text[]) OR
                NOT EXISTS (SELECT 1 FROM acme_http01_node_overlay_cleanup_debts debt
                            WHERE debt.id=coverage.cleanup_debt_id AND debt.node_id=value.node_id
                              AND debt.required_epoch_id=coverage.required_epoch_id) OR
                EXISTS (SELECT 1 FROM acme_http01_node_overlay_cleanup_debt_events resolved
                        WHERE resolved.debt_id=coverage.cleanup_debt_id
                          AND resolved.event IN ('resolved_cleanup', 'resolved_required')
                          AND resolved.generation_id IS DISTINCT FROM value.id) OR
                EXISTS (SELECT 1 FROM acme_http01_node_overlay_generation_tokens carried
                        JOIN acme_http01_node_challenges challenge ON challenge.tenant_scope_id=carried.tenant_scope_id
                         AND challenge.operation_id=carried.operation_id AND challenge.attempt_id=carried.attempt_id
                        WHERE carried.generation_id=value.id AND challenge.tenant_scope_id=coverage.tenant_scope_id
                          AND challenge.site_id=coverage.site_id))))
       ) OR (
        (required_total > 0 OR debt_total > 0) AND EXISTS (
            SELECT 1 FROM acme_http01_node_overlay_generation_tokens carried
            JOIN acme_http01_node_challenges challenge ON challenge.tenant_scope_id=carried.tenant_scope_id
             AND challenge.operation_id=carried.operation_id AND challenge.attempt_id=carried.attempt_id
            WHERE carried.generation_id=value.id AND NOT EXISTS (
                SELECT 1 FROM acme_http01_node_overlay_generation_coverages coverage
                WHERE coverage.generation_id=value.id AND coverage.coverage_kind='required'
                  AND coverage.tenant_scope_id=challenge.tenant_scope_id AND coverage.site_id=challenge.site_id))
       ) THEN
        RAISE EXCEPTION 'ACME HTTP-01 node generation coverage does not match its tokens' USING ERRCODE='P3425';
    END IF;
    IF value.purpose = 'cleanup_only' THEN
        SELECT node.admin_state INTO admin FROM nodes node WHERE node.id=value.node_id;
        IF value.token_count <> 0 OR required_total <> 0 OR debt_total = 0 OR admin NOT IN ('draining', 'retired') OR
           value.non_serving_proof_sha256 IS DISTINCT FROM acme_http01_non_serving_proof(value.node_id, admin, value.generation) OR
           debt_total <> (SELECT count(*) FROM acme_http01_node_overlay_cleanup_debts debt
                          WHERE debt.node_id=value.node_id AND NOT EXISTS (
                              SELECT 1 FROM acme_http01_node_overlay_cleanup_debt_events resolved
                              WHERE resolved.debt_id=debt.id AND resolved.event IN ('resolved_cleanup', 'resolved_required')
                                AND resolved.generation_id IS DISTINCT FROM value.id)) OR
           EXISTS (SELECT 1 FROM node_line_endpoint_published endpoint
                   JOIN node_line_groups line_group ON line_group.tenant_scope_id=endpoint.tenant_scope_id
                    AND line_group.id=endpoint.line_group_id AND line_group.current_revision=endpoint.config_revision
                    AND line_group.deleted_at IS NULL
                   WHERE endpoint.node_id=value.node_id AND endpoint.published) OR
           EXISTS (SELECT 1 FROM acme_http01_site_overlay_epoch_members member
                   JOIN acme_http01_site_overlay_epochs epoch ON epoch.id=member.epoch_id AND epoch.closed_at IS NULL
                   WHERE member.node_id=value.node_id AND NOT EXISTS (
                       SELECT 1 FROM acme_http01_site_overlay_epoch_releases released
                       WHERE released.epoch_id=member.epoch_id AND released.node_id=member.node_id)) THEN
            RAISE EXCEPTION 'ACME HTTP-01 cleanup_only generation needs a non-serving node and exactly its debts'
                USING ERRCODE='P3427';
        END IF;
    END IF;
    RETURN NULL;
END;
$$;
-- Named after the 337 validators so a forged generation still fails with 337's code first.
CREATE CONSTRAINT TRIGGER acme_http01_node_overlay_generations_validate_342
    AFTER INSERT ON acme_http01_node_overlay_generations DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_acme_http01_generation_coverage_342();
CREATE CONSTRAINT TRIGGER acme_http01_node_overlay_generation_coverages_validate_342
    AFTER INSERT ON acme_http01_node_overlay_generation_coverages DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_acme_http01_generation_coverage_342();
CREATE CONSTRAINT TRIGGER acme_http01_node_overlay_generations_validate_342_node
    AFTER INSERT ON acme_http01_node_overlay_generations DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_acme_http01_node_coverage_342();
CREATE CONSTRAINT TRIGGER acme_http01_site_overlay_epoch_members_coverage_342
    AFTER INSERT ON acme_http01_site_overlay_epoch_members DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_acme_http01_node_coverage_342();
CREATE CONSTRAINT TRIGGER acme_http01_node_overlay_cleanup_debts_coverage_342
    AFTER INSERT ON acme_http01_node_overlay_cleanup_debts DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_acme_http01_node_coverage_342();
CREATE CONSTRAINT TRIGGER acme_http01_overlay_backfill_nodes_coverage_342
    AFTER INSERT OR UPDATE ON acme_http01_overlay_backfill_nodes DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_acme_http01_node_coverage_342();

-- Every active member of a site whose version changed must be covered again.
CREATE FUNCTION validate_acme_http01_site_version_members_342()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    member_node uuid;
BEGIN
    FOR member_node IN
        SELECT member.node_id FROM acme_http01_site_overlay_epoch_members member
        WHERE member.epoch_id=NEW.epoch_id ORDER BY member.node_id
    LOOP
        PERFORM assert_acme_http01_node_coverage_342(member_node);
    END LOOP;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER acme_http01_site_overlay_versions_members_342
    AFTER INSERT ON acme_http01_site_overlay_versions DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_acme_http01_site_version_members_342();
-- A debt opens only when the (node, site) has none unresolved, for the
-- earliest non-empty version the node was required to serve; its first event
-- is 'opened' with the same reason, epoch and version.
CREATE FUNCTION guard_acme_http01_cleanup_debt_342()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' OR EXISTS (
        SELECT 1 FROM acme_http01_node_overlay_cleanup_debts debt
        WHERE debt.node_id=NEW.node_id AND debt.tenant_scope_id=NEW.tenant_scope_id AND debt.site_id=NEW.site_id
          AND NOT EXISTS (SELECT 1 FROM acme_http01_node_overlay_cleanup_debt_events resolved
                          WHERE resolved.debt_id=debt.id AND resolved.event IN ('resolved_cleanup', 'resolved_required'))
       ) OR NOT EXISTS (
        SELECT 1 FROM acme_http01_site_overlay_versions version
        WHERE version.id=NEW.earliest_uncovered_site_version_id AND version.token_count=NEW.earliest_token_count
          AND version.token_set_sha256=NEW.earliest_token_set_sha256) THEN
        RAISE EXCEPTION 'ACME HTTP-01 cleanup debt must be the only unresolved debt and name a served version'
            USING ERRCODE='P3426';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER acme_http01_node_overlay_cleanup_debts_guard_342
    BEFORE INSERT OR UPDATE OR DELETE ON acme_http01_node_overlay_cleanup_debts
    FOR EACH ROW EXECUTE FUNCTION guard_acme_http01_cleanup_debt_342();

CREATE FUNCTION validate_acme_http01_cleanup_debt_opened_342()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM acme_http01_node_overlay_cleanup_debt_events event
                   WHERE event.debt_id=NEW.id AND event.sequence=1 AND event.event='opened') THEN
        RAISE EXCEPTION 'ACME HTTP-01 cleanup debt has no opened event' USING ERRCODE='P3426';
    END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER acme_http01_node_overlay_cleanup_debts_validate_342
    AFTER INSERT ON acme_http01_node_overlay_cleanup_debts DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_acme_http01_cleanup_debt_opened_342();

-- Debt events: contiguous, 'opened' first and only first, nothing after a
-- resolution. coalesced keeps the debt and names the later epoch the node was
-- released from; scheduled names a generation covering the debt; a resolution
-- needs the node's latest healthy generation to cover the debt (zero tokens
-- while the node is not required again, or the current non-empty version once
-- it is), so reactivating a node never clears a debt on its own.
CREATE FUNCTION guard_acme_http01_cleanup_debt_event_342()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    debt acme_http01_node_overlay_cleanup_debts%ROWTYPE;
    latest integer;
    latest_event text;
    healthy uuid;
    required_again boolean;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'ACME HTTP-01 cleanup debt events are append-only' USING ERRCODE='P3421';
    END IF;
    SELECT * INTO debt FROM acme_http01_node_overlay_cleanup_debts WHERE id=NEW.debt_id;
    SELECT event.sequence, event.event INTO latest, latest_event FROM acme_http01_node_overlay_cleanup_debt_events event
    WHERE event.debt_id=NEW.debt_id ORDER BY event.sequence DESC LIMIT 1;
    IF NEW.sequence <> COALESCE(latest, 0) + 1 OR (NEW.sequence = 1) <> (NEW.event = 'opened') OR
       latest_event IN ('resolved_cleanup', 'resolved_required') THEN
        RAISE EXCEPTION 'ACME HTTP-01 cleanup debt event is out of order' USING ERRCODE='P3426';
    END IF;
    IF NEW.event = 'opened' AND (NEW.epoch_id <> debt.required_epoch_id OR NEW.reason <> debt.opened_reason OR
       NEW.site_version_id <> debt.earliest_uncovered_site_version_id) THEN
        RAISE EXCEPTION 'ACME HTTP-01 opened event must restate its debt' USING ERRCODE='P3426';
    END IF;
    IF NEW.event = 'coalesced' AND NOT EXISTS (
        SELECT 1 FROM acme_http01_site_overlay_epochs epoch
        JOIN acme_http01_site_overlay_epoch_members member ON member.epoch_id=epoch.id AND member.node_id=debt.node_id
        JOIN acme_http01_site_overlay_versions version ON version.id=NEW.site_version_id AND version.epoch_id=epoch.id
        WHERE epoch.id=NEW.epoch_id AND epoch.id <> debt.required_epoch_id
          AND epoch.tenant_scope_id=debt.tenant_scope_id AND epoch.site_id=debt.site_id) THEN
        RAISE EXCEPTION 'ACME HTTP-01 coalesced event must name a later epoch of the same node and site'
            USING ERRCODE='P3426';
    END IF;
    IF NEW.event = 'scheduled' AND NOT EXISTS (
        SELECT 1 FROM acme_http01_node_overlay_generation_coverages coverage
        WHERE coverage.generation_id=NEW.generation_id AND coverage.cleanup_debt_id=debt.id) THEN
        RAISE EXCEPTION 'ACME HTTP-01 scheduled event needs a generation covering the debt' USING ERRCODE='P3426';
    END IF;
    IF NEW.event IN ('resolved_cleanup', 'resolved_required') THEN
        SELECT state.latest_healthy_generation_id INTO healthy FROM acme_http01_node_overlay_states state
        WHERE state.node_id=debt.node_id;
        SELECT EXISTS (
            SELECT 1 FROM acme_http01_site_overlay_states site
            JOIN acme_http01_site_overlay_epoch_members member ON member.epoch_id=site.open_epoch_id
             AND member.node_id=debt.node_id
            JOIN acme_http01_site_overlay_versions version ON version.id=site.current_version_id AND version.token_count > 0
            WHERE site.tenant_scope_id=debt.tenant_scope_id AND site.site_id=debt.site_id
              AND NOT EXISTS (SELECT 1 FROM acme_http01_site_overlay_epoch_releases released
                              WHERE released.epoch_id=member.epoch_id AND released.node_id=member.node_id))
        INTO required_again;
        IF healthy IS DISTINCT FROM NEW.generation_id OR (NEW.event = 'resolved_cleanup' AND (required_again OR NOT EXISTS (
               SELECT 1 FROM acme_http01_node_overlay_generation_coverages coverage
               WHERE coverage.generation_id=NEW.generation_id AND coverage.cleanup_debt_id=debt.id
                 AND coverage.coverage_kind='cleanup_debt'))) OR
           (NEW.event = 'resolved_required' AND (NOT required_again OR NOT EXISTS (
               SELECT 1 FROM acme_http01_node_overlay_generation_coverages coverage
               JOIN acme_http01_site_overlay_states site ON site.tenant_scope_id=coverage.tenant_scope_id
                AND site.site_id=coverage.site_id AND site.current_version_id=coverage.site_version_id
               WHERE coverage.generation_id=NEW.generation_id AND coverage.cleanup_debt_id=debt.id
                 AND coverage.coverage_kind='required'))) THEN
            RAISE EXCEPTION 'ACME HTTP-01 cleanup debt resolution is not proven by the latest healthy generation'
                USING ERRCODE='P3426';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER acme_http01_node_overlay_cleanup_debt_events_guard_342
    BEFORE INSERT OR UPDATE OR DELETE ON acme_http01_node_overlay_cleanup_debt_events
    FOR EACH ROW EXECUTE FUNCTION guard_acme_http01_cleanup_debt_event_342();

-- Backfill node marks: quarantine is final, the floor only grows, a
-- bootstrapped node names a generation at or above the floor.
CREATE FUNCTION guard_acme_http01_backfill_node_342()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' OR (TG_OP = 'UPDATE' AND (
        NEW.node_id <> OLD.node_id OR NEW.recorded_at <> OLD.recorded_at OR NEW.updated_at < OLD.updated_at OR
        OLD.state = 'quarantined' OR NEW.generation_floor < OLD.generation_floor)) OR
       (NEW.state = 'bootstrapped' AND NOT EXISTS (
        SELECT 1 FROM acme_http01_node_overlay_generations generation
        WHERE generation.id=NEW.bootstrap_generation_id AND generation.node_id=NEW.node_id
          AND generation.generation >= NEW.generation_floor)) THEN
        RAISE EXCEPTION 'ACME HTTP-01 backfill node mark transition is invalid' USING ERRCODE='P3428';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER acme_http01_overlay_backfill_nodes_guard_342
    BEFORE INSERT OR UPDATE OR DELETE ON acme_http01_overlay_backfill_nodes
    FOR EACH ROW EXECUTE FUNCTION guard_acme_http01_backfill_node_342();

-- At commit: a challenge recorded since 342 is linked to the open epoch of its
-- site and targets exactly the epoch's active members at that time.
CREATE FUNCTION validate_acme_http01_challenge_epoch_342()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM acme_http01_node_challenge_epochs link
        JOIN acme_http01_site_overlay_epochs epoch ON epoch.id=link.epoch_id
        WHERE link.tenant_scope_id=NEW.tenant_scope_id AND link.operation_id=NEW.operation_id
          AND link.attempt_id=NEW.attempt_id AND epoch.tenant_scope_id=NEW.tenant_scope_id
          AND epoch.site_id=NEW.site_id AND epoch.opened_at <= NEW.created_at
          AND (epoch.closed_at IS NULL OR epoch.closed_at > NEW.created_at)
          AND ARRAY(SELECT target.node_id FROM acme_http01_node_challenge_targets target
                    WHERE target.tenant_scope_id=NEW.tenant_scope_id AND target.operation_id=NEW.operation_id
                      AND target.attempt_id=NEW.attempt_id ORDER BY target.node_id) =
              ARRAY(SELECT member.node_id FROM acme_http01_site_overlay_epoch_members member
                    WHERE member.epoch_id=epoch.id AND NOT EXISTS (
                        SELECT 1 FROM acme_http01_site_overlay_epoch_releases released
                        WHERE released.epoch_id=member.epoch_id AND released.node_id=member.node_id
                          AND released.released_at <= NEW.created_at)
                    ORDER BY member.node_id)) THEN
        RAISE EXCEPTION 'ACME HTTP-01 challenge must target the active members of its site epoch' USING ERRCODE='P3423';
    END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER acme_http01_node_challenges_epoch_342
    AFTER INSERT ON acme_http01_node_challenges DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_acme_http01_challenge_epoch_342();
CREATE FUNCTION guard_acme_http01_overlay_fact_342()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'ACME HTTP-01 % rows are append-only', TG_TABLE_NAME USING ERRCODE='P3421';
END;
$$;
CREATE TRIGGER acme_http01_site_overlay_version_tokens_append_only_342
    BEFORE UPDATE OR DELETE ON acme_http01_site_overlay_version_tokens
    FOR EACH ROW EXECUTE FUNCTION guard_acme_http01_overlay_fact_342();
CREATE TRIGGER acme_http01_node_challenge_epochs_append_only_342
    BEFORE UPDATE OR DELETE ON acme_http01_node_challenge_epochs
    FOR EACH ROW EXECUTE FUNCTION guard_acme_http01_overlay_fact_342();
CREATE TRIGGER acme_http01_node_overlay_generation_coverages_append_only_342
    BEFORE UPDATE OR DELETE ON acme_http01_node_overlay_generation_coverages
    FOR EACH ROW EXECUTE FUNCTION guard_acme_http01_overlay_fact_342();
CREATE TRIGGER acme_http01_overlay_backfill_sites_append_only_342
    BEFORE UPDATE OR DELETE ON acme_http01_overlay_backfill_sites
    FOR EACH ROW EXECUTE FUNCTION guard_acme_http01_overlay_fact_342();
CREATE TRIGGER acme_http01_overlay_backfill_quarantines_append_only_342
    BEFORE UPDATE OR DELETE ON acme_http01_overlay_backfill_quarantines
    FOR EACH ROW EXECUTE FUNCTION guard_acme_http01_overlay_fact_342();
DO $truncate_guards_342$
DECLARE
    name text;
BEGIN
    FOREACH name IN ARRAY ARRAY['acme_http01_site_overlay_states', 'acme_http01_site_overlay_epochs',
        'acme_http01_site_overlay_epoch_members', 'acme_http01_site_overlay_versions',
        'acme_http01_site_overlay_version_tokens', 'acme_http01_node_challenge_epochs',
        'acme_http01_node_overlay_cleanup_debts', 'acme_http01_node_overlay_generation_coverages',
        'acme_http01_node_overlay_cleanup_debt_events', 'acme_http01_site_overlay_epoch_releases',
        'acme_http01_overlay_backfill_sites', 'acme_http01_overlay_backfill_nodes',
        'acme_http01_overlay_backfill_quarantines']
    LOOP
        EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION %I()',
            name || '_truncate_342', name, 'acme_http01_overlay_append_only_342');
    END LOOP;
END;
$truncate_guards_342$;

-- Re-runnable 063 backfill (ADR-0003 Backfill 与兼容). 063 facts are only
-- read; nothing inherits a 063 healthy receipt. Each 063 site with a current
-- revision becomes a closed epoch whose members (the 063 targets) owe a
-- cleanup of the 063 evidence version; each such node waits for a bootstrap
-- generation above every 063 site revision it saw. Inconsistent facts
-- quarantine the site (or every site of a conflicting node) and keep its
-- nodes out of serving it. Sites already marked are skipped, so a rerun only
-- picks up what is new.
CREATE FUNCTION acme_http01_backfill_063(
    OUT bootstrapped_sites integer, OUT quarantined_sites integer, OUT pending_nodes integer, OUT quarantined_nodes integer)
LANGUAGE plpgsql AS $$
DECLARE
    v_stamp timestamptz := now();
    v_item record;
    v_current_id uuid;
    v_evidence_id uuid;
    v_evidence_count integer;
    v_reason text;
    v_members uuid[];
    v_node uuid;
    v_candidates uuid[];
    v_release text;
    v_existing uuid;
    v_debt uuid;
    v_epoch uuid;
    v_evidence_version uuid;
    v_empty_version uuid;
    v_version bigint;
    v_epochs bigint;
    v_updated timestamptz;
    v_conflicted uuid[] := ARRAY[]::uuid[];
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('acme-http01-overlay', 0));
    bootstrapped_sites := 0;
    quarantined_sites := 0;
    -- A node whose 063 sites disagree on a challenge cannot get one aggregate.
    FOR v_node IN
        WITH pending AS (
            SELECT state.tenant_scope_id, state.site_id, state.current_revision, version.id AS current_id
            FROM acme_http01_overlay_states state
            JOIN acme_http01_overlay_versions version ON version.tenant_scope_id=state.tenant_scope_id
             AND version.site_id=state.site_id AND version.revision=state.current_revision
            WHERE state.current_revision > 0 AND NOT EXISTS (
                SELECT 1 FROM acme_http01_overlay_backfill_sites mark
                WHERE mark.tenant_scope_id=state.tenant_scope_id AND mark.site_id=state.site_id)
        ), evidence AS (
            SELECT pending.current_id, (
                SELECT version.id FROM acme_http01_overlay_versions version
                JOIN acme_http01_overlay_publications publication ON publication.id=version.publication_id
                WHERE version.tenant_scope_id=pending.tenant_scope_id AND version.site_id=pending.site_id
                  AND version.revision <= pending.current_revision AND publication.mode='apply'
                ORDER BY version.revision DESC LIMIT 1) AS evidence_id
            FROM pending
        ), served AS (
            SELECT DISTINCT target.node_id, fact.tenant_scope_id, fact.operation_id, fact.challenge_attempt_id,
                   fact.domain, fact.token_sha256, fact.value_sha256
            FROM evidence
            JOIN acme_http01_overlay_targets target ON target.version_id IN (evidence.current_id, evidence.evidence_id)
            JOIN acme_http01_overlay_token_facts fact ON fact.version_id=evidence.evidence_id
        )
        SELECT DISTINCT a.node_id FROM served a JOIN served b ON a.node_id=b.node_id AND (
            (a.domain=b.domain AND a.token_sha256=b.token_sha256 AND a.value_sha256<>b.value_sha256) OR
            (a.tenant_scope_id=b.tenant_scope_id AND a.operation_id=b.operation_id
             AND a.challenge_attempt_id=b.challenge_attempt_id
             AND (a.domain, a.token_sha256, a.value_sha256) IS DISTINCT FROM (b.domain, b.token_sha256, b.value_sha256)))
        ORDER BY 1
    LOOP
        v_conflicted := v_conflicted || v_node;
        INSERT INTO acme_http01_overlay_backfill_nodes(node_id,state,reason_code,generation_floor,recorded_at,updated_at)
        VALUES(v_node,'quarantined','token_conflict',
               (SELECT COALESCE(max(target.revision),0)+1 FROM acme_http01_overlay_targets target WHERE target.node_id=v_node),
               v_stamp,v_stamp)
        ON CONFLICT (node_id) DO NOTHING;
    END LOOP;
    FOR v_item IN
        SELECT state.tenant_scope_id, state.site_id, state.current_revision
        FROM acme_http01_overlay_states state
        WHERE state.current_revision > 0 AND NOT EXISTS (
            SELECT 1 FROM acme_http01_overlay_backfill_sites mark
            WHERE mark.tenant_scope_id=state.tenant_scope_id AND mark.site_id=state.site_id)
        ORDER BY state.tenant_scope_id, state.site_id
    LOOP
        v_reason := NULL;
        v_current_id := NULL;
        v_evidence_id := NULL;
        v_members := ARRAY[]::uuid[];
        SELECT version.id INTO v_current_id FROM acme_http01_overlay_versions version
        WHERE version.tenant_scope_id=v_item.tenant_scope_id AND version.site_id=v_item.site_id
          AND version.revision=v_item.current_revision;
        IF v_current_id IS NULL THEN
            v_reason := 'unproven_current_version';
        ELSE
            SELECT version.id, publication.token_count INTO v_evidence_id, v_evidence_count
            FROM acme_http01_overlay_versions version
            JOIN acme_http01_overlay_publications publication ON publication.id=version.publication_id
            WHERE version.tenant_scope_id=v_item.tenant_scope_id AND version.site_id=v_item.site_id
              AND version.revision <= v_item.current_revision AND publication.mode='apply'
            ORDER BY version.revision DESC LIMIT 1;
            v_members := ARRAY(SELECT DISTINCT target.node_id FROM acme_http01_overlay_targets target
                               WHERE target.version_id IN (v_current_id, v_evidence_id) ORDER BY 1);
            IF v_evidence_id IS NULL THEN
                v_reason := 'missing_source_fact';
            ELSIF v_evidence_count IS DISTINCT FROM (SELECT count(*) FROM acme_http01_overlay_token_facts fact
                                                     WHERE fact.version_id=v_evidence_id) OR v_evidence_count < 1 THEN
                v_reason := 'missing_source_fact';
            ELSIF cardinality(v_members) = 0 THEN
                v_reason := 'missing_target';
            ELSIF EXISTS (SELECT 1 FROM unnest(v_members) member_node LEFT JOIN nodes node ON node.id=member_node
                          LEFT JOIN access_scopes node_scope ON node_scope.id=node.scope_id
                          WHERE node.id IS NULL OR (node.scope_id <> v_item.tenant_scope_id
                                AND node_scope.kind IS DISTINCT FROM 'platform')) OR EXISTS (
                      SELECT 1 FROM acme_http01_overlay_token_facts fact
                      WHERE fact.version_id=v_evidence_id AND fact.tenant_scope_id <> v_item.tenant_scope_id) THEN
                v_reason := 'cross_tenant_reference';
            ELSIF v_members && v_conflicted OR EXISTS (
                      SELECT 1 FROM acme_http01_overlay_backfill_nodes mark
                      WHERE mark.node_id=ANY(v_members) AND mark.state='quarantined') THEN
                v_reason := 'node_quarantined';
            ELSIF EXISTS (SELECT 1 FROM acme_http01_site_overlay_states live
                          WHERE live.tenant_scope_id=v_item.tenant_scope_id AND live.site_id=v_item.site_id
                            AND live.open_epoch_id IS NOT NULL) THEN
                -- The site already issues through 342; retry once that epoch closes.
                CONTINUE;
            END IF;
        END IF;
        IF v_reason IS NOT NULL THEN
            INSERT INTO acme_http01_overlay_backfill_sites(tenant_scope_id,site_id,legacy_revision,state,reason_code,
                legacy_version_id,recorded_at)
            VALUES(v_item.tenant_scope_id,v_item.site_id,v_item.current_revision,'quarantined',v_reason,v_current_id,v_stamp);
            INSERT INTO acme_http01_overlay_backfill_quarantines(tenant_scope_id,site_id,node_id,reason_code,recorded_at)
            SELECT DISTINCT v_item.tenant_scope_id, v_item.site_id, target.node_id, v_reason, v_stamp
            FROM acme_http01_overlay_versions version
            JOIN acme_http01_overlay_targets target ON target.version_id=version.id
            JOIN nodes node ON node.id=target.node_id
            WHERE version.tenant_scope_id=v_item.tenant_scope_id AND version.site_id=v_item.site_id
            ON CONFLICT DO NOTHING;
            quarantined_sites := quarantined_sites + 1;
            CONTINUE;
        END IF;

        -- Bootstrap: a closed epoch whose members owe the evidence version.
        INSERT INTO acme_http01_site_overlay_states(tenant_scope_id,site_id,current_version,epoch_count,created_at,updated_at)
        VALUES(v_item.tenant_scope_id,v_item.site_id,0,0,v_stamp,v_stamp) ON CONFLICT DO NOTHING;
        SELECT state.current_version, state.epoch_count, greatest(state.updated_at, v_stamp)
        INTO v_version, v_epochs, v_updated
        FROM acme_http01_site_overlay_states state
        WHERE state.tenant_scope_id=v_item.tenant_scope_id AND state.site_id=v_item.site_id FOR UPDATE;
        v_epoch := gen_random_uuid();
        INSERT INTO acme_http01_site_overlay_epochs(id,tenant_scope_id,site_id,sequence,member_count,member_set_sha256,opened_at)
        VALUES(v_epoch,v_item.tenant_scope_id,v_item.site_id,v_epochs+1,cardinality(v_members),
               acme_http01_node_set_digest(v_members),v_updated);
        INSERT INTO acme_http01_site_overlay_epoch_members(epoch_id,node_id) SELECT v_epoch, unnest(v_members);
        UPDATE acme_http01_site_overlay_states SET open_epoch_id=v_epoch, epoch_count=v_epochs+1, updated_at=v_updated
        WHERE tenant_scope_id=v_item.tenant_scope_id AND site_id=v_item.site_id;
        v_evidence_version := gen_random_uuid();
        INSERT INTO acme_http01_site_overlay_versions(id,tenant_scope_id,site_id,version,epoch_id,token_count,
            token_set_sha256,source,legacy_version_id,created_at)
        VALUES(v_evidence_version,v_item.tenant_scope_id,v_item.site_id,v_version+1,v_epoch,v_evidence_count,
               acme_http01_backfill_063_digest(v_item.site_id, v_evidence_id),'backfill_063',v_evidence_id,v_updated);
        UPDATE acme_http01_site_overlay_states SET current_version=v_version+1, current_version_id=v_evidence_version
        WHERE tenant_scope_id=v_item.tenant_scope_id AND site_id=v_item.site_id;
        v_candidates := ARRAY(SELECT acme_http01_site_candidate_nodes(v_item.tenant_scope_id, v_item.site_id));
        FOREACH v_node IN ARRAY v_members LOOP
            v_release := CASE WHEN v_node = ANY(v_candidates) THEN 'backfill_063_serving' ELSE 'backfill_063_removed' END;
            SELECT debt.id INTO v_existing FROM acme_http01_node_overlay_cleanup_debts debt
            WHERE debt.node_id=v_node AND debt.tenant_scope_id=v_item.tenant_scope_id AND debt.site_id=v_item.site_id
              AND NOT EXISTS (SELECT 1 FROM acme_http01_node_overlay_cleanup_debt_events resolved
                              WHERE resolved.debt_id=debt.id AND resolved.event IN ('resolved_cleanup', 'resolved_required'));
            IF v_existing IS NULL THEN
                v_debt := gen_random_uuid();
                INSERT INTO acme_http01_node_overlay_cleanup_debts(id,node_id,tenant_scope_id,site_id,required_epoch_id,
                    earliest_uncovered_site_version_id,earliest_token_set_sha256,earliest_token_count,opened_reason,opened_at)
                VALUES(v_debt,v_node,v_item.tenant_scope_id,v_item.site_id,v_epoch,v_evidence_version,
                       acme_http01_backfill_063_digest(v_item.site_id, v_evidence_id),v_evidence_count,v_release,v_updated);
                INSERT INTO acme_http01_node_overlay_cleanup_debt_events(debt_id,sequence,event,reason,epoch_id,site_version_id,occurred_at)
                VALUES(v_debt,1,'opened',v_release,v_epoch,v_evidence_version,v_updated);
            ELSE
                v_debt := v_existing;
                INSERT INTO acme_http01_node_overlay_cleanup_debt_events(debt_id,sequence,event,reason,epoch_id,site_version_id,occurred_at)
                SELECT v_debt, max(event.sequence)+1, 'coalesced', v_release, v_epoch, v_evidence_version, v_updated
                FROM acme_http01_node_overlay_cleanup_debt_events event WHERE event.debt_id=v_debt;
            END IF;
            INSERT INTO acme_http01_site_overlay_epoch_releases(epoch_id,node_id,reason,debt_id,released_at)
            VALUES(v_epoch,v_node,v_release,v_debt,v_updated);
            INSERT INTO acme_http01_overlay_backfill_nodes(node_id,state,reason_code,generation_floor,recorded_at,updated_at)
            VALUES(v_node,'pending','backfill_063',
                   (SELECT COALESCE(max(target.revision),0)+1 FROM acme_http01_overlay_targets target WHERE target.node_id=v_node),
                   v_stamp,v_stamp)
            ON CONFLICT (node_id) DO UPDATE SET state='pending', bootstrap_generation_id=NULL,
                generation_floor=greatest(acme_http01_overlay_backfill_nodes.generation_floor, EXCLUDED.generation_floor),
                updated_at=greatest(acme_http01_overlay_backfill_nodes.updated_at, EXCLUDED.updated_at)
            WHERE acme_http01_overlay_backfill_nodes.state <> 'quarantined';
        END LOOP;
        v_empty_version := gen_random_uuid();
        INSERT INTO acme_http01_site_overlay_versions(id,tenant_scope_id,site_id,version,epoch_id,token_count,
            token_set_sha256,source,created_at)
        VALUES(v_empty_version,v_item.tenant_scope_id,v_item.site_id,v_version+2,v_epoch,0,
               acme_http01_site_token_set_digest(v_item.site_id, ARRAY[]::text[]),'refresh',v_updated);
        UPDATE acme_http01_site_overlay_states SET current_version=v_version+2, current_version_id=v_empty_version,
            open_epoch_id=NULL
        WHERE tenant_scope_id=v_item.tenant_scope_id AND site_id=v_item.site_id;
        UPDATE acme_http01_site_overlay_epochs SET closed_at=v_updated WHERE id=v_epoch;
        INSERT INTO acme_http01_overlay_backfill_sites(tenant_scope_id,site_id,legacy_revision,state,reason_code,
            epoch_id,legacy_version_id,recorded_at)
        VALUES(v_item.tenant_scope_id,v_item.site_id,v_item.current_revision,'bootstrapped','backfill_063',v_epoch,
               v_current_id,v_stamp);
        bootstrapped_sites := bootstrapped_sites + 1;
    END LOOP;
    SELECT count(*) FILTER (WHERE state='pending'), count(*) FILTER (WHERE state='quarantined')
    INTO pending_nodes, quarantined_nodes FROM acme_http01_overlay_backfill_nodes;
END;
$$;

-- 337 challenges have no epoch: withdraw them once (their only allowed
-- change). The reconciler gives their nodes a generation without them and the
-- ACME worker retries the issuance as a new challenge.
UPDATE acme_http01_node_challenges SET withdrawn_at=greatest(now(), created_at) WHERE withdrawn_at IS NULL;

SELECT acme_http01_backfill_063();

REVOKE ALL ON acme_http01_site_overlay_states, acme_http01_site_overlay_epochs,
    acme_http01_site_overlay_epoch_members, acme_http01_site_overlay_versions,
    acme_http01_site_overlay_version_tokens, acme_http01_node_challenge_epochs,
    acme_http01_node_overlay_cleanup_debts, acme_http01_node_overlay_generation_coverages,
    acme_http01_node_overlay_cleanup_debt_events, acme_http01_site_overlay_epoch_releases,
    acme_http01_overlay_backfill_sites, acme_http01_overlay_backfill_nodes,
    acme_http01_overlay_backfill_quarantines, acme_http01_node_overlay_cleanup_debt_states FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON acme_http01_site_overlay_states, acme_http01_site_overlay_epochs,
    acme_http01_overlay_backfill_nodes TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT ON acme_http01_site_overlay_epoch_members, acme_http01_site_overlay_versions,
    acme_http01_site_overlay_version_tokens, acme_http01_node_challenge_epochs,
    acme_http01_node_overlay_cleanup_debts, acme_http01_node_overlay_generation_coverages,
    acme_http01_node_overlay_cleanup_debt_events, acme_http01_site_overlay_epoch_releases,
    acme_http01_overlay_backfill_sites, acme_http01_overlay_backfill_quarantines
    TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT ON acme_http01_node_overlay_cleanup_debt_states TO cdnca_control_app, cdnca_control_runtime;
