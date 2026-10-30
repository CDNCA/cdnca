LOCK TABLE schema_migrations, site_supplies, site_supply_bindings, site_supply_cdn_sites IN ACCESS EXCLUSIVE MODE;

DO $migration_366_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 365 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 365 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=365 AND
        migration_id='365_theme_error_page_republication' AND
        checksum_sha256='d31f78e809bec9b73384d05e636958c248807eec32c990f3e20f4c7d88933298' AND
        down_checksum_sha256='83e4153e97e6f59a52e8cb8b92aa015e00611bd3d34eec09cf8e90ffd534c3e7' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.aggregated_edge_line_targets') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 366 requires the exact verified 365 release head' USING ERRCODE='P3660';
    END IF;
END;
$migration_366_up$;

-- Aggregated edge scheduling (ADR 0008 §6, P1-b): per (site, line) the
-- supply the site CNAME points at, chosen by health with failback, flap
-- freeze and the DNS provider's line capability. Only sites with at least
-- one third_party_cdn binding are scheduled; market-only sites keep the
-- MarketTarget path.

-- Line scopes a binding can serve: '' (the DNS default line) or one of the
-- unified lines of docs/dns/provider-line-capabilities.md.
ALTER TABLE site_supply_bindings ADD CONSTRAINT site_supply_bindings_line_scope_366_check
    CHECK (line_scope IN ('', 'telecom', 'unicom', 'mobile', 'overseas'));

-- Per-site switching settings and the flap freeze (§6.3).
CREATE TABLE aggregated_edge_site_schedules (
    site_id uuid PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    -- auto: switch back after the minimum stay; manual: only an operator does.
    failback text NOT NULL DEFAULT 'auto' CHECK (failback IN ('auto', 'manual')),
    min_stay_seconds integer NOT NULL DEFAULT 600 CHECK (min_stay_seconds BETWEEN 60 AND 86400),
    flap_limit integer NOT NULL DEFAULT 4 CHECK (flap_limit BETWEEN 2 AND 60),
    -- Frozen after flap_limit switches within an hour; only an operator unfreezes.
    frozen_at timestamptz CHECK (frozen_at IS NULL OR isfinite(frozen_at)),
    frozen_reason text NOT NULL DEFAULT '' CHECK (frozen_reason IN ('', 'flap_limit')),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    CHECK ((frozen_at IS NULL) = (frozen_reason = ''))
);

-- The current choice of one (site, line). kind local = the site's own node
-- group (A/AAAA through cnameallocation Retarget, default line only);
-- follow_default = no record on the line (non-default lines only).
-- target is the CNAME the line points at ('' for local / follow_default).
-- published_target is what the DNS provider holds for a non-default line
-- after the last confirmed write (the default line is published by Retarget).
CREATE TABLE aggregated_edge_line_targets (
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    line_scope text NOT NULL CHECK (line_scope IN ('', 'telecom', 'unicom', 'mobile', 'overseas')),
    kind text NOT NULL CHECK (kind IN ('third_party_cdn', 'market_subscription', 'local', 'follow_default')),
    supply_id uuid REFERENCES site_supplies(id) ON DELETE RESTRICT,
    target text NOT NULL DEFAULT '' CHECK (target = '' OR (target = lower(target) AND char_length(target) <= 253)),
    since timestamptz NOT NULL CHECK (isfinite(since)),
    -- all_unhealthy: every candidate failed, the last choice is kept and alerted.
    alert text NOT NULL DEFAULT '' CHECK (alert IN ('', 'all_unhealthy')),
    published_target text CHECK (published_target IS NULL OR char_length(published_target) <= 253),
    published_at timestamptz CHECK (published_at IS NULL OR isfinite(published_at)),
    publish_error text NOT NULL DEFAULT '' CHECK (char_length(publish_error) <= 64),
    next_publish_at timestamptz NOT NULL CHECK (isfinite(next_publish_at)),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (site_id, line_scope),
    CHECK ((kind IN ('third_party_cdn', 'market_subscription')) = (supply_id IS NOT NULL)),
    CHECK ((kind IN ('third_party_cdn', 'market_subscription')) = (target <> '')),
    CHECK (kind <> 'local' OR line_scope = ''),
    CHECK (kind <> 'follow_default' OR line_scope <> '')
);
CREATE INDEX aggregated_edge_line_targets_supply_366_idx ON aggregated_edge_line_targets (supply_id) WHERE supply_id IS NOT NULL;
CREATE INDEX aggregated_edge_line_targets_publish_366_idx ON aggregated_edge_line_targets (next_publish_at) WHERE line_scope <> '';

-- Probe health of one third-party supply of a site on one line, judged with
-- nodescheduler.HealthPolicy (consecutive results + debounce).
CREATE TABLE aggregated_edge_target_health (
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    supply_id uuid NOT NULL REFERENCES site_supplies(id) ON DELETE RESTRICT,
    line_scope text NOT NULL CHECK (line_scope IN ('', 'telecom', 'unicom', 'mobile', 'overseas')),
    status text NOT NULL DEFAULT 'unknown' CHECK (status IN ('unknown', 'healthy', 'unhealthy')),
    consecutive_successes integer NOT NULL DEFAULT 0 CHECK (consecutive_successes >= 0),
    consecutive_failures integer NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    streak_started_at timestamptz CHECK (streak_started_at IS NULL OR isfinite(streak_started_at)),
    last_changed_at timestamptz CHECK (last_changed_at IS NULL OR isfinite(last_changed_at)),
    -- The last round: when, how many probe sources answered OK / failed.
    -- insufficient = fewer answers than the line needs (no verdict).
    last_round_at timestamptz CHECK (last_round_at IS NULL OR isfinite(last_round_at)),
    last_ok integer NOT NULL DEFAULT 0 CHECK (last_ok >= 0),
    last_failed integer NOT NULL DEFAULT 0 CHECK (last_failed >= 0),
    last_insufficient boolean NOT NULL DEFAULT false,
    next_round_at timestamptz NOT NULL CHECK (isfinite(next_round_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (site_id, supply_id, line_scope)
);
CREATE INDEX aggregated_edge_target_health_due_366_idx ON aggregated_edge_target_health (next_round_at);

-- Switching history (§6.3: time, line, from which supply to which, the probe
-- rounds it was based on). Kept after the site is gone, for the audit trail.
CREATE TABLE aggregated_edge_switch_events (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    site_id uuid NOT NULL,
    line_scope text NOT NULL CHECK (line_scope IN ('', 'telecom', 'unicom', 'mobile', 'overseas')),
    -- failover / failback / manual / unbind / freeze / unfreeze / all_unhealthy / recovered
    reason text NOT NULL CHECK (reason IN ('failover', 'failback', 'manual', 'unbind', 'bind', 'freeze', 'unfreeze',
        'all_unhealthy', 'recovered')),
    from_kind text NOT NULL DEFAULT '' CHECK (from_kind IN ('', 'third_party_cdn', 'market_subscription', 'local', 'follow_default')),
    from_supply_id uuid,
    from_target text NOT NULL DEFAULT '' CHECK (char_length(from_target) <= 253),
    to_kind text NOT NULL DEFAULT '' CHECK (to_kind IN ('', 'third_party_cdn', 'market_subscription', 'local', 'follow_default')),
    to_supply_id uuid,
    to_target text NOT NULL DEFAULT '' CHECK (char_length(to_target) <= 253),
    -- Health of every candidate when deciding, with its last probe round.
    evidence jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(evidence) = 'array' AND octet_length(evidence::text) <= 16384),
    actor_user_id uuid,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at))
);
CREATE INDEX aggregated_edge_switch_events_site_366_idx ON aggregated_edge_switch_events (site_id, created_at DESC, id);
CREATE INDEX aggregated_edge_switch_events_window_366_idx ON aggregated_edge_switch_events (site_id, created_at)
    WHERE reason IN ('failover', 'failback');

-- A config_sync site whose binding is gone is drained (no line points at the
-- supply any more and the default line's committed CNAME moved away) before
-- its vendor resources are deleted (ADR 0008 §3.3 删除). drained_at starts
-- the removal delay.
ALTER TABLE site_supply_cdn_sites ADD COLUMN drained_at timestamptz CHECK (drained_at IS NULL OR isfinite(drained_at));

REVOKE ALL ON aggregated_edge_site_schedules, aggregated_edge_line_targets, aggregated_edge_target_health,
    aggregated_edge_switch_events FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON aggregated_edge_site_schedules, aggregated_edge_line_targets,
    aggregated_edge_target_health TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT ON aggregated_edge_switch_events TO cdnca_control_app, cdnca_control_runtime;
