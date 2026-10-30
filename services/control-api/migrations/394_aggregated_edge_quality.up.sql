LOCK TABLE schema_migrations, aggregated_edge_site_schedules, aggregated_edge_target_health,
    aggregated_edge_switch_events IN ACCESS EXCLUSIVE MODE;

DO $migration_394_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 393 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 393 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=393 AND
        migration_id='393_acme_zero_match_cleanup' AND
        checksum_sha256='6e30e3b5f94026497b7847c26dad04b5d64676c0c757c744384348fd197f05d9' AND
        down_checksum_sha256='54cb2a15504e7363ee8d179a33a7309b3c8d215ae225bb3cc78ae262ec5d7ae5' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.aggregated_edge_probe_rounds') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 394 requires the exact verified 393 release head' USING ERRCODE='P3940';
    END IF;
END;
$migration_394_up$;

-- Aggregated edge quality scheduling (ADR 0008 §6.3 质量优选, AE-PERF).
-- strategy failover: the first healthy supply in priority order (P1-b);
-- quality: among healthy supplies the one with the best quality score
-- (libs/marketproto/quality, the node market's formula), switching only when
-- the best beats the current by quality_margin points (0–3) and the current
-- choice is at least quality_min_interval_seconds old. Quality switches count
-- towards the flap limit like failover/failback.
ALTER TABLE aggregated_edge_site_schedules
    ADD COLUMN strategy text NOT NULL DEFAULT 'failover' CHECK (strategy IN ('failover', 'quality')),
    ADD COLUMN quality_min_interval_seconds integer NOT NULL DEFAULT 600
        CHECK (quality_min_interval_seconds BETWEEN 60 AND 86400),
    ADD COLUMN quality_margin numeric(4,3) NOT NULL DEFAULT 0.3 CHECK (quality_margin BETWEEN 0.05 AND 3);

-- One decided probe round (enough sources) of a third-party supply on a
-- line: healthy by majority, latency_ms the median of the OK answers
-- (NULL when none). The scorer reads the last hour; older rows are pruned.
CREATE TABLE aggregated_edge_probe_rounds (
    site_id uuid NOT NULL,
    supply_id uuid NOT NULL,
    line_scope text NOT NULL,
    round_at timestamptz NOT NULL CHECK (isfinite(round_at)),
    healthy boolean NOT NULL,
    latency_ms integer CHECK (latency_ms IS NULL OR latency_ms BETWEEN 0 AND 600000),
    ok integer NOT NULL CHECK (ok >= 0),
    failed integer NOT NULL CHECK (failed >= 0),
    PRIMARY KEY (site_id, supply_id, line_scope, round_at),
    FOREIGN KEY (site_id, supply_id, line_scope)
        REFERENCES aggregated_edge_target_health (site_id, supply_id, line_scope) ON DELETE CASCADE
);
CREATE INDEX aggregated_edge_probe_rounds_age_394_idx ON aggregated_edge_probe_rounds (round_at);

ALTER TABLE aggregated_edge_switch_events DROP CONSTRAINT aggregated_edge_switch_events_reason_check;
ALTER TABLE aggregated_edge_switch_events ADD CONSTRAINT aggregated_edge_switch_events_reason_394_check
    CHECK (reason IN ('failover', 'failback', 'quality', 'manual', 'unbind', 'bind', 'freeze', 'unfreeze',
        'all_unhealthy', 'recovered'));
DROP INDEX aggregated_edge_switch_events_window_366_idx;
CREATE INDEX aggregated_edge_switch_events_window_394_idx ON aggregated_edge_switch_events (site_id, created_at)
    WHERE reason IN ('failover', 'failback', 'quality');

REVOKE ALL ON aggregated_edge_probe_rounds FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON aggregated_edge_probe_rounds TO cdnca_control_app, cdnca_control_runtime;
