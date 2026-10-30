LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_410_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 409 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 409 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=409 AND
        migration_id='409_tenant_member_handover' AND
        checksum_sha256='619c8bcd003ec67de37e8e96c7e38d9430f4e9b46528748e46cf71d5dcdfd8a7' AND
        down_checksum_sha256='8a5ec6bab67fe7e8a8a63a6efdaf0ee30bdecca5a72c33c39fcf0c3adc85ac25' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 410 requires the exact verified 409 release head' USING ERRCODE='P4100';
    END IF;
END;
$migration_410_up$;

-- 410（r136 ad-wire2，合入时改号）。Baseline drift reports (ADR 0010
-- section 4.3 item 4, "基线漂移待确认"; contract section 5 kind drift): a
-- node's site baseline whose de-weekdayed daily level left the slow
-- reference for days. The control plane keeps the last drift per site and
-- node; the site page shows it until a person confirms it. Nodes report a
-- drift every learning day while it lasts, so a confirmation stands while
-- the reported metrics stay within the confirmed ones (confirmed_metrics);
-- a new metric shows it again. It never changes the node's baseline (nodes
-- are autonomous).
CREATE TABLE autodefense_baseline_drifts (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    metrics text[] NOT NULL CHECK (cardinality(metrics) BETWEEN 1 AND 10 AND
        metrics <@ ARRAY['byte_rate', 'cache_hit', 'latency_p95', 'latency_p99', 'ratio_404', 'ratio_4xx',
        'ratio_5xx', 'request_rate', 'upstream_error', 'upstream_timeout']::text[]),
    days smallint NOT NULL CHECK (days BETWEEN 1 AND 255),
    reported_at timestamptz NOT NULL CHECK (isfinite(reported_at)),
    confirmed_by text CHECK (confirmed_by IS NULL OR length(confirmed_by) BETWEEN 1 AND 128),
    confirmed_at timestamptz CHECK (confirmed_at IS NULL OR isfinite(confirmed_at)),
    confirmed_metrics text[],
    CHECK ((confirmed_by IS NULL) = (confirmed_at IS NULL) AND (confirmed_at IS NULL) = (confirmed_metrics IS NULL)),
    PRIMARY KEY (tenant_scope_id, site_id, node_id),
    FOREIGN KEY (tenant_scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE
);

ALTER TABLE autodefense_report_receipts DROP CONSTRAINT autodefense_report_receipts_kind_check;
ALTER TABLE autodefense_report_receipts ADD CONSTRAINT autodefense_report_receipts_kind_check
    CHECK (kind IN ('minute', 'state', 'candidate', 'verdicts', 'adjust', 'node_event', 'drift'));

REVOKE ALL ON autodefense_baseline_drifts FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON autodefense_baseline_drifts TO cdnca_control_app, cdnca_control_runtime;
