LOCK TABLE schema_migrations,analytics_ingest_receipts,access_scopes,sites
IN ACCESS EXCLUSIVE MODE;

DO $migration_131$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 130 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 130 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL
           OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=130 AND migration_id='130_package_catalog_subtransaction_xid_guard'
          AND checksum_sha256='32ba9ecf6db54415a10985cd1331d65338a27e1948fce53a1b9a5d7aebc628b3'
          AND down_checksum_sha256='f1f263da30b26f45ebf98e9be5c056af93fa3ded6c8c529068b54fd223cb5f2c'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) OR to_regclass('analytics_realtime_expected_counts_131') IS NOT NULL OR
       to_regprocedure('guard_analytics_realtime_expected_count_131()') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 131 requires the exact verified 130 release head'
            USING ERRCODE='P1310';
    END IF;
END;
$migration_131$;

CREATE TABLE analytics_realtime_expected_counts_131 (
    history_epoch uuid NOT NULL,
    stream_sequence numeric(20,0) NOT NULL,
    hour timestamptz NOT NULL,
    scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    site_id uuid NOT NULL,
    host text NOT NULL,
    listen_port integer NOT NULL,
    expected_events integer NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (history_epoch,stream_sequence,hour,tenant_id,site_id,host,listen_port),
    FOREIGN KEY (history_epoch,stream_sequence)
        REFERENCES analytics_ingest_receipts(history_epoch,stream_sequence) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id,tenant_id)
        REFERENCES access_scopes(id,tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id,site_id)
        REFERENCES sites(scope_id,id) ON DELETE RESTRICT,
    CHECK (stream_sequence BETWEEN 1 AND 18446744073709551615),
    CHECK (isfinite(hour) AND hour=date_trunc('hour',hour)),
    CHECK (host=lower(btrim(host)) AND char_length(host) BETWEEN 1 AND 253),
    CHECK (listen_port BETWEEN 0 AND 65535),
    CHECK (expected_events BETWEEN 1 AND 1000),
    CHECK (isfinite(created_at))
);

CREATE INDEX analytics_realtime_expected_counts_scope_hour_131_idx
    ON analytics_realtime_expected_counts_131(scope_id,hour,site_id,host,listen_port)
    INCLUDE (expected_events);

CREATE FUNCTION guard_analytics_realtime_expected_count_131()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'analytics realtime expected counts are append-only'
        USING ERRCODE='P1310';
    RETURN NULL;
END;
$$;

CREATE TRIGGER analytics_realtime_expected_counts_append_only_131
BEFORE UPDATE OR DELETE ON analytics_realtime_expected_counts_131
FOR EACH ROW EXECUTE FUNCTION guard_analytics_realtime_expected_count_131();
CREATE TRIGGER analytics_realtime_expected_counts_no_truncate_131
BEFORE TRUNCATE ON analytics_realtime_expected_counts_131
FOR EACH STATEMENT EXECUTE FUNCTION guard_analytics_realtime_expected_count_131();

REVOKE ALL ON TABLE analytics_realtime_expected_counts_131 FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_analytics_realtime_expected_count_131() FROM PUBLIC;
