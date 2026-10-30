LOCK TABLE schema_migrations,access_scopes,sites,analytics_realtime_expected_counts_131 IN ACCESS EXCLUSIVE MODE;

DO $migration_184$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>183 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>183 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=183 AND migration_id='183_high_risk_operations' AND
              checksum_sha256='6b9944051f89399f001da2943cc9407904961c2149b4f3091c42b3e9dadca590' AND
              down_checksum_sha256='75d27e61685c7a963f197b42d344d958692db03e061b9166728fc603bf59d38c' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass(current_schema() || '.analytics_realtime_source_windows_184') IS NOT NULL OR
         to_regprocedure(current_schema() || '.guard_analytics_realtime_source_window_184()') IS NOT NULL OR
         to_regprocedure(current_schema() || '.reject_analytics_realtime_source_window_truncate_184()') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 184 requires the exact verified 183 release head and an untouched realtime source window schema'
            USING ERRCODE='P1840';
    END IF;
END;
$migration_184$;

CREATE TABLE analytics_realtime_source_windows_184 (
    scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    site_id uuid,
    host text CHECK(host IS NULL OR (
        host=lower(btrim(host)) AND char_length(host) BETWEEN 1 AND 253 AND
        host !~ '[[:cntrl:]]' AND host !~ '[/:@]' AND right(host,1)<>'.'
    )),
    listen_port integer CHECK(listen_port IS NULL OR listen_port BETWEEN 1 AND 65535),
    window_start timestamptz NOT NULL CHECK(isfinite(window_start) AND window_start=date_trunc('hour',window_start)),
    window_end timestamptz NOT NULL CHECK(isfinite(window_end) AND window_end=window_start+interval '1 hour'),
    access_sources_expected integer NOT NULL CHECK(access_sources_expected BETWEEN 1 AND 1000000),
    access_sources_finalized integer NOT NULL CHECK(
        access_sources_finalized BETWEEN 0 AND 1000000 AND access_sources_finalized<=access_sources_expected
    ),
    connection_sources_expected integer NOT NULL CHECK(connection_sources_expected BETWEEN 1 AND 1000000),
    connection_sources_finalized integer NOT NULL CHECK(
        connection_sources_finalized BETWEEN 0 AND 1000000 AND connection_sources_finalized<=connection_sources_expected
    ),
    access_source_watermark timestamptz NOT NULL CHECK(isfinite(access_source_watermark)),
    access_finalized_through timestamptz NOT NULL CHECK(isfinite(access_finalized_through)),
    connection_source_watermark timestamptz NOT NULL CHECK(isfinite(connection_source_watermark)),
    connection_finalized_through timestamptz NOT NULL CHECK(isfinite(connection_finalized_through)),
    evidence_sha256 bytea NOT NULL CHECK(octet_length(evidence_sha256)=32),
    recorded_at timestamptz NOT NULL CHECK(isfinite(recorded_at)),
    UNIQUE NULLS NOT DISTINCT(scope_id,window_start,site_id,host,listen_port),
    FOREIGN KEY(scope_id,tenant_id) REFERENCES access_scopes(id,tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY(scope_id,site_id) REFERENCES sites(scope_id,id) ON DELETE RESTRICT,
    CHECK(access_finalized_through<=access_source_watermark AND connection_finalized_through<=connection_source_watermark),
    CHECK(recorded_at>=access_source_watermark AND recorded_at>=connection_source_watermark)
);

COMMENT ON TABLE analytics_realtime_source_windows_184 IS
    'Immutable exact-filter hourly source coverage facts; event cardinality remains authoritative in analytics_realtime_expected_counts_131.';

CREATE INDEX analytics_realtime_source_windows_184_query_idx
    ON analytics_realtime_source_windows_184(tenant_id,window_start,site_id,host,listen_port);

CREATE FUNCTION guard_analytics_realtime_source_window_184()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'analytics realtime source windows are immutable' USING ERRCODE='P1841';
END;
$$;

CREATE TRIGGER analytics_realtime_source_windows_184_immutable
BEFORE UPDATE OR DELETE ON analytics_realtime_source_windows_184
FOR EACH ROW EXECUTE FUNCTION guard_analytics_realtime_source_window_184();

CREATE FUNCTION reject_analytics_realtime_source_window_truncate_184()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'analytics realtime source windows cannot be truncated' USING ERRCODE='P1841';
END;
$$;

CREATE TRIGGER analytics_realtime_source_windows_184_no_truncate
BEFORE TRUNCATE ON analytics_realtime_source_windows_184
FOR EACH STATEMENT EXECUTE FUNCTION reject_analytics_realtime_source_window_truncate_184();

REVOKE ALL ON analytics_realtime_source_windows_184 FROM PUBLIC;
