LOCK TABLE schema_migrations,analytics_history_streams,analytics_ingest_receipts,access_scopes,sites
IN ACCESS EXCLUSIVE MODE;

DO $migration_208$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>207 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>207 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=207 AND migration_id='207_account_order_records' AND
              checksum_sha256='9430b75c0e43cac163fc3dc3d16dcba4294f67f91237f2d473a91aa1fc3ef6cb' AND
              down_checksum_sha256='88d49bc7e2421b8b8e135d19aa66d666ca10808d8e87d1ba22615880ea02b34f' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid='analytics_history_streams'::regclass AND
              conname='analytics_history_streams_epoch_installation_208_key'
    ) OR to_regclass(current_schema() || '.analytics_access_source_window_contributions_208') IS NOT NULL OR
         to_regprocedure(current_schema() || '.guard_analytics_access_source_window_contribution_208()') IS NOT NULL OR
         to_regprocedure(current_schema() || '.reject_analytics_access_source_window_contribution_truncate_208()') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 208 requires the exact verified 207 release head and an untouched access source contribution schema'
            USING ERRCODE='P2080';
    END IF;
END;
$migration_208$;

ALTER TABLE analytics_history_streams
    ADD CONSTRAINT analytics_history_streams_epoch_installation_208_key
    UNIQUE(history_epoch,installation_id);

CREATE TABLE analytics_access_source_window_contributions_208 (
    history_epoch uuid NOT NULL,
    stream_sequence numeric(20,0) NOT NULL CHECK(stream_sequence BETWEEN 1 AND 18446744073709551615),
    event_id text NOT NULL CHECK(
        char_length(event_id) BETWEEN 1 AND 128 AND event_id !~ '[^A-Za-z0-9._:-]'
    ),
    scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    installation_id text NOT NULL CHECK(
        char_length(installation_id) BETWEEN 1 AND 128 AND installation_id !~ '[^A-Za-z0-9._:-]'
    ),
    site_id uuid NOT NULL,
    node_id uuid NOT NULL,
    package_subscription_id uuid,
    config_version_id uuid NOT NULL,
    host text NOT NULL CHECK(
        host=lower(btrim(host)) AND char_length(host) BETWEEN 1 AND 253 AND
        host !~ '[[:cntrl:]]' AND host !~ '[/:@]' AND right(host,1)<>'.'
    ),
    listen_port integer NOT NULL CHECK(listen_port BETWEEN 1 AND 65535),
    window_start timestamptz NOT NULL CHECK(isfinite(window_start) AND window_start=date_trunc('hour',window_start)),
    window_end timestamptz NOT NULL CHECK(isfinite(window_end) AND window_end=window_start+interval '1 hour'),
    source_watermark numeric(20,0) NOT NULL CHECK(source_watermark BETWEEN 1 AND 18446744073709551615),
    finalized_through timestamptz NOT NULL CHECK(isfinite(finalized_through) AND finalized_through=window_end),
    dependency_state text NOT NULL CHECK(dependency_state='ready'),
    evidence_sha256 bytea NOT NULL CHECK(
        octet_length(evidence_sha256)=32 AND evidence_sha256<>decode(repeat('00',32),'hex')
    ),
    recorded_at timestamptz NOT NULL CHECK(isfinite(recorded_at) AND recorded_at>=window_end),
    PRIMARY KEY(history_epoch,stream_sequence),
    UNIQUE(history_epoch,event_id),
    FOREIGN KEY(history_epoch,stream_sequence)
        REFERENCES analytics_ingest_receipts(history_epoch,stream_sequence) ON DELETE RESTRICT,
    FOREIGN KEY(history_epoch,installation_id)
        REFERENCES analytics_history_streams(history_epoch,installation_id) ON DELETE RESTRICT,
    FOREIGN KEY(scope_id,tenant_id) REFERENCES access_scopes(id,tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY(scope_id,site_id) REFERENCES sites(scope_id,id) ON DELETE RESTRICT
);

CREATE INDEX analytics_access_source_window_contributions_208_window_idx
    ON analytics_access_source_window_contributions_208(
        tenant_id,window_start,site_id,host,listen_port,installation_id,node_id,config_version_id
    ) INCLUDE(source_watermark,finalized_through,evidence_sha256);

CREATE FUNCTION guard_analytics_access_source_window_contribution_208()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'analytics access source window contributions are immutable' USING ERRCODE='P2081';
END;
$$;

CREATE TRIGGER analytics_access_source_window_contributions_208_immutable
BEFORE UPDATE OR DELETE ON analytics_access_source_window_contributions_208
FOR EACH ROW EXECUTE FUNCTION guard_analytics_access_source_window_contribution_208();

CREATE FUNCTION reject_analytics_access_source_window_contribution_truncate_208()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'analytics access source window contributions cannot be truncated' USING ERRCODE='P2081';
END;
$$;

CREATE TRIGGER analytics_access_source_window_contributions_208_no_truncate
BEFORE TRUNCATE ON analytics_access_source_window_contributions_208
FOR EACH STATEMENT EXECUTE FUNCTION reject_analytics_access_source_window_contribution_truncate_208();

COMMENT ON TABLE analytics_access_source_window_contributions_208 IS
    'Durable immutable per-source access coverage barriers staged before NATS ACK; final source-window facts remain in migration 184.';

REVOKE ALL ON analytics_access_source_window_contributions_208 FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_analytics_access_source_window_contribution_208() FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_analytics_access_source_window_contribution_truncate_208() FROM PUBLIC;
