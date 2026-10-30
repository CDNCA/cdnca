LOCK TABLE schema_migrations, node_metric_samples IN ACCESS EXCLUSIVE MODE;

DO $migration_265_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 264 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 264 OR
       NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 264 AND migration_id = '264_traffic_package_management' AND
              checksum_sha256 = 'afdde35a023ebd21840dcf43e237b4b0bda56f5a015edea74faeeef68a94e18d' AND
              down_checksum_sha256 = '6e598f1ae28e8f741486cbb8ddd8dc857b96b9669cefd17b0a5bea5f2ee59a17' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 265 requires the exact verified 264 release head'
            USING ERRCODE = 'P2650';
    END IF;
END;
$migration_265_up$;

ALTER TABLE node_metric_samples
    ADD COLUMN telemetry_json jsonb,
    ADD COLUMN total_rx_bytes bigint,
    ADD COLUMN total_tx_bytes bigint,
    ADD CONSTRAINT node_metric_samples_telemetry_shape_265 CHECK (
        (telemetry_json IS NULL AND total_rx_bytes IS NULL AND total_tx_bytes IS NULL) OR
        (telemetry_json IS NOT NULL AND jsonb_typeof(telemetry_json) = 'object' AND
         total_rx_bytes IS NOT NULL AND total_rx_bytes >= 0 AND
         total_tx_bytes IS NOT NULL AND total_tx_bytes >= 0)
    );

CREATE OR REPLACE VIEW node_metric_latest AS
SELECT DISTINCT ON (node_id)
    event_id,request_id,node_id,schema_version,config_revision,publication_sequence,
    observed_at,metrics_known,cpu_percent,memory_used_bytes,memory_total_bytes,
    active_connections,rx_bandwidth_bps,tx_bandwidth_bps,puback_stream,
    puback_sequence,consumer_durable,consumer_sequence,num_delivered,wire_sha256,ingested_at,
    record_kind,active_config_revision,probe_port,healthy,probe_succeeded,
    consecutive_failures,consecutive_successes,probes_total,probe_failures_total,recovered,
    recovery_notified,rolled_back,recovery_reason_code,telemetry_json,total_rx_bytes,total_tx_bytes
FROM node_metric_samples
WHERE record_kind='metric'
ORDER BY node_id,publication_sequence DESC;

REVOKE ALL ON node_metric_latest FROM PUBLIC;
