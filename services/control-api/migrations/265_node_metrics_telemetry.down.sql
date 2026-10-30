LOCK TABLE schema_migrations, node_metric_samples IN ACCESS EXCLUSIVE MODE;

DO $migration_265_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 265 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 265 OR
       NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 265 AND migration_id = '265_node_metrics_telemetry' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 265 rollback requires the exact verified 265 release head'
            USING ERRCODE = 'P2651';
    END IF;
    IF EXISTS (SELECT 1 FROM node_metric_samples WHERE telemetry_json IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 265 rollback would discard durable node telemetry'
            USING ERRCODE = 'P2652';
    END IF;
END;
$migration_265_down$;

DROP VIEW node_metric_latest;

ALTER TABLE node_metric_samples
    DROP CONSTRAINT node_metric_samples_telemetry_shape_265,
    DROP COLUMN total_tx_bytes,
    DROP COLUMN total_rx_bytes,
    DROP COLUMN telemetry_json;

CREATE VIEW node_metric_latest AS
SELECT DISTINCT ON (node_id)
    event_id,request_id,node_id,schema_version,config_revision,publication_sequence,
    observed_at,metrics_known,cpu_percent,memory_used_bytes,memory_total_bytes,
    active_connections,rx_bandwidth_bps,tx_bandwidth_bps,puback_stream,
    puback_sequence,consumer_durable,consumer_sequence,num_delivered,wire_sha256,ingested_at,
    record_kind,active_config_revision,probe_port,healthy,probe_succeeded,
    consecutive_failures,consecutive_successes,probes_total,probe_failures_total,recovered,
    recovery_notified,rolled_back,recovery_reason_code
FROM node_metric_samples
WHERE record_kind='metric'
ORDER BY node_id,publication_sequence DESC;

REVOKE ALL ON node_metric_latest FROM PUBLIC;
