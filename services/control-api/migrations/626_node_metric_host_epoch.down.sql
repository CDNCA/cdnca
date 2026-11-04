LOCK TABLE schema_migrations, node_metric_samples IN ACCESS EXCLUSIVE MODE;

DO $migration_626_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 626 OR
       (SELECT max(version) FROM schema_migrations) <> 626 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=626 AND
        migration_id='626_node_metric_host_epoch' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 626 down requires the exact verified migration head' USING ERRCODE='P6261';
    END IF;
    -- Samples of a reinstalled host repeat the previous host's event IDs and
    -- sequences; the 150 keys cannot hold them.
    IF EXISTS (SELECT 1 FROM node_metric_samples WHERE host_epoch <> 0) THEN
        RAISE EXCEPTION 'migration 626 rollback would drop reinstalled host node metric samples' USING ERRCODE='P6262';
    END IF;
END;
$migration_626_down$;

CREATE OR REPLACE VIEW node_metric_latest AS
SELECT DISTINCT ON (node_id)
    event_id,request_id,node_id,schema_version,config_revision,publication_sequence,
    observed_at,metrics_known,cpu_percent,memory_used_bytes,memory_total_bytes,
    active_connections,rx_bandwidth_bps,tx_bandwidth_bps,puback_stream,puback_sequence,
    consumer_durable,consumer_sequence,num_delivered,wire_sha256,ingested_at,record_kind,
    active_config_revision,probe_port,healthy,probe_succeeded,consecutive_failures,
    consecutive_successes,probes_total,probe_failures_total,recovered,recovery_notified,
    rolled_back,recovery_reason_code,telemetry_json,total_rx_bytes,total_tx_bytes
FROM node_metric_samples
WHERE record_kind='metric'
ORDER BY node_id, publication_sequence DESC;

CREATE OR REPLACE VIEW node_recovery_latest AS
SELECT DISTINCT ON (node_id)
    event_id,request_id,node_id,schema_version,config_revision,publication_sequence,
    observed_at,recovery_reason_code,puback_stream,puback_sequence,consumer_durable,
    consumer_sequence,num_delivered,wire_sha256,ingested_at
FROM node_metric_samples
WHERE record_kind='recovery_notification'
ORDER BY node_id, publication_sequence DESC;

CREATE OR REPLACE VIEW node_load_latest AS
SELECT DISTINCT ON (node_id)
    event_id,request_id,node_id,schema_version,config_revision,publication_sequence,
    observed_at,metrics_known,cpu_percent,memory_used_bytes,memory_total_bytes,
    active_connections,rx_bandwidth_bps,tx_bandwidth_bps,puback_stream,puback_sequence,
    consumer_durable,consumer_sequence,num_delivered,wire_sha256,ingested_at,record_kind,
    active_config_revision,probe_port,healthy,probe_succeeded,consecutive_failures,
    consecutive_successes,probes_total,probe_failures_total,recovered,recovery_notified,
    rolled_back,recovery_reason_code,telemetry_json,total_rx_bytes,total_tx_bytes
FROM node_metric_samples
WHERE record_kind IN ('metric','host_metric')
ORDER BY node_id, publication_sequence DESC;

DROP TRIGGER node_metric_samples_retention_626 ON node_metric_samples;
CREATE TRIGGER node_metric_samples_retention_320 BEFORE DELETE ON node_metric_samples FOR EACH ROW
    WHEN (current_user = 'cdnca_retention_cleanup' AND NOT node_purge_in_progress())
    EXECUTE FUNCTION guard_retention_delete_node_metric_320();
DROP FUNCTION guard_retention_delete_node_metric_626();

DROP TRIGGER node_metric_sequence_guard_626 ON node_metric_samples;
CREATE TRIGGER node_metric_sequence_guard_150
BEFORE INSERT ON node_metric_samples
FOR EACH ROW EXECUTE FUNCTION guard_node_metric_sequence_150();
DROP FUNCTION guard_node_metric_sequence_626();

DROP INDEX node_metric_samples_latest_626_idx;
DROP INDEX node_metric_samples_metric_latest_626_idx;
DROP INDEX node_metric_samples_recovery_latest_626_idx;
CREATE INDEX node_metric_samples_latest_150_idx
    ON node_metric_samples(node_id, publication_sequence DESC);
CREATE INDEX node_metric_samples_metric_latest_179_idx
    ON node_metric_samples(node_id,publication_sequence DESC) WHERE record_kind='metric';
CREATE INDEX node_metric_samples_recovery_latest_179_idx
    ON node_metric_samples(node_id,publication_sequence DESC) WHERE record_kind='recovery_notification';

ALTER TABLE node_metric_samples
    DROP CONSTRAINT node_metric_samples_pkey_626,
    DROP CONSTRAINT node_metric_samples_host_sequence_626,
    ADD CONSTRAINT node_metric_samples_pkey PRIMARY KEY (event_id),
    ADD CONSTRAINT node_metric_samples_node_id_publication_sequence_key UNIQUE (node_id, publication_sequence);

ALTER TABLE node_metric_samples DROP COLUMN host_epoch;
