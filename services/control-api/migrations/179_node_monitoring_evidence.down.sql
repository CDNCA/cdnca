LOCK TABLE schema_migrations,node_metric_samples IN ACCESS EXCLUSIVE MODE;

DO $migration_179_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>179 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>179 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=179 AND migration_id='179_node_monitoring_evidence' AND
              checksum_sha256='11a46d749b7e28360aa0416c9028c69ff89acc696bf22a48e8e043b8d0b972b5' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 179 rollback requires the exact verified 179 head' USING ERRCODE='P1791';
    END IF;
    IF EXISTS (SELECT 1 FROM node_metric_samples WHERE record_kind<>'legacy_metric') THEN
        RAISE EXCEPTION 'migration 179 rollback would discard durable node monitoring probe or recovery evidence'
            USING ERRCODE='P1792';
    END IF;
END;
$migration_179_down$;

DROP VIEW node_recovery_latest;
DROP VIEW node_metric_latest;
DROP INDEX node_metric_samples_recovery_latest_179_idx;
DROP INDEX node_metric_samples_metric_latest_179_idx;

ALTER TABLE node_metric_samples DROP CONSTRAINT node_metric_samples_record_shape_179;
ALTER TABLE node_metric_samples
    DROP COLUMN recovery_reason_code,
    DROP COLUMN rolled_back,
    DROP COLUMN recovery_notified,
    DROP COLUMN recovered,
    DROP COLUMN probe_failures_total,
    DROP COLUMN probes_total,
    DROP COLUMN consecutive_successes,
    DROP COLUMN consecutive_failures,
    DROP COLUMN probe_succeeded,
    DROP COLUMN healthy,
    DROP COLUMN probe_port,
    DROP COLUMN active_config_revision,
    DROP COLUMN record_kind;

CREATE VIEW node_metric_latest AS
SELECT DISTINCT ON (node_id)
    event_id,request_id,node_id,schema_version,config_revision,publication_sequence,
    observed_at,metrics_known,cpu_percent,memory_used_bytes,memory_total_bytes,
    active_connections,rx_bandwidth_bps,tx_bandwidth_bps,puback_stream,
    puback_sequence,consumer_durable,consumer_sequence,num_delivered,wire_sha256,ingested_at
FROM node_metric_samples
ORDER BY node_id,publication_sequence DESC;

REVOKE ALL ON node_metric_latest FROM PUBLIC;
