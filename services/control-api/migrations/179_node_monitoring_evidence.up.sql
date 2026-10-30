LOCK TABLE schema_migrations,node_metric_samples IN ACCESS EXCLUSIVE MODE;

DO $migration_179$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>178 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>178 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=178 AND migration_id='178_system_configuration_edge_publication' AND
              checksum_sha256='4745546d27de98d94bbb28c3b2cc9d9538c39fdd717bd1ea258bd0cad89780a2' AND
              down_checksum_sha256='5f453e07b3e552a629dfde7ee5193a66829e3da857c0705557d05d754e7addea' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass(current_schema() || '.node_metric_samples') IS NULL OR
         to_regclass(current_schema() || '.node_metric_latest') IS NULL OR
         to_regclass(current_schema() || '.node_recovery_latest') IS NOT NULL OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='node_metric_samples' AND
              column_name IN ('record_kind','active_config_revision','probe_port','healthy',
                  'probe_succeeded','consecutive_failures','consecutive_successes','probes_total',
                  'probe_failures_total','recovered','recovery_notified','rolled_back','recovery_reason_code')
    ) THEN
        RAISE EXCEPTION 'migration 179 requires the exact verified 178 release head and an untouched node monitoring evidence schema'
            USING ERRCODE='P1790';
    END IF;
END;
$migration_179$;

ALTER TABLE node_metric_samples
    ADD COLUMN record_kind text NOT NULL DEFAULT 'legacy_metric',
    ADD COLUMN active_config_revision bigint,
    ADD COLUMN probe_port integer,
    ADD COLUMN healthy boolean,
    ADD COLUMN probe_succeeded boolean,
    ADD COLUMN consecutive_failures smallint,
    ADD COLUMN consecutive_successes smallint,
    ADD COLUMN probes_total bigint,
    ADD COLUMN probe_failures_total bigint,
    ADD COLUMN recovered boolean,
    ADD COLUMN recovery_notified boolean,
    ADD COLUMN rolled_back boolean,
    ADD COLUMN recovery_reason_code text;

ALTER TABLE node_metric_samples ALTER COLUMN record_kind DROP DEFAULT;

ALTER TABLE node_metric_samples
    ADD CONSTRAINT node_metric_samples_record_shape_179 CHECK (
        (record_kind='legacy_metric' AND active_config_revision IS NULL AND probe_port IS NULL AND
         healthy IS NULL AND probe_succeeded IS NULL AND consecutive_failures IS NULL AND
         consecutive_successes IS NULL AND probes_total IS NULL AND probe_failures_total IS NULL AND
         recovered IS NULL AND recovery_notified IS NULL AND rolled_back IS NULL AND
         recovery_reason_code IS NULL) OR
        (record_kind='metric' AND active_config_revision IS NOT NULL AND active_config_revision>0 AND
         probe_port IS NOT NULL AND probe_port BETWEEN 1 AND 65535 AND
         healthy IS NOT NULL AND probe_succeeded IS NOT NULL AND
         consecutive_failures IS NOT NULL AND consecutive_failures BETWEEN 0 AND 20 AND
         consecutive_successes IS NOT NULL AND consecutive_successes BETWEEN 0 AND 20 AND
         NOT (consecutive_failures>0 AND consecutive_successes>0) AND probes_total IS NOT NULL AND
         probes_total>=0 AND probe_failures_total IS NOT NULL AND
         probe_failures_total BETWEEN 0 AND probes_total AND recovered IS NOT NULL AND
         recovery_notified IS NOT NULL AND rolled_back IS NOT NULL AND recovery_reason_code IS NULL AND
         (NOT recovered OR (healthy AND probe_succeeded)) AND
         (NOT rolled_back OR (active_config_revision<config_revision AND NOT probe_succeeded))) OR
        (record_kind='recovery_notification' AND active_config_revision IS NULL AND probe_port IS NULL AND
         healthy IS NULL AND probe_succeeded IS NULL AND consecutive_failures IS NULL AND
         consecutive_successes IS NULL AND probes_total IS NULL AND probe_failures_total IS NULL AND
         recovered IS NULL AND recovery_notified IS NULL AND rolled_back IS NULL AND
         recovery_reason_code='probe_recovered' AND NOT metrics_known AND cpu_percent IS NULL AND
         memory_used_bytes IS NULL AND memory_total_bytes IS NULL AND active_connections IS NULL AND
         rx_bandwidth_bps IS NULL AND tx_bandwidth_bps IS NULL)
    );

CREATE INDEX node_metric_samples_metric_latest_179_idx
    ON node_metric_samples(node_id,publication_sequence DESC) WHERE record_kind='metric';
CREATE INDEX node_metric_samples_recovery_latest_179_idx
    ON node_metric_samples(node_id,publication_sequence DESC) WHERE record_kind='recovery_notification';

CREATE OR REPLACE VIEW node_metric_latest AS
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

CREATE VIEW node_recovery_latest AS
SELECT DISTINCT ON (node_id)
    event_id,request_id,node_id,schema_version,config_revision,publication_sequence,
    observed_at,recovery_reason_code,puback_stream,puback_sequence,consumer_durable,
    consumer_sequence,num_delivered,wire_sha256,ingested_at
FROM node_metric_samples
WHERE record_kind='recovery_notification'
ORDER BY node_id,publication_sequence DESC;

REVOKE ALL ON node_recovery_latest FROM PUBLIC;
