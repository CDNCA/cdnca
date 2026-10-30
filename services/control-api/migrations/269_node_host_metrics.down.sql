LOCK TABLE schema_migrations, node_metric_samples IN ACCESS EXCLUSIVE MODE;

DO $migration_269_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 269 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 269 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 269 AND migration_id = '269_node_host_metrics' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 269 rollback requires the exact verified 269 release head'
            USING ERRCODE = 'P2691';
    END IF;
    IF EXISTS (SELECT 1 FROM node_metric_samples WHERE record_kind='host_metric') THEN
        RAISE EXCEPTION 'migration 269 rollback is blocked while append-only host metrics exist'
            USING ERRCODE = 'P2692';
    END IF;
END;
$migration_269_down$;

DROP VIEW node_load_latest;
ALTER TABLE node_metric_samples
    DROP CONSTRAINT node_metric_samples_config_revision_269,
    DROP CONSTRAINT node_metric_samples_record_shape_269,
    ADD CONSTRAINT node_metric_samples_config_revision_check CHECK (config_revision > 0),
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
