LOCK TABLE schema_migrations, node_metric_samples IN ACCESS EXCLUSIVE MODE;

DO $migration_269_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 268 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 268 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 268 AND migration_id = '268_node_monitoring_command_outbox_trigger_fix' AND
              checksum_sha256 = '8c46ae728dbe1cdd5c405e10af81cd9d6c27129326a3c50da39b45da330134ec' AND
              down_checksum_sha256 = 'baf993e260abbf6a95b62b2414f652e95ad18999a7251c8086d38f0e476934df' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass(current_schema() || '.node_load_latest') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 269 requires the exact verified 268 release head'
            USING ERRCODE = 'P2690';
    END IF;
END;
$migration_269_up$;

ALTER TABLE node_metric_samples
    DROP CONSTRAINT node_metric_samples_config_revision_check,
    DROP CONSTRAINT node_metric_samples_record_shape_179,
    ADD CONSTRAINT node_metric_samples_config_revision_269 CHECK (
        (record_kind = 'host_metric' AND config_revision = 0) OR
        (record_kind <> 'host_metric' AND config_revision > 0)
    ),
    ADD CONSTRAINT node_metric_samples_record_shape_269 CHECK (
        (record_kind IN ('legacy_metric','host_metric') AND active_config_revision IS NULL AND probe_port IS NULL AND
         healthy IS NULL AND probe_succeeded IS NULL AND consecutive_failures IS NULL AND
         consecutive_successes IS NULL AND probes_total IS NULL AND probe_failures_total IS NULL AND
         recovered IS NULL AND recovery_notified IS NULL AND rolled_back IS NULL AND
         recovery_reason_code IS NULL AND (record_kind <> 'host_metric' OR metrics_known)) OR
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

-- Keep node_metric_latest probe-only so existing readers never interpret a
-- host-only sample as a service-health decision.
CREATE VIEW node_load_latest AS
SELECT DISTINCT ON (node_id) *
FROM node_metric_samples
WHERE record_kind IN ('metric','host_metric')
ORDER BY node_id, publication_sequence DESC;

REVOKE ALL ON node_load_latest FROM PUBLIC;
DO $migration_269_grants$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cdnca_control_app') THEN
        GRANT SELECT ON node_load_latest TO cdnca_control_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cdnca_control_runtime') THEN
        GRANT SELECT ON node_load_latest TO cdnca_control_runtime;
    END IF;
END;
$migration_269_grants$;
