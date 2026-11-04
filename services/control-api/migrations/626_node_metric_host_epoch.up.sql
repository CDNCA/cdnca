-- 626（前驱 625 market_offer_delisted_notice）。
-- 节点重装（同一节点 ID 换新机器）后 agent 的监控序号从 1 重新开始（序号存在 /var/lib/cdnca-node-monitoring，
-- 重装/卸载会清掉），event_id 也按 (node, 序号) 派生而与旧机器重复。150 的序号守卫、主键 event_id、
-- UNIQUE(node_id, publication_sequence) 与按序号取"最新"的视图都跨机器比较，新机器的样本一律被拒（P1501）或
-- 被当成冲突丢弃，页面一直显示旧机器的过期样本。
-- host_epoch = 写入时该节点 initial 证书张数 - 1（与 edgedeployment.CurrentHostDeployment 同一界线：最近一次
-- 初始注册之后写入的样本属于当前主机）。序号单调、唯一性与"最新"只在同一 host_epoch 内比较；跨 epoch 按
-- (host_epoch, publication_sequence) 排序。存量样本 host_epoch=0，只注册过一次的节点不变。
LOCK TABLE schema_migrations, node_metric_samples IN ACCESS EXCLUSIVE MODE;

DO $migration_626_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 625 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 625 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=625 AND migration_id='625_market_offer_delisted_notice' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.node_metric_samples') IS NULL OR
         to_regprocedure('guard_node_metric_sequence_150()') IS NULL OR
         to_regprocedure('guard_retention_delete_node_metric_320()') IS NULL OR
         to_regprocedure('guard_node_metric_sequence_626()') IS NOT NULL OR
         to_regprocedure('guard_retention_delete_node_metric_626()') IS NOT NULL OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='node_metric_samples' AND column_name='host_epoch'
       ) THEN
        RAISE EXCEPTION 'migration 626 requires the verified 625 release head with the 150/320 node metric guards and no host_epoch'
            USING ERRCODE='P6260';
    END IF;
END;
$migration_626_up$;

-- Filled by guard_node_metric_sequence_626 on every insert; existing samples are epoch 0.
ALTER TABLE node_metric_samples ADD COLUMN host_epoch integer NOT NULL DEFAULT 0 CHECK (host_epoch >= 0);

ALTER TABLE node_metric_samples
    DROP CONSTRAINT node_metric_samples_pkey,
    DROP CONSTRAINT node_metric_samples_node_id_publication_sequence_key,
    ADD CONSTRAINT node_metric_samples_pkey_626 PRIMARY KEY (event_id, host_epoch),
    ADD CONSTRAINT node_metric_samples_host_sequence_626 UNIQUE (node_id, host_epoch, publication_sequence);

DROP INDEX node_metric_samples_latest_150_idx;
DROP INDEX node_metric_samples_metric_latest_179_idx;
DROP INDEX node_metric_samples_recovery_latest_179_idx;
CREATE INDEX node_metric_samples_latest_626_idx
    ON node_metric_samples(node_id, host_epoch DESC, publication_sequence DESC);
CREATE INDEX node_metric_samples_metric_latest_626_idx
    ON node_metric_samples(node_id, host_epoch DESC, publication_sequence DESC) WHERE record_kind='metric';
CREATE INDEX node_metric_samples_recovery_latest_626_idx
    ON node_metric_samples(node_id, host_epoch DESC, publication_sequence DESC) WHERE record_kind='recovery_notification';

CREATE FUNCTION guard_node_metric_sequence_626()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.node_id::text, 150));
    -- The node's current host: enrollments (initial certificates) so far, minus one.
    NEW.host_epoch := GREATEST((SELECT count(*) FROM node_certificates
        WHERE node_id = NEW.node_id AND issuance_kind = 'initial') - 1, 0);
    -- An exact redelivery of a stored sample (any host) is left to the puback
    -- unique key, so the insert does nothing.
    IF EXISTS (
        SELECT 1 FROM node_metric_samples
        WHERE event_id = NEW.event_id AND node_id = NEW.node_id AND
              publication_sequence = NEW.publication_sequence AND
              puback_stream = NEW.puback_stream AND puback_sequence = NEW.puback_sequence AND
              wire_sha256 = NEW.wire_sha256
    ) THEN
        RETURN NEW;
    END IF;
    IF EXISTS (
        SELECT 1 FROM node_metric_samples
        WHERE node_id = NEW.node_id AND host_epoch = NEW.host_epoch AND
              publication_sequence > NEW.publication_sequence
    ) THEN
        RAISE EXCEPTION 'node metric publication sequence is stale'
            USING ERRCODE = 'P1501';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER node_metric_sequence_guard_150 ON node_metric_samples;
CREATE TRIGGER node_metric_sequence_guard_626
BEFORE INSERT ON node_metric_samples
FOR EACH ROW EXECUTE FUNCTION guard_node_metric_sequence_626();

CREATE FUNCTION guard_retention_delete_node_metric_626()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    -- Old enough, and never the newest sample of its node in (host_epoch,
    -- publication_sequence) order (node_metric_latest and the guard keep working).
    IF NOT COALESCE(OLD.observed_at < retention_cleanup_cutoff_320('node_metrics_days'), false) OR NOT EXISTS (
        SELECT 1 FROM node_metric_samples newer
        WHERE newer.node_id = OLD.node_id AND
              (newer.host_epoch, newer.publication_sequence) > (OLD.host_epoch, OLD.publication_sequence)
    ) THEN
        RAISE EXCEPTION 'node metric sample is within retention' USING ERRCODE='P3202';
    END IF;
    RETURN OLD;
END;
$function$;

DROP TRIGGER node_metric_samples_retention_320 ON node_metric_samples;
CREATE TRIGGER node_metric_samples_retention_626 BEFORE DELETE ON node_metric_samples FOR EACH ROW
    WHEN (current_user = 'cdnca_retention_cleanup' AND NOT node_purge_in_progress())
    EXECUTE FUNCTION guard_retention_delete_node_metric_626();

REVOKE ALL ON FUNCTION guard_node_metric_sequence_626() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_retention_delete_node_metric_626() FROM PUBLIC;

-- "最新"视图：先当前主机（host_epoch 大者），再序号；列不变。
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
ORDER BY node_id, host_epoch DESC, publication_sequence DESC;

CREATE OR REPLACE VIEW node_recovery_latest AS
SELECT DISTINCT ON (node_id)
    event_id,request_id,node_id,schema_version,config_revision,publication_sequence,
    observed_at,recovery_reason_code,puback_stream,puback_sequence,consumer_durable,
    consumer_sequence,num_delivered,wire_sha256,ingested_at
FROM node_metric_samples
WHERE record_kind='recovery_notification'
ORDER BY node_id, host_epoch DESC, publication_sequence DESC;

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
ORDER BY node_id, host_epoch DESC, publication_sequence DESC;
