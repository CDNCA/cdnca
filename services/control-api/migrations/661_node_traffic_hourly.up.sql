-- 661（前驱 660_status_page_auto）。
-- 节点列表的月流量原先每次请求都扫本月全部 node_metric_samples 并逐行解码 telemetry_json
-- （73 上 2 个节点 12 万行 760MB，17 秒）。这里新增按节点、按 UTC 小时的流量汇总，
-- 入库事务内增量维护（nodemetrics.PostgresStore.Put），读取只合并小时桶与桶间差分。
-- 口径与旧算法一致：同节点按 (observed_at, publication_sequence) 排序后相邻差分，
-- 计数器下降视为重置（取当前读数），间隔超过 5 分钟记为有缺口。
-- 存量数据只回填当月（含前后各 2 天余量，覆盖所有时区的当月起点）；回填按节点逐个提交到同一事务，
-- 只读 node_metric_samples（不加锁），不阻塞入库。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_661_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 660 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 660 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=660 AND
        migration_id='660_status_page_auto' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.node_metric_samples') IS NULL
         OR to_regclass(current_schema() || '.node_traffic_hourly') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 661 requires the exact verified 660 release head' USING ERRCODE='P6610';
    END IF;
END;
$migration_661_up$;

CREATE TABLE node_traffic_hourly (
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    hour_start timestamptz NOT NULL CHECK (date_trunc('hour', hour_start AT TIME ZONE 'UTC') = hour_start AT TIME ZONE 'UTC'),
    samples integer NOT NULL CHECK (samples > 0),
    first_observed_at timestamptz NOT NULL,
    first_rx numeric(20,0) NOT NULL CHECK (first_rx >= 0),
    first_tx numeric(20,0) NOT NULL CHECK (first_tx >= 0),
    last_observed_at timestamptz NOT NULL CHECK (last_observed_at >= first_observed_at),
    last_rx numeric(20,0) NOT NULL CHECK (last_rx >= 0),
    last_tx numeric(20,0) NOT NULL CHECK (last_tx >= 0),
    usage_bytes numeric(21,0) NOT NULL CHECK (usage_bytes >= 0),
    counter_resets integer NOT NULL CHECK (counter_resets >= 0),
    has_gap boolean NOT NULL,
    PRIMARY KEY (node_id, hour_start)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON node_traffic_hourly TO cdnca_control_app, cdnca_control_runtime;

-- 回填：与 nodemetrics.selectedCounterTotals 同一规则（默认路由选中的网卡名都存在且不溢出 uint64，
-- 否则该样本不计入）。
DO $migration_661_backfill$
DECLARE
    target uuid;
    since timestamptz := date_trunc('month', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' - interval '2 days';
BEGIN
    FOR target IN SELECT DISTINCT node_id FROM node_metric_samples WHERE observed_at >= since LOOP
        INSERT INTO node_traffic_hourly(node_id,hour_start,samples,first_observed_at,first_rx,first_tx,
                                        last_observed_at,last_rx,last_tx,usage_bytes,counter_resets,has_gap)
        WITH picked AS (
            SELECT metric.node_id, metric.observed_at, metric.publication_sequence, totals.rx, totals.tx
            FROM node_metric_samples metric
            CROSS JOIN LATERAL (
                WITH names AS (
                    SELECT name.value AS name FROM jsonb_array_elements_text(metric.telemetry_json#>'{network_selection,interfaces}') name(value)
                ), found AS (
                    SELECT n.name,
                           (SELECT (iface->>'rx_bytes')::numeric FROM jsonb_array_elements(metric.telemetry_json->'network_interfaces') iface
                             WHERE iface->>'name'=n.name LIMIT 1) AS rx,
                           (SELECT (iface->>'tx_bytes')::numeric FROM jsonb_array_elements(metric.telemetry_json->'network_interfaces') iface
                             WHERE iface->>'name'=n.name LIMIT 1) AS tx
                    FROM names n
                )
                SELECT sum(rx) AS rx, sum(tx) AS tx FROM found
                HAVING count(*) > 0 AND count(rx) = count(*) AND count(tx) = count(*)
                   AND sum(rx) <= 18446744073709551615 AND sum(tx) <= 18446744073709551615
            ) totals
            WHERE metric.node_id = target AND metric.record_kind IN ('metric','host_metric')
              AND metric.telemetry_json IS NOT NULL AND metric.observed_at >= since
              AND metric.telemetry_json#>>'{network_selection,source}' = 'default_route'
        ), diffed AS (
            SELECT p.*, lag(rx) OVER w AS prx, lag(tx) OVER w AS ptx, lag(observed_at) OVER w AS pat,
                   date_trunc('hour', observed_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS hour_start,
                   lag(date_trunc('hour', observed_at AT TIME ZONE 'UTC')) OVER w AS phour
            FROM picked p WINDOW w AS (ORDER BY observed_at, publication_sequence)
        )
        SELECT target, hour_start, count(*)::int,
               (array_agg(observed_at ORDER BY observed_at, publication_sequence))[1],
               (array_agg(rx ORDER BY observed_at, publication_sequence))[1],
               (array_agg(tx ORDER BY observed_at, publication_sequence))[1],
               (array_agg(observed_at ORDER BY observed_at DESC, publication_sequence DESC))[1],
               (array_agg(rx ORDER BY observed_at DESC, publication_sequence DESC))[1],
               (array_agg(tx ORDER BY observed_at DESC, publication_sequence DESC))[1],
               COALESCE(sum(CASE WHEN prx IS NULL OR phour IS DISTINCT FROM date_trunc('hour', observed_at AT TIME ZONE 'UTC') THEN 0
                                 ELSE (CASE WHEN rx < prx THEN rx ELSE rx - prx END) + (CASE WHEN tx < ptx THEN tx ELSE tx - ptx END) END), 0),
               count(*) FILTER (WHERE prx IS NOT NULL AND phour IS NOT DISTINCT FROM date_trunc('hour', observed_at AT TIME ZONE 'UTC')
                                AND (rx < prx OR tx < ptx))::int,
               COALESCE(bool_or(prx IS NOT NULL AND phour IS NOT DISTINCT FROM date_trunc('hour', observed_at AT TIME ZONE 'UTC')
                                AND observed_at - pat > interval '5 minutes'), false)
        FROM diffed GROUP BY hour_start;
    END LOOP;
END;
$migration_661_backfill$;
