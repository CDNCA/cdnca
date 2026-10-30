-- 536（r136 fix-probe，主会话 10-27 分配）：节点互拨可用性日志（用户 10-27："没配置 dnspup 就用自己节点互相拨测"）。
-- 前驱 535（acme_certificate_owner），守卫钉 535 校验和。
-- node_peer_probe_results：主控对节点 IP:端口的外部探测 + 其他在线节点（MARKET_PROBE）互拨，
--   每端点一轮一行（internal/nodeprobe）：有任一失败照写，全部成功每 5 分钟最多一行；保留 8 天。
--   controller_ok：主控结果（NULL 未探测）；failed/total 含主控；failed = 本轮端点判定失败
--   （主控失败且失败对端 ≥ failure_ratio，无对端只看主控）；checkpoints 为逐个检测点明细。
-- 不迁移数据。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_536_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 535 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 535 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=535 AND
        migration_id='535_acme_certificate_owner' AND
        checksum_sha256='cc8f28bdaf66a5ef2e24f24448980e478e0929a72f4859d59d5b8eee24946cae' AND
        down_checksum_sha256='9572b9c6e0aae771a66245b4d2ca7bb62b30294d7a050b36647a30eca1cf849b' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.node_peer_probe_results') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 536 requires the exact verified 535 release head' USING ERRCODE='P5360';
    END IF;
END;
$migration_536_up$;

CREATE TABLE node_peer_probe_results (
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    address inet NOT NULL,
    port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    observed_at timestamptz NOT NULL CHECK (isfinite(observed_at)),
    controller_ok boolean,
    total_checks integer NOT NULL CHECK (total_checks BETWEEN 1 AND 100),
    failed_checks integer NOT NULL CHECK (failed_checks BETWEEN 0 AND total_checks),
    failed boolean NOT NULL,
    checkpoints jsonb NOT NULL CHECK (jsonb_typeof(checkpoints) = 'array'),
    PRIMARY KEY (node_id, observed_at, address, port)
);
CREATE INDEX node_peer_probe_results_observed_536_idx ON node_peer_probe_results (observed_at);
CREATE INDEX node_peer_probe_results_address_536_idx ON node_peer_probe_results (node_id, address, port, observed_at DESC);

REVOKE ALL ON node_peer_probe_results FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON node_peer_probe_results TO cdnca_control_app, cdnca_control_runtime;
