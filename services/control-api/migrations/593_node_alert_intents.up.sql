-- 593（fix-opsnotify；merge-p24 由占位 609 改号，守卫钉 592）：节点告警通知意图持久化（NODE-N03 / ADMIN-CURRENT-02 卡 2）。
-- 节点离线/恢复、带宽摘除/恢复、线路组备用 IP 启用/恢复主 IP 原本只在状态事务的保存点里入队，入队临时失败时状态照常提交、
-- 本次通知永久丢失（下一轮状态不变不会再发）。node_alert_intents 与状态变更同事务写入一行通知意图（原事件时间与模板参数），
-- 入队成功即 status=enqueued；失败保持 pending，由节点服务 worker 每轮补发一次（原事件时间、标“延后通知”），
-- 超过补发时效（6 小时）记 expired 不再补。(scope_id,event_type,source_event_id) 唯一，补发与原入队共用同一源事件 ID 去重。
-- 只记平台作用域节点/线路组（租户节点暂不告警）。1.0.35 全新安装，不涉及旧数据。
-- 前驱：592_node_telemetry_health。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_593_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 592 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 592 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=592 AND
        migration_id='592_node_telemetry_health' AND
        checksum_sha256='0483f201f1b64aa22d9936c3bedfb98b65f16f782651cac1a7a4aa64f0b9c75a' AND
        down_checksum_sha256='362c744da6f0d804302781ab3d11ce142aa3929c6b43f4d426d27ca3c983ebdb' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.node_alert_intents') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 593 requires the exact verified 592 release head' USING ERRCODE='P5930';
    END IF;
END;
$migration_593_up$;

CREATE TABLE node_alert_intents (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE CASCADE,
    event_type text NOT NULL CHECK (event_type IN ('node.availability.offline', 'node.availability.recovered',
        'node.bandwidth.exceeded', 'node.bandwidth.recovered',
        'node.line_group.backup_ip_activated', 'node.line_group.primary_ip_restored')),
    source_event_id text NOT NULL CHECK (source_event_id ~ '^node-[a-z-]+/[A-Za-z0-9/-]{1,200}$'),
    params jsonb NOT NULL CHECK (jsonb_typeof(params) = 'object' AND octet_length(params::text) <= 16384),
    occurred_at timestamptz NOT NULL CHECK (isfinite(occurred_at)),
    status text NOT NULL CHECK (status IN ('pending', 'enqueued', 'expired')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    resolved_at timestamptz,
    CHECK ((status = 'pending') = (resolved_at IS NULL)),
    UNIQUE (scope_id, event_type, source_event_id)
);

CREATE INDEX node_alert_intents_pending_593_idx ON node_alert_intents (occurred_at) WHERE status = 'pending';

REVOKE ALL ON node_alert_intents FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON node_alert_intents TO cdnca_control_app, cdnca_control_runtime;
