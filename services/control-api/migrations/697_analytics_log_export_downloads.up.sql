-- 697（前驱 696_origin_failover_hold_template）。
-- 导出列表的下载次数/最近下载原先聚合 analytics_log_export_grants_v1 里已消费的授权，授权签发 5 分钟后
-- 即被 Cleanup 删除（expires_at<=now），下载约 5 分钟后计数回读为 0。
-- analytics_log_export_downloads_v1 每次成功下载一行，与 analytics_log.export.download/success 审计同事务
-- 写入（id 取被消费授权的 id），只增；用已有的成功下载审计（含 audit_event_archive）回填，id 取审计事件 id。
-- 错误码：头检查 P6970；down 头检查 P6971。
LOCK TABLE schema_migrations, analytics_log_exports_v1 IN ACCESS EXCLUSIVE MODE;

DO $migration_697_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 696 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 696 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=696 AND
        migration_id='696_origin_failover_hold_template' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.analytics_log_export_downloads_v1') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 697 requires the exact verified 696 release head' USING ERRCODE='P6970';
    END IF;
END;
$migration_697_up$;

CREATE TABLE analytics_log_export_downloads_v1 (
    id uuid PRIMARY KEY,
    export_id uuid NOT NULL REFERENCES analytics_log_exports_v1(id) ON DELETE RESTRICT,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    downloaded_at timestamptz NOT NULL CHECK (isfinite(downloaded_at))
);
CREATE INDEX analytics_log_export_downloads_export_697_idx
    ON analytics_log_export_downloads_v1(export_id,downloaded_at DESC,id DESC);

CREATE TRIGGER analytics_log_export_downloads_append_only_697
BEFORE UPDATE OR DELETE ON analytics_log_export_downloads_v1
FOR EACH ROW EXECUTE FUNCTION prevent_analytics_log_export_fact_mutation_132();
CREATE TRIGGER analytics_log_export_downloads_no_truncate_697
BEFORE TRUNCATE ON analytics_log_export_downloads_v1
FOR EACH STATEMENT EXECUTE FUNCTION prevent_analytics_log_export_fact_mutation_132();

INSERT INTO analytics_log_export_downloads_v1(id,export_id,actor_user_id,downloaded_at)
SELECT event.id,request.id,event.actor_user_id,event.occurred_at
FROM (
    SELECT id,actor_user_id,resource_id,occurred_at FROM audit_events
    WHERE action='analytics_log.export.download' AND resource_type='analytics_log_export' AND result='success'
    UNION
    SELECT id,actor_user_id,resource_id,occurred_at FROM audit_event_archive
    WHERE action='analytics_log.export.download' AND resource_type='analytics_log_export' AND result='success'
) event
JOIN analytics_log_exports_v1 request ON request.id::text=event.resource_id
JOIN users downloader ON downloader.id=event.actor_user_id
ON CONFLICT (id) DO NOTHING;

GRANT SELECT, INSERT ON analytics_log_export_downloads_v1 TO cdnca_control_app, cdnca_control_runtime;
