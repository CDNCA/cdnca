-- 645（插件本机停用不再填原因；前驱 644_plugin_local_disables）：删除 plugin_local_disables.reason。
-- 原因只写进这一列和审计日志，租户与页面都不显示；停用人与时间仍在本表与审计日志里。
-- 只删这一列，不改其他表与数据。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_645_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 644 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 644 OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=644 AND migration_id='644_plugin_local_disables'
       ) OR NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='plugin_local_disables' AND column_name='reason'
       ) THEN
        RAISE EXCEPTION 'migration 645 requires the exact verified 644 release head' USING ERRCODE='P6450';
    END IF;
END;
$migration_645_up$;

ALTER TABLE plugin_local_disables DROP COLUMN reason;
