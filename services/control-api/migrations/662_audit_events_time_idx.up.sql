-- 662：日志中心/操作审计列表（auditlog.Store.List）按 occurred_at DESC, id DESC 取前 N 行，
-- 管理员不带 scope 过滤时 audit_events 没有以这两列开头的索引，200 万行下并行顺扫 + 宽行外部归并排序落盘，约 480~600ms。
-- 补全局 (occurred_at DESC, id DESC) 索引，让该查询走索引顺序取前 N 行。
-- 锁影响：迁移加载器（internal/database/migrate.go:114）把每个迁移包在事务里执行，事务内不能用
-- CREATE INDEX CONCURRENTLY，仓库也没有非事务迁移的先例，所以这里是普通 CREATE INDEX。
-- 建索引期间 audit_events 被 ACCESS EXCLUSIVE 锁住（下面的 LOCK TABLE，也挡读）：所有审计写入
-- （几乎每个写接口都会 Append）和审计读取排队等待，时长约等于全表扫描排序的时间。
-- 耗时未实测，按行数增长；生产行数大时应在升级窗口内执行，不要在业务高峰热升级。
LOCK TABLE schema_migrations, audit_events IN ACCESS EXCLUSIVE MODE;

DO $migration_662_up$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) <> 661 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT count(*) FROM schema_migrations) <> 661 OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.audit_events_time_id_662') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 662 requires the exact verified 661 release head' USING ERRCODE='P6620';
    END IF;
END;
$migration_662_up$;

CREATE INDEX audit_events_time_id_662 ON audit_events (occurred_at DESC, id DESC);
