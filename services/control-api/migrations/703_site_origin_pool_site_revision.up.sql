-- 703（前驱 702_edge_publication_serving_nodes）。
-- 源池自己的版本：site_revision 记下源池最近一次变更（建站、改源站、基本信息里改源站）写成的网站修订号。
-- 计费桥客户区改源站只替换主源站：客户读到的网站修订号不小于它、且不大于当前修订号，就说明源池在客户读到之后没变过；
-- 之后只有 CNAME 投影、发布等不碰源池的写入推高了网站修订号时不再 409（乐观并发仍在，源池真被别人改过照样 409）。
-- NULL：本迁移之前的源池（或测试夹具直接插入的行），不知道源池何时变过，改源站仍要求修订号与当前完全一致；下一次源池写入后补上。
-- 只加可空列，不回填：回填会经 site_origin_pools 触发器推高每个范围的边缘配置修订号。错误码：头检查与 down 头检查 P7030。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_703_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 702 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 702 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=702 AND
        migration_id='702_edge_publication_serving_nodes' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='site_origin_pools' AND column_name='site_revision'
       ) THEN
        RAISE EXCEPTION 'migration 703 requires the exact verified 702 release head' USING ERRCODE='P7030';
    END IF;
END;
$migration_703_up$;

ALTER TABLE site_origin_pools ADD COLUMN site_revision bigint
    CONSTRAINT site_origin_pools_site_revision_703 CHECK (site_revision IS NULL OR site_revision >= 1);
