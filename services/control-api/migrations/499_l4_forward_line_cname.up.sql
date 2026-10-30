-- 499（r136 stream-be2，主会话 10-25 08:3x 方案 B「竞品按转发设置，先复刻」；merge-p5 由 491 改号 499，前驱 498）。
-- 四层转发自有 CNAME 域名 / CNAME 生成模式 / 区域 / 线路分组 / 备用线路组：NULL = 继承所属网站，网站也没有再继承套餐快照。
LOCK TABLE schema_migrations, l4_forwards IN ACCESS EXCLUSIVE MODE;

DO $migration_499_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 498 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 498 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=498 AND
        migration_id='498_tenant_order_records_read_only' AND
        checksum_sha256='f3259e3d415e764573a2997e8be3033fc6ca478adf293112ddf112c6065dd8cc' AND
        down_checksum_sha256='c545c1473f21d48e7548e6015259abdc8648298c115a0edb9c771f34c76f74a6' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='l4_forwards' AND column_name IN ('cname_domain', 'cname_mode', 'region_id', 'node_group_id', 'backup_node_group_id')
       ) THEN
        RAISE EXCEPTION 'migration 499 requires the exact verified 498 head' USING ERRCODE='P4990';
    END IF;
END;
$migration_499_up$;

-- 线路组可属本租户或平台（与 sites.node_group_id 相同，无外键），写入时由服务端校验存活与归属。
ALTER TABLE l4_forwards
    ADD COLUMN cname_domain text,
    ADD COLUMN cname_mode text,
    ADD COLUMN region_id uuid REFERENCES region_catalog(id) ON DELETE RESTRICT,
    ADD COLUMN node_group_id uuid,
    ADD COLUMN backup_node_group_id uuid,
    ADD CONSTRAINT l4_forwards_line_cname_499 CHECK (
        (cname_domain IS NULL OR (cname_domain = lower(btrim(cname_domain)) AND octet_length(cname_domain) BETWEEN 1 AND 253 AND
            cname_domain ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$')) AND
        (cname_mode IS NULL OR cname_mode IN ('site', 'package')) AND
        (backup_node_group_id IS NULL OR backup_node_group_id IS DISTINCT FROM node_group_id) AND
        (site_id IS NOT NULL OR (cname_domain IS NULL AND cname_mode IS NULL AND region_id IS NULL AND
            node_group_id IS NULL AND backup_node_group_id IS NULL))
    );
CREATE INDEX l4_forwards_node_group_499_idx ON l4_forwards (node_group_id) WHERE deleted_at IS NULL AND node_group_id IS NOT NULL;
CREATE INDEX l4_forwards_backup_node_group_499_idx ON l4_forwards (backup_node_group_id)
    WHERE deleted_at IS NULL AND backup_node_group_id IS NOT NULL;
