-- 617（r136 fix-sshpanel，前驱 615_billing_adjustment_mfa_waiver，合入时按连号改号）：
--   SSH 安装勾选“仅允许主控 SSH”时可带“额外允许的地址”。主控出口地址未配置也未能自动取得时，
--   这些地址即作为放行地址（节点应用后 5 分钟内未获主控确认仍会自行撤销，不会锁死）。
--   node_ssh_install_jobs.restrict_ssh_allow_cidrs：创建任务时的规范 CIDR 列表，装完开启限制时写入
--   node_ssh_access.allow_cidrs；旧行与未带地址的任务为空数组（与 617 之前一致）。
LOCK TABLE schema_migrations, node_ssh_install_jobs IN ACCESS EXCLUSIVE MODE;

DO $migration_617_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 616 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 616 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=616 AND
        migration_id='616_node_purge_fk_restore' AND
        checksum_sha256='6a59064a53c49344c14bd137f9c4b21599d70c42c997192fdae5cbdc6b43c46f' AND
        down_checksum_sha256='b33468073011b084431f8a45475c0a1cd4a92e5c03770d416d95f044b5fb8f40' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND
        table_name = 'node_ssh_install_jobs' AND column_name = 'restrict_ssh_allow_cidrs'
       ) THEN
        RAISE EXCEPTION 'migration 617 requires the exact verified 616 release head' USING ERRCODE='P6170';
    END IF;
END;
$migration_617_up$;

ALTER TABLE node_ssh_install_jobs ADD COLUMN restrict_ssh_allow_cidrs text[] NOT NULL DEFAULT '{}'
    CONSTRAINT node_ssh_install_jobs_allow_cidrs_617_check CHECK (cardinality(restrict_ssh_allow_cidrs) <= 64);
