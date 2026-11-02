-- 617 回退：去掉 SSH 安装任务的“额外允许的地址”列（之后装完开启限制只放行主控出口地址，与 617 之前一致）。
LOCK TABLE schema_migrations, node_ssh_install_jobs IN ACCESS EXCLUSIVE MODE;

DO $migration_617_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 617 OR
       (SELECT max(version) FROM schema_migrations) <> 617 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=617 AND
        migration_id='617_node_ssh_install_allow_cidrs' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 617 down requires the exact verified migration head' USING ERRCODE='P6171';
    END IF;
END;
$migration_617_down$;

ALTER TABLE node_ssh_install_jobs DROP COLUMN restrict_ssh_allow_cidrs;
