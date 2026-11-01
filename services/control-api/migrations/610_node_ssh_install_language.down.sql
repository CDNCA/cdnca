-- 610 回退：去掉 SSH 安装任务的界面语言列（之后的命令不再附 --lang，与 610 之前一致）。
LOCK TABLE schema_migrations, node_ssh_install_jobs IN ACCESS EXCLUSIVE MODE;

DO $migration_610_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 610 OR
       (SELECT max(version) FROM schema_migrations) <> 610 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=610 AND
        migration_id='610_node_ssh_install_language' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 610 down requires the exact verified migration head' USING ERRCODE='P6101';
    END IF;
END;
$migration_610_down$;

ALTER TABLE node_ssh_install_jobs DROP COLUMN language;
