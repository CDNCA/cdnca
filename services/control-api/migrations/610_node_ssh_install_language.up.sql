-- 610（r136 node-cmd-lang2，主会话分配 control 610，前驱 609_smart_schedule）：SSH 安装命令带界面语言。
--   node_ssh_install_jobs.language：创建任务时操作者的界面语言（'' / 'zh' / 'en'）。worker 构造 install-node.sh
--   命令时按列附 --lang zh / --lang en（Ubuntu 默认 LANG=C.UTF-8 且无终端时安装器默认英文）；
--   旧行与未带语言的请求为空，命令不附 --lang（与 610 之前逐字节一致）。
LOCK TABLE schema_migrations, node_ssh_install_jobs IN ACCESS EXCLUSIVE MODE;

DO $migration_610_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 609 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 609 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=609 AND
        migration_id='609_smart_schedule' AND
        checksum_sha256='084932cdb4c795fc264bc7945353073e78ad51457dd4204f6bbca5b9cf66bc5f' AND
        down_checksum_sha256='e17b463e2ebcfe8f6a6ca39836c8d4f51bf26dbbe5cad1e9b4fa2096effc95e7' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND
        table_name = 'node_ssh_install_jobs' AND column_name = 'language'
       ) THEN
        RAISE EXCEPTION 'migration 610 requires the exact verified 609 release head' USING ERRCODE='P6100';
    END IF;
END;
$migration_610_up$;

ALTER TABLE node_ssh_install_jobs ADD COLUMN language text NOT NULL DEFAULT ''
    CONSTRAINT node_ssh_install_jobs_language_610_check CHECK (language IN ('', 'zh', 'en'));
