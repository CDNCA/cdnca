-- 529（r136 p1-ticket-receipt；派单占位 530，分支本地写 529 以满足连号加载器，合入时按集成头改号，P529x 随号改）。
LOCK TABLE schema_migrations, installation_ban_node_state IN ACCESS EXCLUSIVE MODE;

DO $migration_529_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 528 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 528 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=528 AND
        migration_id='528_region_catalog_code' AND
        checksum_sha256='2b51c14bcf7f303c6303ef14b954d503a4b03fcf6511558fd6f45fd0dd097dc6' AND
        down_checksum_sha256='7442ec629e3bb4afa88ac2e21375346db73003bac453d20462fa0ce41027345d' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.installation_ban_node_state') IS NULL OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='installation_ban_node_state' AND
        column_name IN ('applied_revision', 'failure_class', 'failed_attempts', 'next_retry_at')) THEN
        RAISE EXCEPTION 'migration 529 requires the exact verified 528 release head' USING ERRCODE='P5290';
    END IF;
END;
$migration_529_up$;

-- 节点回执拆成"已送达"与"已应用"（Codex 10-26 全站审测 P1）：
--   revision         = 节点最后回答的修订（已送达）；
--   applied_revision = 节点最后应用成功的修订（已应用），只有 applied=true 才推进；
--   failure_class    = 最后回答未应用时的分级：retryable（持久化/执行失败等，同修订按退避重投）、
--                      permanent（文档本身被拒，只等新修订）；应用成功为空串；
--   failed_attempts  = 同一修订连续失败次数（退避翻倍用，封顶在 Go 侧）；
--   next_retry_at    = retryable 时下次重投时间。
-- 已有行：applied=true 的视为已应用该修订；applied=false 的按可重试处理并立即重投（旧代码把它们当成已报告，
-- 这正是要修的缺陷）。1.0.35 全新安装通常没有存量行。
ALTER TABLE installation_ban_node_state
    ADD COLUMN applied_revision bigint NOT NULL DEFAULT 0,
    ADD COLUMN failure_class text NOT NULL DEFAULT '',
    ADD COLUMN failed_attempts integer NOT NULL DEFAULT 0,
    ADD COLUMN next_retry_at timestamptz;

UPDATE installation_ban_node_state SET
    applied_revision = CASE WHEN applied THEN revision ELSE 0 END,
    failure_class = CASE WHEN applied THEN '' ELSE 'retryable' END,
    failed_attempts = CASE WHEN applied THEN 0 ELSE 1 END,
    next_retry_at = CASE WHEN applied THEN NULL ELSE updated_at END;

ALTER TABLE installation_ban_node_state
    ADD CONSTRAINT installation_ban_node_state_delivery_529_check CHECK (
        applied_revision >= 0 AND applied_revision <= revision AND failed_attempts >= 0 AND
        failure_class IN ('', 'retryable', 'permanent') AND
        (applied = (failure_class = '')) AND
        (applied = (applied_revision = revision)) AND
        ((failure_class = '') = (failed_attempts = 0)) AND
        ((failure_class = 'retryable') = (next_retry_at IS NOT NULL)) AND
        (next_retry_at IS NULL OR isfinite(next_retry_at)));
