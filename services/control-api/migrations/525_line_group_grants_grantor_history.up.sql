-- 525（r136 fz-x1 NODE-N05，派单预留 525）。
-- 线路组授出记录列表 GET /v1/escalate/line-groups/grants：按授出方作用域、含已撤销、按 (created_at, id) 倒序
-- 游标分页。460 只有 revoked_at IS NULL 的部分索引（按线路组），撤销历史与跨线路组列表用不上，补一条全量索引。
LOCK TABLE schema_migrations, node_line_group_grants IN ACCESS EXCLUSIVE MODE;

DO $migration_525_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 524 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 524 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=524 AND
        migration_id='524_market_feedback_notices' AND
        checksum_sha256='9b349165f9c0451316debe7b14810d7c303b1c09a3fe9fc0bfa8c6a33f248db9' AND
        down_checksum_sha256='5349fa91a141170663cc04b9c4a1b2f6db94e81c9dcf51838aee337f1c0d8ec0' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.node_line_group_grants') IS NULL OR
          to_regclass(current_schema() || '.node_line_group_grants_grantor_history_525_idx') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 525 requires the exact verified 524 release head' USING ERRCODE='P5250';
    END IF;
END;
$migration_525_up$;

CREATE INDEX node_line_group_grants_grantor_history_525_idx
    ON node_line_group_grants (grantor_scope_id, created_at DESC, id DESC);
