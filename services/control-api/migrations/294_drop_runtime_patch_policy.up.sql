-- 删除“安全补丁灰度”（runtime patch policy）功能（用户 2026-10-16 拍板）。
-- 156 建的候选/回执/头三张表与函数只被已删除的 runtimepatchpolicy 包使用，默认未启用、
-- 生产为空表；157 只校验 156 的账本行（不碰这些表），156 原样保留，down 重建空结构。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_294_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 293 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 293 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=293 AND
        migration_id='293_l4_tls_passthrough' AND
        checksum_sha256='e9cf0e5df8011f95991400d9f777b577b9c02916880cf2f46fb214926e7cdfd4' AND
        down_checksum_sha256='fda860fd118b23e521776fca729882ebf959b4fb6b5b825a2288b91ad34b271c' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=156 AND
        migration_id='156_runtime_patch_policy' AND
        checksum_sha256='34cc982875f728e86af11479e9f49a5326a1fff85fe2d6b91efe4c0b84448788' AND
        down_checksum_sha256='a29ada54fad54860ca7da7f200bd99cd95132e91e4015d5ebfaf5835f215d495' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR
       to_regclass(current_schema() || '.runtime_patch_policy_candidates_156') IS NULL OR
       to_regclass(current_schema() || '.runtime_patch_policy_receipts_156') IS NULL OR
       to_regclass(current_schema() || '.runtime_patch_policy_heads_156') IS NULL THEN
        RAISE EXCEPTION 'migration 294 requires the exact verified 293 release head with the 156 runtime patch policy' USING ERRCODE='P2940';
    END IF;
END;
$migration_294_up$;

DROP TRIGGER runtime_patch_policy_head_truncate_156 ON runtime_patch_policy_heads_156;
DROP TRIGGER runtime_patch_policy_receipt_truncate_156 ON runtime_patch_policy_receipts_156;
DROP TRIGGER runtime_patch_policy_candidate_truncate_156 ON runtime_patch_policy_candidates_156;
DROP TRIGGER runtime_patch_policy_head_guard_156 ON runtime_patch_policy_heads_156;
DROP TRIGGER runtime_patch_policy_receipt_guard_156 ON runtime_patch_policy_receipts_156;
DROP TRIGGER runtime_patch_policy_candidate_guard_156 ON runtime_patch_policy_candidates_156;
DROP FUNCTION commit_runtime_patch_policy_156(text,text,text,text,bigint,boolean,bigint,bytea,bytea,bytea,bigint,text,text,bigint,text,bytea,bytea,bigint,bytea,bigint,bytea,bytea,bytea,bytea,bytea,bytea,bytea);
DROP FUNCTION append_runtime_patch_policy_receipt_156(text,text,text,text,text,bytea,bytea);
DROP FUNCTION prevent_runtime_patch_policy_truncate_156();
DROP FUNCTION guard_runtime_patch_policy_head_156();
DROP FUNCTION guard_runtime_patch_policy_receipt_156();
DROP FUNCTION guard_runtime_patch_policy_candidate_156();
DROP TABLE runtime_patch_policy_heads_156;
DROP TABLE runtime_patch_policy_receipts_156;
DROP TABLE runtime_patch_policy_candidates_156;
