-- 638（r136 contractfix，子任务按 637 占位，主调度合入时改号 638、前驱 637_market_exclusive_nodes）：
-- POST /v1/security-policies/batch 的批次级幂等。原来只有逐项幂等（每项的键由批次键派生），同一批次键换了
-- action 或 items 时，新项照常写入、旧项按项报 idempotency_conflict，接口没有 409。本表记下批次键对应的请求摘要
-- （action + 按序 items），同键异体在写任何一项之前就返回 409；同键同体：已完成的原样回放结果，
-- 未完成的（上次中途失败）继续执行，已写的项由逐项幂等回放。
-- 只新增一张表，不改已有表、不动数据、不新增权限码。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_638_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 637 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 637 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=637 AND
        migration_id='637_market_exclusive_nodes' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.security_policy_write_requests') IS NULL OR
          to_regclass(current_schema() || '.security_policy_batch_write_requests') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 638 requires the exact verified 637 release head' USING ERRCODE='P6380';
    END IF;
END;
$migration_638_up$;

CREATE TABLE security_policy_batch_write_requests (
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    PRIMARY KEY (actor_user_id, idempotency_key),
    CHECK ((completed_at IS NULL) = (response_body IS NULL))
);
