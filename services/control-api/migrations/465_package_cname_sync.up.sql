LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_465_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 464 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 464 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=464 AND
        migration_id='464_impersonation_direct_switch' AND
        checksum_sha256='b2fd775b5f606d395686a7ecea5f38b5520205710b21507d1f893070dcdeffea' AND
        down_checksum_sha256='03cf9db5368de7102fd1dbd57b0f1bce93bf3bd9fd119622559b6e6c200f9411' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 465 requires the exact verified 464 release head' USING ERRCODE='P4650';
    END IF;
END;
$migration_465_up$;

-- 465（r136 cname-retry3，占位号：合入时改 465，前驱守卫改指合入时的上一号）。
-- 修改套餐的 CNAME（域名/主机名/模式）后，把新值同步到该套餐所有已售订阅的快照，
-- 再让订阅下的站点重新生成 CNAME。平台套餐级任务没有租户，不能放 background_jobs
-- （tenant_id NOT NULL），所以用自有表：
--   package_cname_sync_jobs：每个 (product_id, product_revision) 只有一个任务（幂等）；
--     记下保存人的会话，worker 用它发平台 CNAME 意图（262 要求会话仍有效）；
--     会话失效时停在 failed/actor_session_ended，重试时换成重试人的新会话。
--   package_cname_sync_items：逐订阅结果，(job_id, subscription_id) 唯一，重跑不重复处理。
CREATE TABLE package_cname_sync_jobs (
    id uuid PRIMARY KEY,
    product_id uuid NOT NULL REFERENCES package_products(id) ON DELETE RESTRICT,
    product_revision bigint NOT NULL CHECK (product_revision > 1),
    from_cname jsonb NOT NULL CHECK (jsonb_typeof(from_cname) = 'object'),
    to_cname jsonb NOT NULL CHECK (jsonb_typeof(to_cname) = 'object'),
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_session_id uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE RESTRICT,
    state text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'succeeded', 'failed')),
    cursor_subscription_id uuid,
    synced_count bigint NOT NULL DEFAULT 0 CHECK (synced_count >= 0),
    site_count bigint NOT NULL DEFAULT 0 CHECK (site_count >= 0),
    skipped_count bigint NOT NULL DEFAULT 0 CHECK (skipped_count >= 0),
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    max_attempts integer NOT NULL DEFAULT 5 CHECK (max_attempts BETWEEN 1 AND 20),
    next_attempt_at timestamptz NOT NULL,
    last_error_code text CHECK (last_error_code IS NULL OR last_error_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (product_id, product_revision),
    FOREIGN KEY (product_id, product_revision)
        REFERENCES package_product_versions(product_id, revision) ON DELETE RESTRICT
);
CREATE INDEX package_cname_sync_jobs_due_idx
    ON package_cname_sync_jobs (next_attempt_at, id) WHERE state IN ('queued', 'running');

CREATE TABLE package_cname_sync_items (
    job_id uuid NOT NULL REFERENCES package_cname_sync_jobs(id) ON DELETE CASCADE,
    subscription_id uuid NOT NULL REFERENCES package_subscriptions(id) ON DELETE RESTRICT,
    outcome text NOT NULL CHECK (outcome IN ('synced', 'skipped')),
    reason text CHECK (reason IN ('sold_override', 'future_entitlement', 'inactive')),
    site_count bigint NOT NULL DEFAULT 0 CHECK (site_count >= 0),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (job_id, subscription_id),
    CHECK ((outcome = 'synced' AND reason IS NULL) OR (outcome = 'skipped' AND reason IS NOT NULL AND site_count = 0))
);

GRANT SELECT, INSERT, UPDATE ON package_cname_sync_jobs TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT ON package_cname_sync_items TO cdnca_control_app, cdnca_control_runtime;
