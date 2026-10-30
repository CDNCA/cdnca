LOCK TABLE schema_migrations, cache_operation_node_attempts IN ACCESS EXCLUSIVE MODE;

DO $migration_526_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 525 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 525 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=525 AND
        migration_id='525_line_group_grants_grantor_history' AND
        checksum_sha256='dfb60716fa98ffc014c8d1c7888698eabbdb0727473b656658a7f7021fdcb446' AND
        down_checksum_sha256='0fc826cdab2782fcf7dea35508d3e084811a6ddc724afa262b7273ae96552ee0' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('cache_operation_cancel_deliveries') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 526 requires the exact verified 525 release head' USING ERRCODE='P5260';
    END IF;
END;
$migration_526_up$;

-- 526（r136 fz-x3，CACHE-ADD-07；主会话预留 527，本地按加载器连号写 526，合入改号）。
-- 取消缓存任务时，每个运行中的节点尝试一行：控制面通过节点缓存命令 subject
-- 下发 CacheControlCancel（outbox：published_at 为空即待发布），节点回执结算。
-- state：
--   pending     等待节点确认（已写 outbox，可能尚未发布）
--   cancelled   节点已停止任务，未执行的目标没有执行
--   completed   取消到达前节点已执行完
--   unresponsive 超过确认时限节点未回执（也包括节点没有该任务）
--   unsupported 节点版本未声明 CACHE_CONTROL_CANCEL，只停止后续调度，
--               已下发的任务在节点上会执行完
-- 任务终态仍是 cache_operations.state='cancelled'，这里只是节点确认投影。
CREATE TABLE cache_operation_cancel_deliveries (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    node_id uuid NOT NULL,
    attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 11),
    lease_id uuid NOT NULL,
    command_id uuid NOT NULL,
    state text NOT NULL CHECK (state IN ('pending', 'cancelled', 'completed', 'unresponsive', 'unsupported')),
    succeeded_targets integer CHECK (succeeded_targets IS NULL OR succeeded_targets BETWEEN 0 AND 1000),
    failed_targets integer CHECK (failed_targets IS NULL OR failed_targets BETWEEN 0 AND 1000),
    cancelled_targets integer CHECK (cancelled_targets IS NULL OR cancelled_targets BETWEEN 0 AND 1000),
    requested_at timestamptz NOT NULL,
    published_at timestamptz,
    deadline_at timestamptz NOT NULL,
    settled_at timestamptz,
    receipt_event_id uuid,
    UNIQUE (scope_id, operation_id, node_id, attempt),
    FOREIGN KEY (scope_id, operation_id, node_id, attempt)
        REFERENCES cache_operation_node_attempts(scope_id, operation_id, node_id, attempt) ON DELETE CASCADE,
    CHECK (deadline_at > requested_at),
    CHECK (
        (state = 'pending' AND settled_at IS NULL AND receipt_event_id IS NULL) OR
        (state = 'unsupported' AND published_at IS NULL AND settled_at IS NOT NULL AND receipt_event_id IS NULL) OR
        (state = 'unresponsive' AND settled_at IS NOT NULL AND receipt_event_id IS NULL) OR
        (state IN ('cancelled', 'completed') AND settled_at IS NOT NULL AND receipt_event_id IS NOT NULL AND
         succeeded_targets IS NOT NULL AND failed_targets IS NOT NULL AND cancelled_targets IS NOT NULL)
    )
);

-- The cache runtime publishes unsent pending rows and settles overdue ones.
CREATE INDEX cache_operation_cancel_deliveries_pending_idx
    ON cache_operation_cancel_deliveries (deadline_at, id) WHERE state = 'pending';
