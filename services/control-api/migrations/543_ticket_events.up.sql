-- 543（fix-decide1027b 第6项，用户 10-27：工单状态变更显示系统行）：工单事件 ticket_events。
-- 记录状态 / 优先级 / 处理人变更与关闭、重新打开（含回复引起的状态变化与自动领取），
-- 详情气泡流里居中显示。处理人变更只给客服看。只增不改（运行时角色仅 SELECT、INSERT）。
-- 历史工单不回填。前驱 542（access_log_block_page），守卫钉 542 校验和。
LOCK TABLE schema_migrations, tickets IN ACCESS EXCLUSIVE MODE;

DO $migration_543_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 542 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 542 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=542 AND
        migration_id='542_access_log_block_page' AND
        checksum_sha256='3acb1781eacc91450e79e21296045efb54f2cc1377c78120834b5fd2c8d8af03' AND
        down_checksum_sha256='816e34d5183c3c779bc6b19f50b49b5b7a62f298f0183021a059f224adbfbebe' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('ticket_events') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 543 requires the exact verified 542 release head' USING ERRCODE='P5430';
    END IF;
END;
$migration_543_up$;

CREATE TABLE ticket_events (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    ticket_id uuid NOT NULL REFERENCES tickets(id) ON DELETE RESTRICT,
    kind text NOT NULL CHECK (kind IN ('status', 'priority', 'assignee', 'closed', 'reopened')),
    -- status / priority / closed / reopened：前后取值；assignee：前后处理人。
    from_value text,
    to_value text,
    from_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    to_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_kind text NOT NULL CHECK (actor_kind IN ('customer', 'staff')),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    CONSTRAINT ticket_events_values_543_check CHECK (CASE kind
        WHEN 'assignee' THEN from_value IS NULL AND to_value IS NULL AND from_user_id IS DISTINCT FROM to_user_id
        WHEN 'priority' THEN from_user_id IS NULL AND to_user_id IS NULL AND from_value <> to_value AND
            from_value IN ('low', 'normal', 'high', 'urgent') AND to_value IN ('low', 'normal', 'high', 'urgent')
        ELSE from_user_id IS NULL AND to_user_id IS NULL AND from_value <> to_value AND
            from_value IN ('open', 'processing', 'pending_customer', 'resolved', 'closed') AND
            to_value IN ('open', 'processing', 'pending_customer', 'resolved', 'closed') AND
            (kind <> 'closed' OR to_value = 'closed') AND
            (kind <> 'reopened' OR from_value IN ('resolved', 'closed'))
    END)
);
CREATE INDEX ticket_events_ticket_543_idx ON ticket_events (ticket_id, created_at, id);

REVOKE ALL ON ticket_events FROM PUBLIC;
GRANT SELECT, INSERT ON ticket_events TO cdnca_control_app, cdnca_control_runtime;
