-- 491（r136 tp-b6b：原占位 490，merge-p2 合入时接在 490_aggregated_edge_alert_access_point 之后）。
LOCK TABLE schema_migrations, audit_events, audit_event_archive IN ACCESS EXCLUSIVE MODE;

DO $migration_491_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 490 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 490 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=490 AND
        migration_id='490_aggregated_edge_alert_access_point' AND
        checksum_sha256='309e8d8dcea2473d3be5c88448c7fbb8f3b7f1e7b08750db41142a7e7966b48d' AND
        down_checksum_sha256='12ed9a7ef6d47a8214dcbd8d286266a06670d4262ce44ab18b058cac8484a6eb' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure(current_schema() || '.guard_audit_event_archive_insert_361()') IS NULL OR
       to_regprocedure(current_schema() || '.guard_audit_event_archive_insert_491()') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 491 requires the exact verified 490 release head' USING ERRCODE='P4910';
    END IF;
END;
$migration_491_up$;

-- 操作日志「浏览器UA」：audit.Append 从请求上下文取 User-Agent（去控制字符、截断 512 字节）写入。
-- 后台任务和此前的行为空串，页面显示「—」。非空时进入 v2 事件哈希（canonical 里 omitempty），
-- 空串行的哈希字节不变，所以已有行和 392 的 SQL 哈希函数都无需改动。
ALTER TABLE audit_events
    ADD COLUMN user_agent text NOT NULL DEFAULT '',
    ADD CONSTRAINT audit_events_user_agent_491 CHECK (char_length(user_agent) <= 512 AND
        user_agent !~ '[[:cntrl:]]' AND user_agent = btrim(user_agent));

ALTER TABLE audit_event_archive ADD COLUMN user_agent text NOT NULL DEFAULT '';

-- 归档行仍须是原行的逐列副本，现在包括 user_agent。
CREATE FUNCTION guard_audit_event_archive_insert_491()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF current_user <> 'cdnca_retention_cleanup' OR NOT EXISTS (
        SELECT 1 FROM audit_events source WHERE source.id = NEW.id AND source.scope_id = NEW.scope_id
          AND source.stream_position = NEW.stream_position
          AND source.actor_user_id IS NOT DISTINCT FROM NEW.actor_user_id
          AND source.action = NEW.action AND source.resource_type = NEW.resource_type
          AND source.resource_id = NEW.resource_id AND source.request_id = NEW.request_id
          AND source.result = NEW.result AND source.payload = NEW.payload
          AND source.previous_hash IS NOT DISTINCT FROM NEW.previous_hash
          AND source.event_hash = NEW.event_hash AND source.occurred_at = NEW.occurred_at
          AND source.category = NEW.category AND source.actor_kind = NEW.actor_kind
          AND source.actor_ref = NEW.actor_ref AND source.source_ip = NEW.source_ip
          AND source.reason_code = NEW.reason_code AND source.changes = NEW.changes
          AND source.user_agent = NEW.user_agent
    ) THEN
        RAISE EXCEPTION 'audit archive accepts only exact copies from the cleanup role' USING ERRCODE='P3612';
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION guard_audit_event_archive_insert_491() FROM PUBLIC;

DROP TRIGGER audit_event_archive_insert_361 ON audit_event_archive;
CREATE TRIGGER audit_event_archive_insert_491 BEFORE INSERT ON audit_event_archive
    FOR EACH ROW EXECUTE FUNCTION guard_audit_event_archive_insert_491();
