-- 502（r136 fp-sec SEC-ACCOUNT-07，主会话 10-25：补带资源 ID 的站内事件消息）。merge-p5 由 499 改号 502，
-- 守卫指 501（常量集中在 notification_event_subjects_502_contract_test.go）。
-- notification_events 记下事件发生时的网站/用户套餐 ID：只在入队时写入（表本身不可改），不设外键，
-- 资源删除后消息仍保留原事实；本人消息查询按 (scope_id, recipient_user_id, created_at) 分页。
LOCK TABLE schema_migrations, notification_events IN ACCESS EXCLUSIVE MODE;

DO $migration_502_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 501 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 501 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=501 AND
        migration_id='501_node_line_endpoint_published_per_carrier' AND
        checksum_sha256='b3d177340a3e14288a119c60fb405cc768b6c0cdd7aaa34ba6c6acb47e9bb671' AND
        down_checksum_sha256='f26c8f2b5b8001034e034b18fd71b3d078d7ecbfb23bb4517acadd061fbbe68e' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='notification_events' AND column_name IN ('subject_site_id', 'subject_package_id')
       ) THEN
        RAISE EXCEPTION 'migration 502 requires the exact verified 501 release head' USING ERRCODE='P5020';
    END IF;
END;
$migration_502_up$;

ALTER TABLE notification_events
    ADD COLUMN subject_site_id uuid,
    ADD COLUMN subject_package_id uuid,
    ADD CONSTRAINT notification_events_subjects_member_502 CHECK (
        recipient_kind = 'member' OR (subject_site_id IS NULL AND subject_package_id IS NULL)
    );

CREATE INDEX notification_events_recipient_created_502
    ON notification_events (scope_id, recipient_user_id, created_at DESC, id DESC)
    WHERE recipient_kind = 'member';
