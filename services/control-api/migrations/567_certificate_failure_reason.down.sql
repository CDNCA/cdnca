-- 567 回滚：去掉 CA 原因文本列（分类码不受影响）。
LOCK TABLE schema_migrations, certificate_orders, dns_acme_outbox IN ACCESS EXCLUSIVE MODE;

DO $migration_567_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 567 OR
       (SELECT max(version) FROM schema_migrations) <> 567 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=567 AND
        migration_id='567_certificate_failure_reason' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 567 down requires the exact verified migration head' USING ERRCODE='P5671';
    END IF;
END;
$migration_567_down$;

ALTER TABLE dns_acme_outbox DROP COLUMN last_error_reason;
ALTER TABLE certificate_orders DROP COLUMN failure_reason;
