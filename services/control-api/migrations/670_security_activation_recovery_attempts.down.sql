-- 670 回退：删除恢复回滚尝试/放弃记录与 security_activation.recovery_failed 通知。已写入的恢复回滚不受影响；
-- 回退后恢复回滚重新按旧规则（失败即重建、不限次数）处理。已有该通知的发送记录时拒绝回退。
LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_670_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 670 OR
       (SELECT max(version) FROM schema_migrations) <> 670 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=670 AND
        migration_id='670_security_activation_recovery_attempts' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 670 down requires the exact verified migration head' USING ERRCODE='P6701';
    END IF;
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id='security_activation.recovery_failed.zh-cn') THEN
        RAISE EXCEPTION 'migration 670 rollback would orphan security activation recovery notifications' USING ERRCODE='P6702';
    END IF;
END;
$migration_670_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE version = 1 AND template_id='security_activation.recovery_failed.zh-cn';
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type='security_activation.recovery_failed';
DELETE FROM notification_event_policies WHERE event_type='security_activation.recovery_failed';
DELETE FROM admin_inbox_messages WHERE event_type='security_activation.recovery_failed';

DROP TABLE security_activation_recovery_failures_670;
DROP TABLE security_activation_recovery_attempts_670;
