-- 546 回滚：去掉站内信开关、超时提醒列与 ticket.staff.overdue 事件。
-- 成员已关掉的站内信选择（inbox_enabled=false）和已发出的超时提醒都是用户/运营可见的事实，
-- 回滚会悄悄丢掉它们，此时拒绝回滚。
LOCK TABLE schema_migrations, notification_subscriptions, notification_event_policies, notification_templates, tickets,
    notification_events IN ACCESS EXCLUSIVE MODE;

DO $migration_546_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 546 OR
       (SELECT max(version) FROM schema_migrations) <> 546 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=546 AND
        migration_id='546_ticket_notification_choices' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 546 down requires the exact verified migration head' USING ERRCODE='P5461';
    END IF;
    IF EXISTS (SELECT 1 FROM notification_subscriptions WHERE NOT inbox_enabled) OR
       EXISTS (SELECT 1 FROM notification_events WHERE event_type='ticket.staff.overdue') THEN
        RAISE EXCEPTION 'migration 546 rollback would discard ticket notification choices or overdue reminders'
            USING ERRCODE='P5462';
    END IF;
END;
$migration_546_down$;

DELETE FROM notification_subscriptions WHERE event_type='ticket.staff.overdue';
DELETE FROM notification_event_policies WHERE event_type='ticket.staff.overdue';
ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id='ticket_staff_overdue';
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DROP INDEX tickets_sla_pending_546_idx;
ALTER TABLE tickets DROP COLUMN sla_reminded_at;
ALTER TABLE notification_subscriptions DROP COLUMN inbox_enabled;
