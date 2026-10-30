LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_323_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 322 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 322 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=322 AND
        migration_id='322_domain_ownership_permanent' AND
        checksum_sha256='0a36f436bacd8c9121c8eb0351f95cd13dbbf2bddcecf229d3f21b5954f23bcd' AND
        down_checksum_sha256='09c30b909370ec31691e6fc968902cf70793390838279dacca58dbe5dddcaca3' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='notification_event_policies' AND column_name IN ('default_email', 'default_sms')
       ) OR EXISTS (SELECT 1 FROM notification_event_policies WHERE event_type LIKE 'ticket.staff.%') THEN
        RAISE EXCEPTION 'migration 323 requires the exact verified 322 release head' USING ERRCODE='P3230';
    END IF;
END;
$migration_323_up$;

-- Subscription defaults per event (r136 G6 #9 follow-up). A member without a
-- notification_subscriptions row for an event is treated as subscribed to
-- exactly these channels; any explicit choice is stored as a row and wins.
-- Nothing is written per user.
ALTER TABLE notification_event_policies
    ADD COLUMN default_email boolean NOT NULL DEFAULT false,
    ADD COLUMN default_sms boolean NOT NULL DEFAULT false;

UPDATE notification_event_policies SET default_email = true WHERE event_type IN (
    'package.auto_renew.failed', 'package.monitor.traffic.triggered', 'package.monitor.expiration.triggered',
    'ticket.created', 'ticket.replied', 'ticket.status_changed');

-- Operator side of the ticket system: platform members holding
-- tickets.manage hear about new tickets and customer replies.
INSERT INTO notification_event_policies(event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours,
    supported, default_email, default_sms, updated_at)
VALUES
    ('ticket.staff.created', true, true, true, 1, 24, true, true, false, now()),
    ('ticket.staff.replied', true, true, true, 1, 24, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('ticket_staff_created', 1, 'email', '新工单 #{{.ticket_no}}',
     '用户 {{.username}} 提交了工单 #{{.ticket_no}}「{{.subject}}」，请登录控制台处理。',
     ARRAY['ticket_no','subject','username'], '2026-10-17 00:00:00+00'),
    ('ticket_staff_created', 1, 'sms', '',
     '新工单#{{.ticket_no}}待处理，请登录控制台查看。', ARRAY['ticket_no'], '2026-10-17 00:00:00+00'),
    ('ticket_staff_replied', 1, 'email', '工单 #{{.ticket_no}} 用户回复',
     '用户 {{.username}} 回复了工单 #{{.ticket_no}}「{{.subject}}」，请登录控制台处理。',
     ARRAY['ticket_no','subject','username'], '2026-10-17 00:00:00+00'),
    ('ticket_staff_replied', 1, 'sms', '',
     '工单#{{.ticket_no}}有用户回复，请登录控制台查看。', ARRAY['ticket_no'], '2026-10-17 00:00:00+00');
