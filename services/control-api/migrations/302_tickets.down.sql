LOCK TABLE schema_migrations, permissions, roles, role_permissions, notification_templates,
    notification_event_policies, tickets, ticket_messages, ticket_attachments, ticket_write_requests
    IN ACCESS EXCLUSIVE MODE;

DO $migration_302_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 302 OR
       (SELECT max(version) FROM schema_migrations) <> 302 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=302 AND
        migration_id='302_tickets' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 302 down requires the exact verified migration head' USING ERRCODE='P3021';
    END IF;
    -- Customer conversations and their notifications must not be dropped silently.
    IF EXISTS (SELECT 1 FROM tickets) OR EXISTS (SELECT 1 FROM ticket_attachments) OR
       EXISTS (SELECT 1 FROM notification_events WHERE event_type LIKE 'ticket.%') THEN
        RAISE EXCEPTION 'migration 302 rollback would discard support tickets or their notifications'
            USING ERRCODE='P3021';
    END IF;
END;
$migration_302_down$;

DELETE FROM notification_subscriptions WHERE event_type IN ('ticket.created', 'ticket.replied', 'ticket.status_changed');
DELETE FROM notification_event_policies WHERE event_type IN ('ticket.created', 'ticket.replied', 'ticket.status_changed');
-- Templates are immutable at runtime; no outbox row can reference them here
-- (the guard above refused any ticket notification event).
ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id IN ('ticket_created', 'ticket_replied', 'ticket_status_changed');
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;

DROP TABLE ticket_write_requests;
DROP TABLE ticket_attachments;
DROP TABLE ticket_messages;
DROP TABLE tickets;

DELETE FROM role_permissions WHERE permission_name IN ('tickets.read', 'tickets.manage');
DELETE FROM permissions WHERE name IN ('tickets.read', 'tickets.manage');
