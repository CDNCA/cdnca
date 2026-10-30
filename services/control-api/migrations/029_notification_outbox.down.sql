DROP TRIGGER IF EXISTS notification_outbox_payload_immutable ON notification_outbox;
DROP FUNCTION IF EXISTS protect_notification_outbox_payload();

DROP TRIGGER IF EXISTS notification_outbox_truncate_immutable ON notification_outbox;
DROP TRIGGER IF EXISTS notification_outbox_delete_immutable ON notification_outbox;

DROP TRIGGER IF EXISTS notification_attempt_transition_guard ON notification_attempts;
DROP FUNCTION IF EXISTS protect_notification_attempt_transition();

DROP TRIGGER IF EXISTS notification_events_immutable ON notification_events;
DROP TRIGGER IF EXISTS notification_events_truncate_immutable ON notification_events;
DROP TRIGGER IF EXISTS notification_templates_immutable ON notification_templates;
DROP TRIGGER IF EXISTS notification_templates_truncate_immutable ON notification_templates;
DROP FUNCTION IF EXISTS prevent_notification_immutable_mutation();

DROP TABLE IF EXISTS notification_attempts;
DROP TABLE IF EXISTS notification_outbox;
DROP TABLE IF EXISTS notification_events;
DROP TABLE IF EXISTS notification_subscriptions;
DROP TABLE IF EXISTS notification_channel_settings;
DROP TABLE IF EXISTS notification_templates;
