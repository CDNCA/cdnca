LOCK TABLE schema_migrations, notification_event_policies, notification_templates, probe_dnspup_write_requests
    IN ACCESS EXCLUSIVE MODE;

DO $migration_462_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 462 OR
       (SELECT max(version) FROM schema_migrations) <> 462 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=462 AND
        migration_id='462_node_dnspup_probe' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 462 down requires the exact verified migration head' USING ERRCODE='P4621';
    END IF;
    -- Queued or sent messages reference the templates: refuse instead of
    -- orphaning them.
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id IN ('node.dnspup.unreachable.zh-cn',
        'node.dnspup.recovered.zh-cn', 'probe.dnspup.balance_low.zh-cn', 'probe.dnspup.balance_exhausted.zh-cn')) THEN
        RAISE EXCEPTION 'migration 462 rollback would orphan dnspup node probe notifications' USING ERRCODE='P4622';
    END IF;
END;
$migration_462_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE version = 1 AND template_id IN ('node.dnspup.unreachable.zh-cn',
    'node.dnspup.recovered.zh-cn', 'probe.dnspup.balance_low.zh-cn', 'probe.dnspup.balance_exhausted.zh-cn');
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type IN ('node.dnspup.unreachable', 'node.dnspup.recovered',
    'probe.dnspup.balance_low', 'probe.dnspup.balance_exhausted');
DELETE FROM notification_event_policies WHERE event_type IN ('node.dnspup.unreachable', 'node.dnspup.recovered',
    'probe.dnspup.balance_low', 'probe.dnspup.balance_exhausted');
DELETE FROM admin_inbox_messages WHERE event_type IN ('node.dnspup.unreachable', 'node.dnspup.recovered',
    'probe.dnspup.balance_low', 'probe.dnspup.balance_exhausted');

DELETE FROM probe_dnspup_write_requests WHERE operation = 'node_settings';
ALTER TABLE probe_dnspup_write_requests DROP CONSTRAINT probe_dnspup_write_requests_operation_462_ck,
    ADD CONSTRAINT probe_dnspup_write_requests_operation_check CHECK (operation IN ('settings', 'test'));

DROP TABLE node_dnspup_probe_states;
DROP TABLE node_dnspup_probe_results;
DROP TABLE node_dnspup_probe_settings;
