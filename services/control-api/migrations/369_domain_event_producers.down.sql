LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_369_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 369 OR
       (SELECT max(version) FROM schema_migrations) <> 369 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=369 AND migration_id='369_domain_event_producers' AND
        integrity_state='verified'
       ) THEN
        RAISE EXCEPTION 'migration 369 down requires the verified 369 head' USING ERRCODE='P3699';
    END IF;
    IF EXISTS (SELECT 1 FROM domain_event_outbox_368 WHERE event_type IN (
        'io.cdnca.certificate.v1.status_changed','io.cdnca.node.v1.status_changed',
        'io.cdnca.usage.v1.threshold_reached','io.cdnca.security.v1.incident_detected')) OR
       EXISTS (SELECT 1 FROM plugin_webhook_subscriptions WHERE event_types && ARRAY[
        'io.cdnca.certificate.v1.status_changed','io.cdnca.node.v1.status_changed',
        'io.cdnca.usage.v1.threshold_reached','io.cdnca.security.v1.incident_detected']::text[]) THEN
        RAISE EXCEPTION 'migration 369 down would discard domain event history' USING ERRCODE='P3699';
    END IF;
END;
$migration_369_down$;

LOCK TABLE certificate_orders, node_presence, nodes, package_monitor_transition_facts,
    package_cycle_enforcement_transitions, cc_auto_switch_notification_windows,
    plugin_webhook_event_contracts_122, domain_event_types_368, domain_event_contract_fields_368
    IN ACCESS EXCLUSIVE MODE;

DROP TRIGGER cc_auto_switch_windows_emit_incident_event_369 ON cc_auto_switch_notification_windows;
DROP TRIGGER package_cycle_enforcement_emit_usage_event_369 ON package_cycle_enforcement_transitions;
DROP TRIGGER package_monitor_transition_facts_emit_usage_event_369 ON package_monitor_transition_facts;
DROP TRIGGER nodes_emit_admin_event_369 ON nodes;
DROP TRIGGER node_presence_emit_status_event_369 ON node_presence;
DROP TRIGGER certificate_orders_emit_status_event_369 ON certificate_orders;
DROP FUNCTION emit_cc_incident_event_369();
DROP FUNCTION emit_usage_enforcement_event_369();
DROP FUNCTION emit_usage_monitor_event_369();
DROP FUNCTION emit_node_admin_event_369();
DROP FUNCTION emit_node_presence_event_369();
DROP FUNCTION append_node_status_events_369(uuid, text, text, text, bigint, timestamptz);
DROP FUNCTION emit_certificate_status_event_369();
DROP FUNCTION domain_event_timestamp_369(timestamptz);

ALTER TABLE plugin_webhook_event_contracts_122 DISABLE TRIGGER plugin_webhook_event_contracts_protect_122;
UPDATE plugin_webhook_event_contracts_122 SET status='reserved'
WHERE event_type IN ('io.cdnca.certificate.v1.status_changed','io.cdnca.node.v1.status_changed',
                     'io.cdnca.usage.v1.threshold_reached','io.cdnca.security.v1.incident_detected');
ALTER TABLE plugin_webhook_event_contracts_122 ENABLE TRIGGER plugin_webhook_event_contracts_protect_122;

ALTER TABLE domain_event_contract_fields_368 DISABLE TRIGGER domain_event_contract_fields_protect_368;
DELETE FROM domain_event_contract_fields_368 WHERE event_type IN (
    'io.cdnca.certificate.v1.status_changed','io.cdnca.node.v1.status_changed',
    'io.cdnca.usage.v1.threshold_reached','io.cdnca.security.v1.incident_detected');
ALTER TABLE domain_event_contract_fields_368 ENABLE TRIGGER domain_event_contract_fields_protect_368;
ALTER TABLE domain_event_types_368 DISABLE TRIGGER domain_event_types_protect_368;
DELETE FROM domain_event_types_368 WHERE event_type IN (
    'io.cdnca.certificate.v1.status_changed','io.cdnca.node.v1.status_changed',
    'io.cdnca.usage.v1.threshold_reached','io.cdnca.security.v1.incident_detected');
ALTER TABLE domain_event_types_368 ENABLE TRIGGER domain_event_types_protect_368;
