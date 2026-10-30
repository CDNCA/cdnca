LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_371_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 371 OR
       (SELECT max(version) FROM schema_migrations) <> 371 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=371 AND migration_id='371_certificate_expiry_events' AND
        integrity_state='verified'
       ) THEN
        RAISE EXCEPTION 'migration 371 down requires the verified 371 head' USING ERRCODE='P3719';
    END IF;
    IF EXISTS (SELECT 1 FROM certificate_expiry_facts_371) OR
       EXISTS (SELECT 1 FROM domain_event_outbox_368 WHERE event_type='io.cdnca.certificate.v1.expiry_reached') OR
       EXISTS (SELECT 1 FROM plugin_webhook_subscriptions
               WHERE event_types && ARRAY['io.cdnca.certificate.v1.expiry_reached']::text[]) THEN
        RAISE EXCEPTION 'migration 371 down would discard domain event history' USING ERRCODE='P3719';
    END IF;
    IF EXISTS (SELECT 1 FROM notification_outbox
               WHERE template_id IN ('certificate.expiring.zh-cn','certificate.expired.zh-cn')) OR
       EXISTS (SELECT 1 FROM notification_events WHERE event_type IN ('certificate.expiring','certificate.expired')) THEN
        RAISE EXCEPTION 'migration 371 down would discard certificate notification history' USING ERRCODE='P3719';
    END IF;
END;
$migration_371_down$;

LOCK TABLE certificate_asset_versions, plugin_webhook_event_contracts_122, domain_event_types_368,
    domain_event_contract_fields_368, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id IN ('certificate.expiring.zh-cn','certificate.expired.zh-cn');
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type IN ('certificate.expiring','certificate.expired');
UPDATE notification_event_policies
SET supported=false, enabled=false, sms_enabled=false, email_enabled=false, default_email=false, updated_at=now()
WHERE event_type IN ('certificate.expiring','certificate.expired');

DROP INDEX certificate_asset_versions_not_after_371;
DROP TABLE certificate_expiry_facts_371;
DROP FUNCTION emit_certificate_expiry_event_371();
DROP FUNCTION protect_certificate_expiry_fact_371();

ALTER TABLE domain_event_contract_fields_368 DISABLE TRIGGER domain_event_contract_fields_protect_368;
DELETE FROM domain_event_contract_fields_368 WHERE event_type='io.cdnca.certificate.v1.expiry_reached';
ALTER TABLE domain_event_contract_fields_368 ENABLE TRIGGER domain_event_contract_fields_protect_368;
ALTER TABLE domain_event_types_368 DISABLE TRIGGER domain_event_types_protect_368;
DELETE FROM domain_event_types_368 WHERE event_type='io.cdnca.certificate.v1.expiry_reached';
ALTER TABLE domain_event_types_368 ENABLE TRIGGER domain_event_types_protect_368;
ALTER TABLE plugin_webhook_event_contracts_122 DISABLE TRIGGER plugin_webhook_event_contracts_protect_122;
DELETE FROM plugin_webhook_event_contracts_122 WHERE event_type='io.cdnca.certificate.v1.expiry_reached';
ALTER TABLE plugin_webhook_event_contracts_122 ENABLE TRIGGER plugin_webhook_event_contracts_protect_122;
