LOCK TABLE schema_migrations, node_certificate_events, notification_event_policies, notification_templates
    IN ACCESS EXCLUSIVE MODE;

DO $migration_434_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 434 OR
       (SELECT max(version) FROM schema_migrations) <> 434 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=434 AND
        migration_id='434_node_certificate_recovery' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 434 down requires the exact verified migration head' USING ERRCODE='P4341';
    END IF;
    -- Recovered certificates are immutable facts: refuse rather than drop them.
    IF EXISTS (SELECT 1 FROM node_certificate_recoveries) OR
       EXISTS (SELECT 1 FROM node_certificate_events WHERE event_type = 'recovered') OR
       EXISTS (SELECT 1 FROM notification_outbox WHERE template_id = 'node.certificate.recovered.zh-cn') THEN
        RAISE EXCEPTION 'migration 434 rollback would drop recovered node certificate facts' USING ERRCODE='P4342';
    END IF;
END;
$migration_434_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id = 'node.certificate.recovered.zh-cn' AND version = 1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type = 'node.certificate.recovered';
DELETE FROM notification_event_policies WHERE event_type = 'node.certificate.recovered';

ALTER TABLE node_certificate_events DROP CONSTRAINT node_certificate_events_check,
    DROP CONSTRAINT node_certificate_events_event_type_check,
    ADD CONSTRAINT node_certificate_events_event_type_check
        CHECK (event_type IN ('issued', 'renewed', 'revoked')),
    ADD CONSTRAINT node_certificate_events_check CHECK (
        (event_type = 'issued' AND related_certificate_id IS NULL AND reason IS NULL) OR
        (event_type = 'renewed' AND related_certificate_id IS NOT NULL AND reason IS NULL) OR
        (event_type = 'revoked' AND related_certificate_id IS NULL AND reason IS NOT NULL AND
         reason = btrim(reason) AND char_length(reason) BETWEEN 1 AND 256)
    );

DROP TABLE node_certificate_recoveries;
DROP FUNCTION prevent_node_certificate_recovery_mutation_434();
