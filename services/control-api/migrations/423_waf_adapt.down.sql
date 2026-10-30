LOCK TABLE schema_migrations, autodefense_report_receipts, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_423_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 423 OR
       (SELECT max(version) FROM schema_migrations) <> 423 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=423 AND
        migration_id='423_waf_adapt' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 423 down requires the exact verified migration head' USING ERRCODE='P4231';
    END IF;
    -- Templates referenced by queued or delivered notices cannot be dropped.
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id LIKE 'security.waf.auto\_exclusion\_%') OR
       EXISTS (SELECT 1 FROM notification_events WHERE event_type LIKE 'security.waf.auto\_exclusion\_%') THEN
        RAISE EXCEPTION 'migration 423 rollback would discard WAF auto exclusion notification history' USING ERRCODE='P4232';
    END IF;
END;
$migration_423_down$;

-- waf_evidence receipts would violate the restored kind check; they are
-- idempotency rows only (the report stream keeps one day).
DELETE FROM autodefense_report_receipts WHERE kind='waf_evidence';
ALTER TABLE autodefense_report_receipts DROP CONSTRAINT autodefense_report_receipts_kind_check;
ALTER TABLE autodefense_report_receipts ADD CONSTRAINT autodefense_report_receipts_kind_check
    CHECK (kind IN ('minute', 'state', 'candidate', 'verdicts', 'adjust', 'node_event', 'drift'));
-- Automatic exclusions are re-learned from the next reports; manual ones are lost.
DROP TABLE waf_adapt_typed_params;
DROP TABLE waf_adapt_evidence;
DROP TABLE waf_adapt_exclusions;
DROP TABLE waf_adapt_sites;
ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id IN ('security.waf.auto_exclusion_active.zh-cn',
    'security.waf.auto_exclusion_revoked.zh-cn', 'security.waf.auto_exclusion_expired.zh-cn');
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type IN ('security.waf.auto_exclusion_active',
    'security.waf.auto_exclusion_revoked', 'security.waf.auto_exclusion_expired');
DELETE FROM notification_event_policies WHERE event_type IN ('security.waf.auto_exclusion_active',
    'security.waf.auto_exclusion_revoked', 'security.waf.auto_exclusion_expired');
