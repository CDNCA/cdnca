LOCK TABLE schema_migrations, security_system_rule_visibility, security_system_rule_tenant_states IN ACCESS EXCLUSIVE MODE;

DO $migration_282_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 282 OR
       (SELECT max(version) FROM schema_migrations) <> 282 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=282 AND
        migration_id='282_security_rule_catalog_consumer' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 282 down requires the exact verified migration head' USING ERRCODE='P2820';
    END IF;
    -- System rules can be re-fetched from the license service; local admin
    -- visibility and tenant enable choices cannot.
    IF EXISTS (SELECT 1 FROM security_system_rule_visibility) OR
       EXISTS (SELECT 1 FROM security_system_rule_tenant_states) THEN
        RAISE EXCEPTION 'migration 282 down refuses to discard local security rule choices' USING ERRCODE='P2823';
    END IF;
END;
$migration_282_down$;

DROP TABLE security_rule_catalog_ack_outbox;
DROP TABLE security_system_rule_tenant_states;
DROP TABLE security_system_rule_visibility;
DROP TABLE security_system_rules;
DROP FUNCTION protect_security_system_rules_282();
DROP TABLE security_rule_catalog_consumer_state;
