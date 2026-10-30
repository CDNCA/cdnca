LOCK TABLE schema_migrations, control_installation_entitlement IN ACCESS EXCLUSIVE MODE;

DO $migration_595_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 595 OR
       (SELECT max(version) FROM schema_migrations) <> 595 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=595 AND
        migration_id='595_entitlement_customer_display' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 595 down requires the exact verified migration head' USING ERRCODE='P5951';
    END IF;
END;
$migration_595_down$;

-- 只是展示缓存：下一次续期会重新带回。
ALTER TABLE control_installation_entitlement
    DROP CONSTRAINT control_installation_entitlement_customer_display_595_check,
    DROP COLUMN customer_display;
