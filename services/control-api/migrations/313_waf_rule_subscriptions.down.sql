LOCK TABLE schema_migrations, waf_rule_subscriptions IN ACCESS EXCLUSIVE MODE;

DO $migration_313_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 313 OR
       (SELECT max(version) FROM schema_migrations) <> 313 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=313 AND
        migration_id='313_waf_rule_subscriptions' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 313 down requires the exact verified migration head' USING ERRCODE='P3131';
    END IF;
    -- Tenant copies ("@system/<id>" policies) reference these libraries; the
    -- operator deletes the libraries and tenants unsubscribe first.
    IF EXISTS (SELECT 1 FROM waf_rule_subscriptions) THEN
        RAISE EXCEPTION 'migration 313 rollback would discard WAF rule subscriptions' USING ERRCODE='P3131';
    END IF;
END;
$migration_313_down$;

DROP TABLE waf_rule_subscriptions;
