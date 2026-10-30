LOCK TABLE schema_migrations, rule_pack_artifacts, waf_rule_subscription_packs IN ACCESS EXCLUSIVE MODE;

DO $migration_359_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 359 OR
       (SELECT max(version) FROM schema_migrations) <> 359 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=359 AND
        migration_id='359_waf_subscription_rule_packs' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 359 down requires the exact verified migration head' USING ERRCODE='P3591';
    END IF;
    -- 358 has neither subscriber packs nor subscription artifacts; tenants
    -- delete those packs on the rule pack page first.
    IF EXISTS (SELECT 1 FROM waf_rule_subscription_packs) OR
       EXISTS (SELECT 1 FROM rule_pack_artifacts WHERE source='subscription') THEN
        RAISE EXCEPTION 'migration 359 rollback would discard subscription rule packs' USING ERRCODE='P3591';
    END IF;
END;
$migration_359_down$;

DROP TABLE waf_rule_subscription_packs;
ALTER TABLE rule_pack_artifacts DROP CONSTRAINT rule_pack_artifacts_source_359;
ALTER TABLE rule_pack_artifacts ADD CONSTRAINT rule_pack_artifacts_source_check
    CHECK (source IN ('catalog', 'import', 'tenant'));
