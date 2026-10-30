LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE sites IN SHARE ROW EXCLUSIVE MODE;

DO $migration_474_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 474 OR
       (SELECT max(version) FROM schema_migrations) <> 474 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=474 AND
        migration_id='474_site_claim_guard_runtime_observation' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 474 down requires the exact verified migration head' USING ERRCODE='P4741';
    END IF;
END;
$migration_474_down$;

DROP TRIGGER sites_provider_mutation_claim_guard_089 ON sites;
CREATE TRIGGER sites_provider_mutation_claim_guard_089
BEFORE UPDATE OR DELETE ON sites
FOR EACH ROW EXECUTE FUNCTION block_dns_site_claimed_authority_mutation_089();

DROP FUNCTION block_dns_site_claimed_authority_mutation_474();
