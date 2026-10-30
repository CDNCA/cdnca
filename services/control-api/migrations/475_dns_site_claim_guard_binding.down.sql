LOCK TABLE schema_migrations, sites IN ACCESS EXCLUSIVE MODE;

DO $migration_475_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 475 OR
       (SELECT max(version) FROM schema_migrations) <> 475 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=475 AND
        migration_id='475_dns_site_claim_guard_binding' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 475 down requires the exact verified migration head' USING ERRCODE='P4751';
    END IF;
END;
$migration_475_down$;

-- Back to 474: only the IPv6 observation columns and updated_at pass.
DROP TRIGGER sites_provider_mutation_claim_guard_089 ON sites;
CREATE TRIGGER sites_provider_mutation_claim_guard_089
BEFORE UPDATE OR DELETE ON sites
FOR EACH ROW EXECUTE FUNCTION block_dns_site_claimed_authority_mutation_474();
DROP FUNCTION block_dns_site_claimed_authority_mutation_475();
