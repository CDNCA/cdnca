LOCK TABLE schema_migrations, sites IN ACCESS EXCLUSIVE MODE;

DO $migration_475_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 474 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 474 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=474 AND
        migration_id='474_site_claim_guard_runtime_observation' AND
        checksum_sha256='2ea02118cbf180d14424e57b201a8c76dc16c5908bc8f498874056cda402fb5c' AND
        down_checksum_sha256='a9c1f44b863a6358876eca432fb44c8f4fd2f5cefea559124cd4a7b8b4c13058' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgrelid='sites'::regclass AND
        tgname='sites_provider_mutation_claim_guard_089' AND NOT tgisinternal AND
        tgfoid='block_dns_site_claimed_authority_mutation_474()'::regprocedure
       ) THEN
        RAISE EXCEPTION 'migration 475 requires the exact verified 474 release head' USING ERRCODE='P4750';
    END IF;
END;
$migration_475_up$;

-- r136 n7n8 (N8): an active DNS provider mutation claim (089) pins the site's
-- revision and dns_reconcile_site_config_digest_089 (the claim's binding);
-- every claim transition re-checks both. 474 (n9) let only the IPv6
-- observation columns and updated_at through; other runtime projections that
-- touch neither part of the binding (cname_state, ...) still failed with
-- P8903 while a claim was held. The guard now blocks exactly what would break
-- the binding: a delete, a revision change (every site write advances it) or
-- a change of a digest column. Writes that leave the binding intact go
-- through. The trigger keeps 089's name (474 recreated it under that name).
CREATE FUNCTION block_dns_site_claimed_authority_mutation_475()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF (TG_OP='DELETE' OR NEW.revision IS DISTINCT FROM OLD.revision OR
        dns_reconcile_site_config_digest_089(NEW) IS DISTINCT FROM dns_reconcile_site_config_digest_089(OLD)) AND
       EXISTS (
        SELECT 1 FROM dns_reconcile_provider_mutation_claims claim
        WHERE claim.site_id=OLD.id AND claim.state IN ('claimed','uncertain')
    ) THEN
        RAISE EXCEPTION 'active DNS provider mutation claim blocks site authority mutation'
            USING ERRCODE = 'P8903';
    END IF;
    IF TG_OP='DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER sites_provider_mutation_claim_guard_089 ON sites;
CREATE TRIGGER sites_provider_mutation_claim_guard_089
BEFORE UPDATE OR DELETE ON sites
FOR EACH ROW EXECUTE FUNCTION block_dns_site_claimed_authority_mutation_475();
