LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE sites IN SHARE ROW EXCLUSIVE MODE;

DO $migration_474_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 473 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 473 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=473 AND
        migration_id='473_dns_zone_provider_apex' AND
        checksum_sha256='f8ba83c2aa3d8a7ba315e9d3b6724ef30eff5251999b1e210150af969d1b3ba3' AND
        down_checksum_sha256='b12755c42899557bb44072b6d486f981aaf3120e0c6ba77386f51fd08a7415f1' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgrelid='sites'::regclass AND
        tgname='sites_provider_mutation_claim_guard_089' AND
        tgfoid='block_dns_site_claimed_authority_mutation_089()'::regprocedure AND NOT tgisinternal
       ) OR to_regprocedure('block_dns_site_claimed_authority_mutation_474()') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 474 requires the exact verified 473 release head and 089''s sites claim guard'
            USING ERRCODE='P4740';
    END IF;
END;
$migration_474_up$;

-- r136 n9: ipv6_runtime_state / ipv6_runtime_source_revision (and updated_at)
-- are what the nodes reported; edgedeployment/site_ipv6_projection.go writes
-- them inside the deployment status projection when a rollout ends. They are
-- not site authority (not in dns_reconcile_site_config_digest_089; 335 already
-- treats them as observation). 089's guard refused them too, so while a DNS
-- provider mutation claim stayed claimed/uncertain the last healthy status of
-- every rollout touching the site rolled back and was redelivered forever:
-- the node held a persisted gateway receipt, control never stored healthy.
-- An update that changes nothing but these columns now passes; any other
-- column change and delete are still refused (P8903).
CREATE FUNCTION block_dns_site_claimed_authority_mutation_474()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF (TG_OP='DELETE' OR
        to_jsonb(NEW) - ARRAY['ipv6_runtime_state','ipv6_runtime_source_revision','updated_at'] IS DISTINCT FROM
        to_jsonb(OLD) - ARRAY['ipv6_runtime_state','ipv6_runtime_source_revision','updated_at']) AND EXISTS (
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
FOR EACH ROW EXECUTE FUNCTION block_dns_site_claimed_authority_mutation_474();
