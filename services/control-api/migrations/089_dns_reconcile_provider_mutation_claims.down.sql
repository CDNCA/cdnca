LOCK TABLE schema_migrations,
    dns_reconcile_provider_recovery_continuations,
    dns_reconcile_provider_recovery_failures,
    dns_reconcile_provider_recovery_leases,
    dns_reconcile_provider_mutation_claims,
    dns_reconcile_operations,
    dns_reconcile_tasks,
    background_jobs,
    background_job_items,
    sites,
    dns_zones,
    dns_providers
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 89 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 89 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state <> 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=89 AND migration_id='089_dns_reconcile_provider_mutation_claims'
          AND integrity_state='verified'
    ) THEN
        RAISE EXCEPTION 'migration 089 rollback requires the verified 089 head'
            USING ERRCODE = 'P8900';
    END IF;
    IF EXISTS (SELECT 1 FROM dns_reconcile_provider_mutation_claims) OR
       EXISTS (SELECT 1 FROM dns_reconcile_provider_recovery_continuations) OR
       EXISTS (SELECT 1 FROM dns_reconcile_provider_recovery_failures) OR
       EXISTS (SELECT 1 FROM dns_reconcile_provider_recovery_leases) THEN
        RAISE EXCEPTION 'migration 089 rollback would discard DNS provider mutation claim facts'
            USING ERRCODE = 'P8901';
    END IF;
END;
$$;

DROP TRIGGER background_jobs_protected ON background_jobs;
DROP TRIGGER a_dns_reconcile_background_jobs_recovery_validated_089 ON background_jobs;
CREATE TRIGGER background_jobs_protected
BEFORE UPDATE ON background_jobs
FOR EACH ROW EXECUTE FUNCTION protect_background_job();

DROP TRIGGER background_job_items_protected ON background_job_items;
DROP TRIGGER a_dns_reconcile_background_job_items_recovery_validated_089 ON background_job_items;
CREATE TRIGGER background_job_items_protected
BEFORE UPDATE ON background_job_items
FOR EACH ROW EXECUTE FUNCTION protect_background_job_item();

ALTER TABLE background_job_items DROP CONSTRAINT background_job_items_check;
ALTER TABLE background_job_items ADD CONSTRAINT background_job_items_check CHECK (
    (state='pending' AND sequence=0 AND error_code IS NULL AND completed_at IS NULL) OR
    (state='succeeded' AND attempt>0 AND sequence>0 AND error_code IS NULL AND completed_at IS NOT NULL) OR
    (state='failed' AND attempt>0 AND error_code IS NOT NULL AND completed_at IS NOT NULL) OR
    (state='cancelled' AND error_code='cancelled' AND completed_at IS NOT NULL)
);

DROP FUNCTION validate_dns_reconcile_background_job_item_recovery_retry_089();
DROP FUNCTION validate_dns_reconcile_background_job_recovery_retry_089();
DROP FUNCTION dns_reconcile_background_job_item_recovery_retry_089(background_job_items,background_job_items);
DROP FUNCTION dns_reconcile_background_job_recovery_retry_089(background_jobs,background_jobs);
DROP TRIGGER dns_reconcile_provider_recovery_continuations_consumed_089
    ON dns_reconcile_provider_recovery_continuations;
DROP FUNCTION validate_dns_reconcile_provider_recovery_continuation_089();
DROP TRIGGER dns_reconcile_provider_recovery_continuations_validate_089
    ON dns_reconcile_provider_recovery_continuations;
DROP TRIGGER dns_reconcile_provider_recovery_continuations_protect_089
    ON dns_reconcile_provider_recovery_continuations;
DROP FUNCTION protect_dns_reconcile_provider_recovery_continuation_089();
DROP TABLE dns_reconcile_provider_recovery_continuations;
DROP TRIGGER dns_reconcile_provider_recovery_failures_validate_089
    ON dns_reconcile_provider_recovery_failures;
DROP TRIGGER dns_reconcile_provider_recovery_failures_protect_089
    ON dns_reconcile_provider_recovery_failures;
DROP FUNCTION protect_dns_reconcile_provider_recovery_failure_089();
DROP TABLE dns_reconcile_provider_recovery_failures;
DROP TRIGGER dns_reconcile_provider_recovery_leases_validate_089
    ON dns_reconcile_provider_recovery_leases;
DROP TRIGGER dns_reconcile_provider_recovery_leases_protect_089
    ON dns_reconcile_provider_recovery_leases;
DROP FUNCTION protect_dns_reconcile_provider_recovery_lease_089();
DROP TABLE dns_reconcile_provider_recovery_leases;
DROP TRIGGER dns_providers_provider_mutation_claim_guard_089 ON dns_providers;
DROP FUNCTION block_dns_provider_claimed_authority_mutation_089();
DROP TRIGGER dns_zones_provider_mutation_claim_guard_089 ON dns_zones;
DROP FUNCTION block_dns_zone_claimed_authority_mutation_089();
DROP TRIGGER sites_provider_mutation_claim_guard_089 ON sites;
DROP FUNCTION block_dns_site_claimed_authority_mutation_089();
DROP TRIGGER dns_reconcile_provider_mutation_claims_success_cas_089
    ON dns_reconcile_provider_mutation_claims;
DROP FUNCTION validate_dns_reconcile_provider_mutation_success_089();
DROP TRIGGER dns_reconcile_provider_mutation_claims_validate_089 ON dns_reconcile_provider_mutation_claims;
DROP TRIGGER dns_reconcile_provider_mutation_claims_protect_089 ON dns_reconcile_provider_mutation_claims;
DROP FUNCTION protect_dns_reconcile_provider_mutation_claim_089();
DROP TABLE dns_reconcile_provider_mutation_claims;
DROP TRIGGER dns_reconcile_tasks_bind_site_089 ON dns_reconcile_tasks;
DROP FUNCTION bind_dns_reconcile_task_site_089();
ALTER TABLE dns_reconcile_tasks
    DROP COLUMN provider_mutation_site_config_digest,
    DROP COLUMN provider_mutation_site_revision;
DROP FUNCTION dns_reconcile_authority_digest_089(uuid,sites,dns_zones,dns_providers);
DROP FUNCTION dns_reconcile_provider_config_digest_089(dns_zones,dns_providers);
DROP FUNCTION dns_reconcile_site_config_digest_089(sites);
DROP FUNCTION dns_reconcile_credential_digest_089(text,bytea);
DROP FUNCTION dns_reconcile_operation_digest_089(jsonb);
