LOCK TABLE schema_migrations,sites,cname_allocation_intents IN ACCESS EXCLUSIVE MODE;

DO $migration_479_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 479 OR
       (SELECT max(version) FROM schema_migrations) <> 479 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=479 AND
        migration_id='479_cname_cancelled_intent_fails_site' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 479 down requires the exact verified migration head' USING ERRCODE='P4791';
    END IF;
END;
$migration_479_down$;

-- Restores the 412 intent check (queued/running/failed). Sites already failed
-- on a cancelled intent are not revalidated (the site trigger is per write).

CREATE OR REPLACE FUNCTION validate_sites_cname_authority_113()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
	intent_match record;
    binding_row cname_site_bindings%ROWTYPE;
    allocation_row cname_allocations%ROWTYPE;
    claim_row cname_hostname_claims%ROWTYPE;
    lkg_allocation_row cname_allocations%ROWTYPE;
    lkg_claim_row cname_hostname_claims%ROWTYPE;
    zone_default boolean;
BEGIN
    IF NEW.cname_mode IS NULL THEN RETURN NULL; END IF;
	SELECT intent.*,job.state AS intent_job_state INTO intent_match FROM cname_allocation_intents intent
    JOIN background_jobs job ON job.tenant_id=intent.tenant_id AND job.id=intent.job_id
    WHERE intent.tenant_scope_id=NEW.scope_id AND intent.site_id=NEW.id
      AND intent.package_subscription_id=NEW.package_subscription_id
      AND intent.mode=NEW.cname_mode AND intent.domain=NEW.cname_domain
      AND intent.hostname=NEW.cname_hostname2 AND intent.job_id=NEW.cname_task_id
      AND job.kind='dns.cname.intent'
      AND job.state IN ('queued','running','failed') ORDER BY intent.created_at DESC LIMIT 1;
    IF intent_match.job_id IS NOT NULL THEN
			IF ((intent_match.intent_job_state IN ('queued','running') AND NEW.cname_state<>'pending') OR
			    (intent_match.intent_job_state='failed' AND NEW.cname_state<>'failed')) OR NEW.cname_current_revision IS NULL OR
           (TG_OP='INSERT' AND (NEW.cname<>'' OR NEW.cname_lkg_revision IS NOT NULL)) OR
           (TG_OP='UPDATE' AND (NEW.cname IS DISTINCT FROM OLD.cname OR
                                NEW.cname_lkg_revision IS DISTINCT FROM OLD.cname_lkg_revision)) THEN
            RAISE EXCEPTION 'site CNAME intent projection is invalid' USING ERRCODE='P1264';
        END IF;
        RETURN NULL;
    END IF;
    SELECT * INTO binding_row FROM cname_site_bindings WHERE tenant_scope_id=NEW.scope_id AND site_id=NEW.id;
    SELECT * INTO allocation_row FROM cname_allocations WHERE tenant_scope_id=NEW.scope_id AND id=binding_row.current_allocation_id;
    SELECT * INTO claim_row FROM cname_hostname_claims WHERE id=allocation_row.current_claim_id AND allocation_id=allocation_row.id;
    SELECT is_default INTO zone_default FROM dns_zones WHERE scope_id=claim_row.tenant_scope_id AND id=claim_row.zone_id;
    IF binding_row.site_id IS NULL OR allocation_row.id IS NULL OR claim_row.id IS NULL OR
       allocation_row.mode IS DISTINCT FROM NEW.cname_mode OR allocation_row.state IS DISTINCT FROM NEW.cname_state OR
       allocation_row.job_id IS DISTINCT FROM NEW.cname_task_id OR
       allocation_row.current_revision IS DISTINCT FROM NEW.cname_current_revision OR
       (NEW.cname_domain<>'' AND NEW.cname_domain IS DISTINCT FROM claim_row.domain) OR
       (NEW.cname_domain='' AND zone_default IS DISTINCT FROM true) OR
       (NEW.cname_hostname2='' AND claim_row.explicit_hostname) OR
       (NEW.cname_hostname2<>'' AND (NOT claim_row.explicit_hostname OR NEW.cname_hostname2 IS DISTINCT FROM claim_row.hostname)) THEN
        RAISE EXCEPTION 'site CNAME projection does not match durable allocation authority' USING ERRCODE='P1134';
    END IF;
    IF binding_row.lkg_allocation_id IS NULL THEN
        IF NEW.cname_lkg_revision IS NOT NULL OR NEW.cname<>'' THEN
            RAISE EXCEPTION 'site CNAME without LKG allocation is invalid' USING ERRCODE='P1134';
        END IF;
    ELSE
        SELECT * INTO lkg_allocation_row FROM cname_allocations WHERE tenant_scope_id=NEW.scope_id AND id=binding_row.lkg_allocation_id;
        SELECT * INTO lkg_claim_row FROM cname_hostname_claims WHERE id=lkg_allocation_row.lkg_claim_id AND allocation_id=lkg_allocation_row.id;
        IF lkg_allocation_row.id IS NULL OR lkg_claim_row.id IS NULL OR
           lkg_allocation_row.owner_user_id IS DISTINCT FROM NEW.owner_user_id OR
           lkg_allocation_row.lkg_revision IS DISTINCT FROM NEW.cname_lkg_revision OR
           lkg_claim_row.hostname IS DISTINCT FROM NEW.cname THEN
            RAISE EXCEPTION 'site CNAME LKG projection does not match durable claim' USING ERRCODE='P1134';
        END IF;
    END IF;
    RETURN NULL;
END;
$$;
