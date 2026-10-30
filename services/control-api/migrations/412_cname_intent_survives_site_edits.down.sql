LOCK TABLE schema_migrations,sites,cname_allocation_intents,cname_platform_allocation_jobs IN ACCESS EXCLUSIVE MODE;

DO $migration_412_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 412 OR
       (SELECT max(version) FROM schema_migrations) <> 412 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=412 AND
        migration_id='412_cname_intent_survives_site_edits' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 412 down requires the exact verified migration head' USING ERRCODE='P4121';
    END IF;
END;
$migration_412_down$;

-- Restores the 126/262 whole-site-revision intent checks. Existing rows are
-- not revalidated (the site trigger is deferred per write).

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
      AND intent.expected_site_revision=NEW.revision AND job.kind='dns.cname.intent'
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

CREATE OR REPLACE FUNCTION validate_cname_platform_allocation_job_262() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM cname_allocation_intents intent
  JOIN cname_platform_intent_sessions authority ON authority.tenant_id=intent.tenant_id AND authority.job_id=intent.job_id
  JOIN auth_sessions session ON session.id=authority.actor_session_id AND session.scope_id=intent.actor_scope_id AND session.user_id=intent.actor_user_id
  JOIN cname_allocations allocation ON allocation.id=NEW.allocation_id AND allocation.tenant_id=intent.tenant_id AND allocation.tenant_scope_id=intent.tenant_scope_id
  JOIN cname_hostname_claims claim ON claim.id=allocation.current_claim_id
  JOIN sites site ON site.scope_id=intent.tenant_scope_id AND site.id=intent.site_id AND site.deleted_at IS NULL
  JOIN background_jobs job ON job.tenant_id=NEW.tenant_id AND job.id=NEW.job_id
  WHERE intent.tenant_id=NEW.tenant_id AND intent.job_id=NEW.intent_job_id
   AND intent.actor_scope_id<>intent.tenant_scope_id AND session.revoked_at IS NULL AND session.expires_at>clock_timestamp()
   AND intent.expected_site_revision=site.revision AND intent.mode=allocation.mode
   AND (allocation.site_owner_id=site.id OR allocation.package_subscription_id=site.package_subscription_id)
   AND (intent.domain='' OR lower(intent.domain)=lower(claim.domain))
   AND (intent.hostname='' OR lower(intent.hostname)=lower(claim.hostname))
   AND job.kind='dns.cname.allocation' AND job.request_id=intent.request_id
 ) THEN RAISE EXCEPTION 'CNAME target refresh authority rejected' USING ERRCODE='P2624'; END IF;
 RETURN NEW;
END;
$$;
