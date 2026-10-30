LOCK TABLE schema_migrations,cname_allocation_targets,cname_allocation_intents,cname_allocations,
    cname_site_bindings,cname_hostname_claims,sites,dns_zones,background_jobs,
    package_subscriptions IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) <> 126 OR EXISTS (SELECT 1 FROM cname_allocation_intents) OR EXISTS (
        SELECT 1 FROM cname_allocation_targets
        WHERE child_task_id IS NOT NULL OR allocation_revision > 0
    ) THEN
        RAISE EXCEPTION 'migration 126 rollback would discard durable CNAME target facts' USING ERRCODE='P1266';
    END IF;
END;
$$;

DROP TRIGGER cname_allocation_targets_no_truncate_126 ON cname_allocation_targets;
DROP TRIGGER cname_allocation_targets_protect_126 ON cname_allocation_targets;
DROP TRIGGER cname_allocation_intents_no_truncate_126 ON cname_allocation_intents;
DROP TRIGGER cname_allocation_intents_no_delete_126 ON cname_allocation_intents;
CREATE OR REPLACE FUNCTION validate_sites_cname_authority_113()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    binding_row cname_site_bindings%ROWTYPE;
    allocation_row cname_allocations%ROWTYPE;
    claim_row cname_hostname_claims%ROWTYPE;
    lkg_allocation_row cname_allocations%ROWTYPE;
    lkg_claim_row cname_hostname_claims%ROWTYPE;
    zone_default boolean;
BEGIN
    IF NEW.cname_mode IS NULL THEN RETURN NULL; END IF;
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
            RAISE EXCEPTION 'site CNAME without an LKG allocation must keep an empty legacy projection' USING ERRCODE='P1134';
        END IF;
    ELSE
        SELECT * INTO lkg_allocation_row FROM cname_allocations WHERE tenant_scope_id=NEW.scope_id AND id=binding_row.lkg_allocation_id;
        SELECT * INTO lkg_claim_row FROM cname_hostname_claims WHERE id=lkg_allocation_row.lkg_claim_id AND allocation_id=lkg_allocation_row.id;
        IF lkg_allocation_row.id IS NULL OR lkg_claim_row.id IS NULL OR
           lkg_allocation_row.owner_user_id IS DISTINCT FROM NEW.owner_user_id OR
           lkg_allocation_row.lkg_revision IS DISTINCT FROM NEW.cname_lkg_revision OR
           lkg_claim_row.hostname IS DISTINCT FROM NEW.cname THEN
            RAISE EXCEPTION 'site CNAME LKG projection does not match its bound durable claim' USING ERRCODE='P1134';
        END IF;
    END IF;
    RETURN NULL;
END;
$$;
DROP TABLE cname_allocation_intents;
DROP FUNCTION protect_cname_allocation_intent_126();
DROP FUNCTION protect_cname_allocation_target_126();
DROP TABLE cname_allocation_targets;
ALTER TABLE dns_zones DROP CONSTRAINT dns_zones_scope_id_126_key;
ALTER TABLE package_subscriptions DROP CONSTRAINT package_subscriptions_scope_id_126_key;
