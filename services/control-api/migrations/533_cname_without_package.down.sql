LOCK TABLE schema_migrations, node_line_groups, cname_allocation_targets, cname_allocation_intents, sites
    IN ACCESS EXCLUSIVE MODE;

DO $migration_533_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 533 OR
       (SELECT max(version) FROM schema_migrations) <> 533 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=533 AND
        migration_id='533_cname_without_package' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 533 down requires the exact verified migration head' USING ERRCODE='P5331';
    END IF;
    -- 无套餐的意图/冻结目标是只追加事实，不能删也不能补套餐：拒绝回滚。
    IF EXISTS (SELECT 1 FROM cname_allocation_intents WHERE package_subscription_id IS NULL) OR
       EXISTS (SELECT 1 FROM cname_allocation_targets WHERE package_subscription_id IS NULL) THEN
        RAISE EXCEPTION 'migration 533 rollback would drop CNAME facts of sites without a package' USING ERRCODE='P5333';
    END IF;
END;
$migration_533_down$;

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
      AND job.state IN ('queued','running','failed','cancelled') ORDER BY intent.created_at DESC LIMIT 1;
    IF intent_match.job_id IS NOT NULL THEN
			IF ((intent_match.intent_job_state IN ('queued','running') AND NEW.cname_state<>'pending') OR
			    (intent_match.intent_job_state IN ('failed','cancelled') AND NEW.cname_state<>'failed')) OR NEW.cname_current_revision IS NULL OR
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

CREATE OR REPLACE FUNCTION protect_node_line_group()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'node line groups cannot be physically deleted';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.resolved_value IS NULL OR NEW.resolved_value = '' THEN
            NEW.resolved_value := 'lg-' || replace(NEW.id::text, '-', '');
        END IF;
        IF NEW.ipv4_resolved_value IS NULL OR NEW.ipv4_resolved_value = '' THEN
            NEW.ipv4_resolved_value := 'v4-' || replace(NEW.id::text, '-', '');
        END IF;
        IF NEW.current_revision <> 1 OR NEW.deleted_at IS NOT NULL OR NEW.deleted_by_user_id IS NOT NULL THEN
            RAISE EXCEPTION 'node line group initial revision must be one without a tombstone';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.deleted_at IS NOT NULL THEN
        RAISE EXCEPTION 'deleted node line groups are immutable';
    END IF;
    IF NEW.deleted_at IS NOT NULL THEN
        IF NEW.id IS DISTINCT FROM OLD.id
           OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
           OR NEW.name IS DISTINCT FROM OLD.name
           OR NEW.region IS DISTINCT FROM OLD.region
           OR NEW.resolved_value IS DISTINCT FROM OLD.resolved_value
           OR NEW.ipv4_resolved_value IS DISTINCT FROM OLD.ipv4_resolved_value
           OR NEW.l2_config_id IS DISTINCT FROM OLD.l2_config_id
           OR NEW.failover_mode IS DISTINCT FROM OLD.failover_mode
           OR NEW.note IS DISTINCT FROM OLD.note
           OR NEW.sort_order IS DISTINCT FROM OLD.sort_order
           OR NEW.current_revision IS DISTINCT FROM OLD.current_revision
           OR NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id
           OR NEW.created_at IS DISTINCT FROM OLD.created_at
           OR NEW.deleted_by_user_id IS NULL
           OR NEW.updated_by_user_id IS DISTINCT FROM NEW.deleted_by_user_id
           OR NEW.updated_at IS DISTINCT FROM NEW.deleted_at
           OR NEW.updated_at < OLD.updated_at THEN
            RAISE EXCEPTION 'node line group tombstone must preserve immutable configuration facts';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.deleted_by_user_id IS NOT NULL
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
       OR NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.current_revision <> OLD.current_revision + 1
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'node line group revision must advance by one';
    END IF;
    RETURN NEW;
END;
$$;

ALTER TABLE cname_allocation_intents DROP CONSTRAINT cname_allocation_intents_no_package_533_check,
    ALTER COLUMN package_subscription_id SET NOT NULL;
ALTER TABLE cname_allocation_targets ALTER COLUMN package_subscription_id SET NOT NULL;

DROP TRIGGER node_line_groups_platform_default_533 ON node_line_groups;
DROP FUNCTION assert_node_line_group_platform_default_533();
DROP INDEX node_line_groups_platform_default_533_key;
ALTER TABLE node_line_groups DROP COLUMN is_platform_default;
