-- 505（r136 stream-cname）回退：存在转发自有 CNAME 分配/意图/退役时拒绝回退（这些主机名已写到 DNS 服务商，504 无法表达）。
LOCK TABLE schema_migrations, cname_allocations, cname_allocation_requests, cname_allocation_targets,
    cname_record_retirements, l4_forwards IN ACCESS EXCLUSIVE MODE;

DO $migration_505_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 505 OR
       (SELECT max(version) FROM schema_migrations) <> 505 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=505 AND
        migration_id='505_cname_stream_owner' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 505 down requires the exact verified migration head' USING ERRCODE='P5054';
    END IF;
    IF EXISTS (SELECT 1 FROM cname_allocations WHERE stream_owner_id IS NOT NULL) OR
       EXISTS (SELECT 1 FROM cname_stream_intents) OR
       EXISTS (SELECT 1 FROM cname_record_retirements WHERE stream_id IS NOT NULL) THEN
        RAISE EXCEPTION 'retain L4 forward CNAME allocations during binary rollback' USING ERRCODE='P5055';
    END IF;
END;
$migration_505_down$;

CREATE OR REPLACE FUNCTION validate_cname_allocation_113()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    reused_claim_explicit boolean;
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'CNAME allocations are durable authority facts' USING ERRCODE='P1131';
    END IF;

    IF TG_OP='INSERT' THEN
        IF NEW.current_revision <> 1 OR NEW.generation <> 1 OR NEW.state <> 'pending' OR
           NEW.lkg_claim_id IS NOT NULL OR NEW.lkg_revision IS NOT NULL OR
           NEW.failure_code IS NOT NULL OR NEW.updated_at IS DISTINCT FROM NEW.created_at THEN
            RAISE EXCEPTION 'CNAME allocation must start as revision one pending without LKG'
                USING ERRCODE='P1131';
        END IF;
        RETURN NEW;
    END IF;

    IF ROW(NEW.id,NEW.tenant_id,NEW.tenant_scope_id,NEW.owner_user_id,NEW.mode,
           NEW.site_owner_id,NEW.package_subscription_id,NEW.created_at) IS DISTINCT FROM
       ROW(OLD.id,OLD.tenant_id,OLD.tenant_scope_id,OLD.owner_user_id,OLD.mode,
           OLD.site_owner_id,OLD.package_subscription_id,OLD.created_at) OR
       NEW.current_revision <> OLD.current_revision+1 OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'CNAME allocation identity or CAS revision is invalid' USING ERRCODE='P1131';
    END IF;

    IF NEW.generation=OLD.generation THEN
        IF OLD.state IN ('done','failed') AND NEW.state='pending' AND
           NEW.current_claim_id=OLD.current_claim_id AND NEW.job_id<>OLD.job_id AND
           ROW(NEW.lkg_claim_id,NEW.lkg_revision) IS NOT DISTINCT FROM ROW(OLD.lkg_claim_id,OLD.lkg_revision) AND
           EXISTS(SELECT 1 FROM cname_platform_allocation_jobs refresh
             WHERE refresh.tenant_id=NEW.tenant_id AND refresh.allocation_id=NEW.id AND refresh.job_id=NEW.job_id) THEN
            RETURN NEW;
        END IF;
        IF OLD.state <> 'pending' OR NEW.state NOT IN ('done','failed') OR
           NEW.current_claim_id IS DISTINCT FROM OLD.current_claim_id OR
           NEW.job_id IS DISTINCT FROM OLD.job_id THEN
            RAISE EXCEPTION 'CNAME allocation settlement is not an exact pending replay'
                USING ERRCODE='P1131';
        END IF;
        IF NEW.state='done' AND
           (NEW.lkg_claim_id IS DISTINCT FROM NEW.current_claim_id OR
            NEW.lkg_revision IS DISTINCT FROM NEW.current_revision) THEN
            RAISE EXCEPTION 'successful CNAME allocation must promote the current claim to LKG'
                USING ERRCODE='P1131';
        ELSIF NEW.state='failed' AND
              ROW(NEW.lkg_claim_id,NEW.lkg_revision) IS DISTINCT FROM
              ROW(OLD.lkg_claim_id,OLD.lkg_revision) THEN
            RAISE EXCEPTION 'failed CNAME allocation must preserve the prior LKG'
                USING ERRCODE='P1131';
        END IF;
    ELSIF NEW.generation=OLD.generation+1 THEN
        IF NEW.current_claim_id IS NOT DISTINCT FROM OLD.current_claim_id THEN
            SELECT explicit_hostname INTO reused_claim_explicit
            FROM cname_hostname_claims
            WHERE id=NEW.current_claim_id AND allocation_id=NEW.id;
            IF reused_claim_explicit IS DISTINCT FROM true THEN
                RAISE EXCEPTION 'only an immutable explicit CNAME claim may be reused across generations'
                    USING ERRCODE='P1131';
            END IF;
        END IF;
        IF NEW.state <> 'pending' OR NEW.job_id IS NOT DISTINCT FROM OLD.job_id OR
           (OLD.state='done' AND
            ROW(NEW.lkg_claim_id,NEW.lkg_revision) IS DISTINCT FROM
            ROW(OLD.current_claim_id,OLD.current_revision)) OR
           (OLD.state<>'done' AND
            ROW(NEW.lkg_claim_id,NEW.lkg_revision) IS DISTINCT FROM
            ROW(OLD.lkg_claim_id,OLD.lkg_revision)) THEN
            RAISE EXCEPTION 'CNAME regeneration must create a new pending claim and preserve LKG'
                USING ERRCODE='P1131';
        END IF;
    ELSE
        RAISE EXCEPTION 'CNAME allocation generation must remain or advance by one'
            USING ERRCODE='P1131';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION validate_cname_allocation_request_113()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    allocation_row cname_allocations%ROWTYPE;
    claim_row cname_hostname_claims%ROWTYPE;
    audit_row audit_events%ROWTYPE;
    job_row background_jobs%ROWTYPE;
    binding_row cname_site_bindings%ROWTYPE;
BEGIN
    SELECT * INTO allocation_row FROM cname_allocations
    WHERE tenant_scope_id=NEW.tenant_scope_id AND id=NEW.allocation_id;
    SELECT * INTO claim_row FROM cname_hostname_claims
    WHERE id=allocation_row.current_claim_id AND allocation_id=allocation_row.id;
    SELECT * INTO audit_row FROM audit_events WHERE id=NEW.audit_event_id;
    SELECT * INTO job_row FROM background_jobs
    WHERE tenant_id=NEW.tenant_id AND id=NEW.job_id;
    SELECT * INTO binding_row FROM cname_site_bindings
    WHERE tenant_scope_id=NEW.tenant_scope_id AND site_id=NEW.site_id;

    IF allocation_row.id IS NULL OR claim_row.id IS NULL OR audit_row.id IS NULL OR job_row.id IS NULL OR
       binding_row.current_allocation_id IS DISTINCT FROM NEW.allocation_id OR
       allocation_row.tenant_id IS DISTINCT FROM NEW.tenant_id OR
       allocation_row.job_id IS DISTINCT FROM NEW.job_id OR
       allocation_row.generation IS DISTINCT FROM NEW.generation OR
       allocation_row.current_revision IS DISTINCT FROM NEW.result_revision OR
       allocation_row.lkg_revision IS DISTINCT FROM NEW.result_lkg_revision OR
       allocation_row.state IS DISTINCT FROM NEW.result_state OR
       allocation_row.failure_code IS DISTINCT FROM NEW.failure_code OR
       claim_row.hmac_key_id IS DISTINCT FROM NEW.hmac_key_id OR
       (NEW.operation='bind' AND allocation_row.mode<>'package') OR
       job_row.kind IS DISTINCT FROM 'dns.cname.allocation' OR
       audit_row.scope_id IS DISTINCT FROM NEW.actor_scope_id OR
       audit_row.actor_user_id IS DISTINCT FROM NEW.actor_user_id OR
       audit_row.action IS DISTINCT FROM 'dns.cname.'||NEW.operation OR
       audit_row.resource_type IS DISTINCT FROM 'cname_allocation' OR
       audit_row.resource_id IS DISTINCT FROM NEW.allocation_id::text OR
       audit_row.request_id IS DISTINCT FROM NEW.request_id OR
       audit_row.result IS DISTINCT FROM
           (CASE WHEN NEW.result_state='failed' THEN 'failure' ELSE 'success' END) OR
       audit_row.occurred_at < NEW.created_at THEN
        RAISE EXCEPTION 'CNAME allocation request lacks exact job, actor, audit, or result authority'
            USING ERRCODE='P1135';
    END IF;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION validate_cname_platform_intent_262() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE matched boolean;
BEGIN
 IF TG_TABLE_NAME='cname_allocation_intents' THEN
  IF NEW.actor_scope_id=NEW.tenant_scope_id THEN RETURN NULL; END IF;
  SELECT EXISTS(SELECT 1 FROM cname_platform_intent_sessions authority
   JOIN auth_sessions session ON session.id=authority.actor_session_id
   JOIN access_scopes scope ON scope.id=session.scope_id AND scope.kind='platform'
   JOIN memberships membership ON membership.scope_id=scope.id AND membership.user_id=session.user_id AND membership.status='active'
   JOIN users actor ON actor.id=membership.user_id AND actor.status='active'
   WHERE authority.tenant_id=NEW.tenant_id AND authority.job_id=NEW.job_id
    AND session.scope_id=NEW.actor_scope_id AND session.user_id=NEW.actor_user_id
    AND session.revoked_at IS NULL AND session.expires_at>clock_timestamp()
    AND EXISTS(SELECT 1 FROM role_assignments a JOIN role_permissions p ON p.role_id=a.role_id
     WHERE a.scope_id=scope.id AND a.user_id=actor.id AND p.permission_name IN('platform.admin','package_subscriptions.manage'))
    AND EXISTS(SELECT 1 FROM role_assignments a JOIN role_permissions p ON p.role_id=a.role_id
     WHERE a.scope_id=scope.id AND a.user_id=actor.id AND p.permission_name IN('platform.admin','sites.manage'))
    AND EXISTS(SELECT 1 FROM role_assignments a JOIN role_permissions p ON p.role_id=a.role_id
     WHERE a.scope_id=scope.id AND a.user_id=actor.id AND p.permission_name IN('platform.admin','dns.manage'))
  ) INTO matched;
 ELSE
  IF NEW.actor_scope_id=NEW.tenant_scope_id THEN RETURN NULL; END IF;
  SELECT EXISTS(SELECT 1 FROM cname_allocation_intents intent
   JOIN cname_platform_intent_sessions authority ON authority.tenant_id=intent.tenant_id AND authority.job_id=intent.job_id
   WHERE intent.tenant_scope_id=NEW.tenant_scope_id AND intent.site_id=NEW.site_id
    AND intent.actor_scope_id=NEW.actor_scope_id AND intent.actor_user_id=NEW.actor_user_id
    AND intent.request_id=NEW.request_id) INTO matched;
 END IF;
 IF NOT matched THEN RAISE EXCEPTION 'CNAME platform intent authority rejected' USING ERRCODE='P2621'; END IF;
 RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION cname_claim_released_476(retired_claim_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1 FROM cname_record_retirements retirement
        WHERE retirement.claim_id=retired_claim_id AND retirement.eligible_at<=clock_timestamp()
          AND NOT EXISTS (
            SELECT 1 FROM cname_site_bindings binding
            JOIN sites site ON site.scope_id=binding.tenant_scope_id AND site.id=binding.site_id
             AND site.deleted_at IS NULL
            JOIN cname_allocations allocation ON allocation.tenant_scope_id=binding.tenant_scope_id
             AND allocation.id=retirement.allocation_id
            WHERE binding.tenant_scope_id=retirement.tenant_scope_id AND (
                (binding.current_allocation_id=allocation.id AND
                 retirement.claim_id IN (allocation.current_claim_id,allocation.lkg_claim_id)) OR
                (binding.lkg_allocation_id=allocation.id AND retirement.claim_id=allocation.lkg_claim_id))))
$$;

DROP TRIGGER cname_record_retirements_stream_505 ON cname_record_retirements;
DROP TRIGGER cname_allocation_targets_stream_505 ON cname_allocation_targets;
DROP FUNCTION protect_cname_stream_reference_505();
DROP TABLE cname_stream_intents;
DROP FUNCTION validate_cname_stream_intent_505();
DROP TABLE cname_stream_bindings;
DROP FUNCTION validate_cname_stream_binding_505();
DROP INDEX cname_record_retirements_stream_505_idx;
ALTER TABLE cname_record_retirements DROP CONSTRAINT cname_record_retirements_reason_505_check,
    DROP CONSTRAINT cname_record_retirements_stream_505_fk, DROP COLUMN stream_id,
    ADD CONSTRAINT cname_record_retirements_reason_check CHECK (reason IN ('site_deleted','generation_rotated'));
ALTER TABLE cname_allocation_requests DROP CONSTRAINT cname_allocation_requests_stream_505_fk, DROP COLUMN stream_id;
ALTER TABLE cname_allocation_targets DROP CONSTRAINT cname_allocation_targets_stream_505_fk, DROP COLUMN stream_id;
DROP INDEX cname_allocations_stream_owner_505_uidx;
ALTER TABLE cname_allocations DROP CONSTRAINT cname_allocations_owner_505_check,
    DROP CONSTRAINT cname_allocations_stream_owner_505_fk, DROP COLUMN stream_owner_id,
    -- 113's unnamed owner CHECK, restored under a name no other CHECK takes.
    ADD CONSTRAINT cname_allocations_owner_113_check CHECK (
        (mode='site' AND site_owner_id IS NOT NULL AND package_subscription_id IS NULL) OR
        (mode='package' AND site_owner_id IS NULL AND package_subscription_id IS NOT NULL));
