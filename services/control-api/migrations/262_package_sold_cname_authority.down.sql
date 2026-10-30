LOCK TABLE schema_migrations,cname_allocation_intents,cname_allocation_requests IN ACCESS EXCLUSIVE MODE;
DO $$
BEGIN
 IF (SELECT max(version) FROM schema_migrations)<>262 OR NOT EXISTS(
  SELECT 1 FROM schema_migrations WHERE version=262 AND integrity_state='verified'
 ) THEN RAISE EXCEPTION 'migration 262 rollback requires verified 262 head' USING ERRCODE='P2622'; END IF;
 IF EXISTS(SELECT 1 FROM cname_platform_intent_sessions) THEN
  RAISE EXCEPTION 'migration 262 rollback cannot discard platform CNAME authority' USING ERRCODE='P2623';
 END IF;
END;
$$;
DROP TRIGGER cname_allocation_requests_platform_authority ON cname_allocation_requests;
DROP TRIGGER cname_allocation_intents_platform_authority ON cname_allocation_intents;
DROP FUNCTION validate_cname_platform_intent_262();
ALTER TABLE cname_allocation_intents ADD CONSTRAINT cname_allocation_intents_tenant_actor_262_check CHECK(tenant_scope_id=actor_scope_id);
ALTER TABLE cname_allocation_requests ADD CONSTRAINT cname_allocation_requests_actor_scope_check CHECK(actor_scope_id=tenant_scope_id);
DROP TABLE cname_platform_allocation_jobs;
DROP FUNCTION validate_cname_platform_allocation_job_262();
DROP TABLE cname_platform_intent_sessions;
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
