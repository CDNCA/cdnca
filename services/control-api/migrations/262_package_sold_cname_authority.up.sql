LOCK TABLE schema_migrations,cname_allocation_intents,cname_allocation_requests IN ACCESS EXCLUSIVE MODE;
DO $$
BEGIN
 IF (SELECT max(version) FROM schema_migrations)<>261 OR NOT EXISTS(
  SELECT 1 FROM schema_migrations WHERE version=261 AND integrity_state='verified'
 ) THEN RAISE EXCEPTION 'migration 262 requires verified sold package schema 261' USING ERRCODE='P2620'; END IF;
END;
$$;

-- The original same-tenant checks remain the default. A platform actor must
-- prove a recorded live session and explicit package, site, and DNS authority.
CREATE TABLE cname_platform_intent_sessions (
 tenant_id uuid NOT NULL,
 job_id uuid NOT NULL,
 actor_session_id uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE RESTRICT,
 created_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,job_id),
 FOREIGN KEY(tenant_id,job_id) REFERENCES cname_allocation_intents(tenant_id,job_id) ON DELETE RESTRICT
);
CREATE TRIGGER cname_platform_intent_sessions_append_only
 BEFORE UPDATE OR DELETE ON cname_platform_intent_sessions FOR EACH ROW EXECUTE FUNCTION protect_cname_allocation_intent_126();
CREATE TRIGGER cname_platform_intent_sessions_no_truncate
 BEFORE TRUNCATE ON cname_platform_intent_sessions FOR EACH STATEMENT EXECUTE FUNCTION protect_cname_allocation_intent_126();

DO $$
DECLARE relation regclass; constraint_name name;
BEGIN
 FOREACH relation IN ARRAY ARRAY['cname_allocation_intents'::regclass,'cname_allocation_requests'::regclass] LOOP
  FOR constraint_name IN SELECT conname FROM pg_constraint WHERE conrelid=relation AND contype='c'
    AND pg_get_constraintdef(oid) IN ('CHECK ((tenant_scope_id = actor_scope_id))','CHECK ((actor_scope_id = tenant_scope_id))') LOOP
   EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',relation,constraint_name);
  END LOOP;
 END LOOP;
END;
$$;

CREATE FUNCTION validate_cname_platform_intent_262() RETURNS trigger LANGUAGE plpgsql AS $$
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
CREATE CONSTRAINT TRIGGER cname_allocation_intents_platform_authority
 AFTER INSERT ON cname_allocation_intents DEFERRABLE INITIALLY DEFERRED
 FOR EACH ROW EXECUTE FUNCTION validate_cname_platform_intent_262();
CREATE CONSTRAINT TRIGGER cname_allocation_requests_platform_authority
 AFTER INSERT ON cname_allocation_requests DEFERRABLE INITIALLY DEFERRED
 FOR EACH ROW EXECUTE FUNCTION validate_cname_platform_intent_262();
GRANT SELECT,INSERT ON cname_platform_intent_sessions TO cdnca_control_app;

-- A target refresh retains the generated hostname and generation. Its new job
-- must be linked to the exact authorized platform intent before allocation CAS.
CREATE TABLE cname_platform_allocation_jobs (
 tenant_id uuid NOT NULL,
 job_id uuid NOT NULL,
 intent_job_id uuid NOT NULL,
 allocation_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,job_id),
 FOREIGN KEY(tenant_id,job_id) REFERENCES background_jobs(tenant_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(tenant_id,intent_job_id) REFERENCES cname_platform_intent_sessions(tenant_id,job_id) ON DELETE RESTRICT,
 FOREIGN KEY(allocation_id) REFERENCES cname_allocations(id) ON DELETE RESTRICT
);
CREATE TRIGGER cname_platform_allocation_jobs_append_only
 BEFORE UPDATE OR DELETE ON cname_platform_allocation_jobs FOR EACH ROW EXECUTE FUNCTION protect_cname_allocation_intent_126();
CREATE TRIGGER cname_platform_allocation_jobs_no_truncate
 BEFORE TRUNCATE ON cname_platform_allocation_jobs FOR EACH STATEMENT EXECUTE FUNCTION protect_cname_allocation_intent_126();
CREATE FUNCTION validate_cname_platform_allocation_job_262() RETURNS trigger LANGUAGE plpgsql AS $$
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
CREATE TRIGGER cname_platform_allocation_jobs_validate
 BEFORE INSERT ON cname_platform_allocation_jobs FOR EACH ROW EXECUTE FUNCTION validate_cname_platform_allocation_job_262();
GRANT SELECT,INSERT ON cname_platform_allocation_jobs TO cdnca_control_app;

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
