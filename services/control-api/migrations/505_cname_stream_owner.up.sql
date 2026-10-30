-- 505（r136 stream-cname，主会话 10-25 08:3x 方案 B「竞品每条转发自有 CNAME」；接 L2 拓扑 504（merge-p7 改号，原 498），合入时按连号改号并重钉前驱）。
-- 四层转发设了自有 CNAME域名 / CNAME生成模式时，分配转发自己的 CNAME 主机名并写 DNS：
-- cname_allocations 多一种属主（转发），绑定在 cname_stream_bindings，意图在 cname_stream_intents。
-- DNS 写入任务（076/089）仍以 site_id 为锚：带覆盖的转发必有所属网站（499 约束），租户/区域权限与网站一致。
LOCK TABLE schema_migrations, cname_allocations, cname_allocation_requests, cname_allocation_targets,
    cname_record_retirements, l4_forwards IN ACCESS EXCLUSIVE MODE;

DO $migration_505_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 504 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 504 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=504 AND
        migration_id='504_line_group_l2_topology_config' AND
        checksum_sha256='8cde62e682fafe211948d4e8e36939cb263d1302d562a30b3def7cf328bf4188' AND
        down_checksum_sha256='6305b76f82ed1dcda54f5be0d56943a94cf0a6e21aa715a6eaa426d689ba1291' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('cname_stream_bindings') IS NOT NULL OR
       to_regprocedure('validate_cname_allocation_113()') IS NULL OR
       to_regprocedure('cname_claim_released_476(uuid)') IS NULL THEN
        RAISE EXCEPTION 'migration 505 requires the exact verified 504 head' USING ERRCODE='P5050';
    END IF;
END;
$migration_505_up$;

-- 转发属主：与网站属主、套餐属主三选一（mode 仍为 site；转发的按网站/按套餐只进标签 HMAC，记在绑定上）。
ALTER TABLE cname_allocations ADD COLUMN stream_owner_id uuid,
    ADD CONSTRAINT cname_allocations_stream_owner_505_fk FOREIGN KEY (stream_owner_id,tenant_scope_id)
        REFERENCES l4_forwards(id,scope_id) ON DELETE RESTRICT;
DO $migration_505_owner_check$
DECLARE constraint_name name;
BEGIN
    FOR constraint_name IN SELECT conname FROM pg_constraint WHERE conrelid='cname_allocations'::regclass AND contype='c'
        AND pg_get_constraintdef(oid) LIKE '%site_owner_id IS NOT NULL%package_subscription_id IS NULL%' LOOP
        EXECUTE format('ALTER TABLE cname_allocations DROP CONSTRAINT %I', constraint_name);
    END LOOP;
END;
$migration_505_owner_check$;
ALTER TABLE cname_allocations ADD CONSTRAINT cname_allocations_owner_505_check CHECK (
    (stream_owner_id IS NULL AND (
        (mode='site' AND site_owner_id IS NOT NULL AND package_subscription_id IS NULL) OR
        (mode='package' AND site_owner_id IS NULL AND package_subscription_id IS NOT NULL))) OR
    (stream_owner_id IS NOT NULL AND mode='site' AND site_owner_id IS NULL AND package_subscription_id IS NULL));
CREATE UNIQUE INDEX cname_allocations_stream_owner_505_uidx
    ON cname_allocations (tenant_scope_id,stream_owner_id) WHERE stream_owner_id IS NOT NULL;

ALTER TABLE cname_allocation_targets ADD COLUMN stream_id uuid,
    ADD CONSTRAINT cname_allocation_targets_stream_505_fk FOREIGN KEY (stream_id,tenant_scope_id)
        REFERENCES l4_forwards(id,scope_id) ON DELETE RESTRICT;
ALTER TABLE cname_allocation_requests ADD COLUMN stream_id uuid,
    ADD CONSTRAINT cname_allocation_requests_stream_505_fk FOREIGN KEY (stream_id,tenant_scope_id)
        REFERENCES l4_forwards(id,scope_id) ON DELETE RESTRICT;
ALTER TABLE cname_record_retirements ADD COLUMN stream_id uuid,
    ADD CONSTRAINT cname_record_retirements_stream_505_fk FOREIGN KEY (stream_id,tenant_scope_id)
        REFERENCES l4_forwards(id,scope_id) ON DELETE RESTRICT,
    DROP CONSTRAINT cname_record_retirements_reason_check,
    ADD CONSTRAINT cname_record_retirements_reason_505_check CHECK (
        reason IN ('site_deleted','generation_rotated','stream_deleted','stream_released') AND
        (reason NOT IN ('stream_deleted','stream_released') OR stream_id IS NOT NULL));
CREATE INDEX cname_record_retirements_stream_505_idx ON cname_record_retirements (tenant_scope_id,stream_id)
    WHERE stream_id IS NOT NULL;

-- 一条转发只有一个分配（唯一索引），换域名/模式是它的新一代；mode 记当前代按网站还是按套餐生成。
CREATE TABLE cname_stream_bindings (
    tenant_scope_id uuid NOT NULL,
    stream_id uuid NOT NULL,
    allocation_id uuid NOT NULL,
    mode text NOT NULL CHECK (mode IN ('site','package')),
    binding_revision bigint NOT NULL CHECK (binding_revision > 0),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    PRIMARY KEY (tenant_scope_id,stream_id),
    UNIQUE (tenant_scope_id,allocation_id),
    FOREIGN KEY (stream_id,tenant_scope_id) REFERENCES l4_forwards(id,scope_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,allocation_id) REFERENCES cname_allocations(tenant_scope_id,id) ON DELETE RESTRICT
);

-- 平台「更多操作」修改 CNAME 域名/模式或重试时写入；worker（持 HMAC 密钥）执行。
CREATE TABLE cname_stream_intents (
    tenant_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    job_id uuid NOT NULL,
    stream_id uuid NOT NULL,
    site_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    mode text NOT NULL CHECK (mode IN ('site','package')),
    domain text NOT NULL CHECK (domain=lower(btrim(domain)) AND char_length(domain) <= 253),
    regenerate boolean NOT NULL,
    request_id text NOT NULL CHECK (octet_length(request_id) BETWEEN 1 AND 128 AND request_id !~ '[[:cntrl:]]'),
    trace_id text NOT NULL,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    PRIMARY KEY (tenant_id,job_id),
    FOREIGN KEY (tenant_scope_id,tenant_id) REFERENCES access_scopes(id,tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id,job_id) REFERENCES background_jobs(tenant_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (stream_id,tenant_scope_id,site_id) REFERENCES l4_forwards(id,scope_id,site_id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id,actor_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT
);
CREATE INDEX cname_stream_intents_stream_505_idx ON cname_stream_intents (tenant_scope_id,stream_id,created_at DESC,job_id DESC);
CREATE TRIGGER cname_stream_intents_append_only_505 BEFORE UPDATE OR DELETE ON cname_stream_intents
    FOR EACH ROW EXECUTE FUNCTION protect_cname_allocation_intent_126();
CREATE TRIGGER cname_stream_intents_no_truncate_505 BEFORE TRUNCATE ON cname_stream_intents
    FOR EACH STATEMENT EXECUTE FUNCTION protect_cname_allocation_intent_126();
CREATE FUNCTION validate_cname_stream_binding_505() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE allocation_row cname_allocations%ROWTYPE;
BEGIN
    IF TG_OP<>'INSERT' AND TG_OP<>'UPDATE' THEN
        RAISE EXCEPTION 'CNAME stream bindings are durable authority facts' USING ERRCODE='P5051';
    END IF;
    IF (TG_OP='INSERT' AND (NEW.binding_revision<>1 OR NEW.updated_at IS DISTINCT FROM NEW.created_at)) OR
       (TG_OP='UPDATE' AND (ROW(NEW.tenant_scope_id,NEW.stream_id,NEW.allocation_id,NEW.created_at) IS DISTINCT FROM
            ROW(OLD.tenant_scope_id,OLD.stream_id,OLD.allocation_id,OLD.created_at) OR
            NEW.binding_revision<>OLD.binding_revision+1 OR NEW.updated_at<OLD.updated_at)) THEN
        RAISE EXCEPTION 'CNAME stream binding CAS revision is invalid' USING ERRCODE='P5051';
    END IF;
    SELECT * INTO allocation_row FROM cname_allocations WHERE tenant_scope_id=NEW.tenant_scope_id AND id=NEW.allocation_id;
    IF allocation_row.id IS NULL OR allocation_row.stream_owner_id IS DISTINCT FROM NEW.stream_id THEN
        RAISE EXCEPTION 'CNAME stream binding does not match its stream owner' USING ERRCODE='P5051';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER cname_stream_bindings_validate_505 BEFORE INSERT OR UPDATE OR DELETE ON cname_stream_bindings
    FOR EACH ROW EXECUTE FUNCTION validate_cname_stream_binding_505();
CREATE TRIGGER cname_stream_bindings_no_truncate_505 BEFORE TRUNCATE ON cname_stream_bindings
    FOR EACH STATEMENT EXECUTE FUNCTION validate_cname_stream_binding_505();

-- 冻结目标、退役记录的转发归属不可改。
CREATE FUNCTION protect_cname_stream_reference_505() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.stream_id IS DISTINCT FROM OLD.stream_id THEN
        RAISE EXCEPTION 'CNAME stream reference is immutable' USING ERRCODE='P5052';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER cname_allocation_targets_stream_505 BEFORE UPDATE ON cname_allocation_targets
    FOR EACH ROW EXECUTE FUNCTION protect_cname_stream_reference_505();
CREATE TRIGGER cname_record_retirements_stream_505 BEFORE UPDATE ON cname_record_retirements
    FOR EACH ROW EXECUTE FUNCTION protect_cname_stream_reference_505();
-- 平台意图须由平台作用域内有 streams.manage/platform.admin 的在岗成员写入，转发须仍属该网站且未删除。
CREATE FUNCTION validate_cname_stream_intent_505() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM l4_forwards forward
        JOIN background_jobs job ON job.tenant_id=NEW.tenant_id AND job.id=NEW.job_id AND job.kind='dns.cname.stream_intent'
         AND job.request_id=NEW.request_id
        JOIN access_scopes actor_scope ON actor_scope.id=NEW.actor_scope_id AND actor_scope.kind='platform'
        JOIN memberships membership ON membership.scope_id=actor_scope.id AND membership.user_id=NEW.actor_user_id
         AND membership.status='active'
        WHERE forward.id=NEW.stream_id AND forward.scope_id=NEW.tenant_scope_id AND forward.site_id=NEW.site_id
          AND forward.deleted_at IS NULL
          AND EXISTS (SELECT 1 FROM role_assignments assignment JOIN role_permissions permission ON permission.role_id=assignment.role_id
              WHERE assignment.scope_id=actor_scope.id AND assignment.user_id=NEW.actor_user_id
                AND permission.permission_name IN ('platform.admin','streams.manage'))) THEN
        RAISE EXCEPTION 'CNAME stream intent authority rejected' USING ERRCODE='P5053';
    END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER cname_stream_intents_validate_505 AFTER INSERT ON cname_stream_intents
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION validate_cname_stream_intent_505();

-- 113（经 262）：属主身份不可改，现含转发属主；其余规则不变。
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
           NEW.site_owner_id,NEW.package_subscription_id,NEW.stream_owner_id,NEW.created_at) IS DISTINCT FROM
       ROW(OLD.id,OLD.tenant_id,OLD.tenant_scope_id,OLD.owner_user_id,OLD.mode,
           OLD.site_owner_id,OLD.package_subscription_id,OLD.stream_owner_id,OLD.created_at) OR
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
-- 113：请求事实的“当前绑定”对转发请求（stream_id 非空）看 cname_stream_bindings，其余不变。
CREATE OR REPLACE FUNCTION validate_cname_allocation_request_113()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    allocation_row cname_allocations%ROWTYPE;
    claim_row cname_hostname_claims%ROWTYPE;
    audit_row audit_events%ROWTYPE;
    job_row background_jobs%ROWTYPE;
    bound_allocation_id uuid;
BEGIN
    SELECT * INTO allocation_row FROM cname_allocations
    WHERE tenant_scope_id=NEW.tenant_scope_id AND id=NEW.allocation_id;
    SELECT * INTO claim_row FROM cname_hostname_claims
    WHERE id=allocation_row.current_claim_id AND allocation_id=allocation_row.id;
    SELECT * INTO audit_row FROM audit_events WHERE id=NEW.audit_event_id;
    SELECT * INTO job_row FROM background_jobs
    WHERE tenant_id=NEW.tenant_id AND id=NEW.job_id;
    IF NEW.stream_id IS NULL THEN
        SELECT current_allocation_id INTO bound_allocation_id FROM cname_site_bindings
        WHERE tenant_scope_id=NEW.tenant_scope_id AND site_id=NEW.site_id;
    ELSE
        SELECT binding.allocation_id INTO bound_allocation_id FROM cname_stream_bindings binding
        JOIN l4_forwards forward ON forward.scope_id=binding.tenant_scope_id AND forward.id=binding.stream_id
         AND forward.site_id=NEW.site_id
        WHERE binding.tenant_scope_id=NEW.tenant_scope_id AND binding.stream_id=NEW.stream_id;
    END IF;

    IF allocation_row.id IS NULL OR claim_row.id IS NULL OR audit_row.id IS NULL OR job_row.id IS NULL OR
       bound_allocation_id IS DISTINCT FROM NEW.allocation_id OR
       allocation_row.stream_owner_id IS DISTINCT FROM NEW.stream_id OR
       allocation_row.tenant_id IS DISTINCT FROM NEW.tenant_id OR
       allocation_row.job_id IS DISTINCT FROM NEW.job_id OR
       allocation_row.generation IS DISTINCT FROM NEW.generation OR
       allocation_row.current_revision IS DISTINCT FROM NEW.result_revision OR
       allocation_row.lkg_revision IS DISTINCT FROM NEW.result_lkg_revision OR
       allocation_row.state IS DISTINCT FROM NEW.result_state OR
       allocation_row.failure_code IS DISTINCT FROM NEW.failure_code OR
       claim_row.hmac_key_id IS DISTINCT FROM NEW.hmac_key_id OR
       (NEW.operation='bind' AND (allocation_row.mode<>'package' OR NEW.stream_id IS NOT NULL)) OR
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

-- 262：平台操作者的转发请求由同一转发、同一操作者、同一 request_id 的转发意图授权（不借网站意图）。
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
  IF NEW.stream_id IS NOT NULL THEN
   SELECT EXISTS(SELECT 1 FROM cname_stream_intents intent
    WHERE intent.tenant_scope_id=NEW.tenant_scope_id AND intent.stream_id=NEW.stream_id AND intent.site_id=NEW.site_id
     AND intent.actor_scope_id=NEW.actor_scope_id AND intent.actor_user_id=NEW.actor_user_id
     AND intent.request_id=NEW.request_id) INTO matched;
  ELSE
   SELECT EXISTS(SELECT 1 FROM cname_allocation_intents intent
    JOIN cname_platform_intent_sessions authority ON authority.tenant_id=intent.tenant_id AND authority.job_id=intent.job_id
    WHERE intent.tenant_scope_id=NEW.tenant_scope_id AND intent.site_id=NEW.site_id
     AND intent.actor_scope_id=NEW.actor_scope_id AND intent.actor_user_id=NEW.actor_user_id
     AND intent.request_id=NEW.request_id) INTO matched;
  END IF;
 END IF;
 IF NOT matched THEN RAISE EXCEPTION 'CNAME platform intent authority rejected' USING ERRCODE='P2621'; END IF;
 RETURN NULL;
END;
$$;
-- 476：转发分配的主机名在“转发未删除且仍设覆盖”的绑定上（当前或 LKG）算在用；
-- 分配任务在途（pending）时也不释放，免得清理与正在写入的记录交错。网站分配的判定不变。
CREATE OR REPLACE FUNCTION cname_claim_released_476(retired_claim_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1 FROM cname_record_retirements retirement
        JOIN cname_allocations allocation ON allocation.tenant_scope_id=retirement.tenant_scope_id
         AND allocation.id=retirement.allocation_id
        WHERE retirement.claim_id=retired_claim_id AND retirement.eligible_at<=clock_timestamp()
          AND NOT EXISTS (
            SELECT 1 FROM cname_site_bindings binding
            JOIN sites site ON site.scope_id=binding.tenant_scope_id AND site.id=binding.site_id
             AND site.deleted_at IS NULL
            WHERE binding.tenant_scope_id=retirement.tenant_scope_id AND (
                (binding.current_allocation_id=allocation.id AND
                 retirement.claim_id IN (allocation.current_claim_id,allocation.lkg_claim_id)) OR
                (binding.lkg_allocation_id=allocation.id AND retirement.claim_id=allocation.lkg_claim_id)))
          AND (allocation.stream_owner_id IS NULL OR (allocation.state<>'pending' AND NOT EXISTS (
            SELECT 1 FROM cname_stream_bindings binding
            JOIN l4_forwards forward ON forward.scope_id=binding.tenant_scope_id AND forward.id=binding.stream_id
             AND forward.deleted_at IS NULL AND (forward.cname_domain IS NOT NULL OR forward.cname_mode IS NOT NULL)
            WHERE binding.tenant_scope_id=allocation.tenant_scope_id AND binding.allocation_id=allocation.id
              AND retirement.claim_id IN (allocation.current_claim_id,allocation.lkg_claim_id)))))
$$;

GRANT SELECT, INSERT, UPDATE ON cname_stream_bindings TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT ON cname_stream_intents TO cdnca_control_app, cdnca_control_runtime;
