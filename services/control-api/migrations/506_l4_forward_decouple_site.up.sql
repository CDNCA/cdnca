-- 506（r136 l4-decouple，用户 10-25 12:3x「四层转发与 HTTP 网站完全解耦」；接 stream-cname 505（merge-p7 改号，原 499），合入时按连号改号并重钉前驱）。
-- 转发是独立资源：归属 = 作用域 + 套餐订阅（092 起 NOT NULL），线路/CNAME 自带（499 列，NULL = 跟随套餐快照）。
-- 删 l4_forwards.site_id 与 l4_publish_intents.site_id；所有"有站点 = v2"的检查改为无条件 v2（1.0.35 基线无 v1 行）。
-- 运行时 JSON 顶层与 geo 不再有 site_id（节点 tcp/udp v12）。
LOCK TABLE schema_migrations, l4_forwards, l4_forward_listeners, l4_publish_intents, cname_stream_intents IN ACCESS EXCLUSIVE MODE;

DO $migration_506_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 505 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 505 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=505 AND
        migration_id='505_cname_stream_owner' AND
        checksum_sha256='2b2c88581e062c9c5e749bd563f52c8cc25ddf64a047e769e68cfa3a1d12c5bd' AND
        down_checksum_sha256='ca277385a1be765a1ba82cf7b12fea49d1ec533add60f0da64a3cc726dfce64e' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='l4_forwards' AND column_name='site_id'
       ) THEN
        RAISE EXCEPTION 'migration 506 requires the exact verified 505 head' USING ERRCODE='P5060';
    END IF;
    -- 1.0.35 只发 v2：没有站点的 v1 行不能被解释成独立转发。
    IF EXISTS (SELECT 1 FROM l4_forwards WHERE site_id IS NULL) OR
       EXISTS (SELECT 1 FROM l4_publish_intents WHERE site_id IS NULL) THEN
        RAISE EXCEPTION 'migration 506 refuses v1 L4 forwards without a site' USING ERRCODE='P5061';
    END IF;
END;
$migration_506_up$;

-- 列级约束：先显式删掉所有引用 site_id 的检查，再加同义去 site 的版本（DROP COLUMN 会静默删多列 CHECK）。
ALTER TABLE l4_forwards
    DROP CONSTRAINT l4_forwards_endpoint_151,
    DROP CONSTRAINT l4_forwards_runtime_facts_151,
    DROP CONSTRAINT l4_forwards_tls_passthrough_293,
    DROP CONSTRAINT l4_forwards_new_connection_rate_300,
    DROP CONSTRAINT l4_forwards_toa_316,
    DROP CONSTRAINT l4_forwards_session_log_328,
    DROP CONSTRAINT l4_forwards_port_range_334,
    DROP CONSTRAINT l4_forwards_guard_rules_341,
    DROP CONSTRAINT l4_forwards_origins_496,
    DROP CONSTRAINT l4_forwards_acl_496,
    DROP CONSTRAINT l4_forwards_line_cname_499;

-- stream-cname（505）的转发意图挂在 (id,scope_id,site_id) 上：先改挂转发 + 作用域并删 site_id，
-- 再删 l4_forwards_id_scope_site_151（外键依赖它）。绑定表 505 起就挂 (stream_id,tenant_scope_id)。
DO $migration_506_stream_intents$
DECLARE constraint_name name;
BEGIN
    FOR constraint_name IN SELECT conname FROM pg_constraint WHERE conrelid='cname_stream_intents'::regclass AND
        contype='f' AND confrelid='l4_forwards'::regclass LOOP
        EXECUTE format('ALTER TABLE cname_stream_intents DROP CONSTRAINT %I', constraint_name);
    END LOOP;
END;
$migration_506_stream_intents$;
ALTER TABLE cname_stream_intents
    DROP COLUMN site_id,
    ADD CONSTRAINT cname_stream_intents_stream_506_fk FOREIGN KEY (stream_id,tenant_scope_id)
        REFERENCES l4_forwards(id,scope_id) ON DELETE RESTRICT;

-- 505 的三个校验不再比较转发的网站：意图只要求转发存活、属该作用域。
CREATE OR REPLACE FUNCTION validate_cname_stream_intent_505() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM l4_forwards forward
        JOIN background_jobs job ON job.tenant_id=NEW.tenant_id AND job.id=NEW.job_id AND job.kind='dns.cname.stream_intent'
         AND job.request_id=NEW.request_id
        JOIN access_scopes actor_scope ON actor_scope.id=NEW.actor_scope_id AND actor_scope.kind='platform'
        JOIN memberships membership ON membership.scope_id=actor_scope.id AND membership.user_id=NEW.actor_user_id
         AND membership.status='active'
        WHERE forward.id=NEW.stream_id AND forward.scope_id=NEW.tenant_scope_id
          AND forward.deleted_at IS NULL
          AND EXISTS (SELECT 1 FROM role_assignments assignment JOIN role_permissions permission ON permission.role_id=assignment.role_id
              WHERE assignment.scope_id=actor_scope.id AND assignment.user_id=NEW.actor_user_id
                AND permission.permission_name IN ('platform.admin','streams.manage'))) THEN
        RAISE EXCEPTION 'CNAME stream intent authority rejected' USING ERRCODE='P5053';
    END IF;
    RETURN NULL;
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
    WHERE intent.tenant_scope_id=NEW.tenant_scope_id AND intent.stream_id=NEW.stream_id
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

ALTER TABLE l4_publish_intents
    DROP CONSTRAINT l4_publish_intents_runtime_spec_496,
    DROP CONSTRAINT l4_publish_intents_site_schema_151,
    DROP CONSTRAINT l4_publish_intents_stream_scope_site_151,
    DROP COLUMN site_id;

ALTER TABLE l4_forwards
    DROP CONSTRAINT l4_forwards_id_scope_site_151,
    DROP CONSTRAINT l4_forwards_site_scope_151,
    DROP COLUMN site_id,
    ADD CONSTRAINT l4_forwards_endpoint_506 CHECK (
        (upstream_address IS NOT NULL AND upstream_host IS NULL) OR
        (upstream_address IS NULL AND upstream_host IS NOT NULL AND
         upstream_host = lower(upstream_host) AND upstream_host = btrim(upstream_host) AND
         char_length(upstream_host) BETWEEN 1 AND 253)
    ),
    ADD CONSTRAINT l4_forwards_runtime_facts_506 CHECK (
        jsonb_typeof(dns_policy) = 'object' AND jsonb_typeof(geo_policy) = 'object'
    ),
    ADD CONSTRAINT l4_forwards_tls_passthrough_506 CHECK (
        (NOT tls_passthrough AND cardinality(server_names) = 0) OR
        (tls_passthrough AND protocol = 'tcp' AND valid_l4_server_names_293(server_names))
    ),
    ADD CONSTRAINT l4_forwards_new_connection_rate_506 CHECK (
        max_new_connections_per_client_per_second BETWEEN 0 AND 100000 AND
        new_connection_burst BETWEEN 0 AND 100000 AND new_connection_ban_seconds BETWEEN 0 AND 86400 AND
        (max_new_connections_per_client_per_second > 0 OR (new_connection_burst = 0 AND new_connection_ban_seconds = 0))
    ),
    ADD CONSTRAINT l4_forwards_toa_506 CHECK (
        NOT toa OR (protocol = 'tcp' AND NOT proxy_protocol_inbound AND NOT proxy_protocol_v1)
    ),
    ADD CONSTRAINT l4_forwards_port_range_506 CHECK (
        valid_l4_port_range_334(listen_port, listen_port_end) AND
        (listen_port_end IS NULL OR NOT tls_passthrough) AND
        (NOT upstream_follow_port OR upstream_port = listen_port)
    ),
    ADD CONSTRAINT l4_forwards_guard_rules_506 CHECK (
        guard_rules IS NULL OR valid_l4_guard_rules_341(guard_rules)
    ),
    ADD CONSTRAINT l4_forwards_origins_506 CHECK (
        origins IS NULL OR (upstream_address IS NOT NULL AND upstream_host IS NULL AND
            valid_l4_origins_496(origins) AND origins->0->>'address' = host(upstream_address))
    ),
    ADD CONSTRAINT l4_forwards_acl_506 CHECK (
        acl_default_action IN ('allow', 'deny') AND (acl_rules IS NULL OR valid_l4_acl_rules_496(acl_rules))
    ),
    -- 自有线路/CNAME：NULL = 跟随套餐快照（不再经过网站）。
    ADD CONSTRAINT l4_forwards_line_cname_506 CHECK (
        (cname_domain IS NULL OR (cname_domain = lower(btrim(cname_domain)) AND octet_length(cname_domain) BETWEEN 1 AND 253 AND
            cname_domain ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$')) AND
        (cname_mode IS NULL OR cname_mode IN ('site', 'package')) AND
        (backup_node_group_id IS NULL OR backup_node_group_id IS DISTINCT FROM node_group_id)
    );

-- 附加监听守卫：只要求转发存活（原"site_id IS NULL = v1 不可加"）。
CREATE OR REPLACE FUNCTION protect_l4_listener_334() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE forward_row l4_forwards%ROWTYPE;
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE') THEN
        RAISE EXCEPTION 'listener identities must be retained' USING ERRCODE='P2482';
    END IF;
    IF TG_OP='UPDATE' AND (NEW.id<>OLD.id OR NEW.stream_id<>OLD.stream_id) THEN
        RAISE EXCEPTION 'listener identity is immutable' USING ERRCODE='P2482';
    END IF;
    SELECT * INTO STRICT forward_row FROM l4_forwards WHERE id=NEW.stream_id FOR UPDATE;
    IF NEW.id=NEW.stream_id THEN
        IF pg_trigger_depth()<2 OR NEW.protocol<>forward_row.protocol OR
           NEW.address<>forward_row.listen_address OR NEW.port<>forward_row.listen_port OR
           NEW.port_end IS DISTINCT FROM forward_row.listen_port_end OR NEW.retired_at IS NOT NULL THEN
            RAISE EXCEPTION 'primary listener is database maintained' USING ERRCODE='P2482';
        END IF;
    ELSIF forward_row.deleted_at IS NOT NULL AND pg_trigger_depth()<2 THEN
        RAISE EXCEPTION 'additional listeners require a live v2 stream' USING ERRCODE='P2482';
    END IF;
    NEW.reserved := forward_row.deleted_at IS NULL AND NEW.retired_at IS NULL;
    NEW.tls_passthrough := forward_row.tls_passthrough;
    NEW.server_names := forward_row.server_names;
    RETURN NEW;
END;
$$;

-- 监听/直通事实：v2 判断不再看 site_id。
CREATE OR REPLACE FUNCTION check_l4_listener_facts_334() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    target_id uuid;
    forward_row l4_forwards%ROWTYPE;
    extra_listeners jsonb;
    primary_listener jsonb;
    intent l4_publish_intents%ROWTYPE;
BEGIN
    IF TG_TABLE_NAME='l4_forwards' THEN target_id:=NEW.id; ELSE target_id:=NEW.stream_id; END IF;
    SELECT * INTO STRICT forward_row FROM l4_forwards WHERE id=target_id;
    IF NOT EXISTS(SELECT 1 FROM l4_forward_listeners WHERE stream_id=target_id AND id<>stream_id) AND
       forward_row.listen_port_end IS NULL AND NOT forward_row.upstream_follow_port THEN
        IF TG_TABLE_NAME<>'l4_publish_intents' THEN RETURN NULL; END IF;
        IF NOT NEW.runtime_spec ? 'additional_listeners' AND NOT COALESCE(NEW.runtime_spec->'listener' ? 'port_end', false) AND
           NOT COALESCE(NEW.runtime_spec->'endpoint' ? 'follow_port', false) THEN RETURN NULL; END IF;
    END IF;
    SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'protocol',protocol,'address',address,'port',port) ||
        CASE WHEN port_end IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('port_end',port_end) END ORDER BY id),'[]'::jsonb)
    INTO extra_listeners FROM l4_forward_listeners WHERE stream_id=target_id AND id<>stream_id AND retired_at IS NULL;
    IF jsonb_array_length(extra_listeners)>63 OR
       ((forward_row.proxy_protocol_inbound OR forward_row.proxy_protocol_v1) AND EXISTS (
           SELECT 1 FROM l4_forward_listeners WHERE stream_id=target_id AND retired_at IS NULL AND protocol='udp'
       )) THEN RAISE EXCEPTION 'invalid final listener configuration' USING ERRCODE='P2482'; END IF;
    primary_listener := jsonb_build_object('protocol',forward_row.protocol,'address',forward_row.listen_address,
        'port',forward_row.listen_port) ||
        CASE WHEN forward_row.listen_port_end IS NULL THEN '{}'::jsonb
             ELSE jsonb_build_object('port_end',forward_row.listen_port_end) END;
    SELECT * INTO intent FROM l4_publish_intents WHERE stream_id=target_id ORDER BY version DESC LIMIT 1;
    IF intent.id IS NULL OR intent.resource_revision<>forward_row.revision OR
       COALESCE(intent.runtime_spec->'additional_listeners','[]'::jsonb)<>extra_listeners OR
       intent.runtime_spec->'listener' IS DISTINCT FROM primary_listener OR
       COALESCE(intent.runtime_spec#>'{endpoint,follow_port}'='true'::jsonb, false) IS DISTINCT FROM forward_row.upstream_follow_port THEN
        RAISE EXCEPTION 'listener facts require a matching versioned intent' USING ERRCODE='P2483';
    END IF;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION check_l4_passthrough_facts_293() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    target_id uuid;
    forward_row l4_forwards%ROWTYPE;
    intent l4_publish_intents%ROWTYPE;
BEGIN
    IF TG_TABLE_NAME='l4_forwards' THEN target_id:=NEW.id; ELSE target_id:=NEW.stream_id; END IF;
    SELECT * INTO STRICT forward_row FROM l4_forwards WHERE id=target_id;
    SELECT * INTO intent FROM l4_publish_intents WHERE stream_id=target_id ORDER BY version DESC LIMIT 1;
    IF intent.id IS NULL THEN
        IF forward_row.tls_passthrough THEN
            RAISE EXCEPTION 'passthrough facts require a matching versioned intent' USING ERRCODE='P2931';
        END IF;
        RETURN NULL;
    END IF;
    IF COALESCE(intent.runtime_spec->'tls_passthrough'='true'::jsonb, false) IS DISTINCT FROM forward_row.tls_passthrough OR
       COALESCE(intent.runtime_spec->'server_names','[]'::jsonb) IS DISTINCT FROM to_jsonb(forward_row.server_names) THEN
        RAISE EXCEPTION 'passthrough facts require a matching versioned intent' USING ERRCODE='P2931';
    END IF;
    RETURN NULL;
END;
$$;

-- 意图运行时：顶层与 geo 都没有 site_id；补上 site_id=stream_id 后即为合法 496 意图（旧链只比较 site_id 与目标值相等）。
CREATE FUNCTION validate_l4_runtime_spec_506(
    target_stream_id uuid, target_scope_id uuid, runtime_spec jsonb
) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
    IF target_stream_id IS NULL OR runtime_spec IS NULL OR jsonb_typeof(runtime_spec) <> 'object' OR
       runtime_spec ? 'site_id' OR jsonb_typeof(runtime_spec->'geo') <> 'object' OR runtime_spec->'geo' ? 'site_id' THEN
        RETURN false;
    END IF;
    RETURN validate_l4_runtime_spec_496(target_stream_id, target_scope_id, target_stream_id,
        jsonb_set(runtime_spec || jsonb_build_object('site_id', target_stream_id::text), '{geo}',
            (runtime_spec->'geo') || jsonb_build_object('site_id', target_stream_id::text)));
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;
-- 意图只追加：旧意图保留原文（含 site_id），约束只管新行；每条存活转发追加一条去掉 site_id 的同修订意图，
-- 让"最新意图"都是 v12 形状（下一次发布即下发，目标节点须具备 tcp/udp v12）。
ALTER TABLE l4_publish_intents
    ADD CONSTRAINT l4_publish_intents_runtime_spec_506
    CHECK(validate_l4_runtime_spec_506(stream_id,scope_id,runtime_spec)) NOT VALID;

WITH latest AS (
    SELECT DISTINCT ON (intent.stream_id) intent.*
    FROM l4_publish_intents intent
    JOIN l4_forwards forward ON forward.id=intent.stream_id AND forward.scope_id=intent.scope_id
    WHERE forward.deleted_at IS NULL
    ORDER BY intent.stream_id, intent.version DESC
), numbered AS (
    SELECT latest.*, row_number() OVER (PARTITION BY latest.scope_id ORDER BY latest.stream_id) AS ordinal
    FROM latest
), bumped AS (
    INSERT INTO l4_scope_publish_counters AS counter (scope_id, current_version)
    SELECT scope_id, count(*) FROM numbered GROUP BY scope_id
    ON CONFLICT (scope_id) DO UPDATE SET current_version = counter.current_version + EXCLUDED.current_version
    RETURNING counter.scope_id, counter.current_version
)
INSERT INTO l4_publish_intents (
    id, scope_id, stream_id, version, operation, desired_state, resource_revision,
    configuration_source_revision, runtime_spec, created_by_user_id, created_at
)
SELECT gen_random_uuid(), numbered.scope_id, numbered.stream_id,
       bumped.current_version - (SELECT count(*) FROM numbered other WHERE other.scope_id=numbered.scope_id) + numbered.ordinal,
       'update', numbered.desired_state, numbered.resource_revision,
       (SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=numbered.scope_id),
       jsonb_set(numbered.runtime_spec - 'site_id', '{geo}', (numbered.runtime_spec->'geo') - 'site_id'),
       numbered.created_by_user_id, now()
FROM numbered JOIN bumped ON bumped.scope_id=numbered.scope_id;

REVOKE ALL ON FUNCTION validate_l4_runtime_spec_506(uuid,uuid,jsonb) FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='cdnca_control_app') THEN
        GRANT EXECUTE ON FUNCTION validate_l4_runtime_spec_506(uuid,uuid,jsonb) TO cdnca_control_app;
    END IF;
END $$;
