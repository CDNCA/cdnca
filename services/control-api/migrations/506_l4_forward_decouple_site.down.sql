-- 506（r136 l4-decouple）回退：独立转发在 505 必须挂网站，无法表达；有任何转发行时拒绝回退。
LOCK TABLE schema_migrations, l4_forwards, l4_forward_listeners, l4_publish_intents, cname_stream_intents IN ACCESS EXCLUSIVE MODE;

DO $migration_506_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 506 OR
       (SELECT max(version) FROM schema_migrations) <> 506 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=506 AND
        migration_id='506_l4_forward_decouple_site' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 506 down requires the exact verified migration head' USING ERRCODE='P5062';
    END IF;
    IF EXISTS (SELECT 1 FROM l4_forwards) THEN
        RAISE EXCEPTION 'retain standalone L4 forwards during binary rollback' USING ERRCODE='P5063';
    END IF;
END;
$migration_506_down$;

ALTER TABLE l4_publish_intents DROP CONSTRAINT l4_publish_intents_runtime_spec_506;
DROP FUNCTION validate_l4_runtime_spec_506(uuid,uuid,jsonb);

ALTER TABLE l4_forwards
    DROP CONSTRAINT l4_forwards_endpoint_506,
    DROP CONSTRAINT l4_forwards_runtime_facts_506,
    DROP CONSTRAINT l4_forwards_tls_passthrough_506,
    DROP CONSTRAINT l4_forwards_new_connection_rate_506,
    DROP CONSTRAINT l4_forwards_toa_506,
    DROP CONSTRAINT l4_forwards_port_range_506,
    DROP CONSTRAINT l4_forwards_guard_rules_506,
    DROP CONSTRAINT l4_forwards_origins_506,
    DROP CONSTRAINT l4_forwards_acl_506,
    DROP CONSTRAINT l4_forwards_line_cname_506,
    ADD COLUMN site_id uuid,
    ADD CONSTRAINT l4_forwards_site_scope_151
        FOREIGN KEY (scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT l4_forwards_id_scope_site_151 UNIQUE (id, scope_id, site_id),
    ADD CONSTRAINT l4_forwards_endpoint_151 CHECK (
        (upstream_address IS NOT NULL AND upstream_host IS NULL) OR
        (upstream_address IS NULL AND site_id IS NOT NULL AND upstream_host IS NOT NULL AND
         upstream_host = lower(upstream_host) AND upstream_host = btrim(upstream_host) AND
         char_length(upstream_host) BETWEEN 1 AND 253)
    ),
    ADD CONSTRAINT l4_forwards_runtime_facts_151 CHECK (
        jsonb_typeof(dns_policy) = 'object' AND jsonb_typeof(geo_policy) = 'object' AND
        (
            site_id IS NOT NULL OR
            (upstream_host IS NULL AND NOT proxy_protocol_inbound AND
             dns_policy = '{"positive_min_ttl_seconds":0,"positive_max_ttl_seconds":0,"negative_ttl_seconds":0,"stale_if_error_seconds":0,"allow_private_addresses":false}'::jsonb AND
             geo_policy = '{"enabled":false,"unknown_region_action":"allow","trusted_proxy_cidrs":[],"blocked_regions":[],"region_cidrs":[]}'::jsonb)
        )
    ),
    ADD CONSTRAINT l4_forwards_tls_passthrough_293 CHECK (
        (NOT tls_passthrough AND cardinality(server_names) = 0) OR
        (tls_passthrough AND protocol = 'tcp' AND site_id IS NOT NULL AND valid_l4_server_names_293(server_names))
    ),
    ADD CONSTRAINT l4_forwards_new_connection_rate_300 CHECK (
        max_new_connections_per_client_per_second BETWEEN 0 AND 100000 AND
        new_connection_burst BETWEEN 0 AND 100000 AND new_connection_ban_seconds BETWEEN 0 AND 86400 AND
        (max_new_connections_per_client_per_second > 0 OR (new_connection_burst = 0 AND new_connection_ban_seconds = 0)) AND
        (max_new_connections_per_client_per_second = 0 OR site_id IS NOT NULL)
    ),
    ADD CONSTRAINT l4_forwards_toa_316 CHECK (
        NOT toa OR (protocol = 'tcp' AND site_id IS NOT NULL AND
                    NOT proxy_protocol_inbound AND NOT proxy_protocol_v1)
    ),
    ADD CONSTRAINT l4_forwards_session_log_328 CHECK (NOT session_log_enabled OR site_id IS NOT NULL),
    ADD CONSTRAINT l4_forwards_port_range_334 CHECK (
        valid_l4_port_range_334(listen_port, listen_port_end) AND
        (listen_port_end IS NULL OR (site_id IS NOT NULL AND NOT tls_passthrough)) AND
        (NOT upstream_follow_port OR (site_id IS NOT NULL AND upstream_port = listen_port))
    ),
    ADD CONSTRAINT l4_forwards_guard_rules_341 CHECK (
        guard_rules IS NULL OR (site_id IS NOT NULL AND valid_l4_guard_rules_341(guard_rules))
    ),
    ADD CONSTRAINT l4_forwards_origins_496 CHECK (
        origins IS NULL OR (site_id IS NOT NULL AND upstream_address IS NOT NULL AND upstream_host IS NULL AND
            valid_l4_origins_496(origins) AND origins->0->>'address' = host(upstream_address))
    ),
    ADD CONSTRAINT l4_forwards_acl_496 CHECK (
        acl_default_action IN ('allow', 'deny') AND (acl_rules IS NULL OR valid_l4_acl_rules_496(acl_rules)) AND
        (site_id IS NOT NULL OR (acl_default_action = 'allow' AND acl_rules IS NULL AND NOT listen_ipv6))
    ),
    ADD CONSTRAINT l4_forwards_line_cname_499 CHECK (
        (cname_domain IS NULL OR (cname_domain = lower(btrim(cname_domain)) AND octet_length(cname_domain) BETWEEN 1 AND 253 AND
            cname_domain ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$')) AND
        (cname_mode IS NULL OR cname_mode IN ('site', 'package')) AND
        (backup_node_group_id IS NULL OR backup_node_group_id IS DISTINCT FROM node_group_id) AND
        (site_id IS NOT NULL OR (cname_domain IS NULL AND cname_mode IS NULL AND region_id IS NULL AND
            node_group_id IS NULL AND backup_node_group_id IS NULL))
    );

ALTER TABLE l4_publish_intents
    ADD COLUMN site_id uuid,
    ADD CONSTRAINT l4_publish_intents_stream_scope_site_151
        FOREIGN KEY (stream_id, scope_id, site_id)
        REFERENCES l4_forwards(id, scope_id, site_id) ON DELETE RESTRICT,
    ADD CONSTRAINT l4_publish_intents_site_schema_151 CHECK (
        (site_id IS NULL AND runtime_spec ->> 'schema_version' IS NULL) OR
        (site_id IS NOT NULL AND runtime_spec ->> 'schema_version' = 'cdnca.edge.l4/v2')
    ),
    ADD CONSTRAINT l4_publish_intents_runtime_spec_496
    CHECK(validate_l4_runtime_spec_496(stream_id,scope_id,site_id,runtime_spec));

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
    ELSIF forward_row.site_id IS NULL OR (forward_row.deleted_at IS NOT NULL AND pg_trigger_depth()<2) THEN
        RAISE EXCEPTION 'additional listeners require a live v2 stream' USING ERRCODE='P2482';
    END IF;
    NEW.reserved := forward_row.deleted_at IS NULL AND NEW.retired_at IS NULL;
    NEW.tls_passthrough := forward_row.tls_passthrough;
    NEW.server_names := forward_row.server_names;
    RETURN NEW;
END;
$$;

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
       (forward_row.site_id IS NOT NULL AND
        COALESCE(intent.runtime_spec#>'{endpoint,follow_port}'='true'::jsonb, false) IS DISTINCT FROM forward_row.upstream_follow_port) THEN
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
    IF forward_row.site_id IS NULL THEN RETURN NULL; END IF;
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

-- 恢复 505 的转发意图外键（无转发行，表必为空）与三个校验函数。
ALTER TABLE cname_stream_intents
    DROP CONSTRAINT cname_stream_intents_stream_506_fk,
    ADD COLUMN site_id uuid NOT NULL,
    ADD FOREIGN KEY (stream_id,tenant_scope_id,site_id) REFERENCES l4_forwards(id,scope_id,site_id) ON DELETE RESTRICT;
CREATE OR REPLACE FUNCTION validate_cname_stream_intent_505() RETURNS trigger LANGUAGE plpgsql AS $$
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
