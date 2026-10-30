INSERT INTO permissions (name, description) VALUES
    ('challenge_policies.read', 'Read tenant browser challenge policies'),
    ('challenge_policies.manage', 'Create, edit, enable, disable, and retire tenant browser challenge policies');

INSERT INTO custom_rbac_permission_catalog (permission_name, step_up_required) VALUES
    ('challenge_policies.read', false),
    ('challenge_policies.manage', true);

INSERT INTO role_permissions (role_id, permission_name)
SELECT role.id, permission.name
FROM roles role
JOIN access_scopes scope ON scope.id = role.scope_id
CROSS JOIN (VALUES ('challenge_policies.read'), ('challenge_policies.manage')) AS permission(name)
WHERE role.system_role AND (
    (scope.kind = 'platform' AND role.name IN ('platform_owner', 'platform_admin')) OR
    (scope.kind = 'tenant' AND role.name IN ('tenant_owner', 'tenant_admin'))
)
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_name)
SELECT role.id, 'challenge_policies.read'
FROM roles role
JOIN access_scopes scope ON scope.id = role.scope_id
WHERE role.system_role AND scope.kind = 'tenant'
  AND role.name IN ('tenant_member', 'tenant_viewer')
ON CONFLICT DO NOTHING;

CREATE FUNCTION grant_challenge_policy_permissions_053()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE scope_kind text;
BEGIN
    IF NOT NEW.system_role THEN
        RETURN NEW;
    END IF;
    SELECT kind INTO scope_kind FROM access_scopes WHERE id = NEW.scope_id;
    IF scope_kind = 'platform' AND NEW.name IN ('platform_owner', 'platform_admin') THEN
        INSERT INTO role_permissions (role_id, permission_name) VALUES
            (NEW.id, 'challenge_policies.read'),
            (NEW.id, 'challenge_policies.manage')
        ON CONFLICT DO NOTHING;
    ELSIF scope_kind = 'tenant' AND NEW.name IN ('tenant_owner', 'tenant_admin') THEN
        INSERT INTO role_permissions (role_id, permission_name) VALUES
            (NEW.id, 'challenge_policies.read'),
            (NEW.id, 'challenge_policies.manage')
        ON CONFLICT DO NOTHING;
    ELSIF scope_kind = 'tenant' AND NEW.name IN ('tenant_member', 'tenant_viewer') THEN
        INSERT INTO role_permissions (role_id, permission_name)
        VALUES (NEW.id, 'challenge_policies.read')
        ON CONFLICT DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER roles_challenge_policy_permissions_053
AFTER INSERT ON roles
FOR EACH ROW EXECUTE FUNCTION grant_challenge_policy_permissions_053();

CREATE TABLE challenge_policies (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    host text NOT NULL CHECK (
        host = lower(host) AND octet_length(host) BETWEEN 1 AND 253 AND
        host ~ '^[a-z0-9.-]+$'
    ),
    current_revision bigint NOT NULL CHECK (current_revision > 0),
    current_enabled boolean NOT NULL,
    current_deleted boolean NOT NULL DEFAULT false,
    current_document jsonb NOT NULL CHECK (jsonb_typeof(current_document) = 'object'),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    deleted_at timestamptz,
    FOREIGN KEY (tenant_scope_id, tenant_id)
        REFERENCES access_scopes(id, tenant_id) ON DELETE RESTRICT,
    UNIQUE (tenant_scope_id, id),
    CHECK (updated_at >= created_at),
    CHECK (current_deleted = (deleted_at IS NOT NULL)),
    CHECK (NOT current_deleted OR NOT current_enabled)
);

CREATE UNIQUE INDEX challenge_policies_active_target_053
    ON challenge_policies (tenant_scope_id, site_id, host)
    WHERE deleted_at IS NULL;
CREATE INDEX challenge_policies_tenant_page_053
    ON challenge_policies (tenant_scope_id, created_at DESC, id DESC)
    WHERE deleted_at IS NULL;
CREATE INDEX challenge_policies_site_page_053
    ON challenge_policies (tenant_scope_id, site_id, created_at DESC, id DESC)
    WHERE deleted_at IS NULL;

CREATE TABLE challenge_policy_revisions (
    policy_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    host text NOT NULL CHECK (
        host = lower(host) AND octet_length(host) BETWEEN 1 AND 253 AND
        host ~ '^[a-z0-9.-]+$'
    ),
    revision bigint NOT NULL CHECK (revision > 0),
    action text NOT NULL CHECK (action IN ('create', 'update', 'enable', 'disable', 'delete')),
    priority integer NOT NULL CHECK (priority BETWEEN 1 AND 1000000),
    mode text NOT NULL CHECK (mode IN ('delay', 'click', 'slider', 'captcha', 'external')),
    min_delay_seconds integer NOT NULL CHECK (min_delay_seconds BETWEEN 0 AND 10),
    challenge_ttl_seconds integer NOT NULL CHECK (challenge_ttl_seconds BETWEEN 10 AND 300),
    pass_ttl_seconds integer NOT NULL CHECK (pass_ttl_seconds BETWEEN 1 AND 3600),
    clock_skew_seconds integer NOT NULL CHECK (clock_skew_seconds BETWEEN 0 AND 30),
    attempts_per_nonce integer NOT NULL CHECK (attempts_per_nonce = 1),
    failure_window_seconds integer NOT NULL CHECK (failure_window_seconds BETWEEN 1 AND 3600),
    max_failures_per_window integer NOT NULL CHECK (max_failures_per_window BETWEEN 1 AND 20),
    ip_binding text NOT NULL CHECK (ip_binding IN ('none', 'exact')),
    bind_user_agent boolean NOT NULL,
    bypass_routes jsonb NOT NULL CHECK (
        jsonb_typeof(bypass_routes) = 'array' AND jsonb_array_length(bypass_routes) <= 32
    ),
    key_reference text NOT NULL CHECK (
        octet_length(key_reference) BETWEEN 8 AND 128 AND
        key_reference ~ '^(keyref|vault|kms):[A-Za-z0-9][A-Za-z0-9._:/-]*$'
    ),
    external_provider text CHECK (external_provider IN ('tencent', 'geetest-v4')),
    external_app_reference text CHECK (
        external_app_reference IS NULL OR (
            octet_length(external_app_reference) BETWEEN 8 AND 128 AND
            external_app_reference ~ '^appref:[A-Za-z0-9][A-Za-z0-9._:/-]*$'
        )
    ),
    enabled boolean NOT NULL,
    deleted boolean NOT NULL DEFAULT false,
    document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
    created_by_scope_id uuid NOT NULL,
    created_by_user_id uuid NOT NULL,
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128 AND
        request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    trace_id text NOT NULL CHECK (
        octet_length(trace_id) BETWEEN 1 AND 128 AND
        trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (policy_id, revision),
    FOREIGN KEY (tenant_scope_id, tenant_id)
        REFERENCES access_scopes(id, tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (created_by_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (challenge_ttl_seconds > min_delay_seconds + clock_skew_seconds),
    CHECK (
        (mode = 'delay' AND min_delay_seconds BETWEEN 5 AND 10) OR
        (mode <> 'delay' AND min_delay_seconds = 0)
    ),
    CHECK (
        (mode = 'external' AND external_provider IS NOT NULL AND external_app_reference IS NOT NULL) OR
        (mode <> 'external' AND external_provider IS NULL AND external_app_reference IS NULL)
    ),
    CHECK (NOT deleted OR NOT enabled)
);

CREATE INDEX challenge_policy_revisions_tenant_053
    ON challenge_policy_revisions (tenant_scope_id, policy_id, revision DESC);
CREATE INDEX challenge_policy_revisions_request_053
    ON challenge_policy_revisions (tenant_scope_id, request_id);

CREATE TABLE challenge_policy_write_requests (
    id uuid PRIMARY KEY,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN (
        'challenge_policy.create', 'challenge_policy.update', 'challenge_policy.enable',
        'challenge_policy.disable', 'challenge_policy.delete'
    )),
    idempotency_key text NOT NULL CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128 AND
        idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128 AND
        request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    trace_id text NOT NULL CHECK (
        octet_length(trace_id) BETWEEN 1 AND 128 AND
        trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    outcome text CHECK (outcome IN ('success', 'entitlement_denied', 'entitlement_unavailable')),
    resource_id uuid,
    response_status integer CHECK (response_status BETWEEN 200 AND 599),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (actor_scope_id, actor_user_id, operation, idempotency_key),
    CHECK (
        (completed_at IS NULL AND outcome IS NULL AND resource_id IS NULL AND
         response_status IS NULL AND response_body IS NULL) OR
        (completed_at IS NOT NULL AND outcome IS NOT NULL AND response_status IS NOT NULL AND
         response_body IS NOT NULL AND completed_at >= created_at AND
         ((outcome = 'success' AND resource_id IS NOT NULL AND response_status BETWEEN 200 AND 299) OR
          (outcome <> 'success' AND response_status IN (403, 503))))
    )
);

CREATE INDEX challenge_policy_write_requests_target_053
    ON challenge_policy_write_requests (target_scope_id, created_at DESC);

CREATE FUNCTION challenge_policy_host_valid_053(candidate text)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE label text;
BEGIN
    IF candidate IS NULL OR octet_length(candidate) NOT BETWEEN 1 AND 253
       OR candidate <> lower(candidate) OR candidate !~ '^[a-z0-9.-]+$'
       OR candidate LIKE '.%' OR candidate LIKE '%.' OR candidate LIKE '%..%' THEN
        RETURN false;
    END IF;
    FOREACH label IN ARRAY string_to_array(candidate, '.') LOOP
        IF octet_length(label) NOT BETWEEN 1 AND 63
           OR label LIKE '-%' OR label LIKE '%-' THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
END;
$$;

CREATE FUNCTION challenge_policy_bypass_valid_053(routes jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE route jsonb;
DECLARE route_kind text;
DECLARE route_path text;
BEGIN
    IF routes IS NULL OR jsonb_typeof(routes) <> 'array' OR jsonb_array_length(routes) > 32 THEN
        RETURN false;
    END IF;
    IF (SELECT count(*) FROM jsonb_array_elements(routes)) <>
       (SELECT count(DISTINCT item ->> 'path') FROM jsonb_array_elements(routes) item) THEN
        RETURN false;
    END IF;
    FOR route IN SELECT value FROM jsonb_array_elements(routes) LOOP
        IF jsonb_typeof(route) <> 'object'
           OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(route) key) IS DISTINCT FROM ARRAY['kind','path']::text[] THEN
            RETURN false;
        END IF;
        route_kind := route ->> 'kind';
        route_path := route ->> 'path';
        IF route_kind NOT IN ('exact', 'prefix') OR route_path IS NULL
           OR octet_length(route_path) NOT BETWEEN 1 AND 512
           OR route_path !~ '^[ -~]+$' OR left(route_path, 1) <> '/'
           OR route_path LIKE '//%' OR route_path LIKE '%//%'
           OR position(E'\\' in route_path) > 0 OR position('?' in route_path) > 0
           OR position('#' in route_path) > 0 OR position('%' in route_path) > 0
           OR route_path LIKE '%/./%' OR route_path LIKE '%/../%'
           OR route_path LIKE '%/.' OR route_path LIKE '%/..'
           OR (route_kind = 'prefix' AND (route_path = '/' OR right(route_path, 1) <> '/')) THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
END;
$$;

CREATE FUNCTION challenge_policy_actor_can_053(actor_scope uuid, actor_user uuid, target_scope uuid, permission text)
RETURNS boolean
LANGUAGE plpgsql
STABLE
AS $$
DECLARE actor_kind text;
BEGIN
    SELECT scope.kind INTO actor_kind
    FROM access_scopes scope
    JOIN memberships membership
      ON membership.scope_id = scope.id AND membership.user_id = actor_user
     AND membership.status = 'active'
    JOIN users account ON account.id = membership.user_id AND account.status = 'active'
    WHERE scope.id = actor_scope;
    IF actor_kind = 'tenant' THEN
        RETURN actor_scope = target_scope AND EXISTS (
            SELECT 1 FROM custom_rbac_effective_permissions(actor_scope, actor_user)
            WHERE permission_name = permission
        );
    END IF;
    IF actor_kind = 'platform' THEN
        RETURN EXISTS (
            SELECT 1
            FROM role_assignments assignment
            JOIN role_permissions role_permission ON role_permission.role_id = assignment.role_id
            WHERE assignment.scope_id = actor_scope AND assignment.user_id = actor_user
              AND role_permission.permission_name IN (permission, 'platform.admin')
        );
    END IF;
    RETURN false;
END;
$$;

CREATE FUNCTION validate_challenge_policy_revision_053()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE head challenge_policies%ROWTYPE;
DECLARE previous challenge_policy_revisions%ROWTYPE;
DECLARE site_scope uuid;
DECLARE site_domain text;
DECLARE expected_document jsonb;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('challenge-policy:' || NEW.policy_id::text, 0));
    IF NOT challenge_policy_host_valid_053(NEW.host)
       OR NOT challenge_policy_bypass_valid_053(NEW.bypass_routes) THEN
        RAISE EXCEPTION 'invalid challenge policy host or bypass routes' USING ERRCODE = 'P0001';
    END IF;
    IF NOT challenge_policy_actor_can_053(
        NEW.created_by_scope_id, NEW.created_by_user_id, NEW.tenant_scope_id, 'challenge_policies.manage'
    ) THEN
        RAISE EXCEPTION 'challenge policy actor is not authorized' USING ERRCODE = 'P0001';
    END IF;
    SELECT scope_id, domain INTO site_scope, site_domain
    FROM sites WHERE id = NEW.site_id AND deleted_at IS NULL;
    IF site_scope IS DISTINCT FROM NEW.tenant_scope_id THEN
        RAISE EXCEPTION 'challenge policy site scope mismatch' USING ERRCODE = 'P0001';
    END IF;
    IF left(site_domain, 2) = '*.' THEN
        IF NEW.host = substring(site_domain FROM 3)
           OR NEW.host NOT LIKE '%.' || substring(site_domain FROM 3) THEN
            RAISE EXCEPTION 'challenge policy host is outside the site domain' USING ERRCODE = 'P0001';
        END IF;
    ELSIF NEW.host <> site_domain THEN
        RAISE EXCEPTION 'challenge policy host is outside the site domain' USING ERRCODE = 'P0001';
    END IF;

    expected_document := jsonb_build_object(
        'schema_version', 'cdnca.control.challenge-policy/v1',
        'policy_id', NEW.policy_id::text,
        'tenant_scope_id', NEW.tenant_scope_id::text,
        'site_id', NEW.site_id::text,
        'host', NEW.host,
        'revision', NEW.revision,
        'priority', NEW.priority,
        'mode', NEW.mode,
        'min_delay_seconds', NEW.min_delay_seconds,
        'challenge_ttl_seconds', NEW.challenge_ttl_seconds,
        'pass_ttl_seconds', NEW.pass_ttl_seconds,
        'clock_skew_seconds', NEW.clock_skew_seconds,
        'attempts_per_nonce', NEW.attempts_per_nonce,
        'failure_window_seconds', NEW.failure_window_seconds,
        'max_failures_per_window', NEW.max_failures_per_window,
        'ip_binding', NEW.ip_binding,
        'bind_user_agent', NEW.bind_user_agent,
        'bypass_routes', NEW.bypass_routes,
        'key_reference', NEW.key_reference,
        'external_provider', CASE WHEN NEW.external_provider IS NULL THEN NULL ELSE jsonb_build_object(
            'provider', NEW.external_provider, 'app_reference', NEW.external_app_reference
        ) END,
        'enabled', NEW.enabled,
        'deleted', NEW.deleted
    );
    IF NEW.document IS DISTINCT FROM expected_document THEN
        RAISE EXCEPTION 'challenge policy document does not match revision facts' USING ERRCODE = 'P0001';
    END IF;

    SELECT * INTO head FROM challenge_policies WHERE id = NEW.policy_id FOR UPDATE;
    IF NOT FOUND THEN
        IF NEW.revision <> 1 OR NEW.action <> 'create' OR NEW.deleted THEN
            RAISE EXCEPTION 'challenge policy must start with create revision one' USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;
    IF head.current_deleted OR NEW.action = 'create'
       OR NEW.revision <> head.current_revision + 1
       OR NEW.tenant_scope_id <> head.tenant_scope_id
       OR NEW.tenant_id <> head.tenant_id
       OR NEW.site_id <> head.site_id
       OR NEW.host <> head.host THEN
        RAISE EXCEPTION 'challenge policy revision is not monotonic or changes identity' USING ERRCODE = 'P0001';
    END IF;
    SELECT * INTO previous
    FROM challenge_policy_revisions
    WHERE policy_id = NEW.policy_id AND revision = head.current_revision;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'challenge policy previous revision is missing' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.action IN ('enable', 'disable', 'delete') AND (
        NEW.priority IS DISTINCT FROM previous.priority OR
        NEW.mode IS DISTINCT FROM previous.mode OR
        NEW.min_delay_seconds IS DISTINCT FROM previous.min_delay_seconds OR
        NEW.challenge_ttl_seconds IS DISTINCT FROM previous.challenge_ttl_seconds OR
        NEW.pass_ttl_seconds IS DISTINCT FROM previous.pass_ttl_seconds OR
        NEW.clock_skew_seconds IS DISTINCT FROM previous.clock_skew_seconds OR
        NEW.attempts_per_nonce IS DISTINCT FROM previous.attempts_per_nonce OR
        NEW.failure_window_seconds IS DISTINCT FROM previous.failure_window_seconds OR
        NEW.max_failures_per_window IS DISTINCT FROM previous.max_failures_per_window OR
        NEW.ip_binding IS DISTINCT FROM previous.ip_binding OR
        NEW.bind_user_agent IS DISTINCT FROM previous.bind_user_agent OR
        NEW.bypass_routes IS DISTINCT FROM previous.bypass_routes OR
        NEW.key_reference IS DISTINCT FROM previous.key_reference OR
        NEW.external_provider IS DISTINCT FROM previous.external_provider OR
        NEW.external_app_reference IS DISTINCT FROM previous.external_app_reference
    ) THEN
        RAISE EXCEPTION 'challenge policy state transition cannot change configuration' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.action = 'update' AND (NEW.enabled <> head.current_enabled OR NEW.deleted) THEN
        RAISE EXCEPTION 'challenge policy update cannot change state' USING ERRCODE = 'P0001';
    ELSIF NEW.action = 'enable' AND (head.current_enabled OR NOT NEW.enabled OR NEW.deleted) THEN
        RAISE EXCEPTION 'invalid challenge policy enable transition' USING ERRCODE = 'P0001';
    ELSIF NEW.action = 'disable' AND (NOT head.current_enabled OR NEW.enabled OR NEW.deleted) THEN
        RAISE EXCEPTION 'invalid challenge policy disable transition' USING ERRCODE = 'P0001';
    ELSIF NEW.action = 'delete' AND (NEW.enabled OR NOT NEW.deleted) THEN
        RAISE EXCEPTION 'invalid challenge policy delete transition' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER challenge_policy_revisions_validate_053
BEFORE INSERT ON challenge_policy_revisions
FOR EACH ROW EXECUTE FUNCTION validate_challenge_policy_revision_053();

CREATE FUNCTION project_challenge_policy_revision_053()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.revision = 1 THEN
        INSERT INTO challenge_policies (
            id, tenant_scope_id, tenant_id, site_id, host, current_revision,
            current_enabled, current_deleted, current_document, created_by_user_id,
            created_at, updated_at, deleted_at
        ) VALUES (
            NEW.policy_id, NEW.tenant_scope_id, NEW.tenant_id, NEW.site_id, NEW.host,
            NEW.revision, NEW.enabled, NEW.deleted, NEW.document, NEW.created_by_user_id,
            NEW.created_at, NEW.created_at, CASE WHEN NEW.deleted THEN NEW.created_at END
        );
    ELSE
        UPDATE challenge_policies SET
            current_revision = NEW.revision,
            current_enabled = NEW.enabled,
            current_deleted = NEW.deleted,
            current_document = NEW.document,
            updated_at = NEW.created_at,
            deleted_at = CASE WHEN NEW.deleted THEN NEW.created_at ELSE NULL END
        WHERE id = NEW.policy_id AND current_revision = NEW.revision - 1;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'challenge policy projection did not advance' USING ERRCODE = 'P0001';
        END IF;
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER challenge_policy_revisions_project_053
AFTER INSERT ON challenge_policy_revisions
FOR EACH ROW EXECUTE FUNCTION project_challenge_policy_revision_053();

CREATE FUNCTION protect_challenge_policy_projection_053()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF pg_trigger_depth() < 2 THEN
        RAISE EXCEPTION 'challenge policy projection is revision-managed' USING ERRCODE = 'P0001';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE TRIGGER challenge_policies_projection_guard_053
BEFORE INSERT OR UPDATE OR DELETE ON challenge_policies
FOR EACH ROW EXECUTE FUNCTION protect_challenge_policy_projection_053();
CREATE TRIGGER challenge_policies_no_truncate_053
BEFORE TRUNCATE ON challenge_policies
FOR EACH STATEMENT EXECUTE FUNCTION protect_challenge_policy_projection_053();

CREATE FUNCTION protect_challenge_policy_revision_053()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'challenge policy revisions are append-only' USING ERRCODE = 'P0001';
END;
$$;

CREATE TRIGGER challenge_policy_revisions_append_only_053
BEFORE UPDATE OR DELETE ON challenge_policy_revisions
FOR EACH ROW EXECUTE FUNCTION protect_challenge_policy_revision_053();
CREATE TRIGGER challenge_policy_revisions_no_truncate_053
BEFORE TRUNCATE ON challenge_policy_revisions
FOR EACH STATEMENT EXECUTE FUNCTION protect_challenge_policy_revision_053();

CREATE FUNCTION protect_challenge_policy_write_request_053()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'challenge policy write facts cannot be removed' USING ERRCODE = 'P0001';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.completed_at IS NOT NULL OR NEW.outcome IS NOT NULL OR NEW.resource_id IS NOT NULL
           OR NEW.response_status IS NOT NULL OR NEW.response_body IS NOT NULL THEN
            RAISE EXCEPTION 'challenge policy write must start incomplete' USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.completed_at IS NOT NULL
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.actor_scope_id IS DISTINCT FROM OLD.actor_scope_id
       OR NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id
       OR NEW.target_scope_id IS DISTINCT FROM OLD.target_scope_id
       OR NEW.operation IS DISTINCT FROM OLD.operation
       OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
       OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
       OR NEW.request_id IS DISTINCT FROM OLD.request_id
       OR NEW.trace_id IS DISTINCT FROM OLD.trace_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.completed_at IS NULL OR NEW.outcome IS NULL
       OR NEW.response_status IS NULL OR NEW.response_body IS NULL THEN
        RAISE EXCEPTION 'invalid challenge policy write completion' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER challenge_policy_write_requests_guard_053
BEFORE INSERT OR UPDATE OR DELETE ON challenge_policy_write_requests
FOR EACH ROW EXECUTE FUNCTION protect_challenge_policy_write_request_053();
CREATE TRIGGER challenge_policy_write_requests_no_truncate_053
BEFORE TRUNCATE ON challenge_policy_write_requests
FOR EACH STATEMENT EXECUTE FUNCTION protect_challenge_policy_write_request_053();

CREATE FUNCTION assert_challenge_policy_revision_audited_053()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM audit_events event
        WHERE event.scope_id = NEW.tenant_scope_id
          AND event.actor_user_id = NEW.created_by_user_id
          AND event.action = 'challenge_policy.' || NEW.action
          AND event.resource_type = 'challenge_policy'
          AND event.resource_id = NEW.policy_id::text
          AND event.request_id = NEW.request_id
          AND event.result = 'success'
          AND event.payload ->> 'trace_id' = NEW.trace_id
          AND event.payload ->> 'revision' = NEW.revision::text
    ) THEN
        RAISE EXCEPTION 'challenge policy revision requires matching success audit' USING ERRCODE = 'P0001';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER challenge_policy_revisions_audited_053
AFTER INSERT ON challenge_policy_revisions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_challenge_policy_revision_audited_053();
