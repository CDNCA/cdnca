INSERT INTO permissions (name, description) VALUES
    ('origin_auth.read', 'Read object-storage origin authentication credentials, rules, and publications'),
    ('origin_auth.manage', 'Manage object-storage origin authentication credentials and rules');

INSERT INTO custom_rbac_permission_catalog (permission_name, step_up_required) VALUES
    ('origin_auth.read', false),
    ('origin_auth.manage', true);

INSERT INTO role_permissions (role_id, permission_name)
SELECT role.id, permission.name
FROM roles role
JOIN permissions permission ON permission.name IN ('origin_auth.read', 'origin_auth.manage')
WHERE role.system_role AND role.name IN ('platform_owner', 'tenant_owner')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_name)
SELECT role.id, 'origin_auth.read'
FROM roles role
WHERE role.system_role AND role.name = 'tenant_viewer'
ON CONFLICT DO NOTHING;

CREATE FUNCTION grant_origin_auth_permissions_055()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT NEW.system_role THEN
        RETURN NEW;
    END IF;
    IF NEW.name IN ('platform_owner', 'tenant_owner') THEN
        INSERT INTO role_permissions (role_id, permission_name) VALUES
            (NEW.id, 'origin_auth.read'),
            (NEW.id, 'origin_auth.manage')
        ON CONFLICT DO NOTHING;
    ELSIF NEW.name = 'tenant_viewer' THEN
        INSERT INTO role_permissions (role_id, permission_name)
        VALUES (NEW.id, 'origin_auth.read')
        ON CONFLICT DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER roles_origin_auth_permissions_055
AFTER INSERT ON roles
FOR EACH ROW EXECUTE FUNCTION grant_origin_auth_permissions_055();

CREATE TABLE origin_auth_credentials (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    provider text NOT NULL CHECK (provider IN ('s3', 'oss', 'cos')),
    name text NOT NULL CHECK (
        name = btrim(name) AND octet_length(name) BETWEEN 1 AND 128 AND
        name !~ '[[:cntrl:]]'
    ),
    created_by_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    trace_id text NOT NULL CHECK (trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_scope_id, id),
    FOREIGN KEY (created_by_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX origin_auth_credentials_scope_provider_name_idx
    ON origin_auth_credentials (tenant_scope_id, provider, lower(name));
CREATE INDEX origin_auth_credentials_scope_page_idx
    ON origin_auth_credentials (tenant_scope_id, created_at DESC, id DESC);

CREATE TABLE origin_auth_credential_revisions (
    credential_id uuid NOT NULL REFERENCES origin_auth_credentials(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    revision_ref uuid NOT NULL UNIQUE,
    operation text NOT NULL CHECK (operation IN ('create', 'replace', 'verify', 'disable', 'delete')),
    status text NOT NULL CHECK (status IN ('pending', 'verified', 'disabled', 'deleted')),
    envelope_key_id text NOT NULL CHECK (
        envelope_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    secret_ciphertext bytea NOT NULL CHECK (octet_length(secret_ciphertext) BETWEEN 29 AND 16384),
    secret_ciphertext_sha256 bytea NOT NULL CHECK (octet_length(secret_ciphertext_sha256) = 32),
    not_before timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    verified_at timestamptz,
    verification_code text CHECK (
        verification_code IS NULL OR verification_code ~ '^[a-z][a-z0-9._-]{0,63}$'
    ),
    created_by_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    trace_id text NOT NULL CHECK (trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (credential_id, revision),
    FOREIGN KEY (created_by_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (expires_at > not_before),
    CHECK (
        (status = 'verified' AND verified_at IS NOT NULL AND verification_code = 'verified') OR
        (status <> 'verified' AND verification_code IS NULL)
    )
);

CREATE INDEX origin_auth_credential_revisions_state_idx
    ON origin_auth_credential_revisions (credential_id, revision DESC);

CREATE TABLE origin_auth_rules (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    source_position smallint NOT NULL CHECK (source_position BETWEEN 1 AND 32),
    created_by_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    trace_id text NOT NULL CHECK (trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_scope_id, id),
    FOREIGN KEY (site_id, source_position)
        REFERENCES site_origins(site_id, position) ON DELETE RESTRICT,
    FOREIGN KEY (created_by_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

CREATE INDEX origin_auth_rules_scope_page_idx
    ON origin_auth_rules (tenant_scope_id, created_at DESC, id DESC);

CREATE TABLE origin_auth_rule_revisions (
    rule_id uuid NOT NULL REFERENCES origin_auth_rules(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    operation text NOT NULL CHECK (operation IN ('create', 'update', 'enable', 'disable', 'rotate', 'delete')),
    provider text NOT NULL CHECK (provider IN ('s3', 'oss', 'cos')),
    algorithm text NOT NULL CHECK (algorithm IN ('aws4-hmac-sha256', 'oss4-hmac-sha256', 'cos-hmac-sha1')),
    endpoint text NOT NULL CHECK (
        endpoint = lower(endpoint) AND octet_length(endpoint) BETWEEN 10 AND 512 AND
        endpoint ~ '^https://[a-z0-9][a-z0-9.-]*$'
    ),
    bucket text NOT NULL CHECK (octet_length(bucket) <= 63),
    path_prefix text NOT NULL CHECK (
        octet_length(path_prefix) BETWEEN 1 AND 2048 AND
        left(path_prefix, 1) = '/' AND right(path_prefix, 1) = '/' AND
        path_prefix !~ '[[:cntrl:]?#\\]' AND path_prefix !~ '//|(^|/)\.\.(/|$)'
    ),
    region text NOT NULL CHECK (region ~ '^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$'),
    service text NOT NULL CHECK (service ~ '^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$'),
    signature_ttl_seconds integer NOT NULL CHECK (signature_ttl_seconds BETWEEN 1 AND 3600),
    egress_policy_reference text CHECK (
        egress_policy_reference IS NULL OR
        egress_policy_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    current_credential_id uuid NOT NULL,
    current_credential_revision bigint NOT NULL CHECK (current_credential_revision > 0),
    current_credential_revision_ref uuid NOT NULL,
    previous_credential_id uuid,
    previous_credential_revision bigint CHECK (previous_credential_revision IS NULL OR previous_credential_revision > 0),
    previous_credential_revision_ref uuid,
    activate_current_at timestamptz,
    enabled boolean NOT NULL,
    deleted boolean NOT NULL DEFAULT false,
    created_by_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    trace_id text NOT NULL CHECK (trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (rule_id, revision),
    FOREIGN KEY (current_credential_id, current_credential_revision)
        REFERENCES origin_auth_credential_revisions(credential_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (previous_credential_id, previous_credential_revision)
        REFERENCES origin_auth_credential_revisions(credential_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (created_by_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (NOT deleted OR NOT enabled),
    CHECK (
        (previous_credential_id IS NULL AND previous_credential_revision IS NULL AND
         previous_credential_revision_ref IS NULL AND activate_current_at IS NULL) OR
        (previous_credential_id IS NOT NULL AND previous_credential_revision IS NOT NULL AND
         previous_credential_revision_ref IS NOT NULL AND activate_current_at IS NOT NULL AND
         ROW(current_credential_id, current_credential_revision) <>
             ROW(previous_credential_id, previous_credential_revision) AND
         current_credential_revision_ref <> previous_credential_revision_ref)
    )
);

CREATE INDEX origin_auth_rule_revisions_current_credential_idx
    ON origin_auth_rule_revisions (current_credential_id, current_credential_revision);
CREATE INDEX origin_auth_rule_revisions_previous_credential_idx
    ON origin_auth_rule_revisions (previous_credential_id, previous_credential_revision)
    WHERE previous_credential_id IS NOT NULL;

CREATE TABLE origin_auth_publications (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    schema_version text NOT NULL CHECK (schema_version = 'cdnca.control.originauth-publication/v1'),
    canonical_snapshot bytea NOT NULL CHECK (octet_length(canonical_snapshot) BETWEEN 1 AND 67108864),
    snapshot_sha256 bytea NOT NULL CHECK (octet_length(snapshot_sha256) = 32),
    previous_sha256 bytea CHECK (previous_sha256 IS NULL OR octet_length(previous_sha256) = 32),
    created_by_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    trace_id text NOT NULL CHECK (trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_scope_id, revision),
    FOREIGN KEY (created_by_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

CREATE INDEX origin_auth_publications_scope_page_idx
    ON origin_auth_publications (tenant_scope_id, revision DESC);

CREATE TABLE origin_auth_write_requests (
    id uuid PRIMARY KEY,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN (
        'origin_auth.credential.create', 'origin_auth.credential.replace', 'origin_auth.credential.verify',
        'origin_auth.credential.disable', 'origin_auth.credential.delete',
        'origin_auth.rule.create', 'origin_auth.rule.update', 'origin_auth.rule.enable',
        'origin_auth.rule.disable', 'origin_auth.rule.rotate', 'origin_auth.rule.delete',
        'origin_auth.publication.create'
    )),
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    resource_id uuid,
    response_status integer CHECK (response_status BETWEEN 200 AND 299),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    trace_id text NOT NULL CHECK (trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (actor_scope_id, actor_user_id, operation, idempotency_key),
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (
        (completed_at IS NULL AND resource_id IS NULL AND response_status IS NULL AND response_body IS NULL) OR
        (completed_at IS NOT NULL AND resource_id IS NOT NULL AND response_status IS NOT NULL AND
         response_body IS NOT NULL AND completed_at >= created_at)
    )
);

CREATE INDEX origin_auth_write_requests_scope_created_idx
    ON origin_auth_write_requests (target_scope_id, created_at DESC);

CREATE FUNCTION origin_auth_actor_has_permission(actor_scope uuid, actor_user uuid, requested_permission text)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM memberships membership
        JOIN users account ON account.id = membership.user_id AND account.status = 'active'
        JOIN role_assignments assignment
          ON assignment.scope_id = membership.scope_id AND assignment.user_id = membership.user_id
        JOIN role_permissions grant_row ON grant_row.role_id = assignment.role_id
        WHERE membership.scope_id = actor_scope
          AND membership.user_id = actor_user
          AND membership.status = 'active'
          AND grant_row.permission_name IN (requested_permission, 'platform.admin')
    )
$$;

CREATE FUNCTION origin_auth_has_audit(
    target_scope uuid,
    actor_user uuid,
    requested_action text,
    requested_resource_type text,
    requested_resource_id text,
    requested_request_id text,
    requested_trace_id text
) RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1 FROM audit_events event
        WHERE event.scope_id = target_scope
          AND event.actor_user_id = actor_user
          AND event.action = requested_action
          AND event.resource_type = requested_resource_type
          AND event.resource_id = requested_resource_id
          AND event.request_id = requested_request_id
          AND event.payload->>'trace_id' = requested_trace_id
          AND event.result = 'success'
    )
$$;

CREATE FUNCTION origin_auth_has_pending_write(
    target_scope uuid,
    actor_scope uuid,
    actor_user uuid,
    requested_operation text,
    requested_request_id text,
    requested_trace_id text
) RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1 FROM origin_auth_write_requests request
        WHERE request.target_scope_id = target_scope
          AND request.actor_scope_id = actor_scope
          AND request.actor_user_id = actor_user
          AND request.operation = requested_operation
          AND request.request_id = requested_request_id
          AND request.trace_id = requested_trace_id
          AND request.completed_at IS NULL
    )
$$;

CREATE FUNCTION validate_origin_auth_credential_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    scope_tenant uuid;
    actor_kind text;
BEGIN
    SELECT tenant_id INTO scope_tenant FROM access_scopes
    WHERE id = NEW.tenant_scope_id AND kind = 'tenant';
    SELECT kind INTO actor_kind FROM access_scopes WHERE id = NEW.created_by_scope_id;
    IF scope_tenant IS NULL OR NEW.tenant_id <> scope_tenant OR
       NOT origin_auth_actor_has_permission(NEW.created_by_scope_id, NEW.created_by_user_id, 'origin_auth.manage') OR
       NOT origin_auth_has_pending_write(NEW.tenant_scope_id, NEW.created_by_scope_id,
           NEW.created_by_user_id, 'origin_auth.credential.create', NEW.request_id, NEW.trace_id) OR
       NOT origin_auth_has_audit(NEW.tenant_scope_id, NEW.created_by_user_id,
           'origin_auth.credential.create', 'origin_auth_credential', NEW.id::text,
           NEW.request_id, NEW.trace_id) OR
       (actor_kind = 'tenant' AND NEW.created_by_scope_id <> NEW.tenant_scope_id) OR
       actor_kind NOT IN ('tenant', 'platform') THEN
        RAISE EXCEPTION 'invalid origin authentication credential identity';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER origin_auth_credentials_validate_insert
BEFORE INSERT ON origin_auth_credentials
FOR EACH ROW EXECUTE FUNCTION validate_origin_auth_credential_identity();

CREATE FUNCTION validate_origin_auth_credential_revision()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    identity origin_auth_credentials%ROWTYPE;
    previous origin_auth_credential_revisions%ROWTYPE;
    expected_action text;
BEGIN
    SELECT * INTO identity FROM origin_auth_credentials WHERE id = NEW.credential_id;
    SELECT * INTO previous FROM origin_auth_credential_revisions
    WHERE credential_id = NEW.credential_id ORDER BY revision DESC LIMIT 1;
    expected_action := 'origin_auth.credential.' || NEW.operation;
    IF NOT FOUND THEN
        NULL;
    END IF;
    IF identity.id IS NULL OR NEW.revision <> COALESCE(previous.revision, 0) + 1 OR
       sha256(NEW.secret_ciphertext) <> NEW.secret_ciphertext_sha256 OR
       NOT origin_auth_actor_has_permission(NEW.created_by_scope_id, NEW.created_by_user_id, 'origin_auth.manage') OR
       NOT origin_auth_has_pending_write(identity.tenant_scope_id, NEW.created_by_scope_id,
           NEW.created_by_user_id, expected_action, NEW.request_id, NEW.trace_id) OR
       NOT origin_auth_has_audit(identity.tenant_scope_id, NEW.created_by_user_id, expected_action,
           'origin_auth_credential', NEW.credential_id::text, NEW.request_id, NEW.trace_id) THEN
        RAISE EXCEPTION 'invalid origin authentication credential revision';
    END IF;
    IF NEW.revision = 1 THEN
        IF NEW.operation <> 'create' OR NEW.status <> 'pending' OR NEW.verified_at IS NOT NULL THEN
            RAISE EXCEPTION 'invalid origin authentication credential initial state';
        END IF;
    ELSE
        IF previous.status = 'deleted' OR
           (NEW.operation = 'replace' AND (NEW.status <> 'pending' OR
              NEW.secret_ciphertext_sha256 = previous.secret_ciphertext_sha256)) OR
           (NEW.operation = 'verify' AND (previous.status <> 'pending' OR NEW.status <> 'verified' OR
              NEW.envelope_key_id <> previous.envelope_key_id OR
              NEW.secret_ciphertext <> previous.secret_ciphertext OR
              NEW.secret_ciphertext_sha256 <> previous.secret_ciphertext_sha256 OR
              NEW.not_before <> previous.not_before OR NEW.expires_at <> previous.expires_at)) OR
           (NEW.operation = 'disable' AND (previous.status NOT IN ('pending', 'verified') OR NEW.status <> 'disabled' OR
              NEW.envelope_key_id <> previous.envelope_key_id OR
              NEW.secret_ciphertext <> previous.secret_ciphertext OR
              NEW.secret_ciphertext_sha256 <> previous.secret_ciphertext_sha256 OR
              NEW.not_before <> previous.not_before OR NEW.expires_at <> previous.expires_at)) OR
           (NEW.operation = 'delete' AND (previous.status = 'deleted' OR NEW.status <> 'deleted' OR
              NEW.envelope_key_id <> previous.envelope_key_id OR
              NEW.secret_ciphertext <> previous.secret_ciphertext OR
              NEW.secret_ciphertext_sha256 <> previous.secret_ciphertext_sha256 OR
              NEW.not_before <> previous.not_before OR NEW.expires_at <> previous.expires_at)) OR
           NEW.operation = 'create' THEN
            RAISE EXCEPTION 'invalid origin authentication credential state transition';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER origin_auth_credential_revisions_validate
BEFORE INSERT ON origin_auth_credential_revisions
FOR EACH ROW EXECUTE FUNCTION validate_origin_auth_credential_revision();

CREATE FUNCTION validate_origin_auth_rule_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    scope_tenant uuid;
    actor_kind text;
BEGIN
    SELECT tenant_id INTO scope_tenant FROM access_scopes
    WHERE id = NEW.tenant_scope_id AND kind = 'tenant';
    SELECT kind INTO actor_kind FROM access_scopes WHERE id = NEW.created_by_scope_id;
    IF scope_tenant IS NULL OR NEW.tenant_id <> scope_tenant OR
       NOT EXISTS (SELECT 1 FROM sites site WHERE site.id = NEW.site_id
                   AND site.scope_id = NEW.tenant_scope_id AND site.deleted_at IS NULL) OR
       NOT EXISTS (SELECT 1 FROM site_origins source WHERE source.site_id = NEW.site_id
                   AND source.position = NEW.source_position) OR
       NOT origin_auth_actor_has_permission(NEW.created_by_scope_id, NEW.created_by_user_id, 'origin_auth.manage') OR
       NOT origin_auth_has_pending_write(NEW.tenant_scope_id, NEW.created_by_scope_id,
           NEW.created_by_user_id, 'origin_auth.rule.create', NEW.request_id, NEW.trace_id) OR
       NOT origin_auth_has_audit(NEW.tenant_scope_id, NEW.created_by_user_id,
           'origin_auth.rule.create', 'origin_auth_rule', NEW.id::text,
           NEW.request_id, NEW.trace_id) OR
       (actor_kind = 'tenant' AND NEW.created_by_scope_id <> NEW.tenant_scope_id) OR
       actor_kind NOT IN ('tenant', 'platform') THEN
        RAISE EXCEPTION 'invalid origin authentication rule identity';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER origin_auth_rules_validate_insert
BEFORE INSERT ON origin_auth_rules
FOR EACH ROW EXECUTE FUNCTION validate_origin_auth_rule_identity();

CREATE FUNCTION validate_origin_auth_rule_revision()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    identity origin_auth_rules%ROWTYPE;
    previous origin_auth_rule_revisions%ROWTYPE;
    current_identity origin_auth_credentials%ROWTYPE;
    current_revision origin_auth_credential_revisions%ROWTYPE;
    previous_identity origin_auth_credentials%ROWTYPE;
    previous_revision origin_auth_credential_revisions%ROWTYPE;
    expected_action text;
    effective_at timestamptz;
    endpoint_host text;
BEGIN
    SELECT * INTO identity FROM origin_auth_rules WHERE id = NEW.rule_id;
    SELECT * INTO previous FROM origin_auth_rule_revisions
    WHERE rule_id = NEW.rule_id ORDER BY revision DESC LIMIT 1;
    SELECT * INTO current_identity FROM origin_auth_credentials WHERE id = NEW.current_credential_id;
    SELECT * INTO current_revision FROM origin_auth_credential_revisions
    WHERE credential_id = NEW.current_credential_id AND revision = NEW.current_credential_revision;
    IF NEW.previous_credential_id IS NOT NULL THEN
        SELECT * INTO previous_identity FROM origin_auth_credentials WHERE id = NEW.previous_credential_id;
        SELECT * INTO previous_revision FROM origin_auth_credential_revisions
        WHERE credential_id = NEW.previous_credential_id AND revision = NEW.previous_credential_revision;
    END IF;
    expected_action := 'origin_auth.rule.' || NEW.operation;
    endpoint_host := substring(NEW.endpoint FROM 9);
    IF identity.id IS NULL OR NEW.revision <> COALESCE(previous.revision, 0) + 1 OR
       current_revision.revision_ref IS DISTINCT FROM NEW.current_credential_revision_ref OR
       current_identity.tenant_scope_id <> identity.tenant_scope_id OR current_identity.provider <> NEW.provider OR
       (NEW.previous_credential_id IS NOT NULL AND
          (previous_revision.revision_ref IS DISTINCT FROM NEW.previous_credential_revision_ref OR
           previous_identity.tenant_scope_id <> identity.tenant_scope_id OR previous_identity.provider <> NEW.provider)) OR
       NOT origin_auth_actor_has_permission(NEW.created_by_scope_id, NEW.created_by_user_id, 'origin_auth.manage') OR
       NOT origin_auth_has_pending_write(identity.tenant_scope_id, NEW.created_by_scope_id,
           NEW.created_by_user_id, expected_action, NEW.request_id, NEW.trace_id) OR
       NOT origin_auth_has_audit(identity.tenant_scope_id, NEW.created_by_user_id, expected_action,
           'origin_auth_rule', NEW.rule_id::text, NEW.request_id, NEW.trace_id) THEN
        RAISE EXCEPTION 'invalid origin authentication rule revision';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM site_origins source
        WHERE source.site_id = identity.site_id AND source.position = identity.source_position
          AND source.port = 443 AND NEW.endpoint = 'https://' || source.host
    ) THEN
        RAISE EXCEPTION 'origin authentication endpoint does not match the bound site source';
    END IF;
    IF octet_length(endpoint_host) > 253 OR endpoint_host ~ '^[0-9]+(\.[0-9]+){3}$' OR
       endpoint_host = 'localhost' OR endpoint_host = 'metadata.google.internal' OR
       endpoint_host ~ '\.(localhost|local|internal)$' OR endpoint_host ~ '(^|\.)-' OR
       endpoint_host ~ '-(\.|$)' OR position('..' IN endpoint_host) > 0 THEN
        RAISE EXCEPTION 'invalid origin authentication endpoint host';
    END IF;
    IF NOT NEW.deleted AND EXISTS (
        SELECT 1
        FROM origin_auth_rules other_identity
        JOIN LATERAL (
            SELECT other_revision.* FROM origin_auth_rule_revisions other_revision
            WHERE other_revision.rule_id = other_identity.id
            ORDER BY other_revision.revision DESC LIMIT 1
        ) current ON true
        WHERE other_identity.id <> NEW.rule_id
          AND other_identity.tenant_scope_id = identity.tenant_scope_id
          AND other_identity.site_id = identity.site_id
          AND other_identity.source_position = identity.source_position
          AND NOT current.deleted
    ) THEN
        RAISE EXCEPTION 'origin authentication source already has a live rule';
    END IF;
    IF (NEW.provider = 's3' AND (NEW.algorithm <> 'aws4-hmac-sha256' OR NEW.bucket <> '' OR NEW.service <> 's3')) OR
       (NEW.provider = 'oss' AND (NEW.algorithm <> 'oss4-hmac-sha256' OR NEW.service <> 'oss' OR
          NEW.bucket !~ '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$' OR
          NEW.endpoint <> 'https://' || NEW.bucket || '.oss-' || NEW.region || '.aliyuncs.com' OR
          NEW.egress_policy_reference IS NOT NULL)) OR
       (NEW.provider = 'cos' AND (NEW.algorithm <> 'cos-hmac-sha1' OR NEW.service <> 'cos' OR NEW.bucket <> '' OR
          NEW.endpoint !~ ('^https://[a-z0-9][a-z0-9-]*-[0-9]+\.cos\.' ||
                           replace(NEW.region, '-', '\-') || '\.myqcloud\.com$') OR
          NEW.egress_policy_reference IS NOT NULL)) THEN
        RAISE EXCEPTION 'invalid origin authentication provider binding';
    END IF;
    IF NEW.provider = 's3' AND NEW.egress_policy_reference IS NULL AND
       (endpoint_host !~ ('^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3\.' ||
                          replace(NEW.region, '-', '\-') || '\.amazonaws\.com$') OR
        split_part(endpoint_host, '.s3.', 1) ~ '^[0-9]+(\.[0-9]+){3}$') THEN
        RAISE EXCEPTION 'S3-compatible endpoint requires an egress policy reference';
    END IF;
    IF NEW.activate_current_at IS NOT NULL AND
       (NEW.activate_current_at <= NEW.created_at OR NEW.activate_current_at > NEW.created_at + interval '30 days') THEN
        RAISE EXCEPTION 'invalid origin authentication rotation time';
    END IF;
    IF NEW.revision = 1 THEN
        IF NEW.operation <> 'create' THEN
            RAISE EXCEPTION 'invalid origin authentication rule initial state';
        END IF;
    ELSE
        IF previous.deleted OR NEW.operation = 'create' OR
           (NEW.operation = 'update' AND (NEW.enabled <> previous.enabled OR NEW.deleted <> previous.deleted OR
              ROW(NEW.current_credential_id, NEW.current_credential_revision) <>
                  ROW(previous.current_credential_id, previous.current_credential_revision))) OR
           (NEW.operation = 'enable' AND (previous.enabled OR previous.deleted OR NOT NEW.enabled OR NEW.deleted)) OR
           (NEW.operation = 'disable' AND (NOT previous.enabled OR previous.deleted OR NEW.enabled OR NEW.deleted)) OR
           (NEW.operation = 'rotate' AND (NEW.enabled <> previous.enabled OR NEW.deleted <> previous.deleted OR
              ROW(NEW.previous_credential_id, NEW.previous_credential_revision) <>
                  ROW(previous.current_credential_id, previous.current_credential_revision))) OR
           (NEW.operation = 'delete' AND (previous.deleted OR NEW.enabled OR NOT NEW.deleted)) THEN
            RAISE EXCEPTION 'invalid origin authentication rule state transition';
        END IF;
    END IF;
    IF NEW.enabled AND NOT NEW.deleted THEN
        effective_at := COALESCE(NEW.activate_current_at, NEW.created_at);
        IF current_revision.status <> 'verified' OR current_revision.not_before > effective_at OR
           current_revision.expires_at <= effective_at + make_interval(secs => NEW.signature_ttl_seconds) OR
           (NEW.previous_credential_id IS NOT NULL AND
              (previous_revision.status <> 'verified' OR previous_revision.not_before > NEW.created_at OR
               previous_revision.expires_at <= NEW.activate_current_at + make_interval(secs => NEW.signature_ttl_seconds))) THEN
            RAISE EXCEPTION 'active origin authentication rule requires verified active credentials';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER origin_auth_rule_revisions_validate
BEFORE INSERT ON origin_auth_rule_revisions
FOR EACH ROW EXECUTE FUNCTION validate_origin_auth_rule_revision();

CREATE FUNCTION validate_origin_auth_publication()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    scope_tenant uuid;
    latest_revision bigint;
    latest_sha bytea;
    document jsonb;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('origin-auth-publication:' || NEW.tenant_scope_id::text, 0));
    SELECT tenant_id INTO scope_tenant FROM access_scopes
    WHERE id = NEW.tenant_scope_id AND kind = 'tenant';
    SELECT publication.revision, publication.snapshot_sha256 INTO latest_revision, latest_sha
    FROM origin_auth_publications publication
    WHERE publication.tenant_scope_id = NEW.tenant_scope_id
    ORDER BY publication.revision DESC LIMIT 1;
    BEGIN
        document := convert_from(NEW.canonical_snapshot, 'UTF8')::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'invalid origin authentication publication JSON';
    END;
    IF scope_tenant IS NULL OR NEW.tenant_id <> scope_tenant OR
       NEW.revision <> COALESCE(latest_revision, 0) + 1 OR
       NEW.previous_sha256 IS DISTINCT FROM latest_sha OR
       NEW.snapshot_sha256 <> sha256(NEW.canonical_snapshot) OR
       document->>'schema_version' <> NEW.schema_version OR
       document->>'tenant_scope_id' <> NEW.tenant_scope_id::text OR
       (document->>'publication_revision')::bigint <> NEW.revision OR
       jsonb_typeof(document->'rules') <> 'array' OR
       convert_from(NEW.canonical_snapshot, 'UTF8') ~
          '"(access_key_id|secret_access_key|session_token|ciphertext|envelope_key_id|sha256|digest)"' OR
       NOT origin_auth_actor_has_permission(NEW.created_by_scope_id, NEW.created_by_user_id, 'origin_auth.manage') OR
       NOT origin_auth_has_pending_write(NEW.tenant_scope_id, NEW.created_by_scope_id,
           NEW.created_by_user_id, 'origin_auth.publication.create', NEW.request_id, NEW.trace_id) OR
       NOT origin_auth_has_audit(NEW.tenant_scope_id, NEW.created_by_user_id,
           'origin_auth.publication.create', 'origin_auth_publication', NEW.id::text,
           NEW.request_id, NEW.trace_id) THEN
        RAISE EXCEPTION 'invalid origin authentication publication';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER origin_auth_publications_validate
BEFORE INSERT ON origin_auth_publications
FOR EACH ROW EXECUTE FUNCTION validate_origin_auth_publication();

CREATE FUNCTION protect_origin_auth_write_request()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' OR
       ROW(NEW.id, NEW.actor_scope_id, NEW.actor_user_id, NEW.target_scope_id, NEW.operation,
           NEW.idempotency_key, NEW.request_digest, NEW.request_id, NEW.trace_id, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.actor_scope_id, OLD.actor_user_id, OLD.target_scope_id, OLD.operation,
           OLD.idempotency_key, OLD.request_digest, OLD.request_id, OLD.trace_id, OLD.created_at) OR
       OLD.completed_at IS NOT NULL OR NEW.completed_at IS NULL THEN
        RAISE EXCEPTION 'origin authentication write request is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER origin_auth_write_requests_protected
BEFORE UPDATE OR DELETE ON origin_auth_write_requests
FOR EACH ROW EXECUTE FUNCTION protect_origin_auth_write_request();

CREATE FUNCTION prevent_origin_auth_fact_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'origin authentication facts are append-only';
END;
$$;

CREATE TRIGGER origin_auth_credentials_append_only
BEFORE UPDATE OR DELETE ON origin_auth_credentials
FOR EACH ROW EXECUTE FUNCTION prevent_origin_auth_fact_mutation();
CREATE TRIGGER origin_auth_credential_revisions_append_only
BEFORE UPDATE OR DELETE ON origin_auth_credential_revisions
FOR EACH ROW EXECUTE FUNCTION prevent_origin_auth_fact_mutation();
CREATE TRIGGER origin_auth_rules_append_only
BEFORE UPDATE OR DELETE ON origin_auth_rules
FOR EACH ROW EXECUTE FUNCTION prevent_origin_auth_fact_mutation();
CREATE TRIGGER origin_auth_rule_revisions_append_only
BEFORE UPDATE OR DELETE ON origin_auth_rule_revisions
FOR EACH ROW EXECUTE FUNCTION prevent_origin_auth_fact_mutation();
CREATE TRIGGER origin_auth_publications_append_only
BEFORE UPDATE OR DELETE ON origin_auth_publications
FOR EACH ROW EXECUTE FUNCTION prevent_origin_auth_fact_mutation();

CREATE FUNCTION prevent_origin_auth_truncate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'origin authentication facts cannot be truncated';
END;
$$;

CREATE TRIGGER origin_auth_credentials_no_truncate
BEFORE TRUNCATE ON origin_auth_credentials
FOR EACH STATEMENT EXECUTE FUNCTION prevent_origin_auth_truncate();
CREATE TRIGGER origin_auth_credential_revisions_no_truncate
BEFORE TRUNCATE ON origin_auth_credential_revisions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_origin_auth_truncate();
CREATE TRIGGER origin_auth_rules_no_truncate
BEFORE TRUNCATE ON origin_auth_rules
FOR EACH STATEMENT EXECUTE FUNCTION prevent_origin_auth_truncate();
CREATE TRIGGER origin_auth_rule_revisions_no_truncate
BEFORE TRUNCATE ON origin_auth_rule_revisions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_origin_auth_truncate();
CREATE TRIGGER origin_auth_publications_no_truncate
BEFORE TRUNCATE ON origin_auth_publications
FOR EACH STATEMENT EXECUTE FUNCTION prevent_origin_auth_truncate();
CREATE TRIGGER origin_auth_write_requests_no_truncate
BEFORE TRUNCATE ON origin_auth_write_requests
FOR EACH STATEMENT EXECUTE FUNCTION prevent_origin_auth_truncate();
