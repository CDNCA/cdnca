INSERT INTO permissions (name, description) VALUES
    ('error_pages.read', 'Read custom error page assets, rules, and publication snapshots'),
    ('error_pages.manage', 'Manage custom error page assets and rules');

INSERT INTO custom_rbac_permission_catalog (permission_name, step_up_required) VALUES
    ('error_pages.read', false),
    ('error_pages.manage', true);

INSERT INTO role_permissions (role_id, permission_name)
SELECT role.id, permission.name
FROM roles role
JOIN permissions permission ON permission.name IN ('error_pages.read', 'error_pages.manage')
WHERE role.system_role AND role.name IN ('platform_owner', 'tenant_owner')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_name)
SELECT role.id, 'error_pages.read'
FROM roles role
WHERE role.system_role AND role.name = 'tenant_viewer'
ON CONFLICT DO NOTHING;

CREATE FUNCTION grant_error_page_permissions_054()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT NEW.system_role THEN
        RETURN NEW;
    END IF;
    IF NEW.name IN ('platform_owner', 'tenant_owner') THEN
        INSERT INTO role_permissions (role_id, permission_name) VALUES
            (NEW.id, 'error_pages.read'),
            (NEW.id, 'error_pages.manage')
        ON CONFLICT DO NOTHING;
    ELSIF NEW.name = 'tenant_viewer' THEN
        INSERT INTO role_permissions (role_id, permission_name)
        VALUES (NEW.id, 'error_pages.read')
        ON CONFLICT DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER roles_error_page_permissions_054
AFTER INSERT ON roles
FOR EACH ROW EXECUTE FUNCTION grant_error_page_permissions_054();

CREATE TABLE error_page_assets (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    tenant_id uuid REFERENCES tenants(id) ON DELETE RESTRICT,
    mime_type text NOT NULL CHECK (mime_type IN ('text/html', 'text/plain', 'application/json')),
    size_bytes bigint NOT NULL CHECK (size_bytes BETWEEN 1 AND 1048576),
    sha256 bytea NOT NULL CHECK (octet_length(sha256) = 32),
    staging_object_key text NOT NULL CHECK (
        octet_length(staging_object_key) BETWEEN 1 AND 512 AND
        staging_object_key ~ '^[A-Za-z0-9][A-Za-z0-9._/-]*$' AND
        staging_object_key !~ '(^/|//|(^|/)\.\.(/|$)|\\)'
    ),
    storage_object_key text NOT NULL CHECK (
        octet_length(storage_object_key) BETWEEN 1 AND 512 AND
        storage_object_key ~ '^[A-Za-z0-9][A-Za-z0-9._/-]*$' AND
        storage_object_key !~ '(^/|//|(^|/)\.\.(/|$)|\\)'
    ),
    status text NOT NULL CHECK (status IN (
        'initiated', 'staged', 'scan_failed', 'finalizing', 'ready',
        'rejected', 'delete_pending', 'deleted', 'orphaned'
    )),
    scan_status text NOT NULL CHECK (scan_status IN ('pending', 'passed', 'rejected', 'error')),
    object_state text NOT NULL CHECK (object_state IN ('none', 'staging', 'final', 'cleanup_pending', 'absent')),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_by_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    created_request_id text NOT NULL CHECK (created_request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    created_trace_id text NOT NULL CHECK (created_trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    deleted_at timestamptz,
    FOREIGN KEY (created_by_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (updated_at >= created_at),
    CHECK (
        (status = 'initiated' AND scan_status = 'pending' AND object_state = 'none' AND deleted_at IS NULL) OR
        (status = 'staged' AND scan_status = 'pending' AND object_state = 'staging' AND deleted_at IS NULL) OR
        (status = 'scan_failed' AND scan_status = 'error' AND object_state = 'staging' AND deleted_at IS NULL) OR
        (status = 'finalizing' AND scan_status = 'passed' AND object_state = 'staging' AND deleted_at IS NULL) OR
        (status = 'ready' AND scan_status = 'passed' AND object_state = 'final' AND deleted_at IS NULL) OR
        (status = 'rejected' AND scan_status = 'rejected' AND object_state IN ('cleanup_pending', 'absent') AND deleted_at IS NOT NULL) OR
        (status = 'delete_pending' AND object_state = 'cleanup_pending' AND deleted_at IS NOT NULL) OR
        (status IN ('deleted', 'orphaned') AND object_state = 'absent' AND deleted_at IS NOT NULL)
    )
);

CREATE INDEX error_page_assets_scope_page_idx
    ON error_page_assets (scope_id, created_at DESC, id DESC);
CREATE UNIQUE INDEX error_page_assets_scope_digest_live_idx
    ON error_page_assets (scope_id, sha256)
    WHERE status NOT IN ('rejected', 'deleted', 'orphaned');
CREATE INDEX error_page_assets_reconcile_idx
    ON error_page_assets (status, updated_at, id)
    WHERE status IN ('initiated', 'finalizing', 'rejected', 'delete_pending', 'orphaned');

CREATE TABLE error_page_asset_scan_facts (
    id uuid PRIMARY KEY,
    asset_id uuid NOT NULL REFERENCES error_page_assets(id) ON DELETE RESTRICT,
    attempt bigint NOT NULL CHECK (attempt > 0),
    scanner text NOT NULL CHECK (scanner ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    result text NOT NULL CHECK (result IN ('passed', 'rejected', 'error')),
    content_size bigint NOT NULL CHECK (content_size BETWEEN 1 AND 1048576),
    content_sha256 bytea NOT NULL CHECK (octet_length(content_sha256) = 32),
    error_code text CHECK (error_code IS NULL OR error_code ~ '^[a-z][a-z0-9._-]{0,63}$'),
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    trace_id text NOT NULL CHECK (trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    scanned_at timestamptz NOT NULL,
    UNIQUE (asset_id, attempt),
    CHECK ((result = 'passed' AND error_code IS NULL) OR
           (result <> 'passed' AND error_code IS NOT NULL))
);

CREATE TABLE error_page_rules (
    id uuid PRIMARY KEY,
    scope_kind text NOT NULL CHECK (scope_kind IN ('global', 'site')),
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    tenant_id uuid REFERENCES tenants(id) ON DELETE RESTRICT,
    site_id uuid REFERENCES sites(id) ON DELETE RESTRICT,
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_by_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    FOREIGN KEY (created_by_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK ((scope_kind = 'global' AND tenant_id IS NULL AND site_id IS NULL) OR
           (scope_kind = 'site' AND tenant_id IS NOT NULL AND site_id IS NOT NULL))
);

CREATE INDEX error_page_rules_scope_page_idx
    ON error_page_rules (scope_id, created_at DESC, id DESC);

CREATE TABLE error_page_rule_revisions (
    rule_id uuid NOT NULL REFERENCES error_page_rules(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    category text NOT NULL CHECK (category IN (
        'origin_response', 'edge_route', 'edge_connect', 'no_host', 'unknown_site'
    )),
    match_kind text NOT NULL CHECK (match_kind IN ('exact', 'range')),
    code_from integer NOT NULL CHECK (code_from BETWEEN 400 AND 599),
    code_to integer NOT NULL CHECK (code_to BETWEEN 400 AND 599 AND code_to >= code_from),
    priority integer GENERATED ALWAYS AS (code_to - code_from + 1) STORED,
    asset_id uuid NOT NULL REFERENCES error_page_assets(id) ON DELETE RESTRICT,
    enabled boolean NOT NULL,
    deleted boolean NOT NULL DEFAULT false,
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_by_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    trace_id text NOT NULL CHECK (trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (rule_id, revision),
    FOREIGN KEY (created_by_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK ((match_kind = 'exact' AND code_from = code_to) OR match_kind = 'range'),
    CHECK (NOT deleted OR NOT enabled),
    CHECK ((category IN ('origin_response', 'edge_route')) OR
           (category = 'edge_connect' AND code_from >= 502 AND code_to <= 504) OR
           (category = 'no_host' AND code_from = 400 AND code_to = 400) OR
           (category = 'unknown_site' AND code_from = 404 AND code_to = 404))
);

CREATE INDEX error_page_rule_revisions_asset_idx ON error_page_rule_revisions (asset_id);

CREATE TABLE error_page_publications (
    revision bigint PRIMARY KEY CHECK (revision > 0),
    platform_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    schema text NOT NULL CHECK (schema = 'cdnca.error-pages/v1'),
    version text NOT NULL CHECK (version ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    canonical_snapshot bytea NOT NULL CHECK (octet_length(canonical_snapshot) BETWEEN 1 AND 8388608),
    snapshot_sha256 bytea NOT NULL CHECK (octet_length(snapshot_sha256) = 32),
    previous_sha256 bytea CHECK (previous_sha256 IS NULL OR octet_length(previous_sha256) = 32),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_by_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    trace_id text NOT NULL CHECK (trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    created_at timestamptz NOT NULL,
    FOREIGN KEY (created_by_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

CREATE TABLE error_page_write_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN (
        'error_page.asset.initiate', 'error_page.asset.upload', 'error_page.asset.finalize',
        'error_page.asset.delete', 'error_page.rule.create', 'error_page.rule.update',
        'error_page.rule.enable', 'error_page.rule.disable', 'error_page.rule.delete'
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
    CHECK ((completed_at IS NULL AND resource_id IS NULL AND response_status IS NULL AND response_body IS NULL) OR
           (completed_at IS NOT NULL AND resource_id IS NOT NULL AND response_status IS NOT NULL AND
            response_body IS NOT NULL AND completed_at >= created_at))
);

CREATE INDEX error_page_write_requests_scope_created_idx
    ON error_page_write_requests (target_scope_id, created_at DESC);

CREATE FUNCTION error_page_actor_has_permission(actor_scope uuid, actor_user uuid, requested_permission text)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM memberships membership
        JOIN role_assignments assignment
          ON assignment.scope_id = membership.scope_id AND assignment.user_id = membership.user_id
        JOIN role_permissions grant_row ON grant_row.role_id = assignment.role_id
        WHERE membership.scope_id = actor_scope
          AND membership.user_id = actor_user
          AND membership.status = 'active'
          AND grant_row.permission_name = requested_permission
    )
$$;

CREATE FUNCTION validate_error_page_asset_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    scope_kind text;
    scope_tenant uuid;
BEGIN
    SELECT kind, tenant_id INTO scope_kind, scope_tenant FROM access_scopes WHERE id = NEW.scope_id;
    IF NOT FOUND OR NEW.status <> 'initiated' OR NEW.scan_status <> 'pending' OR NEW.object_state <> 'none' OR
       NEW.revision <> 1 OR NEW.deleted_at IS NOT NULL OR NEW.updated_at <> NEW.created_at OR
       ((scope_kind = 'platform') IS DISTINCT FROM (NEW.tenant_id IS NULL)) OR
       (scope_kind = 'tenant' AND NEW.tenant_id IS DISTINCT FROM scope_tenant) OR
       NOT error_page_actor_has_permission(NEW.created_by_scope_id, NEW.created_by_user_id, 'error_pages.manage') OR
       (scope_kind = 'platform' AND NEW.created_by_scope_id <> NEW.scope_id) OR
       (scope_kind = 'tenant' AND NEW.created_by_scope_id <> NEW.scope_id AND NOT EXISTS (
           SELECT 1 FROM access_scopes actor_scope
           WHERE actor_scope.id = NEW.created_by_scope_id AND actor_scope.kind = 'platform'
       )) THEN
        RAISE EXCEPTION 'invalid error page asset insert';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER error_page_assets_validate_insert
BEFORE INSERT ON error_page_assets
FOR EACH ROW EXECUTE FUNCTION validate_error_page_asset_insert();

CREATE FUNCTION protect_error_page_asset_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    latest_scan text;
BEGIN
    IF TG_OP = 'DELETE' OR
       ROW(NEW.id, NEW.scope_id, NEW.tenant_id, NEW.mime_type, NEW.size_bytes, NEW.sha256,
           NEW.staging_object_key, NEW.storage_object_key, NEW.created_by_user_id,
           NEW.created_by_scope_id, NEW.created_request_id, NEW.created_trace_id, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.scope_id, OLD.tenant_id, OLD.mime_type, OLD.size_bytes, OLD.sha256,
           OLD.staging_object_key, OLD.storage_object_key, OLD.created_by_user_id,
           OLD.created_by_scope_id, OLD.created_request_id, OLD.created_trace_id, OLD.created_at) OR
       NEW.revision <> OLD.revision + 1 OR NEW.updated_at < OLD.updated_at OR NOT (
           (OLD.status = 'initiated' AND NEW.status IN ('staged', 'delete_pending', 'orphaned')) OR
           (OLD.status IN ('staged', 'scan_failed') AND NEW.status IN ('scan_failed', 'finalizing', 'rejected', 'delete_pending', 'orphaned')) OR
           (OLD.status = 'finalizing' AND NEW.status IN ('ready', 'delete_pending', 'orphaned')) OR
           (OLD.status = 'ready' AND NEW.status = 'delete_pending') OR
           (OLD.status = 'rejected' AND NEW.status IN ('rejected', 'orphaned')) OR
           (OLD.status = 'delete_pending' AND NEW.status IN ('deleted', 'orphaned')) OR
           (OLD.status = 'orphaned' AND NEW.status = 'orphaned')
       ) THEN
        RAISE EXCEPTION 'invalid error page asset transition';
    END IF;
    IF NEW.status IN ('scan_failed', 'finalizing', 'rejected') THEN
        SELECT result INTO latest_scan
        FROM error_page_asset_scan_facts
        WHERE asset_id = NEW.id
        ORDER BY attempt DESC LIMIT 1;
        IF latest_scan IS DISTINCT FROM (CASE NEW.status
            WHEN 'scan_failed' THEN 'error'
            WHEN 'finalizing' THEN 'passed'
            WHEN 'rejected' THEN 'rejected'
        END) THEN
            RAISE EXCEPTION 'error page asset transition requires matching scan fact';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER error_page_assets_protect_update
BEFORE UPDATE OR DELETE ON error_page_assets
FOR EACH ROW EXECUTE FUNCTION protect_error_page_asset_update();

CREATE FUNCTION validate_error_page_scan_fact()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    asset error_page_assets%ROWTYPE;
    expected_attempt bigint;
BEGIN
    SELECT * INTO asset FROM error_page_assets WHERE id = NEW.asset_id FOR UPDATE;
    SELECT COALESCE(max(attempt), 0) + 1 INTO expected_attempt
    FROM error_page_asset_scan_facts WHERE asset_id = NEW.asset_id;
    IF NOT FOUND OR asset.status NOT IN ('staged', 'scan_failed') OR
       NEW.attempt <> expected_attempt OR NEW.content_size <> asset.size_bytes OR
       NEW.content_sha256 <> asset.sha256 THEN
        RAISE EXCEPTION 'invalid error page scan fact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER error_page_asset_scan_facts_validate
BEFORE INSERT ON error_page_asset_scan_facts
FOR EACH ROW EXECUTE FUNCTION validate_error_page_scan_fact();

CREATE FUNCTION validate_error_page_rule_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    scope_kind_value text;
    scope_tenant uuid;
    site_scope uuid;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('error-page-publication', 0));
    SELECT kind, tenant_id INTO scope_kind_value, scope_tenant FROM access_scopes WHERE id = NEW.scope_id;
    IF NOT FOUND OR NOT error_page_actor_has_permission(
        NEW.created_by_scope_id, NEW.created_by_user_id, 'error_pages.manage'
    ) THEN
        RAISE EXCEPTION 'invalid error page rule actor';
    END IF;
    IF NEW.scope_kind = 'global' THEN
        IF scope_kind_value <> 'platform' OR NEW.created_by_scope_id <> NEW.scope_id THEN
            RAISE EXCEPTION 'global error page rules require platform scope';
        END IF;
    ELSE
        SELECT scope_id INTO site_scope FROM sites
        WHERE id = NEW.site_id AND deleted_at IS NULL
        FOR SHARE;
        IF scope_kind_value <> 'tenant' OR NEW.tenant_id IS DISTINCT FROM scope_tenant OR
           site_scope IS DISTINCT FROM NEW.scope_id OR
           (NEW.created_by_scope_id <> NEW.scope_id AND NOT EXISTS (
               SELECT 1 FROM access_scopes actor_scope
               WHERE actor_scope.id = NEW.created_by_scope_id AND actor_scope.kind = 'platform'
           )) THEN
            RAISE EXCEPTION 'site error page rule scope mismatch';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER error_page_rules_validate_insert
BEFORE INSERT ON error_page_rules
FOR EACH ROW EXECUTE FUNCTION validate_error_page_rule_identity();

CREATE FUNCTION validate_error_page_rule_revision()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    identity error_page_rules%ROWTYPE;
    previous error_page_rule_revisions%ROWTYPE;
    asset error_page_assets%ROWTYPE;
    site_scope uuid;
    precedence_priority integer;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('error-page-publication', 0));
    SELECT * INTO identity FROM error_page_rules WHERE id = NEW.rule_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'error page rule identity is missing';
    END IF;
    SELECT * INTO previous FROM error_page_rule_revisions
    WHERE rule_id = NEW.rule_id ORDER BY revision DESC LIMIT 1;
    IF NEW.revision <> COALESCE(previous.revision, 0) + 1 OR
       (previous.revision IS NOT NULL AND previous.deleted) OR
       NEW.created_by_scope_id <> identity.scope_id AND NOT EXISTS (
           SELECT 1 FROM access_scopes actor_scope
           WHERE actor_scope.id = NEW.created_by_scope_id AND actor_scope.kind = 'platform'
       ) OR
       NOT error_page_actor_has_permission(NEW.created_by_scope_id, NEW.created_by_user_id, 'error_pages.manage') THEN
        RAISE EXCEPTION 'invalid error page rule revision';
    END IF;
    IF identity.scope_kind = 'site' AND NEW.category IN ('no_host', 'unknown_site') THEN
        RAISE EXCEPTION 'default server categories are global only';
    END IF;
    IF identity.scope_kind = 'site' AND NOT NEW.deleted THEN
        SELECT scope_id INTO site_scope FROM sites
        WHERE id = identity.site_id AND deleted_at IS NULL
        FOR SHARE;
        IF NOT FOUND OR site_scope IS DISTINCT FROM identity.scope_id THEN
            RAISE EXCEPTION 'non-deleted error page rule requires an active site in the same scope';
        END IF;
    END IF;
    precedence_priority := NEW.code_to - NEW.code_from + 1;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'error-page-rule-conflict:' || identity.scope_kind || ':' || identity.scope_id::text || ':' ||
        COALESCE(identity.site_id::text, 'global') || ':' || NEW.category || ':' || precedence_priority::text,
        0
    ));
    SELECT * INTO asset FROM error_page_assets WHERE id = NEW.asset_id;
    IF NOT FOUND OR asset.scope_id <> identity.scope_id OR (NEW.enabled AND NOT NEW.deleted AND asset.status <> 'ready') THEN
        RAISE EXCEPTION 'error page rule asset is not ready in the same scope';
    END IF;
    IF NEW.enabled AND NOT NEW.deleted AND EXISTS (
        SELECT 1
        FROM error_page_rules other_identity
        JOIN LATERAL (
            SELECT other_revision.* FROM error_page_rule_revisions other_revision
            WHERE other_revision.rule_id = other_identity.id
            ORDER BY other_revision.revision DESC LIMIT 1
        ) current ON true
        WHERE other_identity.id <> NEW.rule_id
          AND other_identity.scope_kind = identity.scope_kind
          AND other_identity.scope_id = identity.scope_id
          AND other_identity.site_id IS NOT DISTINCT FROM identity.site_id
          AND current.enabled AND NOT current.deleted
          AND current.category = NEW.category
          AND current.priority = precedence_priority
          AND int4range(current.code_from, current.code_to, '[]') && int4range(NEW.code_from, NEW.code_to, '[]')
    ) THEN
        RAISE EXCEPTION 'ambiguous active error page rule priority';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER error_page_rule_revisions_validate
BEFORE INSERT ON error_page_rule_revisions
FOR EACH ROW EXECUTE FUNCTION validate_error_page_rule_revision();

CREATE FUNCTION validate_error_page_publication()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    latest_revision bigint;
    latest_sha bytea;
    document jsonb;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('error-page-publication', 0));
    SELECT revision, snapshot_sha256 INTO latest_revision, latest_sha
    FROM error_page_publications ORDER BY revision DESC LIMIT 1;
    IF NEW.revision <> COALESCE(latest_revision, 0) + 1 OR
       NEW.previous_sha256 IS DISTINCT FROM latest_sha OR
       NEW.snapshot_sha256 IS DISTINCT FROM sha256(NEW.canonical_snapshot) OR
       NOT EXISTS (SELECT 1 FROM access_scopes WHERE id = NEW.platform_scope_id AND kind = 'platform') THEN
        RAISE EXCEPTION 'invalid error page publication sequence';
    END IF;
    BEGIN
        document := convert_from(NEW.canonical_snapshot, 'UTF8')::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'invalid error page publication JSON';
    END;
    IF document->>'schema' IS DISTINCT FROM NEW.schema OR
       document->>'version' IS DISTINCT FROM NEW.version OR
       (document->>'revision')::bigint IS DISTINCT FROM NEW.revision OR
       jsonb_typeof(document->'global') IS DISTINCT FROM 'object' OR
       jsonb_typeof(document->'sites') IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'error page publication envelope mismatch';
    END IF;
    IF jsonb_array_length(document->'sites') > 256 THEN
        RAISE EXCEPTION 'error page publication site limit exceeded';
    END IF;
    PERFORM site.id
    FROM sites site
    JOIN (
        SELECT DISTINCT site_document->>'site_key' AS site_key
        FROM jsonb_array_elements(document->'sites') site_document
        WHERE jsonb_typeof(site_document) = 'object'
    ) referenced_site ON referenced_site.site_key = site.id::text
    ORDER BY site.id
    FOR SHARE OF site;
    IF EXISTS (
        SELECT 1
        FROM jsonb_array_elements(document->'sites') site_document
        WHERE jsonb_typeof(site_document) IS DISTINCT FROM 'object'
           OR NOT EXISTS (
               SELECT 1 FROM sites site
               WHERE site.id::text = site_document->>'site_key'
                 AND site.deleted_at IS NULL
           )
    ) THEN
        RAISE EXCEPTION 'error page publication references an inactive site';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER error_page_publications_validate
BEFORE INSERT ON error_page_publications
FOR EACH ROW EXECUTE FUNCTION validate_error_page_publication();

CREATE FUNCTION protect_error_page_write_request()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' OR
       ROW(NEW.id, NEW.actor_user_id, NEW.actor_scope_id, NEW.target_scope_id, NEW.operation,
           NEW.idempotency_key, NEW.request_digest, NEW.request_id, NEW.trace_id, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.actor_user_id, OLD.actor_scope_id, OLD.target_scope_id, OLD.operation,
           OLD.idempotency_key, OLD.request_digest, OLD.request_id, OLD.trace_id, OLD.created_at) OR
       OLD.completed_at IS NOT NULL OR NEW.completed_at IS NULL OR NEW.resource_id IS NULL OR
       NEW.response_status IS NULL OR NEW.response_body IS NULL THEN
        RAISE EXCEPTION 'invalid error page write request transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER error_page_write_requests_protected
BEFORE UPDATE OR DELETE ON error_page_write_requests
FOR EACH ROW EXECUTE FUNCTION protect_error_page_write_request();

CREATE FUNCTION prevent_error_page_fact_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'error page facts are append-only';
END;
$$;

CREATE TRIGGER error_page_rules_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON error_page_rules
FOR EACH STATEMENT EXECUTE FUNCTION prevent_error_page_fact_mutation();
CREATE TRIGGER error_page_rule_revisions_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON error_page_rule_revisions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_error_page_fact_mutation();
CREATE TRIGGER error_page_asset_scan_facts_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON error_page_asset_scan_facts
FOR EACH STATEMENT EXECUTE FUNCTION prevent_error_page_fact_mutation();
CREATE TRIGGER error_page_publications_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON error_page_publications
FOR EACH STATEMENT EXECUTE FUNCTION prevent_error_page_fact_mutation();

CREATE FUNCTION prevent_error_page_truncate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'error page table % cannot be truncated', TG_TABLE_NAME;
END;
$$;

CREATE TRIGGER error_page_assets_no_truncate
BEFORE TRUNCATE ON error_page_assets
FOR EACH STATEMENT EXECUTE FUNCTION prevent_error_page_truncate();
CREATE TRIGGER error_page_write_requests_no_truncate
BEFORE TRUNCATE ON error_page_write_requests
FOR EACH STATEMENT EXECUTE FUNCTION prevent_error_page_truncate();
