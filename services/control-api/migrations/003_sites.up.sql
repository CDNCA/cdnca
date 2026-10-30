INSERT INTO permissions (name, description) VALUES
    ('sites.read', 'Read websites in the active tenant scope'),
    ('sites.manage', 'Create, edit, and delete websites in the active tenant scope');

CREATE TABLE sites (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    domain text NOT NULL CHECK (
        domain = lower(btrim(domain)) AND
        char_length(domain) BETWEEN 1 AND 253
    ),
    http_ports text[] NOT NULL DEFAULT ARRAY['80']::text[] CHECK (cardinality(http_ports) > 0),
    https_ports text[] NOT NULL DEFAULT ARRAY[]::text[],
    origins text[] NOT NULL CHECK (cardinality(origins) > 0),
    origin_hosts text[] NOT NULL CHECK (cardinality(origin_hosts) = cardinality(origins)),
    cname text NOT NULL DEFAULT '' CHECK (char_length(cname) <= 253),
    https_enabled boolean NOT NULL DEFAULT false,
    enabled boolean NOT NULL DEFAULT true,
    status text NOT NULL DEFAULT 'active' CHECK (
        status IN ('active', 'disabled', 'package_expired', 'traffic_exceeded', 'locked', 'syncing', 'sync_failed')
    ),
    sync_status text NOT NULL DEFAULT 'synced' CHECK (sync_status IN ('synced', 'pending', 'failed')),
    is_default boolean NOT NULL DEFAULT false,
    package_id uuid,
    package_name text CHECK (package_name IS NULL OR char_length(package_name) BETWEEN 1 AND 128),
    group_id uuid,
    group_name text CHECK (group_name IS NULL OR char_length(group_name) BETWEEN 1 AND 128),
    region_id uuid,
    region_name text CHECK (region_name IS NULL OR char_length(region_name) BETWEEN 1 AND 128),
    node_group_id uuid,
    node_group_name text CHECK (node_group_name IS NULL OR char_length(node_group_name) BETWEEN 1 AND 128),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz,
    CHECK ((https_enabled AND cardinality(https_ports) > 0) OR NOT https_enabled),
    CHECK ((enabled AND status <> 'disabled') OR (NOT enabled AND status = 'disabled')),
    FOREIGN KEY (scope_id, owner_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX sites_scope_domain_lower_active_idx
    ON sites (scope_id, lower(domain)) WHERE deleted_at IS NULL;
CREATE INDEX sites_scope_created_active_idx
    ON sites (scope_id, created_at DESC, id DESC) WHERE deleted_at IS NULL;
CREATE INDEX sites_owner_created_active_idx
    ON sites (owner_user_id, created_at DESC, id DESC) WHERE deleted_at IS NULL;
CREATE INDEX sites_package_active_idx ON sites (package_id) WHERE deleted_at IS NULL;
CREATE INDEX sites_group_active_idx ON sites (group_id) WHERE deleted_at IS NULL;
CREATE INDEX sites_region_active_idx ON sites (region_id) WHERE deleted_at IS NULL;
CREATE INDEX sites_node_group_active_idx ON sites (node_group_id) WHERE deleted_at IS NULL;
CREATE INDEX sites_origin_hosts_gin_idx ON sites USING gin (origin_hosts) WHERE deleted_at IS NULL;

CREATE TABLE site_write_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN ('site.create', 'site.update', 'site.delete')),
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    resource_id uuid,
    response_status integer CHECK (response_status BETWEEN 200 AND 299),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    UNIQUE (actor_user_id, operation, idempotency_key),
    CHECK (
        (completed_at IS NULL AND response_status IS NULL AND resource_id IS NULL AND response_body IS NULL) OR
        (completed_at IS NOT NULL AND response_status IS NOT NULL AND resource_id IS NOT NULL)
    )
);

CREATE INDEX site_write_requests_scope_created_idx
    ON site_write_requests (target_scope_id, created_at DESC);
