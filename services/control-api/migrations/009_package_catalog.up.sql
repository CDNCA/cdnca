INSERT INTO permissions (name, description) VALUES
    ('packages.manage', 'Manage versioned package products and package groups');

INSERT INTO role_permissions (role_id, permission_name)
SELECT roles.id, 'packages.manage'
FROM roles
WHERE roles.system_role AND roles.name = 'platform_owner'
ON CONFLICT DO NOTHING;

CREATE TABLE package_groups (
    id uuid PRIMARY KEY,
    name text NOT NULL CHECK (name = btrim(name) AND char_length(name) BETWEEN 1 AND 128),
    visible boolean NOT NULL DEFAULT true,
    sort_order integer NOT NULL DEFAULT 100 CHECK (sort_order BETWEEN 0 AND 1000000),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    deleted_at timestamptz
);

CREATE UNIQUE INDEX package_groups_name_active_unique
    ON package_groups (lower(name)) WHERE deleted_at IS NULL;

CREATE TABLE package_products (
    id uuid PRIMARY KEY,
    name text NOT NULL CHECK (name = btrim(name) AND char_length(name) BETWEEN 1 AND 128),
    enabled boolean NOT NULL DEFAULT true,
    sort_order integer NOT NULL DEFAULT 100 CHECK (sort_order BETWEEN 0 AND 1000000),
    spec jsonb NOT NULL CHECK (jsonb_typeof(spec) = 'object'),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    deleted_at timestamptz
);

CREATE UNIQUE INDEX package_products_name_active_unique
    ON package_products (lower(name)) WHERE deleted_at IS NULL;
CREATE INDEX package_products_enabled_sort_idx
    ON package_products (enabled, sort_order, created_at DESC) WHERE deleted_at IS NULL;
CREATE INDEX package_products_group_ids_gin_idx
    ON package_products USING gin ((spec -> 'group_ids')) WHERE deleted_at IS NULL;

CREATE TABLE package_product_versions (
    product_id uuid NOT NULL REFERENCES package_products(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    name text NOT NULL,
    enabled boolean NOT NULL,
    sort_order integer NOT NULL,
    spec jsonb NOT NULL CHECK (jsonb_typeof(spec) = 'object'),
    deleted boolean NOT NULL DEFAULT false,
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (product_id, revision)
);

CREATE FUNCTION prevent_package_product_version_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'package product versions are append-only';
END;
$$;

CREATE TRIGGER package_product_versions_append_only
BEFORE UPDATE OR DELETE ON package_product_versions
FOR EACH ROW EXECUTE FUNCTION prevent_package_product_version_mutation();

CREATE TABLE package_catalog_write_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN (
        'package.group.create',
        'package.group.update',
        'package.group.delete',
        'package.product.create',
        'package.product.update',
        'package.product.delete'
    )),
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    resource_id uuid,
    response_status integer CHECK (response_status BETWEEN 200 AND 299),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (actor_user_id, operation, idempotency_key),
    CHECK (
        (completed_at IS NULL AND resource_id IS NULL AND response_status IS NULL AND response_body IS NULL) OR
        (completed_at IS NOT NULL AND resource_id IS NOT NULL AND response_status IS NOT NULL AND response_body IS NOT NULL)
    )
);

CREATE INDEX package_catalog_write_requests_scope_created_idx
    ON package_catalog_write_requests (actor_scope_id, created_at DESC);
