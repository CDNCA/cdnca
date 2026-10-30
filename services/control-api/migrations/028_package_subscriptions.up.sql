INSERT INTO permissions (name, description) VALUES
    ('package_subscriptions.read', 'Read sold package subscriptions in the current tenant scope'),
    ('package_subscriptions.manage', 'Open, renew, and cancel audited sold package subscriptions');

INSERT INTO role_permissions (role_id, permission_name)
SELECT roles.id, permission.name
FROM roles
CROSS JOIN (VALUES ('package_subscriptions.read'), ('package_subscriptions.manage')) AS permission(name)
WHERE roles.system_role AND roles.name = 'platform_owner'
ON CONFLICT DO NOTHING;

CREATE FUNCTION is_valid_package_subscription_timezone(value text)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT value = 'UTC' OR (
        char_length(value) BETWEEN 3 AND 128
        AND value <> 'Local'
        AND value ~ '^[A-Za-z][A-Za-z0-9._+-]*/[A-Za-z0-9][A-Za-z0-9._+/-]*$'
        AND position('..' IN value) = 0
        AND EXISTS (
            SELECT 1 FROM pg_catalog.pg_timezone_names AS zone WHERE zone.name = value
        )
    );
$$;

CREATE TABLE package_subscriptions (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    product_id uuid NOT NULL,
    product_revision bigint NOT NULL CHECK (product_revision > 0),
    product_snapshot jsonb NOT NULL CHECK (
        jsonb_typeof(product_snapshot) = 'object'
        AND jsonb_typeof(product_snapshot -> 'revision') = 'number'
        AND jsonb_typeof(product_snapshot -> 'name') = 'string'
        AND jsonb_typeof(product_snapshot -> 'spec') = 'object'
    ),
    site_limit bigint NOT NULL CHECK (site_limit = -1 OR site_limit BETWEEN 0 AND 1000000000),
    domain_limit bigint NOT NULL CHECK (domain_limit = -1 OR domain_limit BETWEEN 0 AND 1000000000),
    node_limit bigint NOT NULL CHECK (node_limit = -1 OR node_limit BETWEEN 0 AND 1000000000),
    traffic_limit_bytes bigint NOT NULL CHECK (traffic_limit_bytes = -1 OR traffic_limit_bytes >= 0),
    starts_at timestamptz NOT NULL,
    ends_at timestamptz NOT NULL,
    timezone text NOT NULL CHECK (is_valid_package_subscription_timezone(timezone)),
    cycle_kind text NOT NULL CHECK (cycle_kind IN ('daily', 'monthly', 'custom_days')),
    custom_cycle_days integer NOT NULL DEFAULT 0 CHECK (
        (cycle_kind IN ('daily', 'monthly') AND custom_cycle_days = 0) OR
        (cycle_kind = 'custom_days' AND custom_cycle_days BETWEEN 1 AND 366)
    ),
    tcp_factor_numerator bigint NOT NULL CHECK (tcp_factor_numerator BETWEEN 1 AND 1000000),
    tcp_factor_denominator bigint NOT NULL CHECK (tcp_factor_denominator BETWEEN 1 AND 1000000),
    lifecycle_status text NOT NULL DEFAULT 'active' CHECK (lifecycle_status IN ('active', 'cancelled')),
    cancelled_at timestamptz,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (product_id, product_revision)
        REFERENCES package_product_versions(product_id, revision) ON DELETE RESTRICT,
    CHECK (ends_at > starts_at),
    CHECK (tcp_factor_numerator::numeric <= tcp_factor_denominator::numeric * 1000),
    CHECK (
        (lifecycle_status = 'active' AND cancelled_at IS NULL) OR
        (lifecycle_status = 'cancelled' AND cancelled_at IS NOT NULL)
    )
);

CREATE INDEX package_subscriptions_tenant_created_idx
    ON package_subscriptions (tenant_scope_id, created_at DESC, id DESC);
CREATE INDEX package_subscriptions_active_end_idx
    ON package_subscriptions (ends_at, id) WHERE lifecycle_status = 'active';

CREATE FUNCTION assert_package_subscription_scope()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    actual_kind text;
BEGIN
    SELECT kind INTO actual_kind FROM access_scopes WHERE id = NEW.tenant_scope_id;
    IF actual_kind IS DISTINCT FROM 'tenant' THEN
        RAISE EXCEPTION 'package subscription scope must be a tenant scope';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER package_subscriptions_scope_kind
BEFORE INSERT OR UPDATE OF tenant_scope_id ON package_subscriptions
FOR EACH ROW EXECUTE FUNCTION assert_package_subscription_scope();

CREATE FUNCTION assert_package_subscription_product_snapshot()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    expected_snapshot jsonb;
BEGIN
    SELECT jsonb_build_object(
        'id', product_id::text,
        'revision', revision,
        'name', name,
        'spec', spec
    ) INTO expected_snapshot
    FROM package_product_versions
    WHERE product_id = NEW.product_id AND revision = NEW.product_revision;
    IF expected_snapshot IS NULL OR NEW.product_snapshot IS DISTINCT FROM expected_snapshot THEN
        RAISE EXCEPTION 'package subscription product snapshot does not match product version';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER package_subscriptions_product_snapshot
BEFORE INSERT ON package_subscriptions
FOR EACH ROW EXECUTE FUNCTION assert_package_subscription_product_snapshot();

CREATE FUNCTION protect_package_subscription_snapshot()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
       OR NEW.product_id IS DISTINCT FROM OLD.product_id
       OR NEW.product_revision IS DISTINCT FROM OLD.product_revision
       OR NEW.product_snapshot IS DISTINCT FROM OLD.product_snapshot
       OR NEW.site_limit IS DISTINCT FROM OLD.site_limit
       OR NEW.domain_limit IS DISTINCT FROM OLD.domain_limit
       OR NEW.node_limit IS DISTINCT FROM OLD.node_limit
       OR NEW.traffic_limit_bytes IS DISTINCT FROM OLD.traffic_limit_bytes
       OR NEW.starts_at IS DISTINCT FROM OLD.starts_at
       OR NEW.timezone IS DISTINCT FROM OLD.timezone
       OR NEW.cycle_kind IS DISTINCT FROM OLD.cycle_kind
       OR NEW.custom_cycle_days IS DISTINCT FROM OLD.custom_cycle_days
       OR NEW.tcp_factor_numerator IS DISTINCT FROM OLD.tcp_factor_numerator
       OR NEW.tcp_factor_denominator IS DISTINCT FROM OLD.tcp_factor_denominator
       OR NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'package subscription snapshot is immutable';
    END IF;
    IF OLD.lifecycle_status = 'cancelled' THEN
        RAISE EXCEPTION 'cancelled package subscription is immutable';
    END IF;
    IF NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'package subscription revision must advance by one';
    END IF;
    IF NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'package subscription updated_at cannot move backwards';
    END IF;
    IF NEW.lifecycle_status = 'active' THEN
        IF NEW.ends_at <= OLD.ends_at OR NEW.cancelled_at IS NOT NULL THEN
            RAISE EXCEPTION 'active package subscription renewal must strictly extend ends_at';
        END IF;
    ELSIF NEW.lifecycle_status = 'cancelled' THEN
        IF NEW.ends_at IS DISTINCT FROM OLD.ends_at
           OR NEW.cancelled_at IS DISTINCT FROM NEW.updated_at
           OR NEW.cancelled_at < OLD.updated_at THEN
            RAISE EXCEPTION 'package subscription cancellation facts are invalid';
        END IF;
    ELSE
        RAISE EXCEPTION 'invalid package subscription lifecycle transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER package_subscriptions_protect_snapshot
BEFORE UPDATE ON package_subscriptions
FOR EACH ROW EXECUTE FUNCTION protect_package_subscription_snapshot();

CREATE TABLE package_subscription_versions (
    subscription_id uuid NOT NULL REFERENCES package_subscriptions(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    operation text NOT NULL CHECK (operation IN ('open', 'renew', 'cancel')),
    snapshot jsonb NOT NULL CHECK (jsonb_typeof(snapshot) = 'object'),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (subscription_id, revision)
);

CREATE FUNCTION prevent_package_subscription_version_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'package subscription versions are append-only';
END;
$$;

CREATE TRIGGER package_subscription_versions_append_only
BEFORE UPDATE OR DELETE ON package_subscription_versions
FOR EACH ROW EXECUTE FUNCTION prevent_package_subscription_version_mutation();

CREATE TRIGGER package_subscription_versions_no_truncate
BEFORE TRUNCATE ON package_subscription_versions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_package_subscription_version_mutation();

CREATE TABLE package_subscription_write_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    target_tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN (
        'package.subscription.open',
        'package.subscription.renew',
        'package.subscription.cancel'
    )),
    idempotency_key text NOT NULL CHECK (
        char_length(idempotency_key) BETWEEN 1 AND 128
        AND idempotency_key ~ '^[A-Za-z0-9._-]+$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    subscription_id uuid REFERENCES package_subscriptions(id) ON DELETE RESTRICT,
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (actor_user_id, operation, idempotency_key),
    CHECK (
        (completed_at IS NULL AND subscription_id IS NULL AND response_body IS NULL) OR
        (completed_at IS NOT NULL AND subscription_id IS NOT NULL AND response_body IS NOT NULL)
    )
);

CREATE INDEX package_subscription_write_requests_tenant_created_idx
    ON package_subscription_write_requests (target_tenant_scope_id, created_at DESC);

CREATE FUNCTION protect_package_subscription_write_request()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'package subscription write requests cannot be truncated';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.subscription_id IS NOT NULL OR NEW.response_body IS NOT NULL OR NEW.completed_at IS NOT NULL THEN
            RAISE EXCEPTION 'package subscription write request must start unfinished';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'package subscription write requests cannot be deleted';
    END IF;
    IF OLD.completed_at IS NOT NULL THEN
        RAISE EXCEPTION 'completed package subscription write request is immutable';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id
       OR NEW.actor_scope_id IS DISTINCT FROM OLD.actor_scope_id
       OR NEW.target_tenant_scope_id IS DISTINCT FROM OLD.target_tenant_scope_id
       OR NEW.operation IS DISTINCT FROM OLD.operation
       OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
       OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.subscription_id IS NULL
       OR NEW.response_body IS NULL
       OR NEW.completed_at IS NULL
       OR NEW.completed_at < OLD.created_at THEN
        RAISE EXCEPTION 'package subscription write request must complete atomically';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER package_subscription_write_requests_protect
BEFORE INSERT OR UPDATE OR DELETE ON package_subscription_write_requests
FOR EACH ROW EXECUTE FUNCTION protect_package_subscription_write_request();

CREATE TRIGGER package_subscription_write_requests_no_truncate
BEFORE TRUNCATE ON package_subscription_write_requests
FOR EACH STATEMENT EXECUTE FUNCTION protect_package_subscription_write_request();
