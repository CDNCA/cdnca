LOCK TABLE package_subscriptions IN SHARE ROW EXCLUSIVE MODE;

CREATE TABLE package_subscription_state_versions (
    subscription_id uuid NOT NULL REFERENCES package_subscriptions(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    lifecycle_status text NOT NULL CHECK (lifecycle_status IN ('active', 'cancelled')),
    starts_at timestamptz NOT NULL,
    ends_at timestamptz NOT NULL,
    cancelled_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    commit_sequence bigint NOT NULL CHECK (commit_sequence >= 0),
    PRIMARY KEY (subscription_id, revision),
    CHECK (ends_at > starts_at),
    CHECK (updated_at >= created_at),
    CHECK (
        (lifecycle_status = 'active' AND cancelled_at IS NULL)
        OR (lifecycle_status = 'cancelled' AND cancelled_at IS NOT NULL)
    )
);

CREATE TABLE package_subscription_state_commit_watermarks (
    tenant_scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    committed_through bigint NOT NULL CHECK (committed_through > 0)
);

INSERT INTO package_subscription_state_versions (
    subscription_id, revision, tenant_scope_id, owner_user_id, lifecycle_status,
    starts_at, ends_at, cancelled_at, created_at, updated_at, commit_sequence
)
SELECT id, revision, tenant_scope_id, created_by_user_id, lifecycle_status,
       starts_at, ends_at, cancelled_at, created_at, updated_at, 0
FROM package_subscriptions;

CREATE FUNCTION prepare_package_subscription_state_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.commit_sequence IS NOT NULL THEN
        RAISE EXCEPTION 'package subscription state commit sequence is server assigned';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM package_subscriptions subscription
        WHERE subscription.id = NEW.subscription_id
          AND subscription.revision = NEW.revision
          AND subscription.tenant_scope_id = NEW.tenant_scope_id
          AND subscription.created_by_user_id = NEW.owner_user_id
          AND subscription.lifecycle_status = NEW.lifecycle_status
          AND subscription.starts_at = NEW.starts_at
          AND subscription.ends_at = NEW.ends_at
          AND subscription.cancelled_at IS NOT DISTINCT FROM NEW.cancelled_at
          AND subscription.created_at = NEW.created_at
          AND subscription.updated_at = NEW.updated_at
    ) THEN
        RAISE EXCEPTION 'package subscription state version does not match current subscription';
    END IF;
    INSERT INTO package_subscription_state_commit_watermarks (
        tenant_scope_id, committed_through
    ) VALUES (NEW.tenant_scope_id, 1)
    ON CONFLICT (tenant_scope_id) DO UPDATE
    SET committed_through = package_subscription_state_commit_watermarks.committed_through + 1
    RETURNING committed_through INTO NEW.commit_sequence;
    RETURN NEW;
END;
$$;

CREATE TRIGGER package_subscription_state_versions_prepare
BEFORE INSERT ON package_subscription_state_versions
FOR EACH ROW EXECUTE FUNCTION prepare_package_subscription_state_version();

CREATE FUNCTION capture_package_subscription_state_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO package_subscription_state_versions (
        subscription_id, revision, tenant_scope_id, owner_user_id, lifecycle_status,
        starts_at, ends_at, cancelled_at, created_at, updated_at
    ) VALUES (
        NEW.id, NEW.revision, NEW.tenant_scope_id, NEW.created_by_user_id, NEW.lifecycle_status,
        NEW.starts_at, NEW.ends_at, NEW.cancelled_at, NEW.created_at, NEW.updated_at
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER package_subscriptions_capture_state_version
AFTER INSERT OR UPDATE ON package_subscriptions
FOR EACH ROW EXECUTE FUNCTION capture_package_subscription_state_version();

CREATE TRIGGER package_subscription_state_versions_append_only
BEFORE UPDATE OR DELETE ON package_subscription_state_versions
FOR EACH ROW EXECUTE FUNCTION prevent_package_commerce_fact_mutation();

CREATE TRIGGER package_subscription_state_versions_no_truncate
BEFORE TRUNCATE ON package_subscription_state_versions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_package_commerce_fact_mutation();

CREATE UNIQUE INDEX package_subscription_state_versions_tenant_commit_idx
    ON package_subscription_state_versions (tenant_scope_id, commit_sequence)
    WHERE commit_sequence > 0;

CREATE INDEX package_subscription_state_versions_tenant_created_idx
    ON package_subscription_state_versions (
        tenant_scope_id, owner_user_id, created_at DESC, subscription_id DESC, revision DESC
    );
