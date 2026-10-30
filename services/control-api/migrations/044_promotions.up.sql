INSERT INTO permissions (name, description) VALUES
    ('promotions.read', 'Read promotion policies and redemption facts in the authorized scope'),
    ('promotions.manage', 'Publish versioned promotion policies and bind renewal price snapshots'),
    ('promotions.quote', 'Create tenant-scoped promotion quotes'),
    ('promotions.redeem', 'Reserve, consume, release, and adjust tenant promotion redemptions');

INSERT INTO custom_rbac_permission_catalog (permission_name, step_up_required) VALUES
    ('promotions.read', false),
    ('promotions.manage', true),
    ('promotions.quote', false),
    ('promotions.redeem', false);

INSERT INTO role_permissions (role_id, permission_name)
SELECT roles.id, permission.name
FROM roles
CROSS JOIN (VALUES
    ('promotions.read'), ('promotions.manage'), ('promotions.quote'), ('promotions.redeem')
) AS permission(name)
WHERE roles.system_role AND roles.name = 'platform_owner'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_name)
SELECT roles.id, permission.name
FROM roles
CROSS JOIN (VALUES
    ('promotions.read'), ('promotions.quote'), ('promotions.redeem')
) AS permission(name)
WHERE roles.system_role AND roles.name = 'tenant_owner'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_name)
SELECT roles.id, 'promotions.read'
FROM roles
WHERE roles.system_role AND roles.name = 'tenant_viewer'
ON CONFLICT DO NOTHING;

CREATE TABLE promotion_policies (
    id uuid PRIMARY KEY,
    coupon_code text CHECK (
        coupon_code IS NULL OR (
            coupon_code = upper(btrim(coupon_code))
            AND octet_length(coupon_code) BETWEEN 1 AND 64
            AND coupon_code ~ '^[A-Z0-9][A-Z0-9_-]*$'
        )
    ),
    created_by_scope_id uuid NOT NULL,
    created_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    FOREIGN KEY (created_by_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX promotion_policies_coupon_code_unique
    ON promotion_policies (coupon_code) WHERE coupon_code IS NOT NULL;
CREATE INDEX promotion_policies_creator_idx
    ON promotion_policies (created_by_scope_id, created_by_user_id);

CREATE TABLE promotion_policy_catalog_watermark (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    current_position bigint NOT NULL DEFAULT 0 CHECK (current_position >= 0)
);

INSERT INTO promotion_policy_catalog_watermark (singleton, current_position) VALUES (true, 0);

CREATE TABLE promotion_policy_versions (
    policy_id uuid NOT NULL REFERENCES promotion_policies(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    catalog_position bigint NOT NULL UNIQUE CHECK (catalog_position > 0),
    name text NOT NULL CHECK (
        name = btrim(name) AND octet_length(name) BETWEEN 1 AND 128 AND name !~ '[[:cntrl:]]'
    ),
    enabled boolean NOT NULL,
    product_kind text NOT NULL CHECK (product_kind IN ('package_subscription', 'traffic_package')),
    use_purchase boolean NOT NULL,
    use_renewal boolean NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    total_limit bigint NOT NULL DEFAULT 0 CHECK (total_limit >= 0),
    per_user_limit bigint NOT NULL DEFAULT 0 CHECK (per_user_limit >= 0),
    discount_kind text NOT NULL CHECK (discount_kind IN ('fixed', 'percentage')),
    fixed_amount_minor bigint NOT NULL DEFAULT 0 CHECK (fixed_amount_minor >= 0),
    percentage_basis_points integer NOT NULL DEFAULT 0 CHECK (percentage_basis_points BETWEEN 0 AND 10000),
    minimum_amount_minor bigint NOT NULL DEFAULT 0 CHECK (minimum_amount_minor >= 0),
    stacking_mode text NOT NULL CHECK (stacking_mode IN ('stackable', 'exclusive')),
    priority integer NOT NULL CHECK (priority BETWEEN -1000000 AND 1000000),
    renewal_same_price boolean NOT NULL DEFAULT false,
    currency text NOT NULL CHECK (currency = 'CNY'),
    created_by_scope_id uuid NOT NULL,
    created_by_user_id uuid NOT NULL,
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128
        AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (policy_id, revision),
    FOREIGN KEY (created_by_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (use_purchase OR use_renewal),
    CHECK (valid_until > valid_from),
    CHECK (
        (discount_kind = 'fixed' AND fixed_amount_minor > 0 AND percentage_basis_points = 0) OR
        (discount_kind = 'percentage' AND fixed_amount_minor = 0 AND percentage_basis_points BETWEEN 1 AND 10000)
    ),
    CHECK (product_kind = 'package_subscription' OR NOT use_renewal),
    CHECK (NOT renewal_same_price OR (product_kind = 'package_subscription' AND use_purchase))
);

CREATE INDEX promotion_policy_versions_active_idx
    ON promotion_policy_versions (enabled, valid_from, valid_until, priority DESC);
CREATE INDEX promotion_policy_versions_creator_idx
    ON promotion_policy_versions (created_by_scope_id, created_by_user_id);

CREATE TABLE promotion_policy_product_targets (
    policy_id uuid NOT NULL,
    policy_revision bigint NOT NULL,
    product_id uuid NOT NULL,
    PRIMARY KEY (policy_id, policy_revision, product_id),
    FOREIGN KEY (policy_id, policy_revision)
        REFERENCES promotion_policy_versions(policy_id, revision) ON DELETE RESTRICT
);

CREATE INDEX promotion_policy_product_targets_product_idx
    ON promotion_policy_product_targets (product_id, policy_id, policy_revision);

CREATE TABLE promotion_policy_tenant_targets (
    policy_id uuid NOT NULL,
    policy_revision bigint NOT NULL,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    PRIMARY KEY (policy_id, policy_revision, tenant_scope_id),
    FOREIGN KEY (policy_id, policy_revision)
        REFERENCES promotion_policy_versions(policy_id, revision) ON DELETE RESTRICT
);

CREATE INDEX promotion_policy_tenant_targets_tenant_idx
    ON promotion_policy_tenant_targets (tenant_scope_id, policy_id, policy_revision);

CREATE TABLE promotion_quotes (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    user_id uuid NOT NULL,
    product_kind text NOT NULL CHECK (product_kind IN ('package_subscription', 'traffic_package')),
    product_id uuid NOT NULL,
    product_revision bigint NOT NULL CHECK (product_revision > 0),
    package_period text CHECK (package_period IS NULL OR package_period IN ('month', 'quarter', 'year')),
    price_snapshot_id uuid REFERENCES traffic_package_product_snapshots(id) ON DELETE RESTRICT,
    use_kind text NOT NULL CHECK (use_kind IN ('purchase', 'renewal')),
    subscription_id uuid REFERENCES package_subscriptions(id) ON DELETE RESTRICT,
    currency text NOT NULL CHECK (currency = 'CNY'),
    original_amount_minor bigint NOT NULL CHECK (original_amount_minor >= 0),
    discount_amount_minor bigint NOT NULL CHECK (discount_amount_minor >= 0),
    payable_amount_minor bigint NOT NULL CHECK (payable_amount_minor >= 0),
    renewal_snapshot_id uuid,
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128
        AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_scope_id, user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (payable_amount_minor = original_amount_minor - discount_amount_minor),
    CHECK (expires_at > created_at),
    CHECK (
        (product_kind = 'package_subscription' AND package_period IS NOT NULL AND price_snapshot_id IS NULL) OR
        (product_kind = 'traffic_package' AND package_period IS NULL AND price_snapshot_id IS NOT NULL)
    ),
    CHECK (
        (use_kind = 'purchase' AND subscription_id IS NULL) OR
        (use_kind = 'renewal' AND product_kind = 'package_subscription' AND subscription_id IS NOT NULL)
    )
);

CREATE INDEX promotion_quotes_tenant_user_created_idx
    ON promotion_quotes (tenant_scope_id, user_id, created_at DESC, id DESC);
CREATE INDEX promotion_quotes_expiry_idx ON promotion_quotes (expires_at, id);
CREATE INDEX promotion_quotes_product_idx
    ON promotion_quotes (product_kind, product_id, product_revision);
CREATE INDEX promotion_quotes_subscription_idx
    ON promotion_quotes (subscription_id) WHERE subscription_id IS NOT NULL;
CREATE INDEX promotion_quotes_price_snapshot_idx
    ON promotion_quotes (price_snapshot_id) WHERE price_snapshot_id IS NOT NULL;
CREATE INDEX promotion_quotes_renewal_snapshot_idx
    ON promotion_quotes (renewal_snapshot_id) WHERE renewal_snapshot_id IS NOT NULL;

CREATE TABLE promotion_quote_policies (
    quote_id uuid NOT NULL REFERENCES promotion_quotes(id) ON DELETE RESTRICT,
    application_order integer NOT NULL CHECK (application_order >= 0),
    policy_id uuid NOT NULL,
    policy_revision bigint NOT NULL,
    source_kind text NOT NULL CHECK (source_kind IN ('policy', 'renewal_snapshot')),
    discount_minor bigint NOT NULL CHECK (discount_minor >= 0),
    renewal_same_price boolean NOT NULL,
    PRIMARY KEY (quote_id, application_order),
    UNIQUE (quote_id, policy_id, policy_revision),
    FOREIGN KEY (policy_id, policy_revision)
        REFERENCES promotion_policy_versions(policy_id, revision) ON DELETE RESTRICT
);

CREATE INDEX promotion_quote_policies_usage_idx
    ON promotion_quote_policies (policy_id, policy_revision, quote_id);

CREATE TABLE promotion_reservations (
    id uuid PRIMARY KEY,
    quote_id uuid NOT NULL UNIQUE REFERENCES promotion_quotes(id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    user_id uuid NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_scope_id, user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (expires_at > created_at)
);

CREATE INDEX promotion_reservations_tenant_user_idx
    ON promotion_reservations (tenant_scope_id, user_id, created_at DESC);
CREATE INDEX promotion_reservations_expiry_idx ON promotion_reservations (expires_at, id);

CREATE TABLE promotion_reservation_events (
    id uuid PRIMARY KEY,
    reservation_id uuid NOT NULL REFERENCES promotion_reservations(id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    user_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    event_type text NOT NULL CHECK (event_type IN ('reserved', 'consumed', 'released', 'expired')),
    callback_key text CHECK (
        callback_key IS NULL OR (
            octet_length(callback_key) BETWEEN 1 AND 128
            AND callback_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        )
    ),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128
        AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    occurred_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_scope_id, user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (reservation_id, revision),
    CHECK (
        (event_type IN ('reserved', 'expired') AND callback_key IS NULL) OR
        (event_type IN ('consumed', 'released') AND callback_key IS NOT NULL)
    )
);

CREATE UNIQUE INDEX promotion_reservation_events_callback_unique
    ON promotion_reservation_events (tenant_scope_id, callback_key)
    WHERE callback_key IS NOT NULL;
CREATE INDEX promotion_reservation_events_latest_idx
    ON promotion_reservation_events (reservation_id, revision DESC);
CREATE INDEX promotion_reservation_events_subject_idx
    ON promotion_reservation_events (tenant_scope_id, user_id);
CREATE INDEX promotion_reservation_events_actor_idx
    ON promotion_reservation_events (actor_scope_id, actor_user_id);

CREATE TABLE promotion_renewal_price_snapshots (
    id uuid PRIMARY KEY,
    reservation_id uuid NOT NULL UNIQUE REFERENCES promotion_reservations(id) ON DELETE RESTRICT,
    quote_id uuid NOT NULL UNIQUE REFERENCES promotion_quotes(id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    user_id uuid NOT NULL,
    product_id uuid NOT NULL,
    product_revision bigint NOT NULL,
    package_period text NOT NULL CHECK (package_period IN ('month', 'quarter', 'year')),
    currency text NOT NULL CHECK (currency = 'CNY'),
    original_amount_minor bigint NOT NULL CHECK (original_amount_minor >= 0),
    discount_amount_minor bigint NOT NULL CHECK (discount_amount_minor >= 0),
    renewal_amount_minor bigint NOT NULL CHECK (renewal_amount_minor >= 0),
    policies jsonb NOT NULL CHECK (jsonb_typeof(policies) = 'array'),
    created_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_scope_id, user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (product_id, product_revision)
        REFERENCES package_product_versions(product_id, revision) ON DELETE RESTRICT,
    CHECK (renewal_amount_minor = original_amount_minor - discount_amount_minor)
);

CREATE INDEX promotion_renewal_price_snapshots_tenant_user_idx
    ON promotion_renewal_price_snapshots (tenant_scope_id, user_id, created_at DESC);

ALTER TABLE promotion_quotes
    ADD CONSTRAINT promotion_quotes_renewal_snapshot_fk
    FOREIGN KEY (renewal_snapshot_id) REFERENCES promotion_renewal_price_snapshots(id) ON DELETE RESTRICT;

CREATE TABLE promotion_renewal_bindings (
    id uuid PRIMARY KEY,
    renewal_snapshot_id uuid NOT NULL UNIQUE
        REFERENCES promotion_renewal_price_snapshots(id) ON DELETE RESTRICT,
    subscription_id uuid NOT NULL UNIQUE REFERENCES package_subscriptions(id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128
        AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    created_at timestamptz NOT NULL,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

CREATE INDEX promotion_renewal_bindings_tenant_idx
    ON promotion_renewal_bindings (tenant_scope_id, subscription_id);
CREATE INDEX promotion_renewal_bindings_actor_idx
    ON promotion_renewal_bindings (actor_scope_id, actor_user_id);

CREATE TABLE promotion_adjustment_decisions (
    id uuid PRIMARY KEY,
    reservation_id uuid NOT NULL REFERENCES promotion_reservations(id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    kind text NOT NULL CHECK (kind IN ('refund', 'void')),
    source_event_key text NOT NULL CHECK (
        octet_length(source_event_key) BETWEEN 1 AND 128
        AND source_event_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    gross_amount_minor bigint NOT NULL CHECK (gross_amount_minor > 0),
    ledger_amount_minor bigint NOT NULL CHECK (ledger_amount_minor >= 0),
    discount_reversal_minor bigint NOT NULL CHECK (discount_reversal_minor >= 0),
    currency text NOT NULL CHECK (currency = 'CNY'),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128
        AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    created_at timestamptz NOT NULL,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (tenant_scope_id, source_event_key),
    CHECK (gross_amount_minor = ledger_amount_minor + discount_reversal_minor)
);

CREATE INDEX promotion_adjustment_decisions_reservation_idx
    ON promotion_adjustment_decisions (reservation_id, created_at, id);
CREATE INDEX promotion_adjustment_decisions_actor_idx
    ON promotion_adjustment_decisions (actor_scope_id, actor_user_id);

CREATE TABLE promotion_write_requests (
    id uuid PRIMARY KEY,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN (
        'promotion.policy.publish',
        'promotion.quote.create',
        'promotion.reserve',
        'promotion.consume',
        'promotion.release',
        'promotion.renewal.bind',
        'promotion.adjustment.decide'
    )),
    idempotency_key text NOT NULL CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128
        AND idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    resource_id uuid,
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (actor_scope_id, actor_user_id, operation, idempotency_key),
    CHECK (
        (completed_at IS NULL AND resource_id IS NULL AND response_body IS NULL) OR
        (completed_at IS NOT NULL AND resource_id IS NOT NULL AND response_body IS NOT NULL)
    )
);

CREATE INDEX promotion_write_requests_target_created_idx
    ON promotion_write_requests (target_scope_id, created_at DESC);

CREATE FUNCTION assign_promotion_policy_catalog_position()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.catalog_position IS NOT NULL THEN
        RAISE EXCEPTION 'promotion policy catalog position is server assigned';
    END IF;
    UPDATE promotion_policy_catalog_watermark
    SET current_position = current_position + 1
    WHERE singleton
    RETURNING current_position INTO NEW.catalog_position;
    IF NEW.catalog_position IS NULL THEN
        RAISE EXCEPTION 'promotion policy catalog watermark is unavailable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION prevent_promotion_append_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION '% cannot be truncated', TG_TABLE_NAME;
    END IF;
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$;

CREATE FUNCTION protect_promotion_write_request()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'promotion write requests cannot be truncated';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'promotion write requests are append-only';
    END IF;
    IF OLD.completed_at IS NOT NULL
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.actor_scope_id IS DISTINCT FROM OLD.actor_scope_id
       OR NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id
       OR NEW.target_scope_id IS DISTINCT FROM OLD.target_scope_id
       OR NEW.operation IS DISTINCT FROM OLD.operation
       OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
       OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.resource_id IS NULL
       OR NEW.response_body IS NULL
       OR NEW.completed_at IS NULL
       OR NEW.completed_at < OLD.created_at THEN
        RAISE EXCEPTION 'promotion write request may only complete once';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION assert_promotion_policy_target()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE target_kind text;
BEGIN
    SELECT product_kind INTO target_kind
    FROM promotion_policy_versions
    WHERE policy_id = NEW.policy_id AND revision = NEW.policy_revision;
    IF target_kind = 'package_subscription' AND NOT EXISTS (
        SELECT 1 FROM package_product_versions WHERE product_id = NEW.product_id
    ) THEN
        RAISE EXCEPTION 'promotion package target does not exist';
    ELSIF target_kind = 'traffic_package' AND NOT EXISTS (
        SELECT 1 FROM traffic_package_product_snapshots WHERE product_id = NEW.product_id
    ) THEN
        RAISE EXCEPTION 'promotion traffic package target does not exist';
    ELSIF target_kind IS NULL THEN
        RAISE EXCEPTION 'promotion policy version does not exist';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION assert_promotion_tenant_target()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF (SELECT kind FROM access_scopes WHERE id = NEW.tenant_scope_id) IS DISTINCT FROM 'tenant' THEN
        RAISE EXCEPTION 'promotion tenant target must be a tenant scope';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION assert_promotion_policy_complete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM promotion_policy_product_targets
        WHERE policy_id = NEW.policy_id AND policy_revision = NEW.revision
    ) THEN
        RAISE EXCEPTION 'promotion policy version requires a product target';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM audit_events
        WHERE scope_id = NEW.created_by_scope_id
          AND action = 'promotion.policy.publish'
          AND resource_id = NEW.policy_id::text
          AND request_id = NEW.request_id
          AND result = 'success'
    ) THEN
        RAISE EXCEPTION 'promotion policy version requires matching audit';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION assert_promotion_quote_source()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE source_amount bigint;
DECLARE source_currency text;
DECLARE source_tenant uuid;
DECLARE source_product uuid;
BEGIN
    IF (SELECT kind FROM access_scopes WHERE id = NEW.tenant_scope_id) IS DISTINCT FROM 'tenant' THEN
        RAISE EXCEPTION 'promotion quote scope must be a tenant scope';
    END IF;
    IF NEW.product_kind = 'package_subscription' THEN
        SELECT CASE NEW.package_period
                   WHEN 'month' THEN (spec #>> '{prices,monthly_minor}')::bigint
                   WHEN 'quarter' THEN (spec #>> '{prices,quarterly_minor}')::bigint
                   WHEN 'year' THEN (spec #>> '{prices,yearly_minor}')::bigint
               END,
               spec #>> '{prices,currency}'
        INTO source_amount, source_currency
        FROM package_product_versions
        WHERE product_id = NEW.product_id AND revision = NEW.product_revision;
    ELSE
        SELECT price_minor, currency INTO source_amount, source_currency
        FROM traffic_package_product_snapshots
        WHERE id = NEW.price_snapshot_id
          AND product_id = NEW.product_id AND revision = NEW.product_revision;
    END IF;
    IF source_amount IS NULL OR source_currency IS NULL
       OR source_amount <> NEW.original_amount_minor OR source_currency <> NEW.currency THEN
        RAISE EXCEPTION 'promotion quote price does not match immutable source version';
    END IF;
    IF NEW.subscription_id IS NOT NULL THEN
        SELECT tenant_scope_id, product_id INTO source_tenant, source_product
        FROM package_subscriptions WHERE id = NEW.subscription_id;
        IF source_tenant IS DISTINCT FROM NEW.tenant_scope_id OR source_product IS DISTINCT FROM NEW.product_id THEN
            RAISE EXCEPTION 'promotion renewal quote subscription does not match tenant and product';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION reprice_promotion_quote_policies(target_quote_id uuid, renewal_only boolean)
RETURNS TABLE(policies jsonb, payable bigint, item_count bigint)
LANGUAGE plpgsql
AS $$
DECLARE
    quote_fact promotion_quotes%ROWTYPE;
    item record;
    expected_order integer := 0;
    expected_discount bigint;
    policy_payload jsonb;
    has_exclusive boolean := false;
BEGIN
    SELECT * INTO quote_fact FROM promotion_quotes WHERE id = target_quote_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'promotion quote policy snapshot is invalid';
    END IF;
    policies := '[]'::jsonb;
    payable := quote_fact.original_amount_minor;
    item_count := 0;
    FOR item IN
        SELECT applied.application_order, applied.policy_id, applied.policy_revision,
               applied.source_kind, applied.discount_minor, applied.renewal_same_price,
               policy.coupon_code, version.enabled, version.product_kind,
               version.use_purchase, version.use_renewal, version.valid_from, version.valid_until,
               version.discount_kind, version.fixed_amount_minor, version.percentage_basis_points,
               version.minimum_amount_minor, version.stacking_mode, version.priority,
               version.renewal_same_price AS version_renewal_same_price, version.currency,
               EXISTS (
                   SELECT 1 FROM promotion_policy_product_targets target
                   WHERE target.policy_id=applied.policy_id
                     AND target.policy_revision=applied.policy_revision
                     AND target.product_id=quote_fact.product_id
               ) AS product_matches,
               NOT EXISTS (
                   SELECT 1 FROM promotion_policy_tenant_targets target
                   WHERE target.policy_id=applied.policy_id
                     AND target.policy_revision=applied.policy_revision
               ) OR EXISTS (
                   SELECT 1 FROM promotion_policy_tenant_targets target
                   WHERE target.policy_id=applied.policy_id
                     AND target.policy_revision=applied.policy_revision
                     AND target.tenant_scope_id=quote_fact.tenant_scope_id
               ) AS tenant_matches
        FROM promotion_quote_policies applied
        JOIN promotion_policies policy ON policy.id=applied.policy_id
        JOIN promotion_policy_versions version
          ON version.policy_id=applied.policy_id AND version.revision=applied.policy_revision
        WHERE applied.quote_id=target_quote_id
          AND (NOT renewal_only OR applied.renewal_same_price)
        ORDER BY version.priority DESC, applied.policy_id::text
    LOOP
        item_count := item_count + 1;
        IF item.product_kind <> quote_fact.product_kind OR NOT item.product_matches
           OR NOT item.tenant_matches OR item.currency <> quote_fact.currency
           OR item.renewal_same_price IS DISTINCT FROM item.version_renewal_same_price THEN
            RAISE EXCEPTION 'promotion quote policy snapshot is invalid';
        END IF;
        IF quote_fact.renewal_snapshot_id IS NULL THEN
            IF item.source_kind <> 'policy' OR NOT item.enabled
               OR quote_fact.created_at < item.valid_from
               OR quote_fact.created_at >= item.valid_until
               OR quote_fact.expires_at > item.valid_until
               OR (quote_fact.use_kind = 'purchase' AND NOT item.use_purchase)
               OR (quote_fact.use_kind = 'renewal' AND NOT item.use_renewal) THEN
                RAISE EXCEPTION 'promotion quote policy snapshot is invalid';
            END IF;
        ELSIF item.source_kind <> 'renewal_snapshot' OR NOT item.version_renewal_same_price
              OR quote_fact.use_kind <> 'renewal' OR quote_fact.subscription_id IS NULL THEN
            RAISE EXCEPTION 'promotion quote policy snapshot is invalid';
        END IF;
        IF NOT renewal_only AND item.application_order <> expected_order THEN
            RAISE EXCEPTION 'promotion quote policy snapshot is invalid';
        END IF;
        IF quote_fact.original_amount_minor < item.minimum_amount_minor THEN
            RAISE EXCEPTION 'promotion quote policy snapshot is invalid';
        END IF;
        IF item.discount_kind = 'fixed' THEN
            expected_discount := LEAST(item.fixed_amount_minor, payable);
        ELSIF item.discount_kind = 'percentage' THEN
            expected_discount := floor(
                (payable::numeric * item.percentage_basis_points::numeric + 5000) / 10000
            )::bigint;
        ELSE
            RAISE EXCEPTION 'promotion quote policy snapshot is invalid';
        END IF;
        IF NOT renewal_only AND item.discount_minor <> expected_discount THEN
            RAISE EXCEPTION 'promotion quote policy snapshot is invalid';
        END IF;
        payable := payable - expected_discount;
        policy_payload := jsonb_build_object(
            'policy_id', item.policy_id,
            'revision', item.policy_revision,
            'discount_minor', expected_discount,
            'renewal_same_price', item.version_renewal_same_price
        );
        IF item.coupon_code IS NOT NULL THEN
            policy_payload := policy_payload || jsonb_build_object('coupon_code', item.coupon_code);
        END IF;
        policies := policies || jsonb_build_array(policy_payload);
        has_exclusive := has_exclusive OR item.stacking_mode = 'exclusive';
        expected_order := expected_order + 1;
    END LOOP;
    IF item_count < 1 OR (item_count > 1 AND has_exclusive) THEN
        RAISE EXCEPTION 'promotion quote policy snapshot is invalid';
    END IF;
    RETURN NEXT;
END;
$$;

CREATE FUNCTION assert_promotion_quote_complete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE expected_policies jsonb;
DECLARE expected_payable bigint;
DECLARE expected_count bigint;
BEGIN
    SELECT repriced.policies, repriced.payable, repriced.item_count
    INTO expected_policies, expected_payable, expected_count
    FROM reprice_promotion_quote_policies(NEW.id, false) AS repriced;
    IF expected_count < 1 OR expected_payable <> NEW.payable_amount_minor
       OR NEW.discount_amount_minor <> NEW.original_amount_minor - expected_payable THEN
        RAISE EXCEPTION 'promotion quote policy snapshot is invalid';
    END IF;
    IF NEW.renewal_snapshot_id IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM promotion_renewal_price_snapshots snapshot
        JOIN promotion_renewal_bindings binding
          ON binding.renewal_snapshot_id=snapshot.id
        WHERE snapshot.id=NEW.renewal_snapshot_id
          AND binding.subscription_id=NEW.subscription_id
          AND snapshot.tenant_scope_id=NEW.tenant_scope_id
          AND snapshot.user_id=NEW.user_id
          AND snapshot.product_id=NEW.product_id
          AND snapshot.product_revision=NEW.product_revision
          AND snapshot.package_period=NEW.package_period
          AND snapshot.currency=NEW.currency
          AND snapshot.original_amount_minor=NEW.original_amount_minor
          AND snapshot.discount_amount_minor=NEW.discount_amount_minor
          AND snapshot.renewal_amount_minor=NEW.payable_amount_minor
          AND snapshot.policies=expected_policies
    ) THEN
        RAISE EXCEPTION 'promotion renewal quote does not match its bound snapshot';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM audit_events
        WHERE scope_id = NEW.tenant_scope_id
          AND action = 'promotion.quote.create'
          AND resource_id = NEW.id::text
          AND request_id = NEW.request_id
          AND result = 'success'
    ) THEN
        RAISE EXCEPTION 'promotion quote requires matching audit';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION validate_promotion_reservation_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE reservation_tenant uuid;
DECLARE reservation_user uuid;
DECLARE reservation_expiry timestamptz;
DECLARE previous_type text;
DECLARE previous_revision bigint;
DECLARE previous_time timestamptz;
BEGIN
    SELECT tenant_scope_id, user_id, expires_at
    INTO reservation_tenant, reservation_user, reservation_expiry
    FROM promotion_reservations WHERE id = NEW.reservation_id FOR UPDATE;
    IF reservation_tenant IS NULL
       OR reservation_tenant <> NEW.tenant_scope_id OR reservation_user <> NEW.user_id THEN
        RAISE EXCEPTION 'promotion reservation event scope does not match reservation';
    END IF;
    SELECT event_type, revision, occurred_at
    INTO previous_type, previous_revision, previous_time
    FROM promotion_reservation_events
    WHERE reservation_id = NEW.reservation_id
    ORDER BY revision DESC LIMIT 1;
    IF previous_revision IS NULL THEN
        IF NEW.revision <> 1 OR NEW.event_type <> 'reserved' OR NEW.occurred_at >= reservation_expiry THEN
            RAISE EXCEPTION 'promotion reservation must start reserved before expiry';
        END IF;
    ELSE
        IF previous_type <> 'reserved' OR NEW.revision <> previous_revision + 1
           OR NEW.occurred_at < previous_time THEN
            RAISE EXCEPTION 'invalid promotion reservation transition';
        END IF;
        IF NEW.event_type = 'consumed' AND NEW.occurred_at >= reservation_expiry THEN
            RAISE EXCEPTION 'expired promotion reservation cannot be consumed';
        ELSIF NEW.event_type = 'released' AND NEW.occurred_at >= reservation_expiry THEN
            RAISE EXCEPTION 'expired promotion reservation must expire';
        ELSIF NEW.event_type = 'expired' AND NEW.occurred_at < reservation_expiry THEN
            RAISE EXCEPTION 'active promotion reservation cannot expire early';
        ELSIF NEW.event_type = 'reserved' THEN
            RAISE EXCEPTION 'promotion reservation cannot be reserved twice';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION assert_promotion_reservation_complete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM promotion_reservation_events event
        WHERE event.reservation_id = NEW.id AND event.revision = 1 AND event.event_type = 'reserved'
    ) THEN
        RAISE EXCEPTION 'promotion reservation requires reserved event';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION assert_promotion_event_audited()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE expected_action text;
BEGIN
    expected_action := CASE NEW.event_type
        WHEN 'reserved' THEN 'promotion.reserve'
        WHEN 'consumed' THEN 'promotion.consume'
        WHEN 'released' THEN 'promotion.release'
        WHEN 'expired' THEN 'promotion.expire'
    END;
    IF NOT EXISTS (
        SELECT 1 FROM audit_events
        WHERE scope_id = NEW.tenant_scope_id
          AND action = expected_action
          AND resource_id = NEW.reservation_id::text
          AND request_id = NEW.request_id
          AND result = 'success'
    ) THEN
        RAISE EXCEPTION 'promotion reservation event requires matching audit';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION assert_promotion_renewal_snapshot_consumed()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE quote_fact promotion_quotes%ROWTYPE;
DECLARE reservation_tenant uuid;
DECLARE reservation_user uuid;
DECLARE latest_event text;
DECLARE consumed_at timestamptz;
DECLARE expected_policies jsonb;
DECLARE expected_payable bigint;
DECLARE expected_count bigint;
BEGIN
    SELECT * INTO quote_fact FROM promotion_quotes WHERE id=NEW.quote_id;
    SELECT reservation.tenant_scope_id, reservation.user_id, latest.event_type, latest.occurred_at
    INTO reservation_tenant, reservation_user, latest_event, consumed_at
    FROM promotion_reservations reservation
    JOIN LATERAL (
        SELECT event_type, occurred_at
        FROM promotion_reservation_events event
        WHERE event.reservation_id=reservation.id
        ORDER BY revision DESC LIMIT 1
    ) latest ON true
    WHERE reservation.id=NEW.reservation_id AND reservation.quote_id=NEW.quote_id;
    IF quote_fact.id IS NULL OR latest_event <> 'consumed' OR consumed_at <> NEW.created_at
       OR quote_fact.product_kind <> 'package_subscription'
       OR reservation_tenant <> NEW.tenant_scope_id OR reservation_user <> NEW.user_id
       OR quote_fact.tenant_scope_id <> NEW.tenant_scope_id OR quote_fact.user_id <> NEW.user_id
       OR quote_fact.product_id <> NEW.product_id
       OR quote_fact.product_revision <> NEW.product_revision
       OR quote_fact.package_period <> NEW.package_period OR quote_fact.currency <> NEW.currency
       OR quote_fact.original_amount_minor <> NEW.original_amount_minor THEN
        RAISE EXCEPTION 'renewal price snapshot requires a consumed same-price promotion';
    END IF;
    SELECT repriced.policies, repriced.payable, repriced.item_count
    INTO expected_policies, expected_payable, expected_count
    FROM reprice_promotion_quote_policies(NEW.quote_id, true) AS repriced;
    IF expected_count < 1 OR NEW.policies <> expected_policies
       OR NEW.renewal_amount_minor <> expected_payable
       OR NEW.discount_amount_minor <> NEW.original_amount_minor - expected_payable THEN
        RAISE EXCEPTION 'renewal price snapshot does not match consumed quote policy facts';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION assert_promotion_renewal_binding()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE snapshot_tenant uuid;
DECLARE snapshot_product uuid;
DECLARE snapshot_revision bigint;
DECLARE snapshot_period text;
DECLARE snapshot_created timestamptz;
DECLARE subscription_tenant uuid;
DECLARE subscription_product uuid;
DECLARE subscription_revision bigint;
DECLARE subscription_start timestamptz;
DECLARE subscription_end timestamptz;
DECLARE subscription_timezone text;
DECLARE subscription_status text;
DECLARE subscription_created timestamptz;
DECLARE expected_end timestamptz;
BEGIN
    SELECT tenant_scope_id, product_id, product_revision, package_period, created_at
    INTO snapshot_tenant, snapshot_product, snapshot_revision, snapshot_period, snapshot_created
    FROM promotion_renewal_price_snapshots WHERE id = NEW.renewal_snapshot_id;
    SELECT tenant_scope_id, product_id, product_revision, starts_at, ends_at, timezone,
           lifecycle_status, created_at
    INTO subscription_tenant, subscription_product, subscription_revision, subscription_start,
         subscription_end, subscription_timezone, subscription_status, subscription_created
    FROM package_subscriptions WHERE id = NEW.subscription_id;
    expected_end := CASE snapshot_period
        WHEN 'month' THEN ((subscription_start AT TIME ZONE subscription_timezone) + interval '1 month')
            AT TIME ZONE subscription_timezone
        WHEN 'quarter' THEN ((subscription_start AT TIME ZONE subscription_timezone) + interval '3 months')
            AT TIME ZONE subscription_timezone
        WHEN 'year' THEN ((subscription_start AT TIME ZONE subscription_timezone) + interval '1 year')
            AT TIME ZONE subscription_timezone
    END;
    IF snapshot_tenant IS DISTINCT FROM NEW.tenant_scope_id
       OR subscription_tenant IS DISTINCT FROM NEW.tenant_scope_id
       OR snapshot_product IS DISTINCT FROM subscription_product
       OR snapshot_revision IS DISTINCT FROM subscription_revision
       OR subscription_status IS DISTINCT FROM 'active'
       OR subscription_end IS DISTINCT FROM expected_end
       OR subscription_created < snapshot_created
       OR NEW.created_at < subscription_created THEN
        RAISE EXCEPTION 'renewal binding tenant, product, revision, or term mismatch';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM audit_events
        WHERE scope_id = NEW.actor_scope_id
          AND action = 'promotion.renewal.bind'
          AND resource_id = NEW.subscription_id::text
          AND request_id = NEW.request_id
          AND result = 'success'
    ) THEN
        RAISE EXCEPTION 'renewal binding requires matching audit';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION assert_promotion_adjustment()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE quote_original bigint;
DECLARE quote_payable bigint;
DECLARE gross_total numeric;
DECLARE ledger_total numeric;
BEGIN
    SELECT quote.original_amount_minor, quote.payable_amount_minor
    INTO quote_original, quote_payable
    FROM promotion_reservations reservation
    JOIN promotion_quotes quote ON quote.id = reservation.quote_id
    WHERE reservation.id = NEW.reservation_id
      AND reservation.tenant_scope_id = NEW.tenant_scope_id
      AND EXISTS (
          SELECT 1 FROM promotion_reservation_events event
          WHERE event.reservation_id = reservation.id AND event.event_type = 'consumed'
      );
    SELECT COALESCE(sum(gross_amount_minor::numeric), 0),
           COALESCE(sum(ledger_amount_minor::numeric), 0)
    INTO gross_total, ledger_total
    FROM promotion_adjustment_decisions WHERE reservation_id = NEW.reservation_id;
    IF quote_original IS NULL OR gross_total > quote_original OR ledger_total > quote_payable
       OR (NEW.kind = 'void' AND (gross_total <> quote_original OR ledger_total <> quote_payable)) THEN
        RAISE EXCEPTION 'promotion adjustment exceeds consumed quote';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM audit_events
        WHERE scope_id = NEW.tenant_scope_id
          AND action = 'promotion.adjustment.decide'
          AND resource_id = NEW.id::text
          AND request_id = NEW.request_id
          AND result = 'success'
    ) THEN
        RAISE EXCEPTION 'promotion adjustment requires matching audit';
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER promotion_policy_targets_validate
BEFORE INSERT ON promotion_policy_product_targets
FOR EACH ROW EXECUTE FUNCTION assert_promotion_policy_target();
CREATE TRIGGER promotion_tenant_targets_validate
BEFORE INSERT ON promotion_policy_tenant_targets
FOR EACH ROW EXECUTE FUNCTION assert_promotion_tenant_target();
CREATE TRIGGER promotion_quotes_validate_source
BEFORE INSERT ON promotion_quotes
FOR EACH ROW EXECUTE FUNCTION assert_promotion_quote_source();
CREATE TRIGGER promotion_reservation_events_validate
BEFORE INSERT ON promotion_reservation_events
FOR EACH ROW EXECUTE FUNCTION validate_promotion_reservation_event();

CREATE CONSTRAINT TRIGGER promotion_policy_versions_complete
AFTER INSERT ON promotion_policy_versions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_promotion_policy_complete();
CREATE CONSTRAINT TRIGGER promotion_quotes_complete
AFTER INSERT ON promotion_quotes
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_promotion_quote_complete();
CREATE CONSTRAINT TRIGGER promotion_reservations_complete
AFTER INSERT ON promotion_reservations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_promotion_reservation_complete();
CREATE CONSTRAINT TRIGGER promotion_reservation_events_audited
AFTER INSERT ON promotion_reservation_events
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_promotion_event_audited();
CREATE CONSTRAINT TRIGGER promotion_renewal_snapshots_consumed
AFTER INSERT ON promotion_renewal_price_snapshots
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_promotion_renewal_snapshot_consumed();
CREATE CONSTRAINT TRIGGER promotion_renewal_bindings_valid
AFTER INSERT ON promotion_renewal_bindings
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_promotion_renewal_binding();
CREATE CONSTRAINT TRIGGER promotion_adjustments_valid
AFTER INSERT ON promotion_adjustment_decisions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_promotion_adjustment();

CREATE TRIGGER promotion_write_requests_protect
BEFORE UPDATE OR DELETE ON promotion_write_requests
FOR EACH ROW EXECUTE FUNCTION protect_promotion_write_request();
CREATE TRIGGER promotion_write_requests_no_truncate
BEFORE TRUNCATE ON promotion_write_requests
FOR EACH STATEMENT EXECUTE FUNCTION protect_promotion_write_request();

CREATE TRIGGER promotion_policies_append_only
BEFORE UPDATE OR DELETE ON promotion_policies
FOR EACH ROW EXECUTE FUNCTION prevent_promotion_append_mutation();
CREATE TRIGGER promotion_policies_no_truncate
BEFORE TRUNCATE ON promotion_policies
FOR EACH STATEMENT EXECUTE FUNCTION prevent_promotion_append_mutation();
CREATE TRIGGER promotion_policy_versions_assign_catalog_position
BEFORE INSERT ON promotion_policy_versions
FOR EACH ROW EXECUTE FUNCTION assign_promotion_policy_catalog_position();
CREATE TRIGGER promotion_policy_versions_append_only
BEFORE UPDATE OR DELETE ON promotion_policy_versions
FOR EACH ROW EXECUTE FUNCTION prevent_promotion_append_mutation();
CREATE TRIGGER promotion_policy_versions_no_truncate
BEFORE TRUNCATE ON promotion_policy_versions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_promotion_append_mutation();
CREATE TRIGGER promotion_policy_product_targets_append_only
BEFORE UPDATE OR DELETE ON promotion_policy_product_targets
FOR EACH ROW EXECUTE FUNCTION prevent_promotion_append_mutation();
CREATE TRIGGER promotion_policy_product_targets_no_truncate
BEFORE TRUNCATE ON promotion_policy_product_targets
FOR EACH STATEMENT EXECUTE FUNCTION prevent_promotion_append_mutation();
CREATE TRIGGER promotion_policy_tenant_targets_append_only
BEFORE UPDATE OR DELETE ON promotion_policy_tenant_targets
FOR EACH ROW EXECUTE FUNCTION prevent_promotion_append_mutation();
CREATE TRIGGER promotion_policy_tenant_targets_no_truncate
BEFORE TRUNCATE ON promotion_policy_tenant_targets
FOR EACH STATEMENT EXECUTE FUNCTION prevent_promotion_append_mutation();
CREATE TRIGGER promotion_quotes_append_only
BEFORE UPDATE OR DELETE ON promotion_quotes
FOR EACH ROW EXECUTE FUNCTION prevent_promotion_append_mutation();
CREATE TRIGGER promotion_quotes_no_truncate
BEFORE TRUNCATE ON promotion_quotes
FOR EACH STATEMENT EXECUTE FUNCTION prevent_promotion_append_mutation();
CREATE TRIGGER promotion_quote_policies_append_only
BEFORE UPDATE OR DELETE ON promotion_quote_policies
FOR EACH ROW EXECUTE FUNCTION prevent_promotion_append_mutation();
CREATE TRIGGER promotion_quote_policies_no_truncate
BEFORE TRUNCATE ON promotion_quote_policies
FOR EACH STATEMENT EXECUTE FUNCTION prevent_promotion_append_mutation();
CREATE TRIGGER promotion_reservations_append_only
BEFORE UPDATE OR DELETE ON promotion_reservations
FOR EACH ROW EXECUTE FUNCTION prevent_promotion_append_mutation();
CREATE TRIGGER promotion_reservations_no_truncate
BEFORE TRUNCATE ON promotion_reservations
FOR EACH STATEMENT EXECUTE FUNCTION prevent_promotion_append_mutation();
CREATE TRIGGER promotion_reservation_events_append_only
BEFORE UPDATE OR DELETE ON promotion_reservation_events
FOR EACH ROW EXECUTE FUNCTION prevent_promotion_append_mutation();
CREATE TRIGGER promotion_reservation_events_no_truncate
BEFORE TRUNCATE ON promotion_reservation_events
FOR EACH STATEMENT EXECUTE FUNCTION prevent_promotion_append_mutation();
CREATE TRIGGER promotion_renewal_price_snapshots_append_only
BEFORE UPDATE OR DELETE ON promotion_renewal_price_snapshots
FOR EACH ROW EXECUTE FUNCTION prevent_promotion_append_mutation();
CREATE TRIGGER promotion_renewal_price_snapshots_no_truncate
BEFORE TRUNCATE ON promotion_renewal_price_snapshots
FOR EACH STATEMENT EXECUTE FUNCTION prevent_promotion_append_mutation();
CREATE TRIGGER promotion_renewal_bindings_append_only
BEFORE UPDATE OR DELETE ON promotion_renewal_bindings
FOR EACH ROW EXECUTE FUNCTION prevent_promotion_append_mutation();
CREATE TRIGGER promotion_renewal_bindings_no_truncate
BEFORE TRUNCATE ON promotion_renewal_bindings
FOR EACH STATEMENT EXECUTE FUNCTION prevent_promotion_append_mutation();
CREATE TRIGGER promotion_adjustment_decisions_append_only
BEFORE UPDATE OR DELETE ON promotion_adjustment_decisions
FOR EACH ROW EXECUTE FUNCTION prevent_promotion_append_mutation();
CREATE TRIGGER promotion_adjustment_decisions_no_truncate
BEFORE TRUNCATE ON promotion_adjustment_decisions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_promotion_append_mutation();
