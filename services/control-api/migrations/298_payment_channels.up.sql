LOCK TABLE schema_migrations, permissions, access_scopes, roles, role_permissions IN ACCESS EXCLUSIVE MODE;

DO $migration_298_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 297 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 297 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=297 AND
        migration_id='297_cname_target_scope_default' AND
        checksum_sha256='8c947a2ba91cb8a6245788916c8ced7145e4410ec4321b6df3241df074f05a1d' AND
        down_checksum_sha256='c20f6453b2ec1e6805f4fc6c92110ac9357bce614e5cf845ef012bfaee0cdc83' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.payment_channels') IS NOT NULL OR
            EXISTS (SELECT 1 FROM permissions WHERE name = 'billing.payment_channels.manage') THEN
        RAISE EXCEPTION 'migration 298 requires the exact verified 297 release head' USING ERRCODE='P2980';
    END IF;
END;
$migration_298_up$;

-- Recharge collection channels managed in the admin console
-- (docs/architecture/marketplace-buildout.md §6.2). The RECHARGE_PAYMENT_*
-- environment configuration keeps working as a read-only bootstrap channel
-- that is never stored here. Secrets (merchant keys, private keys, APIv3
-- keys, explorer API keys) are one AES-GCM envelope under the DNS credential
-- keyring; the admin API only returns which secret fields are set and a
-- short fingerprint each.
INSERT INTO permissions(name, description)
VALUES ('billing.payment_channels.manage', 'Configure recharge payment channels and their credentials');

INSERT INTO role_permissions(role_id, permission_name)
SELECT role.id, 'billing.payment_channels.manage'
FROM roles role
JOIN access_scopes scope ON scope.id = role.scope_id AND scope.kind = 'platform'
WHERE role.system_role AND role.name = 'platform_owner'
ON CONFLICT DO NOTHING;

CREATE TABLE payment_channels (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    provider text NOT NULL CHECK (provider IN ('alipay_official', 'wechat_official', 'epay', 'codepay', 'crypto')),
    -- Recharge orders are paid with alipay or wechat (recharge_orders_v1.channel).
    method text NOT NULL CHECK (method IN ('alipay', 'wxpay')),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 64 AND display_name !~ '[[:cntrl:]]'),
    icon text NOT NULL DEFAULT '' CHECK (char_length(icon) <= 512 AND icon !~ '[[:cntrl:]]'),
    sort integer NOT NULL DEFAULT 100 CHECK (sort BETWEEN 0 AND 9999),
    is_default boolean NOT NULL DEFAULT false,
    enabled boolean NOT NULL DEFAULT false,
    role text NOT NULL DEFAULT 'standby' CHECK (role IN ('primary', 'standby')),
    min_amount_minor bigint NOT NULL DEFAULT 0 CHECK (min_amount_minor BETWEEN 0 AND 9000000000000000),
    max_amount_minor bigint NOT NULL DEFAULT 0 CHECK (max_amount_minor BETWEEN 0 AND 9000000000000000),
    -- A recharge credits exactly the order amount, so a payer-borne fee
    -- cannot be collected on top; fees are booked as merchant cost.
    fee_bearer text NOT NULL DEFAULT 'merchant' CHECK (fee_bearer = 'merchant'),
    fee_rate_bp integer NOT NULL DEFAULT 0 CHECK (fee_rate_bp BETWEEN 0 AND 10000),
    scenes text[] NOT NULL DEFAULT ARRAY['recharge']::text[] CHECK (scenes = ARRAY['recharge']::text[]),
    config jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(config) = 'object' AND octet_length(config::text) <= 16384),
    secret_key_id text CHECK (secret_key_id IS NULL OR char_length(secret_key_id) BETWEEN 1 AND 255),
    secret_ciphertext bytea CHECK (secret_ciphertext IS NULL OR octet_length(secret_ciphertext) BETWEEN 29 AND 65536),
    -- {"field": "16 hex fingerprint"} for every secret field that is set.
    secret_fingerprints jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(secret_fingerprints) = 'object'),
    platform_public_key text NOT NULL DEFAULT '' CHECK (char_length(platform_public_key) <= 65536),
    risk_acknowledged_by uuid,
    risk_acknowledged_at timestamptz,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by uuid NOT NULL,
    updated_by uuid NOT NULL,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    CHECK (max_amount_minor = 0 OR max_amount_minor >= min_amount_minor),
    CHECK ((secret_key_id IS NULL) = (secret_ciphertext IS NULL)),
    CHECK ((risk_acknowledged_by IS NULL) = (risk_acknowledged_at IS NULL)),
    -- 易支付 / 码支付 are third-party aggregators: they can only be enabled
    -- after an operator acknowledged the compliance and fund-safety warning.
    CHECK (NOT enabled OR provider NOT IN ('epay', 'codepay') OR risk_acknowledged_at IS NOT NULL),
    CHECK (NOT enabled OR secret_key_id IS NOT NULL)
);

-- One enabled primary per payment method; standbys take over when it fails.
CREATE UNIQUE INDEX payment_channels_primary_298_idx ON payment_channels (method) WHERE enabled AND role = 'primary';
CREATE INDEX payment_channels_sort_298_idx ON payment_channels (method, sort, id);

-- Idempotent admin writes: the first response is replayed for the same
-- (session, key); a different request body under the same key is refused.
CREATE TABLE payment_channel_write_requests (
    actor_session_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_digest_sha256 bytea NOT NULL CHECK (octet_length(request_digest_sha256) = 32),
    channel_id uuid NOT NULL REFERENCES payment_channels(id) ON DELETE RESTRICT,
    response_body jsonb NOT NULL CHECK (jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    PRIMARY KEY (actor_session_id, idempotency_key)
);

-- Active query compensation for unpaid recharge checkouts: attempts at
-- +1, +5, +15 and +60 minutes after the checkout, then the row closes.
CREATE TABLE payment_channel_reconcile_schedule (
    order_id uuid PRIMARY KEY,
    channel_ref text NOT NULL CHECK (channel_ref ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    provider text NOT NULL CHECK (provider ~ '^[a-z][a-z0-9._-]{0,63}$'),
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 4),
    next_attempt_at timestamptz NOT NULL CHECK (isfinite(next_attempt_at)),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'settled', 'exhausted')),
    lease_until timestamptz,
    last_error_code text NOT NULL DEFAULT '' CHECK (char_length(last_error_code) <= 64),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    FOREIGN KEY (order_id) REFERENCES recharge_orders_v1(id) ON DELETE RESTRICT
);
CREATE INDEX payment_channel_reconcile_due_298_idx ON payment_channel_reconcile_schedule (next_attempt_at)
    WHERE state = 'pending';

REVOKE ALL ON payment_channels, payment_channel_write_requests, payment_channel_reconcile_schedule FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON payment_channels TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT ON payment_channel_write_requests TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE ON payment_channel_reconcile_schedule TO cdnca_control_app, cdnca_control_runtime;

-- Pre-existing defect: the package-commerce constraint trigger (051) checks
-- every non-manual billing transaction against package_orders, so the online
-- recharge ledger posting (operation recharge_payment, migration 152) could
-- never commit. Recharge rows are exempted; package checks are unchanged.
CREATE OR REPLACE FUNCTION assert_package_commercial_transaction()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE original_target uuid;
DECLARE original_currency text;
DECLARE original_order uuid;
DECLARE original_amount bigint;
DECLARE original_operation text;
DECLARE reversal_total numeric;
DECLARE order_tenant uuid;
DECLARE order_currency text;
DECLARE order_amount bigint;
BEGIN
    -- Recharge ledger rows are bound to their order by
    -- billing_transactions_recharge_event_fk_152 and the commerce shape check;
    -- they have no package order (298).
    IF NEW.operation IN ('manual_adjustment', 'recharge_payment', 'recharge_refund', 'recharge_void') THEN
        RETURN NULL;
    END IF;
    SELECT tenant_scope_id, currency, payable_amount_minor
    INTO order_tenant, order_currency, order_amount
    FROM package_orders WHERE id = NEW.commercial_order_id;
    IF order_tenant IS DISTINCT FROM NEW.target_scope_id
       OR order_currency IS DISTINCT FROM NEW.currency
       OR (NEW.operation <> 'package_refund' AND NEW.operation <> 'package_void'
           AND NEW.amount_minor <> order_amount) THEN
        RAISE EXCEPTION 'commercial billing transaction does not match order';
    END IF;
    IF NEW.operation IN ('package_refund', 'package_void') THEN
        SELECT target_scope_id, currency, commercial_order_id, amount_minor, operation
        INTO original_target, original_currency, original_order, original_amount, original_operation
        FROM billing_transactions WHERE id = NEW.reverses_transaction_id;
        IF original_operation NOT IN ('package_purchase', 'package_renewal', 'package_upgrade',
                                      'package_downgrade', 'traffic_package_purchase')
           OR original_target IS DISTINCT FROM NEW.target_scope_id
           OR original_currency IS DISTINCT FROM NEW.currency
           OR original_order IS DISTINCT FROM NEW.commercial_order_id THEN
            RAISE EXCEPTION 'commercial reversal does not match original sale';
        END IF;
        SELECT COALESCE(sum(amount_minor::numeric), 0)
        INTO reversal_total FROM billing_transactions
        WHERE reverses_transaction_id = NEW.reverses_transaction_id;
        IF reversal_total > original_amount
           OR (NEW.operation = 'package_void' AND
               (reversal_total <> original_amount OR
                (SELECT count(*) FROM billing_transactions
                 WHERE reverses_transaction_id = NEW.reverses_transaction_id) <> 1)) THEN
            RAISE EXCEPTION 'commercial reversal exceeds original sale';
        END IF;
    END IF;
    RETURN NULL;
END;
$$;
