LOCK TABLE schema_migrations, billing_transactions, memberships, notification_event_policies, notification_templates
    IN ACCESS EXCLUSIVE MODE;

DO $migration_446_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 445 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 445 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=445 AND
        migration_id='445_market_deposit_notices' AND
        checksum_sha256='4b3158dd2587cc14bcbe1b3f2b3614f46a5f9027ed716bcf34c2a50a28dc10c3' AND
        down_checksum_sha256='4ec4556cca071125de252c20886aef624d78da41bc699f8983a71bc75e173579' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.migrate_import_jobs') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 446 requires the exact verified 445 release head' USING ERRCODE='P4460';
    END IF;
END;
$migration_446_up$;

-- 446 (r136 migrate-import, ADR 0016; placeholder number, the dispatch
-- reserves 442, renumbered on merge). Import from other CDN systems.
--   migrate_import_jobs      one import: source, options (never credentials),
--                            bundle digest, status machine, counts;
--   migrate_import_items     the plan, one row per source item, payload is
--                            the interchange item (private keys, DNS
--                            credentials and password hashes sealed);
--   migrate_import_mappings  permanent source -> target ids (idempotency);
--   migrate_import_order_archive  read-only history of source orders;
--   migrate_import_legacy_passwords  plan B: sealed source hashes checked at
--                            the first sign-in, deleted on rehash or expiry;
--   migrate_import_balance_credits  final source balances, pending until a
--                            second administrator approves the batch; an
--                            approved row posts one migrate_import_credit
--                            ledger transaction.
CREATE TABLE migrate_import_jobs (
    id uuid PRIMARY KEY,
    source_system text NOT NULL CHECK (source_system ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    source_instance text NOT NULL CHECK (char_length(source_instance) BETWEEN 1 AND 253),
    status text NOT NULL CHECK (status IN ('reading', 'ready', 'confirmed', 'running', 'paused',
        'completed', 'failed', 'cancelled')),
    options jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(options) = 'object'),
    bundle_digest text CHECK (bundle_digest ~ '^[0-9a-f]{64}$'),
    counts jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(counts) = 'object'),
    error_code text CHECK (error_code IS NULL OR char_length(error_code) BETWEEN 1 AND 64),
    error_detail text CHECK (error_detail IS NULL OR char_length(error_detail) <= 512),
    pause_requested boolean NOT NULL DEFAULT false,
    created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    confirmed_by uuid REFERENCES users(id) ON DELETE RESTRICT,
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9._-]{1,128}$'),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    confirmed_at timestamptz,
    finished_at timestamptz,
    payload_cleared_at timestamptz,
    UNIQUE (created_by, idempotency_key),
    CHECK ((status IN ('reading', 'ready')) OR status IN ('failed', 'cancelled') OR confirmed_by IS NOT NULL),
    CHECK ((status IN ('completed', 'failed', 'cancelled')) = (finished_at IS NOT NULL))
);
-- One unfinished job per source bundle (ADR 0016 §5.1).
CREATE UNIQUE INDEX migrate_import_jobs_open_bundle_idx
    ON migrate_import_jobs (source_system, source_instance, bundle_digest)
    WHERE status NOT IN ('completed', 'failed', 'cancelled') AND bundle_digest IS NOT NULL;
CREATE INDEX migrate_import_jobs_created_idx ON migrate_import_jobs (created_at DESC, id DESC);

CREATE TABLE migrate_import_items (
    job_id uuid NOT NULL REFERENCES migrate_import_jobs(id) ON DELETE CASCADE,
    section text NOT NULL CHECK (section IN ('packages', 'users', 'user_packages', 'certs', 'dns', 'sites',
        'balances', 'orders')),
    source_id text NOT NULL CHECK (char_length(source_id) BETWEEN 1 AND 128),
    ordinal integer NOT NULL CHECK (ordinal >= 0),
    action text NOT NULL CHECK (action IN ('create', 'merge', 'rename', 'skip', 'conflict', 'unsupported')),
    target_id text CHECK (target_id IS NULL OR char_length(target_id) BETWEEN 1 AND 128),
    target_name text CHECK (target_name IS NULL OR char_length(target_name) BETWEEN 1 AND 253),
    status text NOT NULL CHECK (status IN ('pending', 'done', 'failed', 'skipped')),
    reason text CHECK (reason IS NULL OR reason ~ '^[a-z][a-z0-9_]{0,63}$'),
    detail text CHECK (detail IS NULL OR char_length(detail) <= 512),
    payload jsonb CHECK (payload IS NULL OR jsonb_typeof(payload) = 'object'),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (job_id, section, source_id)
);
CREATE INDEX migrate_import_items_status_idx ON migrate_import_items (job_id, status, section, ordinal);

CREATE TABLE migrate_import_mappings (
    source_system text NOT NULL,
    source_instance text NOT NULL,
    section text NOT NULL CHECK (section IN ('packages', 'users', 'user_packages', 'certs', 'dns', 'sites',
        'balances', 'orders')),
    source_id text NOT NULL CHECK (char_length(source_id) BETWEEN 1 AND 128),
    target_id text NOT NULL CHECK (char_length(target_id) BETWEEN 1 AND 128),
    job_id uuid NOT NULL,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    PRIMARY KEY (source_system, source_instance, section, source_id)
);

CREATE TABLE migrate_import_order_archive (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    job_id uuid NOT NULL,
    source_system text NOT NULL,
    source_instance text NOT NULL,
    source_order_id text NOT NULL CHECK (char_length(source_order_id) BETWEEN 1 AND 128),
    order_type text NOT NULL CHECK (char_length(order_type) BETWEEN 1 AND 64),
    description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 500),
    amount_minor bigint NOT NULL,
    paid_minor bigint NOT NULL,
    status text NOT NULL CHECK (char_length(status) BETWEEN 1 AND 64),
    pay_method text NOT NULL DEFAULT '' CHECK (char_length(pay_method) <= 64),
    merchant_order_no text NOT NULL DEFAULT '' CHECK (char_length(merchant_order_no) <= 128),
    transaction_no text NOT NULL DEFAULT '' CHECK (char_length(transaction_no) <= 128),
    source_created_at timestamptz,
    source_paid_at timestamptz,
    archived_at timestamptz NOT NULL CHECK (isfinite(archived_at)),
    UNIQUE (source_system, source_instance, source_order_id)
);
CREATE INDEX migrate_import_order_archive_user_idx
    ON migrate_import_order_archive (user_id, source_created_at DESC NULLS LAST, id);

-- Archived orders are history: insert and read only. Deleting the user
-- cascades (the cascade runs as a row DELETE whose user is gone).
CREATE FUNCTION prevent_migrate_import_order_archive_mutation_446()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' AND NOT EXISTS (SELECT 1 FROM users WHERE id = OLD.user_id) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'migrate import order archive is read-only' USING ERRCODE='P4462';
END;
$$;
CREATE TRIGGER migrate_import_order_archive_read_only
BEFORE UPDATE OR DELETE ON migrate_import_order_archive
FOR EACH ROW EXECUTE FUNCTION prevent_migrate_import_order_archive_mutation_446();
CREATE TRIGGER migrate_import_order_archive_no_truncate
BEFORE TRUNCATE ON migrate_import_order_archive
FOR EACH STATEMENT EXECUTE FUNCTION prevent_migrate_import_order_archive_mutation_446();

CREATE TABLE migrate_import_legacy_passwords (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    scheme text NOT NULL CHECK (scheme IN ('md5_hex', 'bcrypt')),
    key_id text NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 64),
    -- dnsacme credential envelope (key id + wrapped DEK + nonce + sealed hash).
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 16 AND 1024),
    source_system text NOT NULL,
    job_id uuid NOT NULL,
    expires_at timestamptz NOT NULL CHECK (isfinite(expires_at)),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at) AND expires_at > created_at)
);
CREATE INDEX migrate_import_legacy_passwords_expiry_idx ON migrate_import_legacy_passwords (expires_at);

-- A user still holding a source hash cannot become a platform member
-- (ADR 0016 §6.1): finish the first sign-in or clear the hash first.
CREATE FUNCTION refuse_legacy_platform_member_446()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM access_scopes WHERE id = NEW.scope_id AND kind = 'platform') AND
       EXISTS (SELECT 1 FROM migrate_import_legacy_passwords WHERE user_id = NEW.user_id) THEN
        RAISE EXCEPTION 'imported user with a source password hash cannot join the platform scope'
            USING ERRCODE='P4465';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER memberships_refuse_legacy_platform_member
BEFORE INSERT OR UPDATE OF scope_id ON memberships
FOR EACH ROW EXECUTE FUNCTION refuse_legacy_platform_member_446();

CREATE TABLE migrate_import_balance_credits (
    job_id uuid NOT NULL REFERENCES migrate_import_jobs(id) ON DELETE RESTRICT,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    source_user_id text NOT NULL CHECK (char_length(source_user_id) BETWEEN 1 AND 128),
    amount_minor bigint NOT NULL CHECK (amount_minor > 0 AND amount_minor <= 9000000000000000),
    reason text NOT NULL CHECK (reason = btrim(reason) AND char_length(reason) BETWEEN 1 AND 500),
    state text NOT NULL CHECK (state IN ('pending', 'approved', 'rejected')),
    proposed_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    proposed_at timestamptz NOT NULL CHECK (isfinite(proposed_at)),
    decided_by uuid REFERENCES users(id) ON DELETE RESTRICT,
    decided_at timestamptz,
    self_approved boolean NOT NULL DEFAULT false,
    step_up_proof_id uuid,
    billing_transaction_id uuid UNIQUE REFERENCES billing_transactions(id) ON DELETE RESTRICT,
    PRIMARY KEY (job_id, user_id),
    CHECK ((state = 'pending') = (decided_by IS NULL AND decided_at IS NULL)),
    CHECK ((state = 'approved') = (billing_transaction_id IS NOT NULL)),
    CHECK (state = 'pending' OR step_up_proof_id IS NOT NULL),
    CHECK (self_approved = (decided_by IS NOT NULL AND decided_by = proposed_by))
);

ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_operation_check;
ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_commerce_shape;
ALTER TABLE billing_transactions
    ADD CONSTRAINT billing_transactions_operation_check CHECK(operation IN (
        'manual_adjustment','provider_payment','package_purchase','package_renewal','package_upgrade',
        'package_downgrade','package_refund','package_void','traffic_package_purchase',
        'recharge_payment','recharge_refund','recharge_void',
        'migrate_import_credit'
    ));
ALTER TABLE billing_transactions
    ADD CONSTRAINT billing_transactions_commerce_shape CHECK(
        (operation='manual_adjustment' AND commercial_order_id IS NULL AND reverses_transaction_id IS NULL
            AND payment_attempt_id IS NULL AND recharge_order_id IS NULL AND recharge_provider_event_id IS NULL)
        OR (operation='provider_payment' AND commercial_order_id IS NOT NULL AND reverses_transaction_id IS NULL
            AND payment_attempt_id IS NOT NULL AND recharge_order_id IS NULL AND recharge_provider_event_id IS NULL AND direction='credit')
        OR (operation IN ('package_purchase','package_renewal','package_upgrade','package_downgrade','traffic_package_purchase')
            AND commercial_order_id IS NOT NULL AND reverses_transaction_id IS NULL AND recharge_order_id IS NULL AND recharge_provider_event_id IS NULL)
        OR (operation IN ('package_refund','package_void') AND commercial_order_id IS NOT NULL
            AND reverses_transaction_id IS NOT NULL AND recharge_order_id IS NULL AND recharge_provider_event_id IS NULL AND direction='credit')
        OR (operation='recharge_payment' AND commercial_order_id IS NULL AND reverses_transaction_id IS NULL
            AND payment_attempt_id IS NULL AND recharge_order_id IS NOT NULL AND recharge_provider_event_id IS NOT NULL AND direction='credit')
        OR (operation IN ('recharge_refund','recharge_void') AND commercial_order_id IS NULL
            AND reverses_transaction_id IS NOT NULL AND payment_attempt_id IS NULL AND recharge_order_id IS NOT NULL
            AND recharge_provider_event_id IS NOT NULL AND direction='debit')
        OR (operation='migrate_import_credit' AND commercial_order_id IS NULL AND reverses_transaction_id IS NULL
            AND payment_attempt_id IS NULL AND recharge_order_id IS NULL AND recharge_provider_event_id IS NULL
            AND adjustment_request_id IS NULL AND direction='credit')
    );

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
    -- they have no package order (298). Migration import credits are bound to
    -- their approved migrate_import_balance_credits row (446).
    IF NEW.operation IN ('manual_adjustment', 'recharge_payment', 'recharge_refund', 'recharge_void',
                         'migrate_import_credit') THEN
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

-- A migrate_import_credit transaction exists only for an approved balance
-- credit row with the same tenant and amount (deferred: the row is updated
-- in the same transaction after the ledger insert).
CREATE FUNCTION assert_migrate_import_credit_446()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.operation <> 'migrate_import_credit' THEN
        RETURN NULL;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM migrate_import_balance_credits credit
        WHERE credit.billing_transaction_id = NEW.id AND credit.state = 'approved'
          AND credit.target_scope_id = NEW.target_scope_id AND credit.amount_minor = NEW.amount_minor
          AND credit.decided_by = NEW.created_by_user_id
    ) THEN
        RAISE EXCEPTION 'migrate import credit lacks an approved balance credit' USING ERRCODE='P4463';
    END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER billing_transactions_migrate_import_credit
AFTER INSERT ON billing_transactions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_migrate_import_credit_446();

INSERT INTO permissions(name, description)
VALUES ('system.migrate_import.manage', 'Import users, packages, sites, certificates and balances from another CDN system');

INSERT INTO role_permissions(role_id, permission_name)
SELECT role.id, 'system.migrate_import.manage'
FROM roles role
JOIN access_scopes scope ON scope.id = role.scope_id AND scope.kind = 'platform'
WHERE role.system_role AND role.name = 'platform_owner'
ON CONFLICT DO NOTHING;

INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES ('identity.migrated_account', true, true, true, 1, 24, true, true, true, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('identity.migrated_account.zh-cn', 1, 'sms', '',
     '您在{{.source_name}}的账号{{.username}}已迁移到新平台，请打开{{.link}}设置新密码后登录。',
     ARRAY['source_name','username','link'], '2026-10-21 00:00:00+00'),
    ('identity.migrated_account.zh-cn', 1, 'email', '您的账号已迁移到新平台',
     '您在{{.source_name}}的账号已迁移到新平台，登录用户名为 {{.username}}。请打开 {{.link}} 用"找回密码"设置新密码后登录。',
     ARRAY['source_name','username','link'], '2026-10-21 00:00:00+00');

-- Platform-scoped step-up proofs (10-21 06:50): a platform administrator has
-- no tenant, so platform-level sensitive operations (import confirmation,
-- batch balance approval, clearing legacy hashes) bind a proof without a
-- tenant. tenant_id may be NULL only when the proof session is a platform
-- session; a tenant session still requires its own active tenant. Uses copy
-- the proof's tenant through the composite FK (MATCH SIMPLE skips NULL, so
-- the use trigger checks it explicitly).
ALTER TABLE mfa_step_up_proofs ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE mfa_step_up_uses ALTER COLUMN tenant_id DROP NOT NULL;

CREATE OR REPLACE FUNCTION validate_mfa_step_up_proof()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    session_valid boolean;
    tenant_active boolean;
    authentication_valid boolean;
BEGIN
    SELECT session.user_id = NEW.actor_user_id AND session.scope_id = NEW.actor_scope_id AND
           session.revoked_at IS NULL AND session.expires_at > NEW.issued_at AND
           ((scope.kind = 'platform') OR
            (scope.kind = 'tenant' AND NEW.tenant_id IS NOT NULL AND scope.tenant_id = NEW.tenant_id))
      INTO session_valid
    FROM auth_sessions session
    JOIN access_scopes scope ON scope.id = session.scope_id
    WHERE session.id = NEW.auth_session_id;
    IF NEW.tenant_id IS NULL THEN
        tenant_active := true;
    ELSE
        SELECT status = 'active' INTO tenant_active FROM tenants WHERE id = NEW.tenant_id;
    END IF;
    SELECT event.credential_id = NEW.credential_id AND event.user_id = NEW.actor_user_id AND
           event.scope_id = NEW.actor_scope_id AND event.request_id = NEW.request_id AND
           event.occurred_at = NEW.issued_at AND
           ((NEW.authentication_method = 'totp' AND event.event_type = 'totp_verified') OR
            (NEW.authentication_method = 'recovery_code' AND event.event_type = 'recovery_verified'))
      INTO authentication_valid
    FROM mfa_credential_events event WHERE event.id = NEW.authentication_event_id;
    IF session_valid IS DISTINCT FROM true OR tenant_active IS DISTINCT FROM true OR
       authentication_valid IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'invalid MFA step-up proof';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION validate_mfa_step_up_use()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    proof_max_uses smallint;
    proof_expires_at timestamptz;
    proof_tenant uuid;
    proof_user uuid;
    proof_scope uuid;
    proof_session uuid;
BEGIN
    SELECT max_uses, expires_at, tenant_id, actor_user_id, actor_scope_id, auth_session_id
      INTO proof_max_uses, proof_expires_at, proof_tenant, proof_user, proof_scope, proof_session
    FROM mfa_step_up_proofs WHERE id = NEW.proof_id;
    IF NOT FOUND OR NEW.use_ordinal > proof_max_uses OR NEW.used_at >= proof_expires_at OR
       proof_tenant IS DISTINCT FROM NEW.tenant_id OR proof_user IS DISTINCT FROM NEW.actor_user_id OR
       proof_scope IS DISTINCT FROM NEW.actor_scope_id OR proof_session IS DISTINCT FROM NEW.auth_session_id THEN
        RAISE EXCEPTION 'invalid MFA step-up use';
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON migrate_import_jobs, migrate_import_items, migrate_import_mappings, migrate_import_order_archive,
    migrate_import_legacy_passwords, migrate_import_balance_credits FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON migrate_import_jobs, migrate_import_items, migrate_import_balance_credits
    TO cdnca_control_app, cdnca_control_runtime;
GRANT DELETE ON migrate_import_items TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT ON migrate_import_mappings, migrate_import_order_archive TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, DELETE ON migrate_import_legacy_passwords TO cdnca_control_app, cdnca_control_runtime;
