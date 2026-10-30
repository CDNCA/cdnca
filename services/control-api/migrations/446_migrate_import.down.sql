LOCK TABLE schema_migrations, billing_transactions, memberships, notification_event_policies, notification_templates
    IN ACCESS EXCLUSIVE MODE;

DO $migration_446_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 446 OR
       (SELECT max(version) FROM schema_migrations) <> 446 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=446 AND
        migration_id='446_migrate_import' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 446 down requires the exact verified migration head' USING ERRCODE='P4461';
    END IF;
    -- Imported ledger credits, legacy hashes and sent notices cannot be
    -- expressed by the 431 schema.
    IF EXISTS (SELECT 1 FROM billing_transactions WHERE operation = 'migrate_import_credit') OR
       EXISTS (SELECT 1 FROM migrate_import_legacy_passwords) OR
       EXISTS (SELECT 1 FROM notification_outbox WHERE template_id = 'identity.migrated_account.zh-cn') OR
       EXISTS (SELECT 1 FROM mfa_step_up_proofs WHERE tenant_id IS NULL) THEN
        RAISE EXCEPTION 'migration 446 rollback would drop migration import facts' USING ERRCODE='P4464';
    END IF;
END;
$migration_446_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id = 'identity.migrated_account.zh-cn' AND version = 1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type = 'identity.migrated_account';
DELETE FROM notification_event_policies WHERE event_type = 'identity.migrated_account';
DELETE FROM role_permissions WHERE permission_name = 'system.migrate_import.manage';
DELETE FROM permissions WHERE name = 'system.migrate_import.manage';

DROP TRIGGER billing_transactions_migrate_import_credit ON billing_transactions;
DROP FUNCTION assert_migrate_import_credit_446();
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

ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_commerce_shape;
ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_operation_check;
ALTER TABLE billing_transactions
    ADD CONSTRAINT billing_transactions_operation_check CHECK(operation IN (
        'manual_adjustment','provider_payment','package_purchase','package_renewal','package_upgrade',
        'package_downgrade','package_refund','package_void','traffic_package_purchase',
        'recharge_payment','recharge_refund','recharge_void'
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
    );

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
           (scope.kind = 'platform' OR (scope.kind = 'tenant' AND scope.tenant_id = NEW.tenant_id))
      INTO session_valid
    FROM auth_sessions session
    JOIN access_scopes scope ON scope.id = session.scope_id
    WHERE session.id = NEW.auth_session_id;
    SELECT status = 'active' INTO tenant_active FROM tenants WHERE id = NEW.tenant_id;
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
BEGIN
    SELECT max_uses, expires_at INTO proof_max_uses, proof_expires_at
    FROM mfa_step_up_proofs WHERE id = NEW.proof_id;
    IF NEW.use_ordinal > proof_max_uses OR NEW.used_at >= proof_expires_at THEN
        RAISE EXCEPTION 'invalid MFA step-up use';
    END IF;
    RETURN NEW;
END;
$$;
ALTER TABLE mfa_step_up_uses ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE mfa_step_up_proofs ALTER COLUMN tenant_id SET NOT NULL;

DROP TRIGGER memberships_refuse_legacy_platform_member ON memberships;
DROP FUNCTION refuse_legacy_platform_member_446();
DROP TABLE migrate_import_balance_credits;
DROP TABLE migrate_import_legacy_passwords;
DROP TABLE migrate_import_order_archive;
DROP FUNCTION prevent_migrate_import_order_archive_mutation_446();
DROP TABLE migrate_import_mappings;
DROP TABLE migrate_import_items;
DROP TABLE migrate_import_jobs;
