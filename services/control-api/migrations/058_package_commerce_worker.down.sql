LOCK TABLE package_commerce_outbox, package_commerce_outbox_deliveries,
    package_commerce_outbox_attempts, package_balance_hold_settlements,
    billing_transactions
    IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM package_commerce_outbox_attempts)
       OR EXISTS (SELECT 1 FROM package_balance_hold_settlements)
       OR EXISTS (SELECT 1 FROM billing_transactions WHERE balance_hold_id IS NOT NULL)
       OR EXISTS (
           SELECT 1 FROM package_commerce_outbox_deliveries
           WHERE state <> 'pending' OR attempt_count <> 0 OR lease_fence <> 0
              OR lease_owner IS NOT NULL OR lease_token IS NOT NULL
              OR lease_expires_at IS NOT NULL OR completed_at IS NOT NULL
              OR last_result_code IS NOT NULL
       )
       OR EXISTS (
           SELECT 1
           FROM package_commerce_outbox outbox
           FULL JOIN package_commerce_outbox_deliveries delivery
               ON delivery.outbox_id = outbox.id
           WHERE outbox.id IS NULL OR delivery.outbox_id IS NULL
              OR delivery.available_at IS DISTINCT FROM outbox.created_at
              OR delivery.created_at IS DISTINCT FROM outbox.created_at
              OR delivery.updated_at IS DISTINCT FROM outbox.created_at
       ) THEN
        RAISE EXCEPTION 'migration 058 rollback requires worker delivery and hold settlement facts to be absent';
    END IF;
END;
$$;

DROP TRIGGER billing_transactions_balance_hold_valid ON billing_transactions;
DROP TRIGGER package_balance_hold_settlements_no_truncate ON package_balance_hold_settlements;
DROP TRIGGER package_balance_hold_settlements_append_only ON package_balance_hold_settlements;
DROP TRIGGER package_balance_hold_settlements_validate ON package_balance_hold_settlements;
DROP FUNCTION assert_package_balance_hold_transaction();
DROP FUNCTION validate_package_balance_hold_settlement();

DROP TRIGGER package_commerce_outbox_attempts_no_truncate ON package_commerce_outbox_attempts;
DROP TRIGGER package_commerce_outbox_attempts_protect ON package_commerce_outbox_attempts;
DROP FUNCTION protect_package_commerce_outbox_attempt();

DROP TRIGGER package_commerce_outbox_enqueue_delivery ON package_commerce_outbox;
DROP FUNCTION enqueue_package_commerce_outbox_delivery();

DROP TABLE package_balance_hold_settlements;
DROP TABLE package_commerce_outbox_attempts;
DROP TABLE package_commerce_outbox_deliveries;

DROP INDEX billing_transactions_balance_hold_idx;
ALTER TABLE billing_transactions
    DROP CONSTRAINT billing_transactions_balance_hold_shape,
    DROP COLUMN balance_hold_id;
