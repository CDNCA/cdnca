-- 584 回退：删除退款意图与外调记录。存在任何意图即拒绝回退（已发生或在途的渠道退款不能丢失记录）。
LOCK TABLE schema_migrations, recharge_payment_compensations_v1, recharge_payment_compensation_attempts_v1,
    recharge_orders_v1, billing_transactions
    IN ACCESS EXCLUSIVE MODE;

DO $migration_584_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 584 OR
       (SELECT max(version) FROM schema_migrations) <> 584 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=584 AND
        migration_id='584_recharge_payment_compensations' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 584 down requires the exact verified migration head' USING ERRCODE='P5843';
    END IF;
    IF EXISTS (SELECT 1 FROM recharge_payment_compensations_v1) THEN
        RAISE EXCEPTION 'migration 584 down: recharge payment compensations exist' USING ERRCODE='P5844';
    END IF;
END;
$migration_584_down$;

-- 恢复 555 定义（无升级包分支）；已有加购流水时会因约束失败而拒绝回退。
ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_commerce_shape;
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
        OR (operation='reseller_sale' AND commercial_order_id IS NOT NULL AND payment_attempt_id IS NULL
            AND recharge_order_id IS NULL AND recharge_provider_event_id IS NULL AND balance_hold_id IS NULL
            AND direction = CASE WHEN reverses_transaction_id IS NULL THEN 'credit' ELSE 'debit' END)
        -- 555：首笔方向由 assert_reseller_transaction_483 按订单核对（升降级可为 credit）。
        OR (operation='reseller_wholesale' AND commercial_order_id IS NOT NULL AND payment_attempt_id IS NULL
            AND recharge_order_id IS NULL AND recharge_provider_event_id IS NULL AND balance_hold_id IS NULL
            AND (reverses_transaction_id IS NULL OR direction='credit'))
    );

-- 存在意图即已拒绝回退，因此不会有 revision>2 的订单（只有退款/作废落账会推高修订号）。
ALTER TABLE recharge_orders_v1 ADD CONSTRAINT recharge_orders_v1_check2
    CHECK((state='pending' AND revision=1) OR (state<>'pending' AND revision=2));

DROP TABLE recharge_payment_compensation_attempts_v1;
DROP TABLE recharge_payment_compensations_v1;
DROP FUNCTION prevent_recharge_payment_compensation_mutation_584();
DROP FUNCTION validate_recharge_payment_compensation_attempt_584();
DROP FUNCTION guard_recharge_payment_compensation_head_584();
