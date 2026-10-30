LOCK TABLE schema_migrations,permissions,role_permissions,auth_sessions,recharge_orders_v1,
    recharge_order_events_v1,recharge_provider_callbacks_v1,recharge_settlements_v1,
    billing_transactions,billing_postings,recharge_payment_checkouts_v1,recharge_payment_provider_events_v1,
    recharge_payment_commands_v1,recharge_payment_reconcile_jobs_v1,recharge_payment_reconcile_receipts_v1
IN ACCESS EXCLUSIVE MODE;

DO $migration_152$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>152 OR (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>152 OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE migration_id IS NULL OR migration_id='' OR
            checksum_sha256 !~ '^[0-9a-f]{64}$' OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
            integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=152 AND migration_id='152_recharge_payment_lifecycle' AND
            checksum_sha256='5aa5c735685cb02cce34fca432592f280c8f53a4f8c8c006067e43e997d279e0' AND integrity_state='verified' AND
            metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=151 AND migration_id='151_l4_domain_geo_runtime' AND
            checksum_sha256='81a2cdcf12d5ddeb456b219c402043fe0b17b79f379da8436b79e3a7a3627668' AND
            down_checksum_sha256='2bad7d25e8c2bbec6a80385a65868efa82e7af2b826c21eead23e6e4ef92b71f' AND
            integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 152 rollback requires the exact verified 152 head' USING ERRCODE='P1520';
    END IF;
    IF EXISTS(SELECT 1 FROM recharge_payment_checkouts_v1) OR
       EXISTS(SELECT 1 FROM recharge_payment_commands_v1) OR
       EXISTS(SELECT 1 FROM recharge_payment_reconcile_jobs_v1) OR
       EXISTS(SELECT 1 FROM recharge_payment_reconcile_receipts_v1) OR
       EXISTS(SELECT 1 FROM recharge_payment_provider_events_v1 WHERE source_callback_id IS NULL) OR
       EXISTS(SELECT 1 FROM billing_transactions WHERE operation IN ('recharge_refund','recharge_void')) OR
       EXISTS(SELECT 1 FROM recharge_orders_v1 WHERE state IN ('partially_refunded','refunded','voided','reconcile_required') OR refunded_minor<>0) THEN
        RAISE EXCEPTION 'migration 152 rollback would discard recharge payment lifecycle facts' USING ERRCODE='P1524';
    END IF;
END;
$migration_152$;

DROP INDEX billing_transactions_recharge_payment_order_152_idx;
DROP INDEX billing_transactions_recharge_provider_event_152_idx;
ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_commerce_shape;
ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_operation_check;
ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_recharge_event_fk_152;
ALTER TABLE billing_transactions DROP COLUMN recharge_provider_event_id;
ALTER TABLE billing_transactions
    ADD CONSTRAINT billing_transactions_operation_check CHECK(operation IN (
        'manual_adjustment','provider_payment','package_purchase','package_renewal','package_upgrade',
        'package_downgrade','package_refund','package_void','traffic_package_purchase','recharge_payment'
    )),
    ADD CONSTRAINT billing_transactions_commerce_shape CHECK(
        (operation='manual_adjustment' AND commercial_order_id IS NULL AND reverses_transaction_id IS NULL
            AND payment_attempt_id IS NULL AND recharge_order_id IS NULL)
        OR (operation='provider_payment' AND commercial_order_id IS NOT NULL AND reverses_transaction_id IS NULL
            AND payment_attempt_id IS NOT NULL AND recharge_order_id IS NULL AND direction='credit')
        OR (operation IN ('package_purchase','package_renewal','package_upgrade','package_downgrade','traffic_package_purchase')
            AND commercial_order_id IS NOT NULL AND reverses_transaction_id IS NULL AND recharge_order_id IS NULL)
        OR (operation IN ('package_refund','package_void') AND commercial_order_id IS NOT NULL
            AND reverses_transaction_id IS NOT NULL AND recharge_order_id IS NULL AND direction='credit')
        OR (operation='recharge_payment' AND commercial_order_id IS NULL AND reverses_transaction_id IS NULL
            AND payment_attempt_id IS NULL AND recharge_order_id IS NOT NULL AND direction='credit')
    );
CREATE UNIQUE INDEX billing_transactions_recharge_order_v1_idx
    ON billing_transactions(recharge_order_id) WHERE recharge_order_id IS NOT NULL;

DROP TRIGGER recharge_payment_reconcile_jobs_guard_v1 ON recharge_payment_reconcile_jobs_v1;
DROP TRIGGER recharge_payment_reconcile_receipts_append_only_v1 ON recharge_payment_reconcile_receipts_v1;
DROP TRIGGER recharge_payment_commands_append_only_v1 ON recharge_payment_commands_v1;
DROP TRIGGER recharge_payment_events_append_only_v1 ON recharge_payment_provider_events_v1;
DROP TRIGGER recharge_payment_checkouts_append_only_v1 ON recharge_payment_checkouts_v1;
DROP FUNCTION guard_recharge_payment_reconcile_job_152();
DROP FUNCTION prevent_recharge_payment_fact_mutation_152();
DROP TABLE recharge_payment_reconcile_receipts_v1;
DROP TABLE recharge_payment_reconcile_jobs_v1;
DROP TABLE recharge_payment_commands_v1;
DROP TABLE recharge_payment_provider_events_v1;
DROP TABLE recharge_payment_checkouts_v1;

DROP TRIGGER recharge_orders_head_guard_v1 ON recharge_orders_v1;
DROP FUNCTION guard_recharge_payment_order_head_152();
ALTER TABLE recharge_order_events_v1
    DROP CONSTRAINT recharge_order_events_state_152,
    DROP CONSTRAINT recharge_order_events_revision_152,
    ADD CONSTRAINT recharge_order_events_v1_revision_check CHECK(revision BETWEEN 1 AND 2),
    ADD CONSTRAINT recharge_order_events_v1_state_check CHECK(state IN ('pending','paid','failed','canceled'));
ALTER TABLE recharge_orders_v1
    DROP CONSTRAINT recharge_orders_id_scope_152,
    DROP CONSTRAINT recharge_orders_revision_152,
    DROP CONSTRAINT recharge_orders_amounts_152,
    DROP CONSTRAINT recharge_orders_state_152,
    DROP COLUMN refunded_minor,
    DROP COLUMN captured_minor,
    ADD CONSTRAINT recharge_orders_v1_state_check CHECK(state IN ('pending','paid','failed','canceled')),
    ADD CONSTRAINT recharge_orders_v1_check1 CHECK((state='pending' AND revision=1) OR (state<>'pending' AND revision=2));

CREATE FUNCTION guard_billing_recharge_order_head_133()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'recharge order head is append-only' USING ERRCODE='P1331';
    END IF;
    IF OLD.id<>NEW.id OR OLD.tenant_scope_id<>NEW.tenant_scope_id OR OLD.tenant_id<>NEW.tenant_id OR
       OLD.user_id<>NEW.user_id OR OLD.channel<>NEW.channel OR OLD.amount_minor<>NEW.amount_minor OR
       OLD.currency<>NEW.currency OR OLD.created_at<>NEW.created_at OR OLD.state<>'pending' OR
       NEW.state NOT IN ('paid','failed','canceled') OR NEW.revision<>OLD.revision+1 OR
       NEW.updated_at<OLD.updated_at THEN
        RAISE EXCEPTION 'recharge order head transition is invalid' USING ERRCODE='P1331';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recharge_orders_head_guard_v1 BEFORE UPDATE OR DELETE ON recharge_orders_v1
FOR EACH ROW EXECUTE FUNCTION guard_billing_recharge_order_head_133();

DELETE FROM role_permissions WHERE permission_name IN ('billing.recharges.compensate','billing.recharges.reconcile');
DELETE FROM permissions WHERE name IN ('billing.recharges.compensate','billing.recharges.reconcile');
