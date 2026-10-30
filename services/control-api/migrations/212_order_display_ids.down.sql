LOCK TABLE schema_migrations, account_order_records, package_orders, recharge_orders_v1,
    account_order_display_id_sequences, package_order_display_id_sequences,
    recharge_order_display_id_sequences IN ACCESS EXCLUSIVE MODE;

DO $migration_212_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>212 OR
       (SELECT max(version) FROM schema_migrations)<>212 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=212 AND migration_id='212_order_display_ids' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 212 rollback requires the exact verified 212 release head'
            USING ERRCODE='P2120';
    END IF;
END;
$migration_212_down$;

DROP TRIGGER account_order_records_display_id_212 ON account_order_records;
DROP TRIGGER package_orders_display_id_212 ON package_orders;
DROP TRIGGER recharge_orders_display_id_212 ON recharge_orders_v1;
DROP FUNCTION allocate_account_order_display_id_212();
DROP FUNCTION allocate_package_order_display_id_212();
DROP FUNCTION allocate_recharge_order_display_id_212();

DROP TRIGGER account_order_records_head_guard_207 ON account_order_records;
DROP TRIGGER package_orders_append_only ON package_orders;
DROP TRIGGER recharge_orders_head_guard_v1 ON recharge_orders_v1;

ALTER TABLE account_order_records
    DROP CONSTRAINT account_order_records_scope_display_id_unique,
    DROP CONSTRAINT account_order_records_display_id_positive,
    DROP COLUMN display_id;
ALTER TABLE package_orders
    DROP CONSTRAINT package_orders_scope_display_id_unique,
    DROP CONSTRAINT package_orders_display_id_positive,
    DROP COLUMN display_id;
ALTER TABLE recharge_orders_v1
    DROP CONSTRAINT recharge_orders_scope_display_id_unique,
    DROP CONSTRAINT recharge_orders_display_id_positive,
    DROP COLUMN display_id;

CREATE OR REPLACE FUNCTION guard_account_order_record_head_207()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'account order record heads cannot be deleted' USING ERRCODE='P2071';
    END IF;
    IF TG_OP='UPDATE' AND (
        OLD.deleted_at IS NOT NULL OR
        ROW(NEW.id,NEW.tenant_scope_id,NEW.tenant_id,NEW.created_by_user_id,NEW.recorded_at) IS DISTINCT FROM
        ROW(OLD.id,OLD.tenant_scope_id,OLD.tenant_id,OLD.created_by_user_id,OLD.recorded_at) OR
        NEW.revision<>OLD.revision+1 OR NEW.updated_at<OLD.updated_at OR
        (OLD.deleted_at IS NOT NULL AND NEW.deleted_at IS DISTINCT FROM OLD.deleted_at)
    ) THEN
        RAISE EXCEPTION 'account order record transition is invalid' USING ERRCODE='P2072';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER account_order_records_head_guard_207
BEFORE UPDATE OR DELETE ON account_order_records
FOR EACH ROW EXECUTE FUNCTION guard_account_order_record_head_207();

CREATE TRIGGER package_orders_append_only BEFORE UPDATE OR DELETE ON package_orders
FOR EACH ROW EXECUTE FUNCTION prevent_package_commerce_fact_mutation();

CREATE OR REPLACE FUNCTION guard_recharge_payment_order_head_152()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'recharge payment order head is append-only' USING ERRCODE='P1521';
    END IF;
    IF OLD.id<>NEW.id OR OLD.tenant_scope_id<>NEW.tenant_scope_id OR OLD.tenant_id<>NEW.tenant_id OR
       OLD.user_id<>NEW.user_id OR OLD.channel<>NEW.channel OR OLD.amount_minor<>NEW.amount_minor OR
       OLD.currency<>NEW.currency OR OLD.created_at<>NEW.created_at OR NEW.revision<>OLD.revision+1 OR
       NEW.updated_at<OLD.updated_at OR
       (OLD.provider IS NOT NULL AND (NEW.provider,NEW.provider_account_id,NEW.external_payment_id) IS DISTINCT FROM
          (OLD.provider,OLD.provider_account_id,OLD.external_payment_id)) OR
       (OLD.provider IS NULL AND NEW.provider IS NULL AND NEW.state NOT IN ('pending','failed','canceled','reconcile_required')) OR
       NOT ((OLD.state='pending' AND NEW.state IN ('paid','failed','canceled','reconcile_required')) OR
            (OLD.state='paid' AND NEW.state IN ('partially_refunded','refunded','voided','reconcile_required')) OR
            (OLD.state='partially_refunded' AND NEW.state IN ('partially_refunded','refunded','voided','reconcile_required')) OR
            (OLD.state='reconcile_required' AND NEW.state IN ('paid','failed','partially_refunded','refunded','voided','reconcile_required'))) THEN
        RAISE EXCEPTION 'recharge payment order transition is invalid' USING ERRCODE='P1521';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recharge_orders_head_guard_v1 BEFORE UPDATE OR DELETE ON recharge_orders_v1
FOR EACH ROW EXECUTE FUNCTION guard_recharge_payment_order_head_152();

DROP TABLE account_order_display_id_sequences;
DROP TABLE package_order_display_id_sequences;
DROP TABLE recharge_order_display_id_sequences;
