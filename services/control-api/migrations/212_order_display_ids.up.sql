LOCK TABLE schema_migrations, access_scopes, account_order_records, package_orders,
    recharge_orders_v1 IN ACCESS EXCLUSIVE MODE;

DO $migration_212$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>211 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>211 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=211 AND migration_id='211_node_display_ids' AND
              checksum_sha256='11a619efabf41fadb21c6684087dfbe91059397c3b317d2a68a9739bd71216c9' AND
              down_checksum_sha256='87dfe8d5e9bdfece27ac09b79512278722b768bfc09c0b264b536592574590a5' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND column_name='display_id' AND
              table_name IN ('account_order_records','package_orders','recharge_orders_v1')
    ) OR to_regclass(current_schema() || '.account_order_display_id_sequences') IS NOT NULL OR
         to_regclass(current_schema() || '.package_order_display_id_sequences') IS NOT NULL OR
         to_regclass(current_schema() || '.recharge_order_display_id_sequences') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 212 requires the exact verified 211 release head and an untouched order display ID schema'
            USING ERRCODE='P2120';
    END IF;
END;
$migration_212$;

CREATE TABLE account_order_display_id_sequences (
    scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    next_value bigint NOT NULL CHECK(next_value>0),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE package_order_display_id_sequences (
    scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    next_value bigint NOT NULL CHECK(next_value>0),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE recharge_order_display_id_sequences (
    scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    next_value bigint NOT NULL CHECK(next_value>0),
    updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE account_order_records ADD COLUMN display_id bigint;
ALTER TABLE package_orders ADD COLUMN display_id bigint;
ALTER TABLE recharge_orders_v1 ADD COLUMN display_id bigint;

DROP TRIGGER account_order_records_head_guard_207 ON account_order_records;
DROP TRIGGER package_orders_append_only ON package_orders;
DROP TRIGGER recharge_orders_head_guard_v1 ON recharge_orders_v1;

WITH ranked AS (
    SELECT id,row_number() OVER(PARTITION BY tenant_scope_id ORDER BY created_at,id) AS display_id
    FROM account_order_records
)
UPDATE account_order_records SET display_id=ranked.display_id FROM ranked
WHERE account_order_records.id=ranked.id;
WITH ranked AS (
    SELECT id,row_number() OVER(PARTITION BY tenant_scope_id ORDER BY created_at,id) AS display_id
    FROM package_orders
)
UPDATE package_orders SET display_id=ranked.display_id FROM ranked
WHERE package_orders.id=ranked.id;
WITH ranked AS (
    SELECT id,row_number() OVER(PARTITION BY tenant_scope_id ORDER BY created_at,id) AS display_id
    FROM recharge_orders_v1
)
UPDATE recharge_orders_v1 SET display_id=ranked.display_id FROM ranked
WHERE recharge_orders_v1.id=ranked.id;

INSERT INTO account_order_display_id_sequences(scope_id,next_value)
SELECT scope.id,COALESCE(max(record.display_id),0)+1 FROM access_scopes scope
LEFT JOIN account_order_records record ON record.tenant_scope_id=scope.id
WHERE scope.kind='tenant' GROUP BY scope.id;
INSERT INTO package_order_display_id_sequences(scope_id,next_value)
SELECT scope.id,COALESCE(max(package_order.display_id),0)+1 FROM access_scopes scope
LEFT JOIN package_orders package_order ON package_order.tenant_scope_id=scope.id
WHERE scope.kind='tenant' GROUP BY scope.id;
INSERT INTO recharge_order_display_id_sequences(scope_id,next_value)
SELECT scope.id,COALESCE(max(recharge.display_id),0)+1 FROM access_scopes scope
LEFT JOIN recharge_orders_v1 recharge ON recharge.tenant_scope_id=scope.id
WHERE scope.kind='tenant' GROUP BY scope.id;

ALTER TABLE account_order_records
    ALTER COLUMN display_id SET NOT NULL,
    ADD CONSTRAINT account_order_records_display_id_positive CHECK(display_id>0),
    ADD CONSTRAINT account_order_records_scope_display_id_unique UNIQUE(tenant_scope_id,display_id);
ALTER TABLE package_orders
    ALTER COLUMN display_id SET NOT NULL,
    ADD CONSTRAINT package_orders_display_id_positive CHECK(display_id>0),
    ADD CONSTRAINT package_orders_scope_display_id_unique UNIQUE(tenant_scope_id,display_id);
ALTER TABLE recharge_orders_v1
    ALTER COLUMN display_id SET NOT NULL,
    ADD CONSTRAINT recharge_orders_display_id_positive CHECK(display_id>0),
    ADD CONSTRAINT recharge_orders_scope_display_id_unique UNIQUE(tenant_scope_id,display_id);

CREATE OR REPLACE FUNCTION guard_account_order_record_head_207()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'account order record heads cannot be deleted' USING ERRCODE='P2071';
    END IF;
    IF TG_OP='UPDATE' AND (
        OLD.deleted_at IS NOT NULL OR
        ROW(NEW.id,NEW.display_id,NEW.tenant_scope_id,NEW.tenant_id,NEW.created_by_user_id,NEW.recorded_at) IS DISTINCT FROM
        ROW(OLD.id,OLD.display_id,OLD.tenant_scope_id,OLD.tenant_id,OLD.created_by_user_id,OLD.recorded_at) OR
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
    IF OLD.id<>NEW.id OR OLD.display_id<>NEW.display_id OR OLD.tenant_scope_id<>NEW.tenant_scope_id OR OLD.tenant_id<>NEW.tenant_id OR
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

CREATE FUNCTION allocate_account_order_display_id_212()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.display_id IS NOT NULL THEN RAISE EXCEPTION 'account order display ID is allocator-owned' USING ERRCODE='P2121'; END IF;
    INSERT INTO account_order_display_id_sequences(scope_id,next_value,updated_at)
    VALUES(NEW.tenant_scope_id,2,now())
    ON CONFLICT(scope_id) DO UPDATE SET next_value=account_order_display_id_sequences.next_value+1,updated_at=now()
    RETURNING next_value-1 INTO NEW.display_id;
    RETURN NEW;
END;
$$;
CREATE FUNCTION allocate_package_order_display_id_212()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.display_id IS NOT NULL THEN RAISE EXCEPTION 'package order display ID is allocator-owned' USING ERRCODE='P2122'; END IF;
    INSERT INTO package_order_display_id_sequences(scope_id,next_value,updated_at)
    VALUES(NEW.tenant_scope_id,2,now())
    ON CONFLICT(scope_id) DO UPDATE SET next_value=package_order_display_id_sequences.next_value+1,updated_at=now()
    RETURNING next_value-1 INTO NEW.display_id;
    RETURN NEW;
END;
$$;
CREATE FUNCTION allocate_recharge_order_display_id_212()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.display_id IS NOT NULL THEN RAISE EXCEPTION 'recharge order display ID is allocator-owned' USING ERRCODE='P2123'; END IF;
    INSERT INTO recharge_order_display_id_sequences(scope_id,next_value,updated_at)
    VALUES(NEW.tenant_scope_id,2,now())
    ON CONFLICT(scope_id) DO UPDATE SET next_value=recharge_order_display_id_sequences.next_value+1,updated_at=now()
    RETURNING next_value-1 INTO NEW.display_id;
    RETURN NEW;
END;
$$;

CREATE TRIGGER account_order_records_display_id_212 BEFORE INSERT ON account_order_records
FOR EACH ROW EXECUTE FUNCTION allocate_account_order_display_id_212();
CREATE TRIGGER package_orders_display_id_212 BEFORE INSERT ON package_orders
FOR EACH ROW EXECUTE FUNCTION allocate_package_order_display_id_212();
CREATE TRIGGER recharge_orders_display_id_212 BEFORE INSERT ON recharge_orders_v1
FOR EACH ROW EXECUTE FUNCTION allocate_recharge_order_display_id_212();

REVOKE ALL ON FUNCTION allocate_account_order_display_id_212(),
    allocate_package_order_display_id_212(),allocate_recharge_order_display_id_212() FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON account_order_display_id_sequences,
    package_order_display_id_sequences,recharge_order_display_id_sequences TO cdnca_control_app;
