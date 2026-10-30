LOCK TABLE schema_migrations, permissions, custom_rbac_permission_catalog,
    roles, role_permissions IN ACCESS EXCLUSIVE MODE;

DO $migration_207$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=206
          AND migration_id='206_dns_legacy_settings'
          AND integrity_state='verified'
          AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 207 requires a verified 206 DNS legacy settings head'
            USING ERRCODE='P2070';
    END IF;
END;
$migration_207$;

INSERT INTO permissions(name,description) VALUES
    ('billing.order_records.manage','Create, edit, and archive tenant compatibility order records');

INSERT INTO custom_rbac_permission_catalog(permission_name,step_up_required)
VALUES ('billing.order_records.manage',false);

INSERT INTO role_permissions(role_id,permission_name)
SELECT role.id,'billing.order_records.manage'
FROM roles role
JOIN access_scopes scope ON scope.id=role.scope_id AND scope.kind='tenant'
WHERE role.system_role AND role.name='tenant_owner'
ON CONFLICT DO NOTHING;

CREATE FUNCTION grant_account_order_record_permission_207()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.system_role AND NEW.name='tenant_owner' AND EXISTS (
        SELECT 1 FROM access_scopes WHERE id=NEW.scope_id AND kind='tenant'
    ) THEN
        INSERT INTO role_permissions(role_id,permission_name)
        VALUES(NEW.id,'billing.order_records.manage') ON CONFLICT DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER roles_account_order_record_permission_207
AFTER INSERT ON roles
FOR EACH ROW EXECUTE FUNCTION grant_account_order_record_permission_207();

REVOKE ALL ON FUNCTION grant_account_order_record_permission_207() FROM PUBLIC;

CREATE TABLE account_order_records (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    order_type text NOT NULL CHECK(order_type IN (
        'recharge','deduction','upgrade','purchase','renewal','package_change'
    )),
    note text NOT NULL DEFAULT '' CHECK(note=btrim(note) AND char_length(note)<=500),
    original_amount_minor bigint NOT NULL CHECK(original_amount_minor BETWEEN 0 AND 9000000000000000),
    paid_amount_minor bigint NOT NULL CHECK(paid_amount_minor BETWEEN 0 AND original_amount_minor),
    payment_method text NOT NULL DEFAULT '' CHECK(
        payment_method=btrim(payment_method) AND char_length(payment_method)<=64
    ),
    merchant_order_number text NOT NULL DEFAULT '' CHECK(
        merchant_order_number=btrim(merchant_order_number) AND char_length(merchant_order_number)<=128
    ),
    transaction_number text NOT NULL DEFAULT '' CHECK(
        transaction_number=btrim(transaction_number) AND char_length(transaction_number)<=128
    ),
    status text NOT NULL CHECK(status IN ('paid','unpaid')),
    paid_at timestamptz CHECK(paid_at IS NULL OR isfinite(paid_at)),
    revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
    created_by_user_id uuid NOT NULL,
    updated_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    recorded_at timestamptz NOT NULL CHECK(isfinite(recorded_at)),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=recorded_at),
    deleted_at timestamptz CHECK(deleted_at IS NULL OR (isfinite(deleted_at) AND deleted_at>=updated_at)),
    FOREIGN KEY(tenant_scope_id,tenant_id) REFERENCES access_scopes(id,tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY(tenant_scope_id,user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    FOREIGN KEY(tenant_scope_id,created_by_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    FOREIGN KEY(tenant_scope_id,updated_by_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    CHECK((status='paid' AND paid_at IS NOT NULL AND paid_at>=created_at) OR
          (status='unpaid' AND paid_at IS NULL))
);

CREATE INDEX account_order_records_scope_created_idx
    ON account_order_records(tenant_scope_id,created_at DESC,id DESC)
    WHERE deleted_at IS NULL;
CREATE INDEX account_order_records_scope_user_created_idx
    ON account_order_records(tenant_scope_id,user_id,created_at DESC,id DESC)
    WHERE deleted_at IS NULL;
CREATE INDEX account_order_records_scope_filter_idx
    ON account_order_records(tenant_scope_id,order_type,status,created_at DESC,id DESC)
    WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX account_order_records_scope_merchant_number_idx
    ON account_order_records(tenant_scope_id,merchant_order_number)
    WHERE merchant_order_number<>'' AND deleted_at IS NULL;

CREATE TABLE account_order_record_events (
    id uuid PRIMARY KEY,
    record_id uuid NOT NULL REFERENCES account_order_records(id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL,
    revision bigint NOT NULL CHECK(revision>0),
    operation text NOT NULL CHECK(operation IN ('created','updated','deleted')),
    actor_user_id uuid NOT NULL,
    request_id text NOT NULL CHECK(request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    snapshot jsonb NOT NULL CHECK(jsonb_typeof(snapshot)='object' AND octet_length(snapshot::text)<=32768),
    occurred_at timestamptz NOT NULL CHECK(isfinite(occurred_at)),
    FOREIGN KEY(tenant_scope_id,actor_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    UNIQUE(record_id,revision),
    UNIQUE(tenant_scope_id,request_id)
);

CREATE INDEX account_order_record_events_scope_occurred_idx
    ON account_order_record_events(tenant_scope_id,occurred_at DESC,id DESC);

CREATE TABLE account_order_record_write_receipts (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    actor_session_id uuid NOT NULL,
    operation text NOT NULL CHECK(operation IN (
        'billing.order_record.create','billing.order_record.update','billing.order_record.delete'
    )),
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    request_id text NOT NULL CHECK(request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    record_id uuid NOT NULL REFERENCES account_order_records(id) ON DELETE RESTRICT,
    response_body jsonb NOT NULL CHECK(jsonb_typeof(response_body)='object' AND octet_length(response_body::text)<=32768),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    FOREIGN KEY(actor_session_id,tenant_scope_id,actor_user_id)
        REFERENCES auth_sessions(id,scope_id,user_id) ON DELETE RESTRICT,
    UNIQUE(actor_session_id,operation,idempotency_key),
    UNIQUE(actor_session_id,request_id)
);

CREATE INDEX account_order_record_write_receipts_record_idx
    ON account_order_record_write_receipts(record_id,created_at DESC);

CREATE FUNCTION guard_account_order_record_head_207()
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

CREATE FUNCTION prevent_account_order_record_fact_mutation_207()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only',TG_TABLE_NAME USING ERRCODE='P2073';
END;
$$;

CREATE TRIGGER account_order_records_head_guard_207
BEFORE UPDATE OR DELETE ON account_order_records
FOR EACH ROW EXECUTE FUNCTION guard_account_order_record_head_207();
CREATE TRIGGER account_order_records_no_truncate_207
BEFORE TRUNCATE ON account_order_records
FOR EACH STATEMENT EXECUTE FUNCTION prevent_account_order_record_fact_mutation_207();
CREATE TRIGGER account_order_record_events_append_only_207
BEFORE UPDATE OR DELETE OR TRUNCATE ON account_order_record_events
FOR EACH STATEMENT EXECUTE FUNCTION prevent_account_order_record_fact_mutation_207();
CREATE TRIGGER account_order_record_write_receipts_append_only_207
BEFORE UPDATE OR DELETE OR TRUNCATE ON account_order_record_write_receipts
FOR EACH STATEMENT EXECUTE FUNCTION prevent_account_order_record_fact_mutation_207();

REVOKE ALL ON account_order_records,account_order_record_events,
    account_order_record_write_receipts FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO cdnca_control_app;
GRANT SELECT,INSERT,UPDATE ON account_order_records TO cdnca_control_app;
GRANT SELECT,INSERT ON account_order_record_events,account_order_record_write_receipts
    TO cdnca_control_app;
