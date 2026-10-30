LOCK TABLE schema_migrations,permissions,roles,role_permissions,auth_sessions,recharge_orders_v1,
    recharge_order_events_v1,recharge_provider_callbacks_v1,recharge_settlements_v1,
    billing_transactions,billing_postings IN ACCESS EXCLUSIVE MODE;

DO $migration_152$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 151 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 151 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=151 AND migration_id='151_l4_domain_geo_runtime' AND
              checksum_sha256='81a2cdcf12d5ddeb456b219c402043fe0b17b79f379da8436b79e3a7a3627668' AND
              down_checksum_sha256='2bad7d25e8c2bbec6a80385a65868efa82e7af2b826c21eead23e6e4ef92b71f' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('recharge_payment_provider_events_v1') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 152 requires the exact verified 151 release head' USING ERRCODE='P1520';
    END IF;
END;
$migration_152$;

INSERT INTO permissions(name,description) VALUES
    ('billing.recharges.compensate','Create signed recharge refund or void commands'),
    ('billing.recharges.reconcile','Reconcile an uncertain recharge provider result');

INSERT INTO role_permissions(role_id,permission_name)
SELECT role.id,permission.name
FROM roles role
CROSS JOIN (VALUES('billing.recharges.compensate'),('billing.recharges.reconcile')) permission(name)
JOIN access_scopes scope ON scope.id=role.scope_id AND scope.kind='platform'
WHERE role.system_role AND role.name='platform_owner'
ON CONFLICT DO NOTHING;

DROP TRIGGER recharge_orders_head_guard_v1 ON recharge_orders_v1;
DROP FUNCTION guard_billing_recharge_order_head_133();

ALTER TABLE recharge_orders_v1
    DROP CONSTRAINT recharge_orders_v1_state_check,
    DROP CONSTRAINT recharge_orders_v1_check1,
    ADD COLUMN captured_minor bigint NOT NULL DEFAULT 0,
    ADD COLUMN refunded_minor bigint NOT NULL DEFAULT 0;

UPDATE recharge_orders_v1 SET captured_minor=amount_minor WHERE state='paid';

ALTER TABLE recharge_orders_v1
    ADD CONSTRAINT recharge_orders_state_152 CHECK(state IN (
        'pending','paid','partially_refunded','refunded','voided','failed','canceled','reconcile_required'
    )),
    ADD CONSTRAINT recharge_orders_amounts_152 CHECK(
        captured_minor BETWEEN 0 AND amount_minor AND refunded_minor BETWEEN 0 AND captured_minor AND
        ((state IN ('pending','failed','canceled') AND captured_minor=0 AND refunded_minor=0) OR
         (state='paid' AND captured_minor=amount_minor AND refunded_minor=0) OR
         (state='partially_refunded' AND captured_minor=amount_minor AND refunded_minor BETWEEN 1 AND amount_minor-1) OR
         (state IN ('refunded','voided') AND captured_minor=amount_minor AND refunded_minor=amount_minor) OR
         state='reconcile_required')
    ),
    ADD CONSTRAINT recharge_orders_revision_152 CHECK(
        (state='pending' AND revision=1) OR (state<>'pending' AND revision>=2)
    ),
    ADD CONSTRAINT recharge_orders_id_scope_152 UNIQUE(id,tenant_scope_id);

ALTER TABLE recharge_order_events_v1
    DROP CONSTRAINT recharge_order_events_v1_revision_check,
    DROP CONSTRAINT recharge_order_events_v1_state_check,
    ADD CONSTRAINT recharge_order_events_revision_152 CHECK(revision>0),
    ADD CONSTRAINT recharge_order_events_state_152 CHECK(state IN (
        'pending','paid','partially_refunded','refunded','voided','failed','canceled','reconcile_required'
    ));

CREATE FUNCTION guard_recharge_payment_order_head_152()
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

CREATE TABLE recharge_payment_checkouts_v1 (
    id uuid PRIMARY KEY,
    order_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    actor_session_id uuid NOT NULL,
    provider text NOT NULL CHECK(provider ~ '^[a-z][a-z0-9._-]{0,63}$'),
    provider_account_id text NOT NULL CHECK(provider_account_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    expected_revision bigint NOT NULL CHECK(expected_revision>0),
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_id text NOT NULL CHECK(request_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_digest_sha256 bytea NOT NULL CHECK(octet_length(request_digest_sha256)=32),
    verification_key_id text NOT NULL CHECK(verification_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    payload_sha256 bytea NOT NULL CHECK(octet_length(payload_sha256)=32),
    signature_sha256 bytea NOT NULL CHECK(octet_length(signature_sha256)=32),
    expires_at timestamptz NOT NULL CHECK(isfinite(expires_at)),
    response_body jsonb NOT NULL CHECK(jsonb_typeof(response_body)='object' AND octet_length(response_body::text)<=16384),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at) AND expires_at>created_at),
    FOREIGN KEY(order_id,tenant_scope_id) REFERENCES recharge_orders_v1(id,tenant_scope_id) ON DELETE RESTRICT,
    FOREIGN KEY(actor_session_id,tenant_scope_id,actor_user_id) REFERENCES auth_sessions(id,scope_id,user_id) ON DELETE RESTRICT,
    UNIQUE(actor_session_id,idempotency_key),UNIQUE(actor_session_id,request_id),
    UNIQUE(id,order_id,tenant_scope_id)
);

CREATE TABLE recharge_payment_provider_events_v1 (
    id uuid PRIMARY KEY,
    source_callback_id uuid UNIQUE REFERENCES recharge_provider_callbacks_v1(id) ON DELETE RESTRICT,
    order_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    provider text NOT NULL CHECK(provider ~ '^[a-z][a-z0-9._-]{0,63}$'),
    provider_account_id text NOT NULL CHECK(provider_account_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    external_event_id text NOT NULL CHECK(external_event_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@-]{0,191}$'),
    external_payment_id text NOT NULL CHECK(external_payment_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@-]{0,191}$'),
    external_refund_id text CHECK(external_refund_id IS NULL OR external_refund_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@-]{0,191}$'),
    event_kind text NOT NULL CHECK(event_kind IN ('payment','refund','void')),
    provider_status text NOT NULL CHECK(provider_status IN ('succeeded','failed','unknown')),
    amount_minor bigint NOT NULL CHECK(amount_minor BETWEEN 0 AND 9000000000000000),
    currency text NOT NULL CHECK(currency='CNY'),
    occurred_at timestamptz NOT NULL CHECK(isfinite(occurred_at)),
    received_at timestamptz NOT NULL CHECK(isfinite(received_at) AND received_at>=occurred_at),
    verification_key_id text NOT NULL CHECK(verification_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    payload_sha256 bytea NOT NULL CHECK(octet_length(payload_sha256)=32),
    signature_sha256 bytea NOT NULL CHECK(octet_length(signature_sha256)=32),
    event_digest_sha256 bytea NOT NULL CHECK(octet_length(event_digest_sha256)=32),
    processing_result text NOT NULL CHECK(processing_result IN ('applied','deferred','ignored')),
    reason_code text NOT NULL CHECK(reason_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    FOREIGN KEY(order_id,tenant_scope_id) REFERENCES recharge_orders_v1(id,tenant_scope_id) ON DELETE RESTRICT,
    UNIQUE(provider,provider_account_id,external_event_id),
    UNIQUE(id,order_id),
    UNIQUE(id,order_id,tenant_scope_id,amount_minor,currency),
    CHECK((event_kind='payment' AND external_refund_id IS NULL) OR
          (event_kind IN ('refund','void') AND external_refund_id IS NOT NULL))
);

INSERT INTO recharge_payment_provider_events_v1(
    id,source_callback_id,order_id,tenant_scope_id,provider,provider_account_id,external_event_id,
    external_payment_id,event_kind,provider_status,amount_minor,currency,occurred_at,received_at,
    verification_key_id,payload_sha256,signature_sha256,event_digest_sha256,processing_result,reason_code,created_at)
SELECT callback.id,callback.id,callback.order_id,callback.tenant_scope_id,callback.provider,
       callback.provider_account_id,callback.external_event_id,callback.external_payment_id,'payment',
       CASE callback.state WHEN 'paid' THEN 'succeeded' ELSE 'failed' END,callback.amount_minor,callback.currency,
       callback.occurred_at,callback.received_at,callback.verification_key_id,callback.payload_sha256,
       callback.signature_sha256,sha256(callback.payload_sha256||callback.signature_sha256||
           convert_to(callback.verification_key_id,'UTF8')),
       CASE callback.processing_result WHEN 'applied' THEN 'applied' ELSE 'ignored' END,
       CASE callback.state WHEN 'paid' THEN 'PAYMENT_APPLIED' ELSE 'PAYMENT_FAILED' END,callback.received_at
FROM recharge_provider_callbacks_v1 callback;

CREATE TABLE recharge_payment_commands_v1 (
    id uuid PRIMARY KEY,
    order_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    actor_session_id uuid NOT NULL,
    provider text NOT NULL CHECK(provider ~ '^[a-z][a-z0-9._-]{0,63}$'),
    provider_account_id text NOT NULL CHECK(provider_account_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    external_payment_id text NOT NULL CHECK(external_payment_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@-]{0,191}$'),
    operation text NOT NULL CHECK(operation IN ('refund','void')),
    amount_minor bigint NOT NULL CHECK(amount_minor BETWEEN 0 AND 9000000000000000),
    expected_revision bigint NOT NULL CHECK(expected_revision>0),
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_id text NOT NULL CHECK(request_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_digest_sha256 bytea NOT NULL CHECK(octet_length(request_digest_sha256)=32),
    verification_key_id text NOT NULL CHECK(verification_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    payload_sha256 bytea NOT NULL CHECK(octet_length(payload_sha256)=32),
    signature_sha256 bytea NOT NULL CHECK(octet_length(signature_sha256)=32),
    expires_at timestamptz NOT NULL CHECK(isfinite(expires_at)),
    response_body jsonb NOT NULL CHECK(jsonb_typeof(response_body)='object' AND octet_length(response_body::text)<=16384),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at) AND expires_at>created_at),
    FOREIGN KEY(order_id,tenant_scope_id) REFERENCES recharge_orders_v1(id,tenant_scope_id) ON DELETE RESTRICT,
    FOREIGN KEY(actor_session_id,actor_scope_id,actor_user_id) REFERENCES auth_sessions(id,scope_id,user_id) ON DELETE RESTRICT,
    UNIQUE(actor_session_id,idempotency_key),UNIQUE(actor_session_id,request_id),
    CHECK((operation='refund' AND amount_minor>0) OR operation='void')
);

CREATE TABLE recharge_payment_reconcile_jobs_v1 (
    id uuid PRIMARY KEY,
    order_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    provider text NOT NULL,
    state text NOT NULL CHECK(state IN ('pending','running','succeeded','failed')),
    attempt bigint NOT NULL DEFAULT 0 CHECK(attempt>=0),
    revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
    next_attempt_at timestamptz NOT NULL CHECK(isfinite(next_attempt_at)),
    lease_owner text CHECK(lease_owner IS NULL OR lease_owner ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    lease_expires_at timestamptz CHECK(lease_expires_at IS NULL OR isfinite(lease_expires_at)),
    last_error_code text CHECK(last_error_code IS NULL OR last_error_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at),
    FOREIGN KEY(order_id,tenant_scope_id) REFERENCES recharge_orders_v1(id,tenant_scope_id) ON DELETE RESTRICT,
    UNIQUE(order_id),
    UNIQUE(id,order_id),
    CHECK((state='running')=(lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL))
);

CREATE TABLE recharge_payment_reconcile_receipts_v1 (
    id uuid PRIMARY KEY,
    job_id uuid NOT NULL,
    order_id uuid NOT NULL,
    attempt bigint NOT NULL CHECK(attempt>0),
    result_state text NOT NULL CHECK(result_state IN ('retry','succeeded','failed')),
    provider_event_id uuid,
    reason_code text NOT NULL CHECK(reason_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
    retry_after timestamptz CHECK(retry_after IS NULL OR isfinite(retry_after)),
    occurred_at timestamptz NOT NULL CHECK(isfinite(occurred_at)),
    FOREIGN KEY(job_id,order_id) REFERENCES recharge_payment_reconcile_jobs_v1(id,order_id) ON DELETE RESTRICT,
    FOREIGN KEY(provider_event_id,order_id) REFERENCES recharge_payment_provider_events_v1(id,order_id) ON DELETE RESTRICT,
    UNIQUE(job_id,attempt),
    CHECK((result_state='retry')=(retry_after IS NOT NULL))
);

CREATE FUNCTION prevent_recharge_payment_fact_mutation_152()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only',TG_TABLE_NAME USING ERRCODE='P1522';
END;
$$;

CREATE FUNCTION guard_recharge_payment_reconcile_job_152()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR OLD.id<>NEW.id OR OLD.order_id<>NEW.order_id OR OLD.tenant_scope_id<>NEW.tenant_scope_id OR
       OLD.provider<>NEW.provider OR OLD.created_at<>NEW.created_at OR NEW.revision<>OLD.revision+1 OR
       NEW.attempt<OLD.attempt OR NEW.updated_at<OLD.updated_at OR
       NOT ((OLD.state='pending' AND NEW.state IN ('running','failed')) OR
            (OLD.state='running' AND NEW.state IN ('pending','succeeded','failed'))) THEN
        RAISE EXCEPTION 'recharge reconciliation job transition is invalid' USING ERRCODE='P1523';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER recharge_payment_checkouts_append_only_v1 BEFORE UPDATE OR DELETE ON recharge_payment_checkouts_v1
FOR EACH ROW EXECUTE FUNCTION prevent_recharge_payment_fact_mutation_152();
CREATE TRIGGER recharge_payment_events_append_only_v1 BEFORE UPDATE OR DELETE ON recharge_payment_provider_events_v1
FOR EACH ROW EXECUTE FUNCTION prevent_recharge_payment_fact_mutation_152();
CREATE TRIGGER recharge_payment_commands_append_only_v1 BEFORE UPDATE OR DELETE ON recharge_payment_commands_v1
FOR EACH ROW EXECUTE FUNCTION prevent_recharge_payment_fact_mutation_152();
CREATE TRIGGER recharge_payment_reconcile_receipts_append_only_v1 BEFORE UPDATE OR DELETE ON recharge_payment_reconcile_receipts_v1
FOR EACH ROW EXECUTE FUNCTION prevent_recharge_payment_fact_mutation_152();
CREATE TRIGGER recharge_payment_reconcile_jobs_guard_v1 BEFORE UPDATE OR DELETE ON recharge_payment_reconcile_jobs_v1
FOR EACH ROW EXECUTE FUNCTION guard_recharge_payment_reconcile_job_152();

ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_commerce_shape;
ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_operation_check;
DROP INDEX billing_transactions_recharge_order_v1_idx;
ALTER TABLE billing_transactions
    ADD COLUMN recharge_provider_event_id uuid,
    ADD CONSTRAINT billing_transactions_recharge_event_fk_152 FOREIGN KEY(
        recharge_provider_event_id,recharge_order_id,target_scope_id,amount_minor,currency)
        REFERENCES recharge_payment_provider_events_v1(id,order_id,tenant_scope_id,amount_minor,currency) ON DELETE RESTRICT,
    ADD CONSTRAINT billing_transactions_operation_check CHECK(operation IN (
        'manual_adjustment','provider_payment','package_purchase','package_renewal','package_upgrade',
        'package_downgrade','package_refund','package_void','traffic_package_purchase',
        'recharge_payment','recharge_refund','recharge_void'
    ));

UPDATE billing_transactions transaction SET recharge_provider_event_id=settlement.callback_id
FROM recharge_settlements_v1 settlement WHERE settlement.transaction_id=transaction.id;

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

CREATE UNIQUE INDEX billing_transactions_recharge_provider_event_152_idx
    ON billing_transactions(recharge_provider_event_id) WHERE recharge_provider_event_id IS NOT NULL;
CREATE UNIQUE INDEX billing_transactions_recharge_payment_order_152_idx
    ON billing_transactions(recharge_order_id) WHERE operation='recharge_payment';

CREATE INDEX recharge_payment_events_order_time_v1_idx
    ON recharge_payment_provider_events_v1(order_id,occurred_at,id);
CREATE INDEX recharge_payment_reconcile_ready_v1_idx
    ON recharge_payment_reconcile_jobs_v1(next_attempt_at,id) WHERE state='pending';

REVOKE ALL ON recharge_payment_checkouts_v1,recharge_payment_provider_events_v1,recharge_payment_commands_v1,
    recharge_payment_reconcile_jobs_v1,recharge_payment_reconcile_receipts_v1 FROM PUBLIC;
