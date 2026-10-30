LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_357_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 357 OR
       (SELECT max(version) FROM schema_migrations) <> 357 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=357 AND
        migration_id='357_recharge_payment_legacy_reconcile_drop' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 357 down requires the exact verified migration head' USING ERRCODE='P3579';
    END IF;
END;
$migration_357_down$;

-- Restores the empty 152 reconcile job queue (definitions as in 152).
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

CREATE TRIGGER recharge_payment_reconcile_receipts_append_only_v1 BEFORE UPDATE OR DELETE ON recharge_payment_reconcile_receipts_v1
FOR EACH ROW EXECUTE FUNCTION prevent_recharge_payment_fact_mutation_152();
CREATE TRIGGER recharge_payment_reconcile_jobs_guard_v1 BEFORE UPDATE OR DELETE ON recharge_payment_reconcile_jobs_v1
FOR EACH ROW EXECUTE FUNCTION guard_recharge_payment_reconcile_job_152();

CREATE INDEX recharge_payment_reconcile_ready_v1_idx
    ON recharge_payment_reconcile_jobs_v1(next_attempt_at,id) WHERE state='pending';

REVOKE ALL ON recharge_payment_reconcile_jobs_v1,recharge_payment_reconcile_receipts_v1 FROM PUBLIC;
