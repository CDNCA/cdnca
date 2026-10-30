LOCK TABLE schema_migrations,permissions,custom_rbac_permission_catalog,roles,role_permissions,auth_sessions,
    recharge_orders_v1,recharge_order_events_v1 IN ACCESS EXCLUSIVE MODE;

DO $migration_168$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>167 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>167 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=167 AND migration_id='167_http_policy_edge_source_revision' AND
              checksum_sha256='a4409fe5ab7ced09a42212526a956979a1dabe2d6a036fbb59a8169f0fdaf1e3' AND
              down_checksum_sha256='23784306af9c4f4dc12439b019961e650891b3db9ac01f2ebb2853e08ed73da4' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('recharge_payment_cancellations_v1') IS NOT NULL OR
         to_regclass('recharge_payment_cancellation_attempts_v1') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 168 requires the exact verified 167 release head' USING ERRCODE='P1680';
    END IF;
END;
$migration_168$;

INSERT INTO permissions(name,description)
VALUES('billing.recharges.cancel','Cancel an owned pending tenant recharge payment');
INSERT INTO custom_rbac_permission_catalog(permission_name,step_up_required)
VALUES('billing.recharges.cancel',false);
INSERT INTO role_permissions(role_id,permission_name)
SELECT role.id,'billing.recharges.cancel' FROM roles role
JOIN access_scopes scope ON scope.id=role.scope_id AND scope.kind='tenant'
WHERE role.system_role AND role.name IN ('tenant_owner','tenant_admin')
ON CONFLICT DO NOTHING;

CREATE FUNCTION grant_recharge_payment_cancel_permission_168()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.system_role AND NEW.name IN ('tenant_owner','tenant_admin') AND EXISTS (
        SELECT 1 FROM access_scopes WHERE id=NEW.scope_id AND kind='tenant'
    ) THEN
        INSERT INTO role_permissions(role_id,permission_name)
        VALUES(NEW.id,'billing.recharges.cancel') ON CONFLICT DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER roles_recharge_payment_cancel_permission_168
AFTER INSERT ON roles FOR EACH ROW EXECUTE FUNCTION grant_recharge_payment_cancel_permission_168();

CREATE TABLE recharge_payment_cancellations_v1 (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    order_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    actor_session_id uuid NOT NULL,
    provider text NOT NULL CHECK(provider IN ('alipay','wechat')),
    provider_account_id text NOT NULL CHECK(provider_account_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    external_payment_id text NOT NULL CHECK(external_payment_id='' OR external_payment_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@-]{0,191}$'),
    expected_revision bigint NOT NULL CHECK(expected_revision>0),
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_id text NOT NULL CHECK(request_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_digest_sha256 bytea NOT NULL CHECK(octet_length(request_digest_sha256)=32),
    provider_request_id text NOT NULL CHECK(provider_request_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    status text NOT NULL CHECK(status IN ('pending','succeeded','failed','unknown')),
    reason_code text NOT NULL CHECK(reason_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
    attempt_count bigint NOT NULL CHECK(attempt_count>0),
    revision bigint NOT NULL CHECK(revision>0),
    lease_token uuid,
    lease_started_at timestamptz CHECK(lease_started_at IS NULL OR isfinite(lease_started_at)),
    lease_expires_at timestamptz CHECK(lease_expires_at IS NULL OR isfinite(lease_expires_at)),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at),
    completed_at timestamptz CHECK(completed_at IS NULL OR isfinite(completed_at)),
    FOREIGN KEY(order_id,tenant_scope_id) REFERENCES recharge_orders_v1(id,tenant_scope_id) ON DELETE RESTRICT,
    FOREIGN KEY(tenant_scope_id,tenant_id) REFERENCES access_scopes(id,tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY(tenant_scope_id,user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    FOREIGN KEY(actor_session_id,tenant_scope_id,actor_user_id) REFERENCES auth_sessions(id,scope_id,user_id) ON DELETE RESTRICT,
    UNIQUE(actor_session_id,idempotency_key),
    UNIQUE(actor_session_id,request_id),
    UNIQUE(provider,provider_account_id,provider_request_id),
    UNIQUE(id,order_id,tenant_scope_id,provider_request_id),
    CHECK(actor_user_id=user_id),
    CHECK((lease_token IS NULL AND lease_started_at IS NULL AND lease_expires_at IS NULL) OR
          (lease_token IS NOT NULL AND lease_started_at IS NOT NULL AND lease_expires_at>lease_started_at)),
    CHECK((status='pending' AND lease_token IS NOT NULL AND completed_at IS NULL) OR
          (status='unknown' AND lease_token IS NULL AND completed_at IS NULL) OR
          (status IN ('succeeded','failed') AND lease_token IS NULL AND completed_at IS NOT NULL))
);

CREATE UNIQUE INDEX recharge_payment_cancellations_order_active_168_idx
    ON recharge_payment_cancellations_v1(order_id) WHERE status IN ('pending','unknown');

CREATE TABLE recharge_payment_cancellation_attempts_v1 (
    id uuid PRIMARY KEY,
    cancellation_id uuid NOT NULL,
    order_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    attempt_number bigint NOT NULL CHECK(attempt_number>0),
    provider_request_id text NOT NULL CHECK(provider_request_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    started_at timestamptz NOT NULL CHECK(isfinite(started_at)),
    finished_at timestamptz NOT NULL CHECK(isfinite(finished_at) AND finished_at>=started_at),
    provider_status text NOT NULL CHECK(provider_status IN ('succeeded','failed','unknown')),
    definite boolean NOT NULL,
    response_signed boolean NOT NULL,
    verification_key_id text CHECK(verification_key_id IS NULL OR verification_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    payload_sha256 bytea CHECK(payload_sha256 IS NULL OR octet_length(payload_sha256)=32),
    signature_sha256 bytea CHECK(signature_sha256 IS NULL OR octet_length(signature_sha256)=32),
    error_code text NOT NULL CHECK(error_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
    retryable boolean NOT NULL,
    FOREIGN KEY(cancellation_id,order_id,tenant_scope_id,provider_request_id)
        REFERENCES recharge_payment_cancellations_v1(id,order_id,tenant_scope_id,provider_request_id) ON DELETE RESTRICT,
    UNIQUE(cancellation_id,attempt_number),
    CHECK(definite=(provider_status IN ('succeeded','failed'))),
    CHECK(retryable=(NOT definite)),
    CHECK((response_signed AND verification_key_id IS NOT NULL AND payload_sha256 IS NOT NULL AND signature_sha256 IS NOT NULL) OR
          (NOT response_signed AND verification_key_id IS NULL AND payload_sha256 IS NULL AND signature_sha256 IS NULL))
);

CREATE FUNCTION guard_recharge_payment_cancellation_head_168()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('recharge-cancel-head:'||OLD.id::text,0));
    IF TG_OP='DELETE' OR OLD.id<>NEW.id OR OLD.order_id<>NEW.order_id OR
       OLD.tenant_scope_id<>NEW.tenant_scope_id OR OLD.tenant_id<>NEW.tenant_id OR OLD.user_id<>NEW.user_id OR
       OLD.actor_user_id<>NEW.actor_user_id OR OLD.actor_session_id<>NEW.actor_session_id OR
       OLD.provider<>NEW.provider OR OLD.provider_account_id<>NEW.provider_account_id OR
       OLD.external_payment_id<>NEW.external_payment_id OR OLD.expected_revision<>NEW.expected_revision OR
       OLD.idempotency_key<>NEW.idempotency_key OR OLD.request_id<>NEW.request_id OR
       OLD.request_digest_sha256<>NEW.request_digest_sha256 OR OLD.provider_request_id<>NEW.provider_request_id OR
       OLD.created_at<>NEW.created_at OR NEW.revision<>OLD.revision+1 OR
       NOT ((NEW.status='pending' AND NEW.attempt_count=OLD.attempt_count+1) OR
            (NEW.status IN ('succeeded','failed','unknown') AND NEW.attempt_count=OLD.attempt_count)) OR
       NEW.updated_at<OLD.updated_at OR NOT (
          (OLD.status='pending' AND NEW.status IN ('pending','succeeded','failed','unknown')) OR
          (OLD.status='unknown' AND NEW.status='pending')
       ) THEN
        RAISE EXCEPTION 'recharge payment cancellation transition is invalid' USING ERRCODE='P1681';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_recharge_payment_cancellation_attempt_168()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('recharge-cancel-head:'||NEW.cancellation_id::text,0));
    IF NOT EXISTS (
        SELECT 1 FROM recharge_payment_cancellations_v1 cancellation
        WHERE cancellation.id=NEW.cancellation_id AND cancellation.order_id=NEW.order_id AND
              cancellation.tenant_scope_id=NEW.tenant_scope_id AND
              cancellation.provider_request_id=NEW.provider_request_id AND
              NEW.attempt_number<=cancellation.attempt_count
    ) THEN
        RAISE EXCEPTION 'recharge payment cancellation attempt binding is invalid' USING ERRCODE='P1682';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION prevent_recharge_payment_cancellation_attempt_mutation_168()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'recharge payment cancellation attempts are append-only' USING ERRCODE='P1682';
END;
$$;

CREATE FUNCTION prevent_recharge_payment_cancellation_truncate_168()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'recharge payment cancellation facts cannot be truncated' USING ERRCODE='P1682';
END;
$$;

CREATE TRIGGER recharge_payment_cancellations_guard_168
BEFORE UPDATE OR DELETE ON recharge_payment_cancellations_v1
FOR EACH ROW EXECUTE FUNCTION guard_recharge_payment_cancellation_head_168();
CREATE TRIGGER recharge_payment_cancellation_attempts_append_only_168
BEFORE UPDATE OR DELETE ON recharge_payment_cancellation_attempts_v1
FOR EACH ROW EXECUTE FUNCTION prevent_recharge_payment_cancellation_attempt_mutation_168();
CREATE TRIGGER recharge_payment_cancellation_attempts_validate_168
BEFORE INSERT ON recharge_payment_cancellation_attempts_v1
FOR EACH ROW EXECUTE FUNCTION validate_recharge_payment_cancellation_attempt_168();
CREATE TRIGGER recharge_payment_cancellations_truncate_168
BEFORE TRUNCATE ON recharge_payment_cancellations_v1
FOR EACH STATEMENT EXECUTE FUNCTION prevent_recharge_payment_cancellation_truncate_168();
CREATE TRIGGER recharge_payment_cancellation_attempts_truncate_168
BEFORE TRUNCATE ON recharge_payment_cancellation_attempts_v1
FOR EACH STATEMENT EXECUTE FUNCTION prevent_recharge_payment_cancellation_truncate_168();

REVOKE ALL ON recharge_payment_cancellations_v1,recharge_payment_cancellation_attempts_v1 FROM PUBLIC;
