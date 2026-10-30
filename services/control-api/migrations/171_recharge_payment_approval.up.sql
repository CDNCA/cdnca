LOCK TABLE schema_migrations,permissions,custom_rbac_permission_catalog,roles,role_permissions,
    auth_sessions,recharge_orders_v1 IN ACCESS EXCLUSIVE MODE;

DO $migration_171$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>170 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>170 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=170 AND migration_id='170_node_configuration_hpke' AND
              checksum_sha256='140d1689a8d3ce17e34cc8bc46598711364d9fe129ec36bb3e5f591c71f8f089' AND
              down_checksum_sha256='02db4682dcbcabdf057a714cfd10cd32332e5b8540872d41697cb78483fa2609' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('recharge_payment_approval_requests_v1') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 171 requires the exact verified 170 release head' USING ERRCODE='P1710';
    END IF;
END;
$migration_171$;

INSERT INTO permissions(name,description)
VALUES('billing.recharges.approve','Approve or reject recharge refund and void proposals');
INSERT INTO custom_rbac_permission_catalog(permission_name,step_up_required)
VALUES('billing.recharges.approve',false);
INSERT INTO role_permissions(role_id,permission_name)
SELECT role.id,'billing.recharges.approve' FROM roles role
JOIN access_scopes scope ON scope.id=role.scope_id AND scope.kind='platform'
WHERE role.system_role AND role.name='platform_owner'
ON CONFLICT DO NOTHING;

CREATE FUNCTION grant_recharge_payment_approval_permission_171()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.system_role AND NEW.name='platform_owner' AND EXISTS (
        SELECT 1 FROM access_scopes WHERE id=NEW.scope_id AND kind='platform'
    ) THEN
        INSERT INTO role_permissions(role_id,permission_name)
        VALUES(NEW.id,'billing.recharges.approve') ON CONFLICT DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER roles_recharge_payment_approval_permission_171
AFTER INSERT ON roles FOR EACH ROW EXECUTE FUNCTION grant_recharge_payment_approval_permission_171();

CREATE TABLE recharge_payment_approval_requests_v1 (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    order_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    operation text NOT NULL CHECK(operation IN ('refund','void')),
    amount_minor bigint NOT NULL CHECK(amount_minor BETWEEN 0 AND 9000000000000000),
    currency text NOT NULL CHECK(currency='CNY'),
    expected_order_revision bigint NOT NULL CHECK(expected_order_revision>0),
    reason text NOT NULL CHECK(char_length(reason) BETWEEN 1 AND 500),
    request_digest_sha256 bytea NOT NULL CHECK(octet_length(request_digest_sha256)=32),
    proposed_by_scope_id uuid NOT NULL,
    proposed_by_user_id uuid NOT NULL,
    proposed_by_session_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_id text NOT NULL CHECK(request_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    proposed_at timestamptz NOT NULL CHECK(isfinite(proposed_at)),
    expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at>proposed_at),
    FOREIGN KEY(order_id,tenant_scope_id) REFERENCES recharge_orders_v1(id,tenant_scope_id) ON DELETE RESTRICT,
    FOREIGN KEY(proposed_by_session_id,proposed_by_scope_id,proposed_by_user_id)
        REFERENCES auth_sessions(id,scope_id,user_id) ON DELETE RESTRICT,
    UNIQUE(proposed_by_session_id,idempotency_key),
    UNIQUE(proposed_by_session_id,request_id),
    UNIQUE(id,order_id,tenant_scope_id,operation,amount_minor,expected_order_revision),
    CHECK((operation='refund' AND amount_minor>0) OR operation='void')
);
CREATE INDEX recharge_payment_approval_requests_created_171_idx
    ON recharge_payment_approval_requests_v1(proposed_at DESC,id DESC);
CREATE INDEX recharge_payment_approval_requests_order_171_idx
    ON recharge_payment_approval_requests_v1(order_id,proposed_at DESC,id DESC);

CREATE TABLE recharge_payment_approval_decisions_v1 (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    approval_request_id uuid NOT NULL UNIQUE REFERENCES recharge_payment_approval_requests_v1(id) ON DELETE RESTRICT,
    decision text NOT NULL CHECK(decision IN ('approved','rejected')),
    expected_revision bigint NOT NULL CHECK(expected_revision=1),
    request_digest_sha256 bytea NOT NULL CHECK(octet_length(request_digest_sha256)=32),
    decided_by_scope_id uuid NOT NULL,
    decided_by_user_id uuid NOT NULL,
    decided_by_session_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_id text NOT NULL CHECK(request_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    decided_at timestamptz NOT NULL CHECK(isfinite(decided_at)),
    FOREIGN KEY(decided_by_session_id,decided_by_scope_id,decided_by_user_id)
        REFERENCES auth_sessions(id,scope_id,user_id) ON DELETE RESTRICT,
    UNIQUE(decided_by_session_id,idempotency_key),
    UNIQUE(decided_by_session_id,request_id)
);

CREATE TABLE recharge_payment_approval_executions_v1 (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    approval_request_id uuid NOT NULL UNIQUE REFERENCES recharge_payment_approval_requests_v1(id) ON DELETE RESTRICT,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    actor_session_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_id text NOT NULL CHECK(request_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_digest_sha256 bytea NOT NULL CHECK(octet_length(request_digest_sha256)=32),
    authorized_at timestamptz NOT NULL CHECK(isfinite(authorized_at)),
    FOREIGN KEY(actor_session_id,actor_scope_id,actor_user_id)
        REFERENCES auth_sessions(id,scope_id,user_id) ON DELETE RESTRICT,
    UNIQUE(actor_session_id,idempotency_key),
    UNIQUE(actor_session_id,request_id)
);

CREATE TABLE recharge_payment_approval_receipts_v1 (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    actor_session_id uuid NOT NULL,
    operation text NOT NULL CHECK(operation IN ('propose','decide')),
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_id text NOT NULL CHECK(request_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_digest_sha256 bytea NOT NULL CHECK(octet_length(request_digest_sha256)=32),
    approval_request_id uuid NOT NULL REFERENCES recharge_payment_approval_requests_v1(id) ON DELETE RESTRICT,
    response_status integer NOT NULL CHECK(response_status IN (200,201)),
    response_body jsonb NOT NULL CHECK(jsonb_typeof(response_body)='object'),
    completed_at timestamptz NOT NULL CHECK(isfinite(completed_at)),
    FOREIGN KEY(actor_session_id,actor_scope_id,actor_user_id)
        REFERENCES auth_sessions(id,scope_id,user_id) ON DELETE RESTRICT,
    UNIQUE(actor_session_id,operation,idempotency_key),
    UNIQUE(actor_session_id,operation,request_id)
);

CREATE FUNCTION validate_recharge_payment_approval_171()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    request recharge_payment_approval_requests_v1%ROWTYPE;
    decision recharge_payment_approval_decisions_v1%ROWTYPE;
    order_scope uuid;
    order_revision bigint;
    order_state text;
    captured bigint;
    refunded bigint;
BEGIN
    IF TG_TABLE_NAME='recharge_payment_approval_requests_v1' THEN
        IF NOT EXISTS(SELECT 1 FROM access_scopes WHERE id=NEW.proposed_by_scope_id AND kind='platform') THEN
            RAISE EXCEPTION 'approval proposer must belong to the platform scope' USING ERRCODE='P1711';
        END IF;
        SELECT tenant_scope_id,revision,state,captured_minor,refunded_minor
        INTO order_scope,order_revision,order_state,captured,refunded
        FROM recharge_orders_v1 WHERE id=NEW.order_id FOR SHARE;
        IF order_scope IS NULL OR order_scope<>NEW.tenant_scope_id OR order_revision<>NEW.expected_order_revision OR
           order_state NOT IN ('paid','partially_refunded') OR captured<=0 OR NEW.amount_minor>captured-refunded THEN
            RAISE EXCEPTION 'approval proposal does not match the live recharge order' USING ERRCODE='P1712';
        END IF;
    ELSIF TG_TABLE_NAME='recharge_payment_approval_decisions_v1' THEN
        SELECT * INTO request FROM recharge_payment_approval_requests_v1
        WHERE id=NEW.approval_request_id FOR SHARE;
        IF request.id IS NULL OR NEW.decided_by_user_id=request.proposed_by_user_id OR
           NEW.decided_at>=request.expires_at OR
           NOT EXISTS(SELECT 1 FROM access_scopes WHERE id=NEW.decided_by_scope_id AND kind='platform') THEN
            RAISE EXCEPTION 'approval decision violates maker-checker or expiry' USING ERRCODE='P1713';
        END IF;
        IF EXISTS(SELECT 1 FROM recharge_payment_approval_decisions_v1 WHERE approval_request_id=request.id) THEN
            RAISE EXCEPTION 'approval request already has a decision' USING ERRCODE='P1714';
        END IF;
    ELSIF TG_TABLE_NAME='recharge_payment_approval_executions_v1' THEN
        SELECT * INTO request FROM recharge_payment_approval_requests_v1
        WHERE id=NEW.approval_request_id FOR SHARE;
        SELECT * INTO decision FROM recharge_payment_approval_decisions_v1
        WHERE approval_request_id=NEW.approval_request_id AND decision='approved' FOR SHARE;
        IF request.id IS NULL OR decision.id IS NULL OR NEW.authorized_at>=request.expires_at OR
           (NEW.actor_scope_id,NEW.actor_user_id,NEW.actor_session_id) IS DISTINCT FROM
           (decision.decided_by_scope_id,decision.decided_by_user_id,decision.decided_by_session_id) THEN
            RAISE EXCEPTION 'approval execution is not bound to the approved checker' USING ERRCODE='P1715';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recharge_payment_approval_requests_validate_171
BEFORE INSERT ON recharge_payment_approval_requests_v1 FOR EACH ROW EXECUTE FUNCTION validate_recharge_payment_approval_171();
CREATE TRIGGER recharge_payment_approval_decisions_validate_171
BEFORE INSERT ON recharge_payment_approval_decisions_v1 FOR EACH ROW EXECUTE FUNCTION validate_recharge_payment_approval_171();
CREATE TRIGGER recharge_payment_approval_executions_validate_171
BEFORE INSERT ON recharge_payment_approval_executions_v1 FOR EACH ROW EXECUTE FUNCTION validate_recharge_payment_approval_171();

CREATE FUNCTION prevent_recharge_payment_approval_mutation_171()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'recharge payment approval facts are append-only' USING ERRCODE='P1716';
END;
$$;
CREATE TRIGGER recharge_payment_approval_requests_immutable_171 BEFORE UPDATE OR DELETE ON recharge_payment_approval_requests_v1
FOR EACH ROW EXECUTE FUNCTION prevent_recharge_payment_approval_mutation_171();
CREATE TRIGGER recharge_payment_approval_decisions_immutable_171 BEFORE UPDATE OR DELETE ON recharge_payment_approval_decisions_v1
FOR EACH ROW EXECUTE FUNCTION prevent_recharge_payment_approval_mutation_171();
CREATE TRIGGER recharge_payment_approval_executions_immutable_171 BEFORE UPDATE OR DELETE ON recharge_payment_approval_executions_v1
FOR EACH ROW EXECUTE FUNCTION prevent_recharge_payment_approval_mutation_171();
CREATE TRIGGER recharge_payment_approval_receipts_immutable_171 BEFORE UPDATE OR DELETE ON recharge_payment_approval_receipts_v1
FOR EACH ROW EXECUTE FUNCTION prevent_recharge_payment_approval_mutation_171();

CREATE FUNCTION prevent_recharge_payment_approval_truncate_171()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'recharge payment approval facts cannot be truncated' USING ERRCODE='P1717';
END;
$$;
CREATE TRIGGER recharge_payment_approval_requests_truncate_171 BEFORE TRUNCATE ON recharge_payment_approval_requests_v1
FOR EACH STATEMENT EXECUTE FUNCTION prevent_recharge_payment_approval_truncate_171();
CREATE TRIGGER recharge_payment_approval_decisions_truncate_171 BEFORE TRUNCATE ON recharge_payment_approval_decisions_v1
FOR EACH STATEMENT EXECUTE FUNCTION prevent_recharge_payment_approval_truncate_171();
CREATE TRIGGER recharge_payment_approval_executions_truncate_171 BEFORE TRUNCATE ON recharge_payment_approval_executions_v1
FOR EACH STATEMENT EXECUTE FUNCTION prevent_recharge_payment_approval_truncate_171();
CREATE TRIGGER recharge_payment_approval_receipts_truncate_171 BEFORE TRUNCATE ON recharge_payment_approval_receipts_v1
FOR EACH STATEMENT EXECUTE FUNCTION prevent_recharge_payment_approval_truncate_171();

REVOKE ALL ON recharge_payment_approval_requests_v1,recharge_payment_approval_decisions_v1,
    recharge_payment_approval_executions_v1,recharge_payment_approval_receipts_v1 FROM PUBLIC;
DO $grants$
BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='cdnca_control') THEN
        GRANT SELECT,INSERT ON recharge_payment_approval_requests_v1,recharge_payment_approval_decisions_v1,
            recharge_payment_approval_executions_v1,recharge_payment_approval_receipts_v1 TO cdnca_control;
    END IF;
END;
$grants$;
