LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 99 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 99 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL
           OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=99 AND migration_id='099_billing_adjustment_denial_receipts'
          AND checksum_sha256='ec616f2b6851956945ef67a4940e09051470b8e30431efee188034592692dc1a'
          AND down_checksum_sha256='0afc07827ca395c1b9393fc6cf606377f6979140177084be18621e2eb062d1b3'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 100 requires the exact verified 099 release head'
            USING ERRCODE='P1000';
    END IF;
END;
$$;

LOCK TABLE permissions,roles,role_permissions,memberships,auth_sessions,
    billing_accounts,billing_transactions,billing_postings,billing_write_requests,
    mfa_step_up_proofs,mfa_step_up_uses,audit_events
IN SHARE ROW EXCLUSIVE MODE;

INSERT INTO permissions(name,description) VALUES
    ('billing.adjustments.propose','Propose an MFA-bound manual billing adjustment'),
    ('billing.adjustments.approve','Approve or reject another operator manual billing adjustment');

INSERT INTO role_permissions(role_id,permission_name)
SELECT role.id,permission.name
FROM roles role
CROSS JOIN (VALUES('billing.adjustments.propose'),('billing.adjustments.approve')) permission(name)
JOIN access_scopes scope ON scope.id=role.scope_id AND scope.kind='platform'
WHERE role.system_role AND role.name='platform_owner'
ON CONFLICT DO NOTHING;

ALTER TABLE billing_transactions
    ADD COLUMN adjustment_request_id uuid,
    ADD CONSTRAINT billing_transactions_adjustment_request_unique_100
        UNIQUE(adjustment_request_id),
    ADD CONSTRAINT billing_transactions_adjustment_request_shape_100 CHECK (
        operation='manual_adjustment' OR adjustment_request_id IS NULL
    );

CREATE FUNCTION billing_adjustment_transaction_digest_100(target_transaction_id uuid)
RETURNS bytea
LANGUAGE sql
STABLE
STRICT
AS $$
    SELECT sha256(convert_to(concat_ws(E'\x1f',
        transaction.id::text,
        transaction.target_scope_id::text,
        transaction.operation,
        transaction.direction,
        transaction.amount_minor::text,
        transaction.currency,
        transaction.reason,
        transaction.created_by_user_id::text,
        to_char(transaction.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
    ),'UTF8'))
    FROM billing_transactions transaction
    WHERE transaction.id=target_transaction_id
$$;

CREATE TABLE billing_adjustment_legacy_authority (
    transaction_id uuid PRIMARY KEY REFERENCES billing_transactions(id) ON DELETE RESTRICT,
    transaction_digest bytea NOT NULL CHECK(octet_length(transaction_digest)=32),
    recorded_at timestamptz NOT NULL CHECK(isfinite(recorded_at))
);

INSERT INTO billing_adjustment_legacy_authority(transaction_id,transaction_digest,recorded_at)
SELECT id,billing_adjustment_transaction_digest_100(id),transaction_timestamp()
FROM billing_transactions
WHERE operation='manual_adjustment';

CREATE TABLE billing_adjustment_requests (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    target_tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    target_account_id uuid NOT NULL REFERENCES billing_accounts(id) ON DELETE RESTRICT,
    direction text NOT NULL CHECK(direction IN ('credit','debit')),
    amount_minor bigint NOT NULL CHECK(amount_minor>0 AND amount_minor<=9000000000000000),
    currency text NOT NULL CHECK(currency='CNY'),
    reason text NOT NULL CHECK(reason=btrim(reason) AND char_length(reason) BETWEEN 1 AND 500),
    expected_account_revision bigint NOT NULL CHECK(expected_account_revision>0),
    request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    step_up_binding_digest bytea NOT NULL CHECK(octet_length(step_up_binding_digest)=32),
    proposed_by_scope_id uuid NOT NULL,
    proposed_by_user_id uuid NOT NULL,
    proposed_by_session_id uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE RESTRICT,
    proposed_step_up_proof_id uuid NOT NULL,
    proposed_step_up_use_ordinal smallint NOT NULL CHECK(proposed_step_up_use_ordinal=1),
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9._-]{1,128}$'),
    request_id text NOT NULL CHECK(request_id ~ '^[A-Za-z0-9._-]{1,128}$'),
    proposed_at timestamptz NOT NULL CHECK(isfinite(proposed_at)),
    expires_at timestamptz NOT NULL CHECK(
        isfinite(expires_at) AND expires_at>proposed_at AND
        expires_at<=proposed_at+interval '15 minutes'
    ),
    FOREIGN KEY(proposed_by_scope_id,proposed_by_user_id)
        REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    FOREIGN KEY(proposed_step_up_proof_id,proposed_step_up_use_ordinal)
        REFERENCES mfa_step_up_uses(proof_id,use_ordinal) ON DELETE RESTRICT,
    UNIQUE(proposed_by_scope_id,proposed_by_user_id,idempotency_key),
    UNIQUE(id,target_scope_id,target_tenant_id,target_account_id,request_digest)
);

ALTER TABLE billing_transactions
    ADD CONSTRAINT billing_transactions_adjustment_request_fk_100
        FOREIGN KEY(adjustment_request_id)
        REFERENCES billing_adjustment_requests(id) ON DELETE RESTRICT;

CREATE TABLE billing_adjustment_decisions (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    adjustment_request_id uuid NOT NULL UNIQUE
        REFERENCES billing_adjustment_requests(id) ON DELETE RESTRICT,
    decision text NOT NULL CHECK(decision IN ('approved','rejected','cancelled')),
    expected_revision bigint NOT NULL CHECK(expected_revision=1),
    request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    step_up_binding_digest bytea CHECK(
        step_up_binding_digest IS NULL OR octet_length(step_up_binding_digest)=32
    ),
    approved_by_scope_id uuid NOT NULL,
    approved_by_user_id uuid NOT NULL,
    approved_by_session_id uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE RESTRICT,
    approved_step_up_proof_id uuid,
    approved_step_up_use_ordinal smallint,
    billing_transaction_id uuid UNIQUE REFERENCES billing_transactions(id) ON DELETE RESTRICT,
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9._-]{1,128}$'),
    request_id text NOT NULL CHECK(request_id ~ '^[A-Za-z0-9._-]{1,128}$'),
    decided_at timestamptz NOT NULL CHECK(isfinite(decided_at)),
    FOREIGN KEY(approved_by_scope_id,approved_by_user_id)
        REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    FOREIGN KEY(approved_step_up_proof_id,approved_step_up_use_ordinal)
        REFERENCES mfa_step_up_uses(proof_id,use_ordinal) ON DELETE RESTRICT,
    UNIQUE(approved_by_scope_id,approved_by_user_id,decision,idempotency_key),
    CHECK(
        (decision IN ('approved','rejected') AND step_up_binding_digest IS NOT NULL
            AND approved_step_up_proof_id IS NOT NULL AND approved_step_up_use_ordinal=1)
        OR
        (decision='cancelled' AND step_up_binding_digest IS NULL
            AND approved_step_up_proof_id IS NULL AND approved_step_up_use_ordinal IS NULL)
    ),
    CHECK((decision='approved')=(billing_transaction_id IS NOT NULL))
);

CREATE TABLE billing_adjustment_write_receipts (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    operation text NOT NULL CHECK(operation IN (
        'billing.adjustment.propose','billing.adjustment.approve',
        'billing.adjustment.reject','billing.adjustment.cancel'
    )),
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9._-]{1,128}$'),
    request_id text NOT NULL CHECK(request_id ~ '^[A-Za-z0-9._-]{1,128}$'),
    request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    adjustment_request_id uuid NOT NULL REFERENCES billing_adjustment_requests(id) ON DELETE RESTRICT,
    response_status integer NOT NULL CHECK(response_status IN (200,201)),
    response_body jsonb NOT NULL CHECK(jsonb_typeof(response_body)='object'),
    completed_at timestamptz NOT NULL CHECK(isfinite(completed_at)),
    FOREIGN KEY(actor_scope_id,actor_user_id)
        REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    UNIQUE(actor_scope_id,actor_user_id,operation,idempotency_key)
);

CREATE INDEX billing_adjustment_requests_created_100
    ON billing_adjustment_requests(proposed_at DESC,id DESC);
CREATE INDEX billing_adjustment_requests_target_100
    ON billing_adjustment_requests(target_scope_id,proposed_at DESC,id DESC);
CREATE INDEX billing_adjustment_decisions_actor_100
    ON billing_adjustment_decisions(approved_by_scope_id,approved_by_user_id,decided_at DESC,id DESC);

CREATE FUNCTION prevent_billing_adjustment_authority_mutation_100()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'billing adjustment approval authority facts are append-only'
        USING ERRCODE='P1002';
END;
$$;

CREATE FUNCTION validate_billing_adjustment_legacy_authority_100()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    actual_digest bytea;
BEGIN
    SELECT billing_adjustment_transaction_digest_100(NEW.transaction_id)
      INTO actual_digest;
    IF actual_digest IS NULL OR actual_digest<>NEW.transaction_digest OR NOT EXISTS (
        SELECT 1 FROM billing_transactions transaction
        WHERE transaction.id=NEW.transaction_id
          AND transaction.operation='manual_adjustment'
          AND transaction.adjustment_request_id IS NULL
    ) THEN
        RAISE EXCEPTION 'invalid legacy billing adjustment authority inventory'
            USING ERRCODE='P1002';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_billing_adjustment_request_100()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    proof_max_uses smallint;
    proof_action text;
    proof_audience text;
    use_actor_user uuid;
    use_actor_scope uuid;
    use_session uuid;
    use_tenant uuid;
    use_binding bytea;
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM billing_accounts account
        JOIN access_scopes scope ON scope.id=account.scope_id AND scope.kind='tenant'
        JOIN tenants tenant ON tenant.id=scope.tenant_id
        WHERE account.id=NEW.target_account_id AND account.scope_id=NEW.target_scope_id
          AND account.kind='tenant_liability' AND tenant.id=NEW.target_tenant_id
    ) THEN
        RAISE EXCEPTION 'invalid billing adjustment target authority'
            USING ERRCODE='P1002';
    END IF;
    SELECT proof.max_uses,proof.action,proof.audience,
           use_row.actor_user_id,use_row.actor_scope_id,use_row.auth_session_id,
           use_row.tenant_id,use_row.resource_binding_sha256
      INTO proof_max_uses,proof_action,proof_audience,use_actor_user,use_actor_scope,
           use_session,use_tenant,use_binding
    FROM mfa_step_up_uses use_row
    JOIN mfa_step_up_proofs proof ON proof.id=use_row.proof_id
    WHERE use_row.proof_id=NEW.proposed_step_up_proof_id
      AND use_row.use_ordinal=NEW.proposed_step_up_use_ordinal;
    IF proof_max_uses IS DISTINCT FROM 1 OR proof_action IS DISTINCT FROM 'billing.adjustment.propose'
       OR proof_audience IS DISTINCT FROM 'billing-adjustments'
       OR use_actor_user IS DISTINCT FROM NEW.proposed_by_user_id
       OR use_actor_scope IS DISTINCT FROM NEW.proposed_by_scope_id
       OR use_session IS DISTINCT FROM NEW.proposed_by_session_id
       OR use_tenant IS DISTINCT FROM NEW.target_tenant_id
       OR use_binding IS DISTINCT FROM NEW.step_up_binding_digest THEN
        RAISE EXCEPTION 'billing adjustment proposal requires max_uses=1 bound MFA evidence'
            USING ERRCODE='P1002';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_billing_adjustment_decision_100()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    request billing_adjustment_requests%ROWTYPE;
    proof_max_uses smallint;
    proof_action text;
    proof_audience text;
    use_actor_user uuid;
    use_actor_scope uuid;
    use_session uuid;
    use_tenant uuid;
    use_binding bytea;
BEGIN
    SELECT * INTO request FROM billing_adjustment_requests
    WHERE id=NEW.adjustment_request_id;
    IF NOT FOUND OR NEW.decided_at<request.proposed_at OR NEW.decided_at>=request.expires_at THEN
        RAISE EXCEPTION 'billing adjustment request is not decidable'
            USING ERRCODE='P1002';
    END IF;
    IF NEW.decision='cancelled' THEN
        IF NEW.approved_by_user_id<>request.proposed_by_user_id
           OR NEW.approved_by_scope_id<>request.proposed_by_scope_id
           OR NEW.approved_by_session_id<>request.proposed_by_session_id THEN
            RAISE EXCEPTION 'only the proposal session may cancel a billing adjustment'
                USING ERRCODE='P1002';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.approved_by_user_id=request.proposed_by_user_id THEN
        RAISE EXCEPTION 'approved_by_user_id <> proposed_by_user_id is required'
            USING ERRCODE='P1002';
    END IF;
    SELECT proof.max_uses,proof.action,proof.audience,
           use_row.actor_user_id,use_row.actor_scope_id,use_row.auth_session_id,
           use_row.tenant_id,use_row.resource_binding_sha256
      INTO proof_max_uses,proof_action,proof_audience,use_actor_user,use_actor_scope,
           use_session,use_tenant,use_binding
    FROM mfa_step_up_uses use_row
    JOIN mfa_step_up_proofs proof ON proof.id=use_row.proof_id
    WHERE use_row.proof_id=NEW.approved_step_up_proof_id
      AND use_row.use_ordinal=NEW.approved_step_up_use_ordinal;
    IF proof_max_uses IS DISTINCT FROM 1
       OR proof_action IS DISTINCT FROM 'billing.adjustment.'||(CASE NEW.decision
            WHEN 'approved' THEN 'approve' ELSE 'reject' END)
       OR proof_audience IS DISTINCT FROM 'billing-adjustments'
       OR use_actor_user IS DISTINCT FROM NEW.approved_by_user_id
       OR use_actor_scope IS DISTINCT FROM NEW.approved_by_scope_id
       OR use_session IS DISTINCT FROM NEW.approved_by_session_id
       OR use_tenant IS DISTINCT FROM request.target_tenant_id
       OR use_binding IS DISTINCT FROM NEW.step_up_binding_digest THEN
        RAISE EXCEPTION 'billing adjustment decision requires max_uses=1 bound MFA evidence'
            USING ERRCODE='P1002';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_billing_adjustment_commit_100()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    target_transaction_id uuid;
    request billing_adjustment_requests%ROWTYPE;
    decision billing_adjustment_decisions%ROWTYPE;
    transaction billing_transactions%ROWTYPE;
    exact_audit_count bigint;
    exact_posting_count bigint;
    exact_tenant_posting_count bigint;
    exact_clearing_posting_count bigint;
BEGIN
    IF TG_TABLE_NAME='billing_transactions' THEN
        target_transaction_id:=NEW.id;
    ELSE
        target_transaction_id:=NEW.billing_transaction_id;
    END IF;
    IF target_transaction_id IS NULL THEN
        RETURN NULL;
    END IF;
    SELECT * INTO transaction FROM billing_transactions WHERE id=target_transaction_id;
    IF transaction.operation<>'manual_adjustment' THEN
        IF transaction.adjustment_request_id IS NOT NULL THEN
            RAISE EXCEPTION 'commercial billing transaction cannot bind adjustment approval'
                USING ERRCODE='P1002';
        END IF;
        RETURN NULL;
    END IF;
    IF transaction.adjustment_request_id IS NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM billing_adjustment_legacy_authority legacy
            WHERE legacy.transaction_id=transaction.id
              AND legacy.transaction_digest=billing_adjustment_transaction_digest_100(transaction.id)
        ) THEN
            RAISE EXCEPTION 'manual billing adjustment lacks approval authority'
                USING ERRCODE='P1002';
        END IF;
        RETURN NULL;
    END IF;
    SELECT * INTO request FROM billing_adjustment_requests
    WHERE id=transaction.adjustment_request_id;
    SELECT decision_row.* INTO decision FROM billing_adjustment_decisions decision_row
    WHERE decision_row.adjustment_request_id=request.id AND decision_row.decision='approved';
    IF request.id IS NULL OR decision.id IS NULL
       OR decision.billing_transaction_id<>transaction.id
       OR transaction.target_scope_id<>request.target_scope_id
       OR transaction.direction<>request.direction
       OR transaction.amount_minor<>request.amount_minor
       OR transaction.currency<>request.currency
       OR transaction.reason<>request.reason
       OR transaction.created_by_user_id<>decision.approved_by_user_id
       OR transaction.created_at<>decision.decided_at THEN
        RAISE EXCEPTION 'manual billing transaction does not match approved request'
            USING ERRCODE='P1002';
    END IF;
    SELECT count(*) INTO exact_audit_count
    FROM audit_events audit
    WHERE audit.scope_id=decision.approved_by_scope_id
      AND audit.actor_user_id=decision.approved_by_user_id
      AND audit.action='billing.adjustment.approve'
      AND audit.resource_type='billing_adjustment_request'
      AND audit.resource_id=request.id::text
      AND audit.request_id=decision.request_id
      AND audit.result='success';
    IF exact_audit_count<>1 THEN
        RAISE EXCEPTION 'approved billing adjustment lacks exact audit'
            USING ERRCODE='P1002';
    END IF;
    SELECT count(*),
           count(*) FILTER (WHERE posting.account_id=request.target_account_id
             AND posting.side=request.direction AND posting.amount_minor=request.amount_minor),
           count(*) FILTER (WHERE account.scope_id=decision.approved_by_scope_id
             AND account.kind='platform_clearing'
             AND posting.side=CASE request.direction WHEN 'credit' THEN 'debit' ELSE 'credit' END
             AND posting.amount_minor=request.amount_minor)
      INTO exact_posting_count,exact_tenant_posting_count,exact_clearing_posting_count
    FROM billing_postings posting
    JOIN billing_accounts account ON account.id=posting.account_id
    WHERE posting.transaction_id=transaction.id;
    IF exact_posting_count<>2 OR exact_tenant_posting_count<>1 OR exact_clearing_posting_count<>1 THEN
        RAISE EXCEPTION 'approved billing adjustment lacks exact double-entry postings'
            USING ERRCODE='P1002';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION validate_billing_adjustment_fact_audit_100()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    authority_request billing_adjustment_requests%ROWTYPE;
    authority_decision billing_adjustment_decisions%ROWTYPE;
    expected_action text;
    actor_scope uuid;
    actor_user uuid;
    expected_request_id text;
    expected_idempotency_key text;
    expected_digest bytea;
    expected_status integer;
    expected_completed_at timestamptz;
    adjustment_id uuid;
    proposed_at_json text;
    expires_at_json text;
    decided_at_json text;
    expected_response_body jsonb;
    exact_count bigint;
    exact_receipt_count bigint;
BEGIN
    IF TG_TABLE_NAME='billing_adjustment_requests' THEN
        authority_request:=NEW;
        expected_action:='billing.adjustment.propose';
        actor_scope:=NEW.proposed_by_scope_id;
        actor_user:=NEW.proposed_by_user_id;
        expected_request_id:=NEW.request_id;
        expected_idempotency_key:=NEW.idempotency_key;
        expected_digest:=NEW.request_digest;
        expected_status:=201;
        expected_completed_at:=NEW.proposed_at;
        adjustment_id:=NEW.id;
    ELSIF TG_TABLE_NAME='billing_adjustment_decisions' THEN
        authority_decision:=NEW;
        SELECT * INTO authority_request FROM billing_adjustment_requests
        WHERE id=NEW.adjustment_request_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'billing adjustment authority fact has no request'
                USING ERRCODE='P1002';
        END IF;
        expected_action:='billing.adjustment.'||CASE NEW.decision
            WHEN 'approved' THEN 'approve'
            WHEN 'rejected' THEN 'reject'
            ELSE 'cancel' END;
        actor_scope:=NEW.approved_by_scope_id;
        actor_user:=NEW.approved_by_user_id;
        expected_request_id:=NEW.request_id;
        expected_idempotency_key:=NEW.idempotency_key;
        expected_digest:=NEW.request_digest;
        expected_status:=200;
        expected_completed_at:=NEW.decided_at;
        adjustment_id:=NEW.adjustment_request_id;
    ELSIF TG_TABLE_NAME='billing_adjustment_write_receipts' THEN
        SELECT * INTO authority_request FROM billing_adjustment_requests
        WHERE id=NEW.adjustment_request_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'billing adjustment receipt has no request authority'
                USING ERRCODE='P1002';
        END IF;
        adjustment_id:=authority_request.id;
        IF NEW.operation='billing.adjustment.propose' THEN
            expected_action:='billing.adjustment.propose';
            actor_scope:=authority_request.proposed_by_scope_id;
            actor_user:=authority_request.proposed_by_user_id;
            expected_request_id:=authority_request.request_id;
            expected_idempotency_key:=authority_request.idempotency_key;
            expected_digest:=authority_request.request_digest;
            expected_status:=201;
            expected_completed_at:=authority_request.proposed_at;
        ELSE
            SELECT * INTO authority_decision FROM billing_adjustment_decisions
            WHERE adjustment_request_id=authority_request.id;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'billing adjustment terminal receipt has no decision authority'
                    USING ERRCODE='P1002';
            END IF;
            expected_action:='billing.adjustment.'||CASE authority_decision.decision
                WHEN 'approved' THEN 'approve'
                WHEN 'rejected' THEN 'reject'
                ELSE 'cancel' END;
            actor_scope:=authority_decision.approved_by_scope_id;
            actor_user:=authority_decision.approved_by_user_id;
            expected_request_id:=authority_decision.request_id;
            expected_idempotency_key:=authority_decision.idempotency_key;
            expected_digest:=authority_decision.request_digest;
            expected_status:=200;
            expected_completed_at:=authority_decision.decided_at;
        END IF;
    ELSE
        RAISE EXCEPTION 'unsupported billing adjustment authority trigger source'
            USING ERRCODE='P1002';
    END IF;
    proposed_at_json:=to_char(authority_request.proposed_at AT TIME ZONE 'UTC',
        'YYYY-MM-DD"T"HH24:MI:SS')||CASE
        WHEN extract(microseconds FROM authority_request.proposed_at)::bigint%1000000=0 THEN ''
        ELSE '.'||rtrim(to_char(
            extract(microseconds FROM authority_request.proposed_at)::bigint%1000000,
            'FM000000'),'0')
        END||'Z';
    expires_at_json:=to_char(authority_request.expires_at AT TIME ZONE 'UTC',
        'YYYY-MM-DD"T"HH24:MI:SS')||CASE
        WHEN extract(microseconds FROM authority_request.expires_at)::bigint%1000000=0 THEN ''
        ELSE '.'||rtrim(to_char(
            extract(microseconds FROM authority_request.expires_at)::bigint%1000000,
            'FM000000'),'0')
        END||'Z';
    expected_response_body:=jsonb_build_object(
        'id',authority_request.id::text,
        'target_scope_id',authority_request.target_scope_id::text,
        'target_tenant_id',authority_request.target_tenant_id::text,
        'target_account_id',authority_request.target_account_id::text,
        'direction',authority_request.direction,
        'amount_minor',authority_request.amount_minor,
        'currency',authority_request.currency,
        'reason',authority_request.reason,
        'expected_account_revision',authority_request.expected_account_revision,
        'state',CASE WHEN authority_decision.id IS NULL THEN 'pending' ELSE authority_decision.decision END,
        'revision',CASE WHEN authority_decision.id IS NULL THEN 1 ELSE 2 END,
        'proposed_by_scope_id',authority_request.proposed_by_scope_id::text,
        'proposed_by_user_id',authority_request.proposed_by_user_id::text,
        'proposed_at',proposed_at_json,
        'expires_at',expires_at_json
    );
    IF authority_decision.id IS NOT NULL THEN
        decided_at_json:=to_char(authority_decision.decided_at AT TIME ZONE 'UTC',
            'YYYY-MM-DD"T"HH24:MI:SS')||CASE
            WHEN extract(microseconds FROM authority_decision.decided_at)::bigint%1000000=0 THEN ''
            ELSE '.'||rtrim(to_char(
                extract(microseconds FROM authority_decision.decided_at)::bigint%1000000,
                'FM000000'),'0')
            END||'Z';
        expected_response_body:=expected_response_body||jsonb_build_object('decision',
            jsonb_build_object(
                'id',authority_decision.id::text,
                'decision',authority_decision.decision,
                'approved_by_scope_id',authority_decision.approved_by_scope_id::text,
                'approved_by_user_id',authority_decision.approved_by_user_id::text,
                'decided_at',decided_at_json
            )||CASE WHEN authority_decision.billing_transaction_id IS NULL THEN '{}'::jsonb
                ELSE jsonb_build_object(
                    'billing_transaction_id',authority_decision.billing_transaction_id::text)
                END
        );
    END IF;
    IF TG_TABLE_NAME='billing_adjustment_write_receipts' THEN
        IF NEW.actor_scope_id IS DISTINCT FROM actor_scope
           OR NEW.actor_user_id IS DISTINCT FROM actor_user
           OR NEW.operation IS DISTINCT FROM expected_action
           OR NEW.idempotency_key IS DISTINCT FROM expected_idempotency_key
           OR NEW.request_id IS DISTINCT FROM expected_request_id
           OR NEW.request_digest IS DISTINCT FROM expected_digest
           OR NEW.adjustment_request_id IS DISTINCT FROM adjustment_id
           OR NEW.response_status IS DISTINCT FROM expected_status
           OR NEW.response_body IS DISTINCT FROM expected_response_body
           OR NEW.completed_at IS DISTINCT FROM expected_completed_at THEN
            RAISE EXCEPTION 'billing adjustment receipt does not match exact authority facts'
                USING ERRCODE='P1002';
        END IF;
    END IF;
    SELECT count(*) INTO exact_count FROM audit_events audit
    WHERE audit.scope_id=actor_scope AND audit.actor_user_id=actor_user
      AND audit.action=expected_action
      AND audit.resource_type='billing_adjustment_request'
      AND audit.resource_id=adjustment_id::text
      AND audit.request_id=expected_request_id AND audit.result='success';
    IF exact_count<>1 THEN
        RAISE EXCEPTION 'billing adjustment authority fact lacks exact audit'
            USING ERRCODE='P1002';
    END IF;
    SELECT count(*) INTO exact_receipt_count
    FROM billing_adjustment_write_receipts receipt
    WHERE receipt.actor_scope_id=actor_scope AND receipt.actor_user_id=actor_user
      AND receipt.operation=expected_action
      AND receipt.idempotency_key=expected_idempotency_key
      AND receipt.request_id=expected_request_id
      AND receipt.request_digest=expected_digest
      AND receipt.adjustment_request_id=adjustment_id
      AND receipt.response_status=expected_status
      AND receipt.response_body=expected_response_body
      AND receipt.completed_at=expected_completed_at;
    IF exact_receipt_count<>1 THEN
        RAISE EXCEPTION 'billing adjustment authority fact lacks exact receipt'
            USING ERRCODE='P1002';
    END IF;
    RETURN NULL;
END;
$$;

DO $$
DECLARE
    trusted_schema text:=current_schema();
BEGIN
    IF trusted_schema IS NULL OR trusted_schema IN ('pg_catalog','pg_temp') THEN
        RAISE EXCEPTION 'migration 100 requires an explicit trusted control schema'
            USING ERRCODE='P1000';
    END IF;
    EXECUTE format(
        'ALTER FUNCTION %I.validate_billing_adjustment_commit_100() SET search_path = %I, pg_catalog, pg_temp',
        trusted_schema,trusted_schema);
    EXECUTE format(
        'ALTER FUNCTION %I.validate_billing_adjustment_fact_audit_100() SET search_path = %I, pg_catalog, pg_temp',
        trusted_schema,trusted_schema);
END;
$$;

CREATE TRIGGER billing_adjustment_legacy_validate_100
BEFORE INSERT ON billing_adjustment_legacy_authority
FOR EACH ROW EXECUTE FUNCTION validate_billing_adjustment_legacy_authority_100();
CREATE TRIGGER billing_adjustment_requests_validate_100
BEFORE INSERT ON billing_adjustment_requests
FOR EACH ROW EXECUTE FUNCTION validate_billing_adjustment_request_100();
CREATE TRIGGER billing_adjustment_decisions_validate_100
BEFORE INSERT ON billing_adjustment_decisions
FOR EACH ROW EXECUTE FUNCTION validate_billing_adjustment_decision_100();

CREATE CONSTRAINT TRIGGER billing_adjustment_transactions_commit_100
AFTER INSERT OR UPDATE OF adjustment_request_id ON billing_transactions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_billing_adjustment_commit_100();
CREATE CONSTRAINT TRIGGER billing_adjustment_decisions_commit_100
AFTER INSERT ON billing_adjustment_decisions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_billing_adjustment_commit_100();
CREATE CONSTRAINT TRIGGER billing_adjustment_requests_audit_100
AFTER INSERT ON billing_adjustment_requests
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_billing_adjustment_fact_audit_100();
CREATE CONSTRAINT TRIGGER billing_adjustment_decisions_audit_100
AFTER INSERT ON billing_adjustment_decisions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_billing_adjustment_fact_audit_100();
CREATE CONSTRAINT TRIGGER billing_adjustment_receipts_audit_100
AFTER INSERT ON billing_adjustment_write_receipts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_billing_adjustment_fact_audit_100();

CREATE TRIGGER billing_adjustment_legacy_immutable_100
BEFORE UPDATE OR DELETE ON billing_adjustment_legacy_authority
FOR EACH ROW EXECUTE FUNCTION prevent_billing_adjustment_authority_mutation_100();
CREATE TRIGGER billing_adjustment_requests_immutable_100
BEFORE UPDATE OR DELETE ON billing_adjustment_requests
FOR EACH ROW EXECUTE FUNCTION prevent_billing_adjustment_authority_mutation_100();
CREATE TRIGGER billing_adjustment_decisions_immutable_100
BEFORE UPDATE OR DELETE ON billing_adjustment_decisions
FOR EACH ROW EXECUTE FUNCTION prevent_billing_adjustment_authority_mutation_100();
CREATE TRIGGER billing_adjustment_receipts_immutable_100
BEFORE UPDATE OR DELETE ON billing_adjustment_write_receipts
FOR EACH ROW EXECUTE FUNCTION prevent_billing_adjustment_authority_mutation_100();
CREATE TRIGGER billing_adjustment_legacy_no_truncate_100
BEFORE TRUNCATE ON billing_adjustment_legacy_authority
FOR EACH STATEMENT EXECUTE FUNCTION prevent_billing_adjustment_authority_mutation_100();
CREATE TRIGGER billing_adjustment_requests_no_truncate_100
BEFORE TRUNCATE ON billing_adjustment_requests
FOR EACH STATEMENT EXECUTE FUNCTION prevent_billing_adjustment_authority_mutation_100();
CREATE TRIGGER billing_adjustment_decisions_no_truncate_100
BEFORE TRUNCATE ON billing_adjustment_decisions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_billing_adjustment_authority_mutation_100();
CREATE TRIGGER billing_adjustment_receipts_no_truncate_100
BEFORE TRUNCATE ON billing_adjustment_write_receipts
FOR EACH STATEMENT EXECUTE FUNCTION prevent_billing_adjustment_authority_mutation_100();

REVOKE ALL ON billing_adjustment_legacy_authority,billing_adjustment_requests,
    billing_adjustment_decisions,billing_adjustment_write_receipts FROM PUBLIC;
REVOKE ALL ON FUNCTION billing_adjustment_transaction_digest_100(uuid),
    prevent_billing_adjustment_authority_mutation_100(),
    validate_billing_adjustment_legacy_authority_100(),
    validate_billing_adjustment_request_100(),
    validate_billing_adjustment_decision_100(),
    validate_billing_adjustment_commit_100(),
    validate_billing_adjustment_fact_audit_100() FROM PUBLIC;

DO $$
BEGIN
    IF to_regrole('cdnca_control_app') IS NOT NULL THEN
        EXECUTE format('GRANT USAGE ON SCHEMA %I TO cdnca_control_app',current_schema());
        GRANT SELECT ON billing_adjustment_legacy_authority TO cdnca_control_app;
        GRANT SELECT,INSERT ON billing_adjustment_requests,billing_adjustment_decisions,
            billing_adjustment_write_receipts TO cdnca_control_app;
    END IF;
END;
$$;
