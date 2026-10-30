INSERT INTO permissions (name, description) VALUES
    ('identity_verification.evidence_settlement.requeue',
     'Requeue a permanently failed identity verification evidence settlement');

INSERT INTO custom_rbac_permission_catalog (permission_name, step_up_required) VALUES
    ('identity_verification.evidence_settlement.requeue', true);

INSERT INTO role_permissions (role_id, permission_name)
SELECT role.id, 'identity_verification.evidence_settlement.requeue'
FROM roles role
JOIN access_scopes scope ON scope.id = role.scope_id
WHERE role.system_role AND role.name = 'tenant_owner' AND scope.kind = 'tenant'
ON CONFLICT DO NOTHING;

ALTER TABLE identity_verification_cases
    ADD COLUMN evidence_settlement_required boolean NOT NULL DEFAULT false;
ALTER TABLE identity_verification_cases
    ALTER COLUMN evidence_settlement_required SET DEFAULT true,
    ADD CONSTRAINT identity_verification_cases_settlement_binding_key
        UNIQUE (tenant_scope_id, id, applicant_user_id);

ALTER TABLE identity_verification_write_requests
    ADD CONSTRAINT identity_verification_write_requests_settlement_binding_key
        UNIQUE (id, tenant_scope_id, actor_user_id, operation, idempotency_key, request_digest);

CREATE TABLE identity_verification_evidence_settlements (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    case_id uuid NOT NULL,
    write_request_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation = 'identity_verification.create_draft'),
    idempotency_key text NOT NULL CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128 AND
        idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    evidence_claim_digest bytea NOT NULL CHECK (octet_length(evidence_claim_digest) = 32),
    resolver_name text NOT NULL CHECK (
        octet_length(resolver_name) BETWEEN 1 AND 64 AND
        resolver_name ~ '^[a-z][a-z0-9._-]*$'
    ),
    resolver_reference text NOT NULL CHECK (
        octet_length(resolver_reference) BETWEEN 1 AND 256 AND
        resolver_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
    ),
    state text NOT NULL CHECK (state IN (
        'commit_pending', 'leased', 'retry_wait', 'settled', 'permanent_failed'
    )),
    revision bigint NOT NULL CHECK (revision > 0),
    attempt_count integer NOT NULL CHECK (attempt_count >= 0),
    available_at timestamptz NOT NULL,
    lease_token uuid,
    lease_expires_at timestamptz,
    last_failure_code text CHECK (
        last_failure_code IS NULL OR (
            octet_length(last_failure_code) BETWEEN 1 AND 64 AND
            last_failure_code ~ '^[a-z][a-z0-9._-]*$'
        )
    ),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    settled_at timestamptz,
    permanent_failed_at timestamptz,
    CONSTRAINT identity_verification_evidence_settlements_case_key UNIQUE (case_id),
    CONSTRAINT identity_verification_evidence_settlements_write_key UNIQUE (write_request_id),
    CONSTRAINT identity_verification_evidence_resolver_reference_key
        UNIQUE (resolver_name, resolver_reference),
    FOREIGN KEY (tenant_scope_id, case_id, actor_user_id)
        REFERENCES identity_verification_cases(tenant_scope_id, id, applicant_user_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (
        write_request_id, tenant_scope_id, actor_user_id, operation,
        idempotency_key, request_digest
    ) REFERENCES identity_verification_write_requests(
        id, tenant_scope_id, actor_user_id, operation, idempotency_key, request_digest
    ) ON DELETE RESTRICT,
    CHECK (updated_at >= created_at AND available_at >= created_at),
    CHECK (
        (state = 'commit_pending' AND attempt_count = 0 AND
         lease_token IS NULL AND lease_expires_at IS NULL AND last_failure_code IS NULL AND
         settled_at IS NULL AND permanent_failed_at IS NULL) OR
        (state = 'leased' AND attempt_count > 0 AND
         lease_token IS NOT NULL AND lease_expires_at > updated_at AND last_failure_code IS NULL AND
         settled_at IS NULL AND permanent_failed_at IS NULL) OR
        (state = 'retry_wait' AND lease_token IS NULL AND lease_expires_at IS NULL AND
         settled_at IS NULL AND permanent_failed_at IS NULL AND available_at >= updated_at) OR
        (state = 'settled' AND attempt_count > 0 AND
         lease_token IS NULL AND lease_expires_at IS NULL AND last_failure_code IS NULL AND
         settled_at = updated_at AND permanent_failed_at IS NULL) OR
        (state = 'permanent_failed' AND attempt_count > 0 AND
         lease_token IS NULL AND lease_expires_at IS NULL AND last_failure_code IS NOT NULL AND
         settled_at IS NULL AND permanent_failed_at = updated_at)
    )
);

CREATE INDEX identity_verification_evidence_settlements_ready_idx
    ON identity_verification_evidence_settlements (available_at, id)
    WHERE state IN ('commit_pending', 'retry_wait');
CREATE INDEX identity_verification_evidence_settlements_expired_lease_idx
    ON identity_verification_evidence_settlements (lease_expires_at, id)
    WHERE state = 'leased';

CREATE FUNCTION protect_identity_verification_evidence_settlement()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'identity verification evidence settlements cannot be truncated';
    ELSIF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'identity verification evidence settlements cannot be deleted';
    ELSIF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'commit_pending' OR NEW.revision <> 1 OR NEW.attempt_count <> 0 OR
           NEW.available_at <> NEW.created_at OR NEW.updated_at <> NEW.created_at OR
           NEW.lease_token IS NOT NULL OR NEW.lease_expires_at IS NOT NULL OR
           NEW.last_failure_code IS NOT NULL OR NEW.settled_at IS NOT NULL OR
           NEW.permanent_failed_at IS NOT NULL THEN
            RAISE EXCEPTION 'identity verification evidence settlement must start commit pending';
        END IF;
        RETURN NEW;
    END IF;

    IF ROW(NEW.id, NEW.tenant_scope_id, NEW.actor_user_id, NEW.case_id,
           NEW.write_request_id, NEW.operation, NEW.idempotency_key, NEW.request_digest,
           NEW.evidence_claim_digest, NEW.resolver_name, NEW.resolver_reference, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.tenant_scope_id, OLD.actor_user_id, OLD.case_id,
           OLD.write_request_id, OLD.operation, OLD.idempotency_key, OLD.request_digest,
           OLD.evidence_claim_digest, OLD.resolver_name, OLD.resolver_reference, OLD.created_at) OR
       NEW.revision <> OLD.revision + 1 OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'identity verification evidence settlement payload is immutable';
    END IF;

    IF NEW.state = 'leased' AND OLD.state IN ('commit_pending', 'retry_wait', 'leased') THEN
        IF OLD.state = 'leased' AND OLD.lease_expires_at > NEW.updated_at THEN
            RAISE EXCEPTION 'identity verification evidence settlement lease is still active';
        END IF;
        IF OLD.state IN ('commit_pending', 'retry_wait') AND OLD.available_at > NEW.updated_at THEN
            RAISE EXCEPTION 'identity verification evidence settlement is not available';
        END IF;
        IF NEW.attempt_count <> OLD.attempt_count + 1 OR
           NEW.lease_token IS NULL OR NEW.lease_token IS NOT DISTINCT FROM OLD.lease_token OR
           NEW.lease_expires_at <= NEW.updated_at OR NEW.available_at <> OLD.available_at OR
           NEW.last_failure_code IS NOT NULL OR NEW.settled_at IS NOT NULL OR
           NEW.permanent_failed_at IS NOT NULL THEN
            RAISE EXCEPTION 'invalid identity verification evidence settlement lease';
        END IF;
    ELSIF OLD.state = 'leased' AND NEW.state = 'retry_wait' THEN
        IF NEW.attempt_count <> OLD.attempt_count OR NEW.lease_token IS NOT NULL OR
           NEW.lease_expires_at IS NOT NULL OR NEW.last_failure_code IS NULL OR
           NEW.available_at < NEW.updated_at OR NEW.settled_at IS NOT NULL OR
           NEW.permanent_failed_at IS NOT NULL THEN
            RAISE EXCEPTION 'invalid identity verification evidence settlement retry';
        END IF;
    ELSIF OLD.state = 'leased' AND NEW.state = 'settled' THEN
        IF NEW.attempt_count <> OLD.attempt_count OR NEW.lease_token IS NOT NULL OR
           NEW.lease_expires_at IS NOT NULL OR NEW.last_failure_code IS NOT NULL OR
           NEW.available_at <> OLD.available_at OR NEW.settled_at <> NEW.updated_at OR
           NEW.permanent_failed_at IS NOT NULL THEN
            RAISE EXCEPTION 'invalid identity verification evidence settlement completion';
        END IF;
    ELSIF OLD.state = 'leased' AND NEW.state = 'permanent_failed' THEN
        IF NEW.attempt_count <> OLD.attempt_count OR NEW.lease_token IS NOT NULL OR
           NEW.lease_expires_at IS NOT NULL OR NEW.last_failure_code IS NULL OR
           NEW.available_at <> OLD.available_at OR NEW.settled_at IS NOT NULL OR
           NEW.permanent_failed_at <> NEW.updated_at THEN
            RAISE EXCEPTION 'invalid identity verification evidence settlement exhaustion';
        END IF;
    ELSIF OLD.state = 'permanent_failed' AND NEW.state = 'retry_wait' THEN
        IF NEW.attempt_count <> 0 OR NEW.lease_token IS NOT NULL OR NEW.lease_expires_at IS NOT NULL OR
           NEW.last_failure_code IS NOT NULL OR NEW.available_at <> NEW.updated_at OR
           NEW.settled_at IS NOT NULL OR NEW.permanent_failed_at IS NOT NULL THEN
            RAISE EXCEPTION 'invalid identity verification evidence settlement requeue';
        END IF;
    ELSE
        RAISE EXCEPTION 'invalid identity verification evidence settlement transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER identity_verification_evidence_settlements_protected
BEFORE INSERT OR UPDATE OR DELETE ON identity_verification_evidence_settlements
FOR EACH ROW EXECUTE FUNCTION protect_identity_verification_evidence_settlement();
CREATE TRIGGER identity_verification_evidence_settlements_no_truncate
BEFORE TRUNCATE ON identity_verification_evidence_settlements
FOR EACH STATEMENT EXECUTE FUNCTION protect_identity_verification_evidence_settlement();
ALTER TABLE identity_verification_evidence_settlements
    ENABLE ALWAYS TRIGGER identity_verification_evidence_settlements_protected;
ALTER TABLE identity_verification_evidence_settlements
    ENABLE ALWAYS TRIGGER identity_verification_evidence_settlements_no_truncate;

CREATE FUNCTION protect_identity_verification_case_settlement_requirement()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' AND NEW.evidence_settlement_required IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'new identity verification cases require evidence settlement';
    ELSIF TG_OP = 'UPDATE' AND
          NEW.evidence_settlement_required IS DISTINCT FROM OLD.evidence_settlement_required THEN
        RAISE EXCEPTION 'identity verification evidence settlement requirement is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER identity_verification_cases_settlement_requirement
BEFORE INSERT OR UPDATE OF evidence_settlement_required ON identity_verification_cases
FOR EACH ROW EXECUTE FUNCTION protect_identity_verification_case_settlement_requirement();
ALTER TABLE identity_verification_cases
    ENABLE ALWAYS TRIGGER identity_verification_cases_settlement_requirement;

CREATE FUNCTION require_identity_verification_settlement_before_submission()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    settlement_required boolean;
BEGIN
    SELECT evidence_settlement_required INTO settlement_required
    FROM identity_verification_cases
    WHERE tenant_scope_id = NEW.tenant_scope_id AND id = NEW.case_id;
    IF settlement_required AND NOT EXISTS (
        SELECT 1 FROM identity_verification_evidence_settlements settlement
        WHERE settlement.tenant_scope_id = NEW.tenant_scope_id
          AND settlement.case_id = NEW.case_id
          AND settlement.actor_user_id = NEW.applicant_user_id
          AND settlement.state = 'settled'
    ) THEN
        RAISE EXCEPTION 'identity verification evidence settlement is not settled';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER identity_verification_submissions_require_settlement
BEFORE INSERT ON identity_verification_submissions
FOR EACH ROW EXECUTE FUNCTION require_identity_verification_settlement_before_submission();
ALTER TABLE identity_verification_submissions
    ENABLE ALWAYS TRIGGER identity_verification_submissions_require_settlement;

CREATE FUNCTION validate_identity_verification_settlement_commit()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_TABLE_NAME = 'identity_verification_cases' THEN
        IF NEW.evidence_settlement_required AND NOT EXISTS (
            SELECT 1 FROM identity_verification_evidence_settlements settlement
            WHERE settlement.tenant_scope_id = NEW.tenant_scope_id
              AND settlement.case_id = NEW.id
              AND settlement.actor_user_id = NEW.applicant_user_id
        ) THEN
            RAISE EXCEPTION 'identity verification case requires an evidence settlement binding';
        END IF;
    ELSIF TG_TABLE_NAME = 'identity_verification_evidence_settlements' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM identity_verification_cases verification_case
            JOIN identity_verification_write_requests write_request
              ON write_request.id = NEW.write_request_id
             AND write_request.tenant_scope_id = NEW.tenant_scope_id
             AND write_request.actor_user_id = NEW.actor_user_id
             AND write_request.operation = NEW.operation
             AND write_request.idempotency_key = NEW.idempotency_key
             AND write_request.request_digest = NEW.request_digest
            WHERE verification_case.tenant_scope_id = NEW.tenant_scope_id
              AND verification_case.id = NEW.case_id
              AND verification_case.applicant_user_id = NEW.actor_user_id
              AND verification_case.evidence_settlement_required
              AND write_request.completed_at IS NOT NULL
              AND write_request.response_body->>'id' = NEW.case_id::text
              AND write_request.response_body->>'tenant_scope_id' = NEW.tenant_scope_id::text
              AND write_request.response_body->>'applicant_user_id' = NEW.actor_user_id::text
        ) THEN
            RAISE EXCEPTION 'identity verification evidence settlement binding is incomplete';
        END IF;
    ELSIF TG_TABLE_NAME = 'identity_verification_write_requests' AND
          NEW.operation = 'identity_verification.create_draft' AND NEW.completed_at IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1
            FROM identity_verification_evidence_settlements settlement
            JOIN identity_verification_cases verification_case
              ON verification_case.tenant_scope_id = settlement.tenant_scope_id
             AND verification_case.id = settlement.case_id
             AND verification_case.applicant_user_id = settlement.actor_user_id
            WHERE settlement.write_request_id = NEW.id
              AND settlement.tenant_scope_id = NEW.tenant_scope_id
              AND settlement.actor_user_id = NEW.actor_user_id
              AND settlement.operation = NEW.operation
              AND settlement.idempotency_key = NEW.idempotency_key
              AND settlement.request_digest = NEW.request_digest
              AND verification_case.evidence_settlement_required
              AND NEW.response_body->>'id' = verification_case.id::text
              AND NEW.response_body->>'tenant_scope_id' = verification_case.tenant_scope_id::text
              AND NEW.response_body->>'applicant_user_id' = verification_case.applicant_user_id::text
        ) THEN
            RAISE EXCEPTION 'completed identity verification draft requires an evidence settlement binding';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER identity_verification_cases_validate_settlement_commit
AFTER INSERT ON identity_verification_cases
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_identity_verification_settlement_commit();
CREATE CONSTRAINT TRIGGER identity_verification_evidence_settlements_validate_commit
AFTER INSERT OR UPDATE ON identity_verification_evidence_settlements
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_identity_verification_settlement_commit();
CREATE CONSTRAINT TRIGGER identity_verification_write_requests_validate_settlement_commit
AFTER INSERT OR UPDATE ON identity_verification_write_requests
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_identity_verification_settlement_commit();
