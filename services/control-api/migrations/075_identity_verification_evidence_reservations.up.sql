CREATE UNIQUE INDEX auth_sessions_identity_evidence_binding_075_idx
    ON auth_sessions (id, scope_id, user_id);

CREATE TABLE identity_verification_evidence_reservations (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    session_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN (
        'personal_initial', 'personal_reverification', 'enterprise'
    )),
    idempotency_digest bytea CHECK (
        idempotency_digest IS NULL OR octet_length(idempotency_digest) = 32
    ),
    token_digest bytea NOT NULL UNIQUE CHECK (octet_length(token_digest) = 32),
    resolver_name text NOT NULL CHECK (
        octet_length(resolver_name) BETWEEN 1 AND 64 AND
        resolver_name ~ '^[a-z][a-z0-9._-]*$'
    ),
    resolver_reference text NOT NULL UNIQUE CHECK (
        octet_length(resolver_reference) BETWEEN 1 AND 256 AND
        resolver_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
    ),
    private_object_reference text NOT NULL CHECK (
        octet_length(private_object_reference) BETWEEN 1 AND 1024 AND
        private_object_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:/=@+-]*$'
    ),
    private_envelope_digest bytea NOT NULL CHECK (octet_length(private_envelope_digest) = 32),
    evidence_request_digest bytea NOT NULL CHECK (octet_length(evidence_request_digest) = 32),
    evidence_claim_digest bytea NOT NULL CHECK (octet_length(evidence_claim_digest) = 32),
    evidence_payload jsonb NOT NULL CHECK (
        jsonb_typeof(evidence_payload) = 'object' AND
        octet_length(evidence_payload::text) BETWEEN 2 AND 131072
    ),
    state text NOT NULL CHECK (state IN (
        'issued', 'reserved', 'aborted', 'quarantined', 'published'
    )),
    revision bigint NOT NULL CHECK (revision > 0),
    case_id uuid,
    core_request_digest bytea CHECK (
        core_request_digest IS NULL OR octet_length(core_request_digest) = 32
    ),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT identity_verification_evidence_reservations_session_binding_fk
    FOREIGN KEY (session_id, tenant_scope_id, actor_user_id)
        REFERENCES auth_sessions(id, scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, case_id, actor_user_id)
        REFERENCES identity_verification_cases(tenant_scope_id, id, applicant_user_id)
        ON DELETE RESTRICT,
    CHECK (isfinite(created_at) AND isfinite(updated_at) AND isfinite(expires_at)),
    CHECK (updated_at >= created_at AND expires_at > created_at),
    CHECK (
        (state = 'issued' AND revision = 1 AND idempotency_digest IS NULL AND
         case_id IS NULL AND core_request_digest IS NULL) OR
        (state IN ('reserved', 'aborted', 'quarantined') AND revision >= 2 AND
         idempotency_digest IS NOT NULL AND case_id IS NULL AND core_request_digest IS NULL) OR
        (state = 'published' AND revision >= 3 AND idempotency_digest IS NOT NULL AND
         case_id IS NOT NULL AND core_request_digest IS NOT NULL)
    )
);

CREATE UNIQUE INDEX identity_verification_evidence_reservations_actor_digest_idx
    ON identity_verification_evidence_reservations (
        tenant_scope_id, actor_user_id, session_id, kind, idempotency_digest
    )
    WHERE idempotency_digest IS NOT NULL;

CREATE INDEX identity_verification_evidence_reservations_expiry_idx
    ON identity_verification_evidence_reservations (expires_at, id)
    WHERE state = 'issued';

CREATE FUNCTION protect_identity_verification_evidence_reservation_075()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'identity verification evidence reservations cannot be truncated';
    ELSIF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'identity verification evidence reservations cannot be deleted';
    ELSIF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'issued' OR NEW.revision <> 1 OR NEW.idempotency_digest IS NOT NULL OR
           NEW.case_id IS NOT NULL OR NEW.core_request_digest IS NOT NULL OR
           NEW.updated_at <> NEW.created_at THEN
            RAISE EXCEPTION 'identity verification evidence reservation must start issued';
        END IF;
        RETURN NEW;
    END IF;

    IF ROW(NEW.id, NEW.tenant_scope_id, NEW.actor_user_id, NEW.session_id, NEW.kind,
           NEW.token_digest, NEW.resolver_name, NEW.resolver_reference,
           NEW.private_object_reference, NEW.private_envelope_digest,
           NEW.evidence_request_digest, NEW.evidence_claim_digest,
           NEW.evidence_payload, NEW.created_at, NEW.expires_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.tenant_scope_id, OLD.actor_user_id, OLD.session_id, OLD.kind,
           OLD.token_digest, OLD.resolver_name, OLD.resolver_reference,
           OLD.private_object_reference, OLD.private_envelope_digest,
           OLD.evidence_request_digest, OLD.evidence_claim_digest,
           OLD.evidence_payload, OLD.created_at, OLD.expires_at) OR
       NEW.revision <> OLD.revision + 1 OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'identity verification evidence reservation payload is immutable';
    END IF;

    IF OLD.state = 'issued' AND NEW.state = 'reserved' THEN
        IF NEW.idempotency_digest IS NULL OR NEW.case_id IS NOT NULL OR
           NEW.core_request_digest IS NOT NULL THEN
            RAISE EXCEPTION 'invalid identity verification evidence reservation';
        END IF;
    ELSIF OLD.state = 'reserved' AND NEW.state IN ('aborted', 'quarantined') THEN
        IF NEW.idempotency_digest IS DISTINCT FROM OLD.idempotency_digest OR
           NEW.case_id IS NOT NULL OR NEW.core_request_digest IS NOT NULL THEN
            RAISE EXCEPTION 'invalid identity verification evidence release';
        END IF;
    ELSIF OLD.state = 'reserved' AND NEW.state = 'published' THEN
        IF NEW.idempotency_digest IS DISTINCT FROM OLD.idempotency_digest OR
           NEW.case_id IS NULL OR NEW.core_request_digest IS NULL THEN
            RAISE EXCEPTION 'invalid identity verification evidence publication';
        END IF;
    ELSE
        RAISE EXCEPTION 'invalid identity verification evidence reservation transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER identity_verification_evidence_reservations_protected_075
BEFORE INSERT OR UPDATE OR DELETE ON identity_verification_evidence_reservations
FOR EACH ROW EXECUTE FUNCTION protect_identity_verification_evidence_reservation_075();

CREATE TRIGGER identity_verification_evidence_reservations_no_truncate_075
BEFORE TRUNCATE ON identity_verification_evidence_reservations
FOR EACH STATEMENT EXECUTE FUNCTION protect_identity_verification_evidence_reservation_075();

ALTER TABLE identity_verification_evidence_reservations
    ENABLE ALWAYS TRIGGER identity_verification_evidence_reservations_protected_075;
ALTER TABLE identity_verification_evidence_reservations
    ENABLE ALWAYS TRIGGER identity_verification_evidence_reservations_no_truncate_075;

CREATE FUNCTION require_identity_verification_evidence_reservation_audit_075()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    expected_action text;
BEGIN
    expected_action := CASE NEW.state
        WHEN 'issued' THEN 'identity_verification.evidence_reservation.issued'
        WHEN 'reserved' THEN 'identity_verification.evidence_reservation.reserved'
        WHEN 'aborted' THEN 'identity_verification.evidence_reservation.aborted'
        WHEN 'quarantined' THEN 'identity_verification.evidence_reservation.quarantined'
        WHEN 'published' THEN 'identity_verification.evidence_reservation.published'
    END;
    IF NOT EXISTS (
        SELECT 1 FROM audit_events event
        WHERE event.scope_id = NEW.tenant_scope_id
          AND event.actor_user_id = NEW.actor_user_id
          AND event.action = expected_action
          AND event.resource_type = 'identity_verification_evidence_reservation'
          AND event.resource_id = NEW.id::text
          AND event.result = 'success'
          AND event.payload->>'state' = NEW.state
          AND event.payload->>'revision' = NEW.revision::text
    ) THEN
        RAISE EXCEPTION 'identity verification evidence reservation requires audit';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER identity_verification_evidence_reservations_require_audit_075
AFTER INSERT OR UPDATE ON identity_verification_evidence_reservations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION require_identity_verification_evidence_reservation_audit_075();

ALTER TABLE identity_verification_evidence_reservations
    ENABLE ALWAYS TRIGGER identity_verification_evidence_reservations_require_audit_075;
