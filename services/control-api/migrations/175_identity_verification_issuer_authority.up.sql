LOCK TABLE schema_migrations,identity_verification_cases,
    identity_verification_provider_sessions_v1,identity_verification_provider_uploads_v1,
    identity_verification_provider_settlements_v1,identity_verification_evidence_reservations,
    audit_events IN ACCESS EXCLUSIVE MODE;

DO $migration_175$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>174 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>174 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=174 AND migration_id='174_firewall_action_authority' AND
              checksum_sha256='d73f059af5beffa4fe3d76b9ff1a360b02a1a40a0a4be0a3cab085f3900d082a' AND
              down_checksum_sha256='7b81cf1d669f70ebc8e9696280b3daf3ccc2cad831a86cd27302b4a1be323331' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('identity_verification_provider_material_envelopes_v1') IS NOT NULL OR
         to_regclass('identity_verification_evidence_issue_bindings_v1') IS NOT NULL OR
         to_regprocedure('protect_identity_verification_case()') IS NULL THEN
        RAISE EXCEPTION 'migration 175 requires the exact verified 174 release head and identity verification authority'
            USING ERRCODE='P1750';
    END IF;
    IF EXISTS (
        SELECT 1 FROM identity_verification_provider_settlements_v1 WHERE kind='enterprise'
    ) THEN
        RAISE EXCEPTION 'migration 175 cannot infer enterprise settlement facts'
            USING ERRCODE='P1751';
    END IF;
END;
$migration_175$;

ALTER TABLE identity_verification_provider_settlements_v1
    ADD COLUMN organization_name text,
    ADD COLUMN legal_person_fingerprint bytea,
    ADD COLUMN agent_fingerprint bytea,
    ADD COLUMN agent_relationship text,
    ADD CONSTRAINT identity_verification_provider_settlement_enterprise_175 CHECK (
        (kind='enterprise' AND organization_name=btrim(organization_name) AND
         char_length(organization_name) BETWEEN 2 AND 256 AND
         octet_length(legal_person_fingerprint)=32 AND octet_length(agent_fingerprint)=32 AND
         agent_relationship IN ('legal_person','employee','authorized_representative')) OR
        (kind<>'enterprise' AND organization_name IS NULL AND legal_person_fingerprint IS NULL AND
         agent_fingerprint IS NULL AND agent_relationship IS NULL)
    );

ALTER TABLE identity_verification_provider_uploads_v1
    ADD CONSTRAINT identity_verification_provider_upload_binding_175
    UNIQUE(tenant_scope_id,session_id,actor_user_id,id);

ALTER TABLE identity_verification_evidence_reservations
    ADD CONSTRAINT identity_verification_evidence_reservation_issue_binding_175
    UNIQUE(id,tenant_scope_id,actor_user_id,session_id,kind,token_digest,evidence_claim_digest,expires_at);

CREATE TABLE identity_verification_provider_material_envelopes_v1 (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    upload_id uuid NOT NULL UNIQUE,
    session_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    envelope_provider text NOT NULL CHECK(envelope_provider ~ '^[a-z][a-z0-9._-]{0,63}$'),
    envelope_key_id text NOT NULL CHECK(
        envelope_key_id=btrim(envelope_key_id) AND octet_length(envelope_key_id) BETWEEN 1 AND 512
    ),
    encrypted_envelope bytea NOT NULL CHECK(octet_length(encrypted_envelope) BETWEEN 16 AND 65536),
    envelope_aad_sha256 bytea NOT NULL CHECK(octet_length(envelope_aad_sha256)=32),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    FOREIGN KEY(tenant_scope_id,session_id,actor_user_id,upload_id)
        REFERENCES identity_verification_provider_uploads_v1(tenant_scope_id,session_id,actor_user_id,id)
        ON DELETE RESTRICT,
    FOREIGN KEY(tenant_scope_id,session_id,actor_user_id)
        REFERENCES identity_verification_provider_sessions_v1(tenant_scope_id,id,actor_user_id)
        ON DELETE RESTRICT
);

CREATE TABLE identity_verification_evidence_issue_bindings_v1 (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    reservation_id uuid NOT NULL UNIQUE,
    tenant_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    session_id uuid NOT NULL,
    kind text NOT NULL CHECK(kind IN ('personal_initial','personal_reverification','enterprise')),
    workload_id text NOT NULL CHECK(workload_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    certificate_fingerprint bytea NOT NULL CHECK(octet_length(certificate_fingerprint)=32),
    idempotency_digest bytea NOT NULL CHECK(octet_length(idempotency_digest)=32),
    issuer_request_digest bytea NOT NULL CHECK(octet_length(issuer_request_digest)=32),
    evidence_claim_digest bytea NOT NULL CHECK(octet_length(evidence_claim_digest)=32),
    token_digest bytea NOT NULL CHECK(octet_length(token_digest)=32),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at>created_at),
    UNIQUE(workload_id,idempotency_digest),
    FOREIGN KEY(reservation_id,tenant_scope_id,actor_user_id,session_id,kind,token_digest,
                evidence_claim_digest,expires_at)
        REFERENCES identity_verification_evidence_reservations(
            id,tenant_scope_id,actor_user_id,session_id,kind,token_digest,evidence_claim_digest,expires_at
        ) ON DELETE RESTRICT,
    FOREIGN KEY(session_id,tenant_scope_id,actor_user_id)
        REFERENCES auth_sessions(id,scope_id,user_id) ON DELETE RESTRICT
);

CREATE FUNCTION prevent_identity_verification_issuer_fact_mutation_175()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only',TG_TABLE_NAME USING ERRCODE='P1752';
END;
$$;

CREATE FUNCTION prevent_identity_verification_issuer_fact_truncate_175()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% cannot be truncated',TG_TABLE_NAME USING ERRCODE='P1752';
END;
$$;

CREATE FUNCTION require_identity_verification_material_envelope_audit_175()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM audit_events event
        WHERE event.scope_id=NEW.tenant_scope_id AND event.actor_user_id=NEW.actor_user_id
          AND event.action='identity_verification.material_envelope.created'
          AND event.resource_type='identity_verification_material_envelope'
          AND event.resource_id=NEW.id::text
          AND event.request_id='identity-material-envelope-'||NEW.id::text
          AND event.result='success'
          AND event.payload->>'session_id'=NEW.session_id::text
          AND event.payload->>'upload_id'=NEW.upload_id::text
    ) THEN
        RAISE EXCEPTION 'identity verification material envelope requires matching audit'
            USING ERRCODE='P1753';
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER identity_verification_material_envelopes_append_only_175
BEFORE UPDATE OR DELETE ON identity_verification_provider_material_envelopes_v1
FOR EACH ROW EXECUTE FUNCTION prevent_identity_verification_issuer_fact_mutation_175();
CREATE TRIGGER identity_verification_evidence_issue_bindings_append_only_175
BEFORE UPDATE OR DELETE ON identity_verification_evidence_issue_bindings_v1
FOR EACH ROW EXECUTE FUNCTION prevent_identity_verification_issuer_fact_mutation_175();
CREATE TRIGGER identity_verification_material_envelopes_no_truncate_175
BEFORE TRUNCATE ON identity_verification_provider_material_envelopes_v1
FOR EACH STATEMENT EXECUTE FUNCTION prevent_identity_verification_issuer_fact_truncate_175();
CREATE TRIGGER identity_verification_evidence_issue_bindings_no_truncate_175
BEFORE TRUNCATE ON identity_verification_evidence_issue_bindings_v1
FOR EACH STATEMENT EXECUTE FUNCTION prevent_identity_verification_issuer_fact_truncate_175();
CREATE CONSTRAINT TRIGGER identity_verification_material_envelopes_require_audit_175
AFTER INSERT ON identity_verification_provider_material_envelopes_v1
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION require_identity_verification_material_envelope_audit_175();

CREATE OR REPLACE FUNCTION protect_identity_verification_case()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    terminal_transition boolean;
    configured_retention interval;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'identity verification cases cannot be deleted';
    END IF;
    terminal_transition := OLD.status NOT IN ('approved','rejected','withdrawn','expired') AND
                           NEW.status IN ('approved','rejected','withdrawn','expired');
    configured_retention := OLD.retention_until-OLD.created_at;
    IF ROW(NEW.id, NEW.tenant_scope_id, NEW.applicant_user_id, NEW.kind,
           NEW.subject_fingerprint, NEW.organization_name, NEW.legal_person_fingerprint,
           NEW.agent_fingerprint, NEW.agent_relationship, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.tenant_scope_id, OLD.applicant_user_id, OLD.kind,
           OLD.subject_fingerprint, OLD.organization_name, OLD.legal_person_fingerprint,
           OLD.agent_fingerprint, OLD.agent_relationship, OLD.created_at) OR
       NEW.revision <> OLD.revision + 1 OR NEW.state_changed_at < OLD.state_changed_at OR NOT (
           (OLD.status = 'draft' AND NEW.status IN ('submitted', 'withdrawn')) OR
           (OLD.status = 'submitted' AND NEW.status IN ('reviewing', 'withdrawn', 'expired')) OR
           (OLD.status = 'reviewing' AND NEW.status IN ('approved', 'rejected', 'expired'))
       ) THEN
        RAISE EXCEPTION 'invalid identity verification case transition';
    END IF;
    IF terminal_transition THEN
        IF OLD.terminal_at IS NOT NULL OR NEW.terminal_at IS NULL OR
           NEW.terminal_at<>NEW.state_changed_at OR configured_retention<=interval '0 seconds' OR
           NEW.retention_until<>NEW.terminal_at+configured_retention THEN
            RAISE EXCEPTION 'identity verification terminal retention is invalid' USING ERRCODE='P1754';
        END IF;
    ELSIF NEW.terminal_at IS DISTINCT FROM OLD.terminal_at OR
          NEW.retention_until IS DISTINCT FROM OLD.retention_until THEN
        RAISE EXCEPTION 'identity verification retention is immutable before terminal transition'
            USING ERRCODE='P1754';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM identity_verification_state_events event
        WHERE event.tenant_scope_id = NEW.tenant_scope_id AND event.case_id = NEW.id
          AND event.case_revision = NEW.revision AND event.from_status = OLD.status
          AND event.to_status = NEW.status AND event.occurred_at = NEW.state_changed_at
    ) THEN
        RAISE EXCEPTION 'identity verification transition requires an immutable state event';
    END IF;
    IF NEW.status = 'submitted' THEN
        IF NOT EXISTS (
            SELECT 1 FROM identity_verification_submissions submission
            WHERE submission.tenant_scope_id = NEW.tenant_scope_id AND submission.case_id = NEW.id
              AND submission.applicant_user_id = NEW.applicant_user_id
              AND submission.case_revision = NEW.revision
              AND submission.submitted_at = NEW.submitted_at AND submission.expires_at = NEW.expires_at
        ) THEN
            RAISE EXCEPTION 'identity verification submission fact is required';
        END IF;
        IF NEW.kind = 'personal_initial' AND EXISTS (
            SELECT 1 FROM identity_verified_persons person
            WHERE person.tenant_scope_id = NEW.tenant_scope_id
              AND person.applicant_user_id = NEW.applicant_user_id
        ) THEN
            RAISE EXCEPTION 'initial identity is already approved';
        END IF;
        IF NEW.kind = 'personal_reverification' AND NOT EXISTS (
            SELECT 1 FROM identity_verified_persons person
            WHERE person.tenant_scope_id = NEW.tenant_scope_id
              AND person.applicant_user_id = NEW.applicant_user_id
              AND person.identity_fingerprint = NEW.subject_fingerprint
        ) THEN
            RAISE EXCEPTION 'reverification identity fingerprint mismatch';
        END IF;
        IF NEW.kind = 'enterprise' AND NOT EXISTS (
            SELECT 1 FROM identity_verified_persons person
            WHERE person.tenant_scope_id = NEW.tenant_scope_id
              AND person.applicant_user_id = NEW.applicant_user_id
              AND person.identity_fingerprint = NEW.agent_fingerprint
        ) THEN
            RAISE EXCEPTION 'enterprise agent identity fingerprint mismatch';
        END IF;
    ELSIF NEW.status = 'reviewing' THEN
        IF NOT EXISTS (
            SELECT 1 FROM identity_verification_review_assignments assignment
            WHERE assignment.tenant_scope_id = NEW.tenant_scope_id AND assignment.case_id = NEW.id
              AND assignment.reviewer_user_id = NEW.reviewer_user_id
              AND assignment.case_revision = NEW.revision AND assignment.assigned_at = NEW.state_changed_at
        ) THEN
            RAISE EXCEPTION 'identity verification reviewer assignment is required';
        END IF;
    ELSIF NEW.status IN ('approved', 'rejected') THEN
        IF NOT EXISTS (
            SELECT 1 FROM identity_verification_reviews review
            WHERE review.tenant_scope_id = NEW.tenant_scope_id AND review.case_id = NEW.id
              AND review.reviewer_user_id = NEW.reviewer_user_id AND review.decision = NEW.status
              AND review.expected_revision = OLD.revision AND review.resulting_revision = NEW.revision
              AND review.reviewed_at = NEW.state_changed_at
        ) THEN
            RAISE EXCEPTION 'identity verification review fact is required';
        END IF;
        IF NEW.status = 'approved' AND NEW.kind = 'personal_initial' AND NOT EXISTS (
            SELECT 1 FROM identity_verified_persons person
            WHERE person.tenant_scope_id = NEW.tenant_scope_id
              AND person.applicant_user_id = NEW.applicant_user_id
              AND person.identity_fingerprint = NEW.subject_fingerprint
              AND person.initial_case_id = NEW.id
              AND person.approved_at = NEW.state_changed_at
        ) THEN
            RAISE EXCEPTION 'approved initial identity requires a stable subject binding';
        END IF;
        IF NEW.status = 'approved' AND NEW.kind = 'personal_reverification' AND NOT EXISTS (
            SELECT 1 FROM identity_verified_persons person
            WHERE person.tenant_scope_id = NEW.tenant_scope_id
              AND person.applicant_user_id = NEW.applicant_user_id
              AND person.identity_fingerprint = NEW.subject_fingerprint
        ) THEN
            RAISE EXCEPTION 'approved reverification identity fingerprint mismatch';
        END IF;
        IF NEW.status = 'approved' AND NEW.kind = 'enterprise' AND NOT EXISTS (
            SELECT 1 FROM identity_verified_organizations organization
            WHERE organization.tenant_scope_id = NEW.tenant_scope_id
              AND organization.subject_fingerprint = NEW.subject_fingerprint
              AND organization.approved_case_id = NEW.id
              AND organization.approved_at = NEW.state_changed_at
        ) THEN
            RAISE EXCEPTION 'approved enterprise verification requires a stable subject binding';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON identity_verification_provider_material_envelopes_v1,
    identity_verification_evidence_issue_bindings_v1 FROM PUBLIC;
