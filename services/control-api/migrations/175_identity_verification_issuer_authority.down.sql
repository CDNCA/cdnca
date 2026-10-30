LOCK TABLE schema_migrations,identity_verification_provider_material_envelopes_v1,
    identity_verification_evidence_issue_bindings_v1,identity_verification_provider_settlements_v1,
    identity_verification_provider_uploads_v1,identity_verification_evidence_reservations,
    identity_verification_cases,audit_events IN ACCESS EXCLUSIVE MODE;

DO $migration_175_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>175 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>175 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=175 AND migration_id='175_identity_verification_issuer_authority' AND
              checksum_sha256='55dd21f5024894066f3bc20ff100229027e0051e3f33fadf64503c28b9305448' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 175 rollback requires the exact verified 175 head'
            USING ERRCODE='P1755';
    END IF;
    IF EXISTS (SELECT 1 FROM identity_verification_provider_material_envelopes_v1) OR
       EXISTS (SELECT 1 FROM identity_verification_evidence_issue_bindings_v1) OR
       EXISTS (
        SELECT 1 FROM identity_verification_provider_settlements_v1
        WHERE organization_name IS NOT NULL OR legal_person_fingerprint IS NOT NULL OR
              agent_fingerprint IS NOT NULL OR agent_relationship IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM audit_events
        WHERE action='identity_verification.material_envelope.created' OR
              resource_type='identity_verification_material_envelope'
    ) THEN
        RAISE EXCEPTION 'migration 175 rollback refuses to discard identity verification issuer facts'
            USING ERRCODE='P1756';
    END IF;
END;
$migration_175_down$;

DROP TRIGGER identity_verification_material_envelopes_require_audit_175
    ON identity_verification_provider_material_envelopes_v1;
DROP TRIGGER identity_verification_evidence_issue_bindings_no_truncate_175
    ON identity_verification_evidence_issue_bindings_v1;
DROP TRIGGER identity_verification_material_envelopes_no_truncate_175
    ON identity_verification_provider_material_envelopes_v1;
DROP TRIGGER identity_verification_evidence_issue_bindings_append_only_175
    ON identity_verification_evidence_issue_bindings_v1;
DROP TRIGGER identity_verification_material_envelopes_append_only_175
    ON identity_verification_provider_material_envelopes_v1;

DROP TABLE identity_verification_evidence_issue_bindings_v1;
DROP TABLE identity_verification_provider_material_envelopes_v1;
DROP FUNCTION require_identity_verification_material_envelope_audit_175();
DROP FUNCTION prevent_identity_verification_issuer_fact_truncate_175();
DROP FUNCTION prevent_identity_verification_issuer_fact_mutation_175();

ALTER TABLE identity_verification_evidence_reservations
    DROP CONSTRAINT identity_verification_evidence_reservation_issue_binding_175;
ALTER TABLE identity_verification_provider_uploads_v1
    DROP CONSTRAINT identity_verification_provider_upload_binding_175;
ALTER TABLE identity_verification_provider_settlements_v1
    DROP CONSTRAINT identity_verification_provider_settlement_enterprise_175,
    DROP COLUMN agent_relationship,
    DROP COLUMN agent_fingerprint,
    DROP COLUMN legal_person_fingerprint,
    DROP COLUMN organization_name;

CREATE OR REPLACE FUNCTION protect_identity_verification_case()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'identity verification cases cannot be deleted';
    END IF;
    IF ROW(NEW.id, NEW.tenant_scope_id, NEW.applicant_user_id, NEW.kind,
           NEW.subject_fingerprint, NEW.organization_name, NEW.legal_person_fingerprint,
           NEW.agent_fingerprint, NEW.agent_relationship, NEW.created_at, NEW.retention_until)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.tenant_scope_id, OLD.applicant_user_id, OLD.kind,
           OLD.subject_fingerprint, OLD.organization_name, OLD.legal_person_fingerprint,
           OLD.agent_fingerprint, OLD.agent_relationship, OLD.created_at, OLD.retention_until) OR
       NEW.revision <> OLD.revision + 1 OR NEW.state_changed_at < OLD.state_changed_at OR NOT (
           (OLD.status = 'draft' AND NEW.status IN ('submitted', 'withdrawn')) OR
           (OLD.status = 'submitted' AND NEW.status IN ('reviewing', 'withdrawn', 'expired')) OR
           (OLD.status = 'reviewing' AND NEW.status IN ('approved', 'rejected', 'expired'))
       ) THEN
        RAISE EXCEPTION 'invalid identity verification case transition';
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
