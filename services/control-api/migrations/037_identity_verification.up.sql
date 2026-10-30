INSERT INTO permissions (name, description) VALUES
    ('identity_verification.self.manage', 'Create and manage the current user identity verification cases'),
    ('identity_verification.read', 'Read identity verification cases in the current tenant'),
    ('identity_verification.review', 'Review identity verification cases in the current tenant');

INSERT INTO role_permissions (role_id, permission_name)
SELECT roles.id, permissions.name
FROM roles
CROSS JOIN permissions
WHERE roles.system_role
  AND (
      (roles.name = 'tenant_owner' AND permissions.name IN (
          'identity_verification.self.manage', 'identity_verification.read', 'identity_verification.review'
      )) OR
      (roles.name = 'tenant_viewer' AND permissions.name = 'identity_verification.self.manage')
  )
ON CONFLICT DO NOTHING;

CREATE TABLE identity_verification_cases (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    applicant_user_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('personal_initial', 'personal_reverification', 'enterprise')),
    status text NOT NULL CHECK (status IN (
        'draft', 'submitted', 'reviewing', 'approved', 'rejected', 'withdrawn', 'expired'
    )),
    subject_fingerprint bytea NOT NULL CHECK (octet_length(subject_fingerprint) = 32),
    organization_name text,
    legal_person_fingerprint bytea,
    agent_fingerprint bytea,
    agent_relationship text,
    reviewer_user_id uuid,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    state_changed_at timestamptz NOT NULL,
    submitted_at timestamptz,
    expires_at timestamptz,
    terminal_at timestamptz,
    retention_until timestamptz NOT NULL,
    UNIQUE (tenant_scope_id, id),
    FOREIGN KEY (tenant_scope_id, applicant_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, reviewer_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (state_changed_at >= created_at),
    CHECK (retention_until > created_at),
    CHECK (reviewer_user_id IS NULL OR reviewer_user_id <> applicant_user_id),
    CHECK (
        (kind IN ('personal_initial', 'personal_reverification') AND
         organization_name IS NULL AND legal_person_fingerprint IS NULL AND
         agent_fingerprint IS NULL AND agent_relationship IS NULL) OR
        (kind = 'enterprise' AND organization_name IS NOT NULL AND
         legal_person_fingerprint IS NOT NULL AND agent_fingerprint IS NOT NULL AND
         agent_relationship IS NOT NULL AND
         organization_name = btrim(organization_name) AND char_length(organization_name) BETWEEN 2 AND 256 AND
         octet_length(legal_person_fingerprint) = 32 AND octet_length(agent_fingerprint) = 32 AND
         agent_relationship IN ('legal_person', 'employee', 'authorized_representative') AND
         (agent_relationship <> 'legal_person' OR agent_fingerprint = legal_person_fingerprint))
    ),
    CHECK (
        (status = 'draft' AND submitted_at IS NULL AND expires_at IS NULL AND
         reviewer_user_id IS NULL AND terminal_at IS NULL) OR
        (status = 'submitted' AND submitted_at IS NOT NULL AND expires_at IS NOT NULL AND
         expires_at > submitted_at AND
         reviewer_user_id IS NULL AND terminal_at IS NULL) OR
        (status = 'reviewing' AND submitted_at IS NOT NULL AND expires_at IS NOT NULL AND
         expires_at > submitted_at AND
         reviewer_user_id IS NOT NULL AND terminal_at IS NULL) OR
        (status IN ('approved', 'rejected') AND submitted_at IS NOT NULL AND expires_at IS NOT NULL AND
         expires_at > submitted_at AND reviewer_user_id IS NOT NULL AND terminal_at IS NOT NULL AND
         terminal_at >= state_changed_at) OR
        (status = 'withdrawn' AND reviewer_user_id IS NULL AND terminal_at IS NOT NULL AND
         terminal_at >= state_changed_at) OR
        (status = 'expired' AND submitted_at IS NOT NULL AND expires_at IS NOT NULL AND
         expires_at > submitted_at AND terminal_at IS NOT NULL AND terminal_at >= expires_at)
    )
);

CREATE INDEX identity_verification_cases_user_created_idx
    ON identity_verification_cases (tenant_scope_id, applicant_user_id, created_at DESC);
CREATE INDEX identity_verification_cases_expiry_idx
    ON identity_verification_cases (expires_at)
    WHERE status IN ('submitted', 'reviewing');
CREATE INDEX identity_verification_cases_reviewer_idx
    ON identity_verification_cases (tenant_scope_id, reviewer_user_id)
    WHERE reviewer_user_id IS NOT NULL;
CREATE UNIQUE INDEX identity_verification_one_active_personal_review_idx
    ON identity_verification_cases (tenant_scope_id, applicant_user_id)
    WHERE kind IN ('personal_initial', 'personal_reverification') AND status IN ('submitted', 'reviewing');
CREATE UNIQUE INDEX identity_verification_one_active_enterprise_review_idx
    ON identity_verification_cases (tenant_scope_id, subject_fingerprint)
    WHERE kind = 'enterprise' AND status IN ('submitted', 'reviewing');

CREATE TABLE identity_verification_materials (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    case_id uuid NOT NULL,
    ordinal smallint NOT NULL CHECK (ordinal BETWEEN 1 AND 16),
    material_kind text NOT NULL CHECK (material_kind IN (
        'identity_document', 'liveness_evidence', 'business_license',
        'legal_person_identity', 'agent_identity', 'authorization_letter', 'supplementary'
    )),
    envelope_provider text NOT NULL CHECK (
        octet_length(envelope_provider) BETWEEN 1 AND 64 AND
        envelope_provider ~ '^[a-z][a-z0-9._-]*$'
    ),
    envelope_key_id text NOT NULL CHECK (
        octet_length(envelope_key_id) BETWEEN 1 AND 256 AND
        envelope_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
    ),
    encrypted_envelope bytea NOT NULL CHECK (octet_length(encrypted_envelope) BETWEEN 16 AND 16384),
    envelope_sha256 bytea NOT NULL CHECK (octet_length(envelope_sha256) = 32),
    object_reference text NOT NULL CHECK (
        octet_length(object_reference) BETWEEN 1 AND 1024 AND
        object_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:/=@+-]*$'
    ),
    object_sha256 bytea NOT NULL CHECK (octet_length(object_sha256) = 32),
    mime_type text NOT NULL CHECK (mime_type IN ('image/jpeg', 'image/png', 'application/pdf')),
    size_bytes bigint NOT NULL CHECK (size_bytes BETWEEN 1 AND 20971520),
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_scope_id, case_id, ordinal),
    FOREIGN KEY (tenant_scope_id, case_id)
        REFERENCES identity_verification_cases(tenant_scope_id, id) ON DELETE RESTRICT
);

CREATE TABLE identity_verification_state_events (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    case_id uuid NOT NULL,
    case_revision bigint NOT NULL CHECK (case_revision > 0),
    from_status text,
    to_status text NOT NULL CHECK (to_status IN (
        'draft', 'submitted', 'reviewing', 'approved', 'rejected', 'withdrawn', 'expired'
    )),
    actor_user_id uuid NOT NULL,
    reason_code text NOT NULL CHECK (
        octet_length(reason_code) BETWEEN 1 AND 64 AND reason_code ~ '^[a-z][a-z0-9._-]*$'
    ),
    occurred_at timestamptz NOT NULL,
    UNIQUE (tenant_scope_id, case_id, case_revision),
    FOREIGN KEY (tenant_scope_id, case_id)
        REFERENCES identity_verification_cases(tenant_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (
        (case_revision = 1 AND from_status IS NULL AND to_status = 'draft') OR
        (case_revision > 1 AND from_status IN (
            'draft', 'submitted', 'reviewing', 'approved', 'rejected', 'withdrawn', 'expired'
        ))
    )
);

CREATE INDEX identity_verification_state_events_actor_idx
    ON identity_verification_state_events (tenant_scope_id, actor_user_id, occurred_at DESC);

CREATE TABLE identity_verification_submissions (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    case_id uuid NOT NULL,
    applicant_user_id uuid NOT NULL,
    case_revision bigint NOT NULL CHECK (case_revision > 1),
    submission_digest bytea NOT NULL CHECK (octet_length(submission_digest) = 32),
    submitted_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > submitted_at),
    UNIQUE (tenant_scope_id, case_id),
    FOREIGN KEY (tenant_scope_id, case_id)
        REFERENCES identity_verification_cases(tenant_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, applicant_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

CREATE INDEX identity_verification_submissions_applicant_idx
    ON identity_verification_submissions (tenant_scope_id, applicant_user_id);

CREATE TABLE identity_verification_review_assignments (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    case_id uuid NOT NULL,
    reviewer_user_id uuid NOT NULL,
    case_revision bigint NOT NULL CHECK (case_revision > 1),
    assigned_at timestamptz NOT NULL,
    UNIQUE (tenant_scope_id, case_id),
    FOREIGN KEY (tenant_scope_id, case_id)
        REFERENCES identity_verification_cases(tenant_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, reviewer_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

CREATE INDEX identity_verification_review_assignments_reviewer_idx
    ON identity_verification_review_assignments (tenant_scope_id, reviewer_user_id);

CREATE TABLE identity_verification_reviews (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    case_id uuid NOT NULL,
    reviewer_user_id uuid NOT NULL,
    decision text NOT NULL CHECK (decision IN ('approved', 'rejected')),
    reason_code text NOT NULL CHECK (
        reason_code IN (
            'evidence_verified', 'identity_mismatch', 'evidence_incomplete', 'evidence_unreadable',
            'organization_mismatch', 'authorization_invalid', 'suspected_fraud'
        )
    ),
    expected_revision bigint NOT NULL CHECK (expected_revision > 1),
    resulting_revision bigint NOT NULL CHECK (resulting_revision = expected_revision + 1),
    reviewed_at timestamptz NOT NULL,
    UNIQUE (tenant_scope_id, case_id),
    FOREIGN KEY (tenant_scope_id, case_id)
        REFERENCES identity_verification_cases(tenant_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, reviewer_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (
        (decision = 'approved' AND reason_code = 'evidence_verified') OR
        (decision = 'rejected' AND reason_code <> 'evidence_verified')
    )
);

CREATE INDEX identity_verification_reviews_reviewer_idx
    ON identity_verification_reviews (tenant_scope_id, reviewer_user_id, reviewed_at DESC);

CREATE TABLE identity_verified_persons (
    tenant_scope_id uuid NOT NULL,
    applicant_user_id uuid NOT NULL,
    identity_fingerprint bytea NOT NULL CHECK (octet_length(identity_fingerprint) = 32),
    initial_case_id uuid NOT NULL,
    approved_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, applicant_user_id),
    FOREIGN KEY (tenant_scope_id, applicant_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, initial_case_id)
        REFERENCES identity_verification_cases(tenant_scope_id, id) ON DELETE RESTRICT
);

CREATE INDEX identity_verified_persons_initial_case_idx
    ON identity_verified_persons (tenant_scope_id, initial_case_id);

CREATE TABLE identity_verified_organizations (
    tenant_scope_id uuid NOT NULL,
    subject_fingerprint bytea NOT NULL CHECK (octet_length(subject_fingerprint) = 32),
    organization_name text NOT NULL CHECK (
        organization_name = btrim(organization_name) AND char_length(organization_name) BETWEEN 2 AND 256
    ),
    legal_person_fingerprint bytea NOT NULL CHECK (octet_length(legal_person_fingerprint) = 32),
    agent_fingerprint bytea NOT NULL CHECK (octet_length(agent_fingerprint) = 32),
    agent_relationship text NOT NULL CHECK (
        agent_relationship IN ('legal_person', 'employee', 'authorized_representative')
    ),
    approved_case_id uuid NOT NULL,
    approved_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, subject_fingerprint),
    FOREIGN KEY (tenant_scope_id, approved_case_id)
        REFERENCES identity_verification_cases(tenant_scope_id, id) ON DELETE RESTRICT
);

CREATE INDEX identity_verified_organizations_case_idx
    ON identity_verified_organizations (tenant_scope_id, approved_case_id);

CREATE TABLE identity_verification_write_requests (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    actor_user_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation IN (
        'identity_verification.create_draft', 'identity_verification.submit',
        'identity_verification.start_review', 'identity_verification.review',
        'identity_verification.withdraw', 'identity_verification.expire'
    )),
    idempotency_key text NOT NULL CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128 AND
        idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (tenant_scope_id, actor_user_id, operation, idempotency_key),
    FOREIGN KEY (tenant_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK ((completed_at IS NULL AND response_body IS NULL) OR
           (completed_at IS NOT NULL AND response_body IS NOT NULL AND completed_at >= created_at))
);

CREATE INDEX identity_verification_write_requests_created_idx
    ON identity_verification_write_requests (tenant_scope_id, created_at DESC);

CREATE FUNCTION identity_verification_actor_has_permission(
    scope_id uuid,
    user_id uuid,
    required_permission text
)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM memberships membership
        JOIN users actor_user
          ON actor_user.id = membership.user_id AND actor_user.status = 'active'
        JOIN role_assignments assignment
          ON assignment.scope_id = membership.scope_id
         AND assignment.user_id = membership.user_id
        JOIN role_permissions role_permission ON role_permission.role_id = assignment.role_id
        WHERE membership.scope_id = $1
          AND membership.user_id = $2
          AND membership.status = 'active'
          AND role_permission.permission_name = $3
    );
$$;

CREATE FUNCTION validate_identity_verification_tenant_scope()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM access_scopes
        WHERE id = NEW.tenant_scope_id AND kind = 'tenant' AND tenant_id IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'identity verification requires a tenant scope';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER identity_verification_cases_tenant_scope
BEFORE INSERT OR UPDATE ON identity_verification_cases
FOR EACH ROW EXECUTE FUNCTION validate_identity_verification_tenant_scope();

CREATE FUNCTION validate_identity_verification_case_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status <> 'draft' OR NEW.revision <> 1 OR
       NEW.state_changed_at <> NEW.created_at OR
       NEW.reviewer_user_id IS NOT NULL OR NEW.submitted_at IS NOT NULL OR
       NEW.expires_at IS NOT NULL OR NEW.terminal_at IS NOT NULL OR
       NOT isfinite(NEW.created_at) OR NOT isfinite(NEW.retention_until) THEN
        RAISE EXCEPTION 'identity verification cases must start as a valid revision 1 draft';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER identity_verification_cases_validate_insert
BEFORE INSERT ON identity_verification_cases
FOR EACH ROW EXECUTE FUNCTION validate_identity_verification_case_insert();

CREATE FUNCTION validate_identity_verification_case_creation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    material_count integer;
    first_ordinal smallint;
    last_ordinal smallint;
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM identity_verification_state_events event
        WHERE event.tenant_scope_id = NEW.tenant_scope_id
          AND event.case_id = NEW.id
          AND event.case_revision = 1
          AND event.from_status IS NULL
          AND event.to_status = 'draft'
          AND event.actor_user_id = NEW.applicant_user_id
          AND event.reason_code = 'case.created'
          AND event.occurred_at = NEW.created_at
    ) THEN
        RAISE EXCEPTION 'identity verification draft requires an exact revision 1 creation event';
    END IF;

    SELECT count(*), min(ordinal), max(ordinal)
      INTO material_count, first_ordinal, last_ordinal
    FROM identity_verification_materials material
    WHERE material.tenant_scope_id = NEW.tenant_scope_id AND material.case_id = NEW.id;

    IF material_count < 2 OR material_count > 16 OR
       first_ordinal <> 1 OR last_ordinal <> material_count THEN
        RAISE EXCEPTION 'identity verification draft requires a contiguous compliant material set';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM identity_verification_materials material
        WHERE material.tenant_scope_id = NEW.tenant_scope_id
          AND material.case_id = NEW.id
          AND material.material_kind <> 'supplementary'
        GROUP BY material.material_kind
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION 'identity verification draft contains duplicate required materials';
    END IF;
    IF NEW.kind IN ('personal_initial', 'personal_reverification') AND (
        EXISTS (
            SELECT 1 FROM identity_verification_materials material
            WHERE material.tenant_scope_id = NEW.tenant_scope_id AND material.case_id = NEW.id
              AND material.material_kind NOT IN ('identity_document', 'liveness_evidence', 'supplementary')
        ) OR NOT EXISTS (
            SELECT 1 FROM identity_verification_materials material
            WHERE material.tenant_scope_id = NEW.tenant_scope_id AND material.case_id = NEW.id
              AND material.material_kind = 'identity_document'
        ) OR NOT EXISTS (
            SELECT 1 FROM identity_verification_materials material
            WHERE material.tenant_scope_id = NEW.tenant_scope_id AND material.case_id = NEW.id
              AND material.material_kind = 'liveness_evidence'
        )
    ) THEN
        RAISE EXCEPTION 'personal identity verification draft has an invalid material set';
    END IF;
    IF NEW.kind = 'enterprise' AND (
        EXISTS (
            SELECT 1 FROM identity_verification_materials material
            WHERE material.tenant_scope_id = NEW.tenant_scope_id AND material.case_id = NEW.id
              AND material.material_kind NOT IN (
                  'business_license', 'legal_person_identity', 'agent_identity',
                  'authorization_letter', 'supplementary'
              )
        ) OR NOT EXISTS (
            SELECT 1 FROM identity_verification_materials material
            WHERE material.tenant_scope_id = NEW.tenant_scope_id AND material.case_id = NEW.id
              AND material.material_kind = 'business_license'
        ) OR NOT EXISTS (
            SELECT 1 FROM identity_verification_materials material
            WHERE material.tenant_scope_id = NEW.tenant_scope_id AND material.case_id = NEW.id
              AND material.material_kind = 'legal_person_identity'
        ) OR NOT EXISTS (
            SELECT 1 FROM identity_verification_materials material
            WHERE material.tenant_scope_id = NEW.tenant_scope_id AND material.case_id = NEW.id
              AND material.material_kind = 'agent_identity'
        ) OR (NEW.agent_relationship <> 'legal_person' AND NOT EXISTS (
            SELECT 1 FROM identity_verification_materials material
            WHERE material.tenant_scope_id = NEW.tenant_scope_id AND material.case_id = NEW.id
              AND material.material_kind = 'authorization_letter'
        ))
    ) THEN
        RAISE EXCEPTION 'enterprise identity verification draft has an invalid material set';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER identity_verification_cases_validate_creation
AFTER INSERT ON identity_verification_cases
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_identity_verification_case_creation();

CREATE FUNCTION validate_identity_verification_material_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM identity_verification_cases verification_case
        WHERE verification_case.tenant_scope_id = NEW.tenant_scope_id
          AND verification_case.id = NEW.case_id AND verification_case.status = 'draft'
          AND verification_case.revision = 1 AND verification_case.created_at = NEW.created_at
    ) OR EXISTS (
        SELECT 1 FROM identity_verification_state_events event
        WHERE event.tenant_scope_id = NEW.tenant_scope_id AND event.case_id = NEW.case_id
    ) THEN
        RAISE EXCEPTION 'identity verification materials must be fixed at case creation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER identity_verification_materials_validate_insert
BEFORE INSERT ON identity_verification_materials
FOR EACH ROW EXECUTE FUNCTION validate_identity_verification_material_insert();

CREATE FUNCTION validate_identity_verification_state_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_case identity_verification_cases%ROWTYPE;
BEGIN
    SELECT * INTO current_case
    FROM identity_verification_cases
    WHERE tenant_scope_id = NEW.tenant_scope_id AND id = NEW.case_id;
    IF NOT FOUND OR current_case.applicant_user_id IS NULL THEN
        RAISE EXCEPTION 'identity verification state event case does not exist';
    END IF;
    IF NEW.case_revision = 1 THEN
        IF current_case.revision <> 1 OR current_case.status <> 'draft' OR
           NEW.from_status IS NOT NULL OR NEW.to_status <> 'draft' OR
           NEW.actor_user_id <> current_case.applicant_user_id OR
           NEW.reason_code <> 'case.created' OR NEW.occurred_at <> current_case.created_at OR
           NOT identity_verification_actor_has_permission(
               NEW.tenant_scope_id, NEW.actor_user_id, 'identity_verification.self.manage'
           ) THEN
            RAISE EXCEPTION 'invalid identity verification creation event';
        END IF;
    ELSIF current_case.revision <> NEW.case_revision - 1 OR current_case.status <> NEW.from_status THEN
        RAISE EXCEPTION 'identity verification state event is not current';
    ELSIF NEW.occurred_at < current_case.state_changed_at OR
          NEW.reason_code <> (CASE NEW.to_status
              WHEN 'submitted' THEN 'case.submitted'
              WHEN 'reviewing' THEN 'review.started'
              WHEN 'approved' THEN 'review.decided'
              WHEN 'rejected' THEN 'review.decided'
              WHEN 'withdrawn' THEN 'case.withdrawn'
              WHEN 'expired' THEN 'case.expired'
          END) THEN
        RAISE EXCEPTION 'invalid identity verification state event reason or time';
    ELSIF NEW.to_status IN ('submitted', 'withdrawn', 'expired') AND
          (NEW.actor_user_id <> current_case.applicant_user_id OR
           NOT identity_verification_actor_has_permission(
               NEW.tenant_scope_id, NEW.actor_user_id, 'identity_verification.self.manage'
           )) THEN
        RAISE EXCEPTION 'identity verification applicant transition actor mismatch';
    ELSIF NEW.to_status = 'reviewing' AND (
        NEW.actor_user_id = current_case.applicant_user_id OR NOT EXISTS (
            SELECT 1 FROM identity_verification_review_assignments assignment
            WHERE assignment.tenant_scope_id = NEW.tenant_scope_id
              AND assignment.case_id = NEW.case_id
              AND assignment.reviewer_user_id = NEW.actor_user_id
              AND assignment.case_revision = NEW.case_revision
        ) OR NOT identity_verification_actor_has_permission(
            NEW.tenant_scope_id, NEW.actor_user_id, 'identity_verification.review'
        )
    ) THEN
        RAISE EXCEPTION 'identity verification review assignment actor mismatch';
    ELSIF NEW.to_status IN ('approved', 'rejected') AND (
          NEW.actor_user_id IS DISTINCT FROM current_case.reviewer_user_id OR
          NOT identity_verification_actor_has_permission(
              NEW.tenant_scope_id, NEW.actor_user_id, 'identity_verification.review'
          )) THEN
        RAISE EXCEPTION 'identity verification decision actor mismatch';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER identity_verification_state_events_validate
BEFORE INSERT ON identity_verification_state_events
FOR EACH ROW EXECUTE FUNCTION validate_identity_verification_state_event();

CREATE FUNCTION validate_identity_verification_submission_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM identity_verification_cases verification_case
        WHERE verification_case.tenant_scope_id = NEW.tenant_scope_id
          AND verification_case.id = NEW.case_id AND verification_case.status = 'draft'
          AND verification_case.revision + 1 = NEW.case_revision
          AND verification_case.applicant_user_id = NEW.applicant_user_id
          AND NEW.submitted_at >= verification_case.state_changed_at
          AND identity_verification_actor_has_permission(
              NEW.tenant_scope_id, NEW.applicant_user_id, 'identity_verification.self.manage'
          )
    ) THEN
        RAISE EXCEPTION 'identity verification submission does not match current draft';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER identity_verification_submissions_validate_insert
BEFORE INSERT ON identity_verification_submissions
FOR EACH ROW EXECUTE FUNCTION validate_identity_verification_submission_insert();

CREATE FUNCTION validate_identity_verification_assignment_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM identity_verification_cases verification_case
        WHERE verification_case.tenant_scope_id = NEW.tenant_scope_id
          AND verification_case.id = NEW.case_id AND verification_case.status = 'submitted'
          AND verification_case.revision + 1 = NEW.case_revision
          AND verification_case.applicant_user_id <> NEW.reviewer_user_id
          AND NEW.assigned_at >= verification_case.state_changed_at
          AND EXISTS (
              SELECT 1 FROM memberships reviewer_membership
              JOIN users reviewer_user
                ON reviewer_user.id = reviewer_membership.user_id AND reviewer_user.status = 'active'
              JOIN role_assignments assignment
                ON assignment.scope_id = reviewer_membership.scope_id
               AND assignment.user_id = reviewer_membership.user_id
              JOIN role_permissions role_permission ON role_permission.role_id = assignment.role_id
              WHERE reviewer_membership.scope_id = NEW.tenant_scope_id
                AND reviewer_membership.user_id = NEW.reviewer_user_id
                AND reviewer_membership.status = 'active'
                AND role_permission.permission_name = 'identity_verification.review'
          )
    ) THEN
        RAISE EXCEPTION 'identity verification assignment does not match current submission';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER identity_verification_review_assignments_validate_insert
BEFORE INSERT ON identity_verification_review_assignments
FOR EACH ROW EXECUTE FUNCTION validate_identity_verification_assignment_insert();

CREATE FUNCTION validate_identity_verification_review_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM identity_verification_cases verification_case
        JOIN identity_verification_review_assignments assignment
          ON assignment.tenant_scope_id = verification_case.tenant_scope_id
         AND assignment.case_id = verification_case.id
         AND assignment.reviewer_user_id = NEW.reviewer_user_id
         AND assignment.case_revision = verification_case.revision
        WHERE verification_case.tenant_scope_id = NEW.tenant_scope_id
          AND verification_case.id = NEW.case_id AND verification_case.status = 'reviewing'
          AND verification_case.reviewer_user_id = NEW.reviewer_user_id
          AND verification_case.revision = NEW.expected_revision
          AND NEW.resulting_revision = verification_case.revision + 1
          AND NEW.reviewed_at >= verification_case.state_changed_at
          AND identity_verification_actor_has_permission(
              NEW.tenant_scope_id, NEW.reviewer_user_id, 'identity_verification.review'
          )
    ) THEN
        RAISE EXCEPTION 'identity verification review does not match current assignment';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER identity_verification_reviews_validate_insert
BEFORE INSERT ON identity_verification_reviews
FOR EACH ROW EXECUTE FUNCTION validate_identity_verification_review_insert();

CREATE FUNCTION validate_identity_verified_person_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM identity_verification_cases verification_case
        WHERE verification_case.tenant_scope_id = NEW.tenant_scope_id
          AND verification_case.id = NEW.initial_case_id
          AND verification_case.applicant_user_id = NEW.applicant_user_id
          AND verification_case.kind = 'personal_initial' AND verification_case.status = 'reviewing'
          AND verification_case.subject_fingerprint = NEW.identity_fingerprint
          AND NEW.approved_at >= verification_case.state_changed_at
    ) THEN
        RAISE EXCEPTION 'verified person does not match a reviewing initial identity case';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER identity_verified_persons_validate_insert
BEFORE INSERT ON identity_verified_persons
FOR EACH ROW EXECUTE FUNCTION validate_identity_verified_person_insert();

CREATE FUNCTION validate_identity_verified_organization_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM identity_verification_cases verification_case
        WHERE verification_case.tenant_scope_id = NEW.tenant_scope_id
          AND verification_case.id = NEW.approved_case_id
          AND verification_case.kind = 'enterprise' AND verification_case.status = 'reviewing'
          AND ROW(verification_case.subject_fingerprint, verification_case.organization_name,
                  verification_case.legal_person_fingerprint, verification_case.agent_fingerprint,
                  verification_case.agent_relationship)
              IS NOT DISTINCT FROM
              ROW(NEW.subject_fingerprint, NEW.organization_name, NEW.legal_person_fingerprint,
                  NEW.agent_fingerprint, NEW.agent_relationship)
          AND NEW.approved_at >= verification_case.state_changed_at
    ) THEN
        RAISE EXCEPTION 'verified organization does not match a reviewing enterprise case';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER identity_verified_organizations_validate_insert
BEFORE INSERT ON identity_verified_organizations
FOR EACH ROW EXECUTE FUNCTION validate_identity_verified_organization_insert();

CREATE FUNCTION validate_identity_verification_fact_commit()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_TABLE_NAME = 'identity_verification_state_events' THEN
        IF (NEW.to_status IN ('draft', 'submitted', 'withdrawn', 'expired') AND
            NOT identity_verification_actor_has_permission(
                NEW.tenant_scope_id, NEW.actor_user_id, 'identity_verification.self.manage'
            )) OR
           (NEW.to_status IN ('reviewing', 'approved', 'rejected') AND
            NOT identity_verification_actor_has_permission(
                NEW.tenant_scope_id, NEW.actor_user_id, 'identity_verification.review'
            )) OR NOT EXISTS (
                SELECT 1 FROM identity_verification_cases verification_case
                WHERE verification_case.tenant_scope_id = NEW.tenant_scope_id
                  AND verification_case.id = NEW.case_id
                  AND verification_case.revision >= NEW.case_revision
            ) OR (NEW.case_revision > 1 AND NOT EXISTS (
                SELECT 1 FROM identity_verification_state_events previous_event
                WHERE previous_event.tenant_scope_id = NEW.tenant_scope_id
                  AND previous_event.case_id = NEW.case_id
                  AND previous_event.case_revision = NEW.case_revision - 1
                  AND previous_event.to_status = NEW.from_status
                  AND previous_event.occurred_at <= NEW.occurred_at
            )) OR NOT (
                EXISTS (
                    SELECT 1 FROM identity_verification_cases verification_case
                    WHERE verification_case.tenant_scope_id = NEW.tenant_scope_id
                      AND verification_case.id = NEW.case_id
                      AND verification_case.revision = NEW.case_revision
                      AND verification_case.status = NEW.to_status
                      AND verification_case.state_changed_at = NEW.occurred_at
                ) OR EXISTS (
                    SELECT 1 FROM identity_verification_cases verification_case
                    JOIN identity_verification_state_events next_event
                      ON next_event.tenant_scope_id = verification_case.tenant_scope_id
                     AND next_event.case_id = verification_case.id
                     AND next_event.case_revision = NEW.case_revision + 1
                     AND next_event.from_status = NEW.to_status
                     AND next_event.occurred_at >= NEW.occurred_at
                    WHERE verification_case.tenant_scope_id = NEW.tenant_scope_id
                      AND verification_case.id = NEW.case_id
                      AND verification_case.revision > NEW.case_revision
                )
            ) THEN
                RAISE EXCEPTION 'identity verification state event was not applied to the case projection';
        END IF;
    ELSIF TG_TABLE_NAME = 'identity_verification_submissions' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM identity_verification_cases verification_case
            JOIN identity_verification_state_events event
              ON event.tenant_scope_id = verification_case.tenant_scope_id
             AND event.case_id = verification_case.id
             AND event.case_revision = NEW.case_revision
             AND event.from_status = 'draft' AND event.to_status = 'submitted'
             AND event.actor_user_id = NEW.applicant_user_id
             AND event.occurred_at = NEW.submitted_at
            WHERE verification_case.tenant_scope_id = NEW.tenant_scope_id
              AND verification_case.id = NEW.case_id
              AND verification_case.applicant_user_id = NEW.applicant_user_id
              AND verification_case.revision >= NEW.case_revision
              AND verification_case.submitted_at = NEW.submitted_at
              AND verification_case.expires_at = NEW.expires_at
        ) THEN
            RAISE EXCEPTION 'identity verification submission was not applied to the case projection';
        END IF;
    ELSIF TG_TABLE_NAME = 'identity_verification_review_assignments' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM identity_verification_cases verification_case
            JOIN identity_verification_state_events event
              ON event.tenant_scope_id = verification_case.tenant_scope_id
             AND event.case_id = verification_case.id
             AND event.case_revision = NEW.case_revision
             AND event.from_status = 'submitted' AND event.to_status = 'reviewing'
             AND event.actor_user_id = NEW.reviewer_user_id
             AND event.occurred_at = NEW.assigned_at
            WHERE verification_case.tenant_scope_id = NEW.tenant_scope_id
              AND verification_case.id = NEW.case_id
              AND verification_case.reviewer_user_id = NEW.reviewer_user_id
              AND verification_case.revision >= NEW.case_revision
              AND identity_verification_actor_has_permission(
                  NEW.tenant_scope_id, NEW.reviewer_user_id, 'identity_verification.review'
              )
        ) THEN
            RAISE EXCEPTION 'identity verification assignment was not applied to the case projection';
        END IF;
    ELSIF TG_TABLE_NAME = 'identity_verification_reviews' THEN
        IF NOT identity_verification_actor_has_permission(
            NEW.tenant_scope_id, NEW.reviewer_user_id, 'identity_verification.review'
        ) OR NOT EXISTS (
            SELECT 1
            FROM identity_verification_cases verification_case
            JOIN identity_verification_state_events event
              ON event.tenant_scope_id = verification_case.tenant_scope_id
             AND event.case_id = verification_case.id
             AND event.case_revision = NEW.resulting_revision
             AND event.from_status = 'reviewing' AND event.to_status = NEW.decision
             AND event.actor_user_id = NEW.reviewer_user_id
             AND event.occurred_at = NEW.reviewed_at
            WHERE verification_case.tenant_scope_id = NEW.tenant_scope_id
              AND verification_case.id = NEW.case_id
              AND verification_case.reviewer_user_id = NEW.reviewer_user_id
              AND verification_case.status = NEW.decision
              AND verification_case.revision = NEW.resulting_revision
              AND verification_case.state_changed_at = NEW.reviewed_at
              AND verification_case.terminal_at = NEW.reviewed_at
        ) THEN
            RAISE EXCEPTION 'identity verification review was not applied to the case projection';
        END IF;
    ELSIF TG_TABLE_NAME = 'identity_verified_persons' THEN
        IF NOT EXISTS (
            SELECT 1 FROM identity_verification_cases verification_case
            WHERE verification_case.tenant_scope_id = NEW.tenant_scope_id
              AND verification_case.id = NEW.initial_case_id
              AND verification_case.applicant_user_id = NEW.applicant_user_id
              AND verification_case.kind = 'personal_initial'
              AND verification_case.status = 'approved'
              AND verification_case.subject_fingerprint = NEW.identity_fingerprint
              AND verification_case.state_changed_at = NEW.approved_at
              AND verification_case.terminal_at = NEW.approved_at
        ) THEN
            RAISE EXCEPTION 'verified person was not applied to an approved initial identity case';
        END IF;
    ELSIF TG_TABLE_NAME = 'identity_verified_organizations' THEN
        IF NOT EXISTS (
            SELECT 1 FROM identity_verification_cases verification_case
            WHERE verification_case.tenant_scope_id = NEW.tenant_scope_id
              AND verification_case.id = NEW.approved_case_id
              AND verification_case.kind = 'enterprise'
              AND verification_case.status = 'approved'
              AND verification_case.state_changed_at = NEW.approved_at
              AND verification_case.terminal_at = NEW.approved_at
              AND ROW(verification_case.subject_fingerprint, verification_case.organization_name,
                      verification_case.legal_person_fingerprint, verification_case.agent_fingerprint,
                      verification_case.agent_relationship)
                  IS NOT DISTINCT FROM
                  ROW(NEW.subject_fingerprint, NEW.organization_name, NEW.legal_person_fingerprint,
                      NEW.agent_fingerprint, NEW.agent_relationship)
        ) THEN
            RAISE EXCEPTION 'verified organization was not applied to an approved enterprise case';
        END IF;
    ELSE
        RAISE EXCEPTION 'unsupported identity verification fact table';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER identity_verification_state_events_validate_commit
AFTER INSERT ON identity_verification_state_events
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_identity_verification_fact_commit();
CREATE CONSTRAINT TRIGGER identity_verification_submissions_validate_commit
AFTER INSERT ON identity_verification_submissions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_identity_verification_fact_commit();
CREATE CONSTRAINT TRIGGER identity_verification_review_assignments_validate_commit
AFTER INSERT ON identity_verification_review_assignments
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_identity_verification_fact_commit();
CREATE CONSTRAINT TRIGGER identity_verification_reviews_validate_commit
AFTER INSERT ON identity_verification_reviews
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_identity_verification_fact_commit();
CREATE CONSTRAINT TRIGGER identity_verified_persons_validate_commit
AFTER INSERT ON identity_verified_persons
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_identity_verification_fact_commit();
CREATE CONSTRAINT TRIGGER identity_verified_organizations_validate_commit
AFTER INSERT ON identity_verified_organizations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_identity_verification_fact_commit();

CREATE FUNCTION protect_identity_verification_case()
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

CREATE TRIGGER identity_verification_cases_protected
BEFORE UPDATE OR DELETE ON identity_verification_cases
FOR EACH ROW EXECUTE FUNCTION protect_identity_verification_case();

CREATE FUNCTION protect_identity_verification_write_request()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.completed_at IS NOT NULL OR NEW.response_body IS NOT NULL THEN
            RAISE EXCEPTION 'identity verification write requests must be inserted unfinished';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND
       ROW(NEW.id, NEW.tenant_scope_id, NEW.actor_user_id, NEW.operation,
           NEW.idempotency_key, NEW.request_digest, NEW.created_at)
       IS NOT DISTINCT FROM
       ROW(OLD.id, OLD.tenant_scope_id, OLD.actor_user_id, OLD.operation,
           OLD.idempotency_key, OLD.request_digest, OLD.created_at) AND
       OLD.completed_at IS NULL AND OLD.response_body IS NULL AND
       NEW.completed_at IS NOT NULL AND NEW.response_body IS NOT NULL THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'identity verification write requests cannot be truncated';
    ELSE
        RAISE EXCEPTION 'invalid identity verification write request transition';
    END IF;
END;
$$;

CREATE TRIGGER identity_verification_write_requests_protected
BEFORE INSERT OR UPDATE OR DELETE ON identity_verification_write_requests
FOR EACH ROW EXECUTE FUNCTION protect_identity_verification_write_request();
CREATE TRIGGER identity_verification_write_requests_no_truncate
BEFORE TRUNCATE ON identity_verification_write_requests
FOR EACH STATEMENT EXECUTE FUNCTION protect_identity_verification_write_request();

CREATE FUNCTION prevent_identity_verification_fact_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'identity verification facts are append-only';
END;
$$;

CREATE TRIGGER identity_verification_materials_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON identity_verification_materials
FOR EACH STATEMENT EXECUTE FUNCTION prevent_identity_verification_fact_mutation();
CREATE TRIGGER identity_verification_state_events_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON identity_verification_state_events
FOR EACH STATEMENT EXECUTE FUNCTION prevent_identity_verification_fact_mutation();
CREATE TRIGGER identity_verification_submissions_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON identity_verification_submissions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_identity_verification_fact_mutation();
CREATE TRIGGER identity_verification_review_assignments_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON identity_verification_review_assignments
FOR EACH STATEMENT EXECUTE FUNCTION prevent_identity_verification_fact_mutation();
CREATE TRIGGER identity_verification_reviews_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON identity_verification_reviews
FOR EACH STATEMENT EXECUTE FUNCTION prevent_identity_verification_fact_mutation();
CREATE TRIGGER identity_verified_persons_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON identity_verified_persons
FOR EACH STATEMENT EXECUTE FUNCTION prevent_identity_verification_fact_mutation();
CREATE TRIGGER identity_verified_organizations_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON identity_verified_organizations
FOR EACH STATEMENT EXECUTE FUNCTION prevent_identity_verification_fact_mutation();

CREATE FUNCTION prevent_identity_verification_case_truncate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'identity verification cases cannot be truncated';
END;
$$;

CREATE TRIGGER identity_verification_cases_no_truncate
BEFORE TRUNCATE ON identity_verification_cases
FOR EACH STATEMENT EXECUTE FUNCTION prevent_identity_verification_case_truncate();

CREATE TRIGGER audit_events_no_truncate
BEFORE TRUNCATE ON audit_events
FOR EACH STATEMENT EXECUTE FUNCTION prevent_audit_event_mutation();
