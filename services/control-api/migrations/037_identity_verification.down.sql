LOCK TABLE identity_verification_write_requests IN ACCESS EXCLUSIVE MODE;
LOCK TABLE identity_verification_cases IN ACCESS EXCLUSIVE MODE;
LOCK TABLE identity_verification_materials IN ACCESS EXCLUSIVE MODE;
LOCK TABLE identity_verification_state_events IN ACCESS EXCLUSIVE MODE;
LOCK TABLE identity_verification_submissions IN ACCESS EXCLUSIVE MODE;
LOCK TABLE identity_verification_review_assignments IN ACCESS EXCLUSIVE MODE;
LOCK TABLE identity_verification_reviews IN ACCESS EXCLUSIVE MODE;
LOCK TABLE identity_verified_persons IN ACCESS EXCLUSIVE MODE;
LOCK TABLE identity_verified_organizations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE audit_events IN SHARE ROW EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM identity_verification_write_requests)
       OR EXISTS (SELECT 1 FROM identity_verification_cases)
       OR EXISTS (SELECT 1 FROM identity_verification_materials)
       OR EXISTS (SELECT 1 FROM identity_verification_state_events)
       OR EXISTS (SELECT 1 FROM identity_verification_submissions)
       OR EXISTS (SELECT 1 FROM identity_verification_review_assignments)
       OR EXISTS (SELECT 1 FROM identity_verification_reviews)
       OR EXISTS (SELECT 1 FROM identity_verified_persons)
       OR EXISTS (SELECT 1 FROM identity_verified_organizations)
       OR EXISTS (
           SELECT 1 FROM audit_events
           WHERE resource_type = 'identity_verification_case'
              OR action LIKE 'identity_verification.%'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'cannot roll back identity verification while persistent facts exist';
    END IF;
END;
$$;

DROP TRIGGER audit_events_no_truncate ON audit_events;
DROP TRIGGER identity_verification_cases_no_truncate ON identity_verification_cases;
DROP FUNCTION prevent_identity_verification_case_truncate();

DROP TRIGGER identity_verified_organizations_validate_commit ON identity_verified_organizations;
DROP TRIGGER identity_verified_persons_validate_commit ON identity_verified_persons;
DROP TRIGGER identity_verification_reviews_validate_commit ON identity_verification_reviews;
DROP TRIGGER identity_verification_review_assignments_validate_commit ON identity_verification_review_assignments;
DROP TRIGGER identity_verification_submissions_validate_commit ON identity_verification_submissions;
DROP TRIGGER identity_verification_state_events_validate_commit ON identity_verification_state_events;
DROP FUNCTION validate_identity_verification_fact_commit();

DROP TRIGGER identity_verified_organizations_append_only ON identity_verified_organizations;
DROP TRIGGER identity_verified_persons_append_only ON identity_verified_persons;
DROP TRIGGER identity_verification_reviews_append_only ON identity_verification_reviews;
DROP TRIGGER identity_verification_review_assignments_append_only ON identity_verification_review_assignments;
DROP TRIGGER identity_verification_submissions_append_only ON identity_verification_submissions;
DROP TRIGGER identity_verification_state_events_append_only ON identity_verification_state_events;
DROP TRIGGER identity_verification_materials_append_only ON identity_verification_materials;
DROP FUNCTION prevent_identity_verification_fact_mutation();

DROP TRIGGER identity_verification_write_requests_no_truncate ON identity_verification_write_requests;
DROP TRIGGER identity_verification_write_requests_protected ON identity_verification_write_requests;
DROP FUNCTION protect_identity_verification_write_request();
DROP TRIGGER identity_verification_cases_protected ON identity_verification_cases;
DROP FUNCTION protect_identity_verification_case();
DROP TRIGGER identity_verified_organizations_validate_insert ON identity_verified_organizations;
DROP FUNCTION validate_identity_verified_organization_insert();
DROP TRIGGER identity_verified_persons_validate_insert ON identity_verified_persons;
DROP FUNCTION validate_identity_verified_person_insert();
DROP TRIGGER identity_verification_reviews_validate_insert ON identity_verification_reviews;
DROP FUNCTION validate_identity_verification_review_insert();
DROP TRIGGER identity_verification_review_assignments_validate_insert ON identity_verification_review_assignments;
DROP FUNCTION validate_identity_verification_assignment_insert();
DROP TRIGGER identity_verification_submissions_validate_insert ON identity_verification_submissions;
DROP FUNCTION validate_identity_verification_submission_insert();
DROP TRIGGER identity_verification_state_events_validate ON identity_verification_state_events;
DROP FUNCTION validate_identity_verification_state_event();
DROP TRIGGER identity_verification_materials_validate_insert ON identity_verification_materials;
DROP FUNCTION validate_identity_verification_material_insert();
DROP TRIGGER identity_verification_cases_validate_creation ON identity_verification_cases;
DROP FUNCTION validate_identity_verification_case_creation();
DROP TRIGGER identity_verification_cases_validate_insert ON identity_verification_cases;
DROP FUNCTION validate_identity_verification_case_insert();
DROP TRIGGER identity_verification_cases_tenant_scope ON identity_verification_cases;
DROP FUNCTION validate_identity_verification_tenant_scope();
DROP FUNCTION identity_verification_actor_has_permission(uuid, uuid, text);

DROP TABLE identity_verification_write_requests;
DROP TABLE identity_verified_organizations;
DROP TABLE identity_verified_persons;
DROP TABLE identity_verification_reviews;
DROP TABLE identity_verification_review_assignments;
DROP TABLE identity_verification_submissions;
DROP TABLE identity_verification_state_events;
DROP TABLE identity_verification_materials;
DROP TABLE identity_verification_cases;

DELETE FROM role_permissions
WHERE permission_name IN (
    'identity_verification.self.manage', 'identity_verification.read', 'identity_verification.review'
);
DELETE FROM permissions
WHERE name IN (
    'identity_verification.self.manage', 'identity_verification.read', 'identity_verification.review'
);
