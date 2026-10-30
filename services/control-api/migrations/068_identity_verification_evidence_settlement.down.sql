LOCK TABLE identity_verification_evidence_settlements IN ACCESS EXCLUSIVE MODE;
LOCK TABLE identity_verification_cases IN ACCESS EXCLUSIVE MODE;
LOCK TABLE audit_events IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE custom_role_revisions, custom_rbac_permission_catalog, roles,
    role_permissions, permissions IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM identity_verification_evidence_settlements)
       OR EXISTS (
           SELECT 1 FROM identity_verification_cases
           WHERE evidence_settlement_required
       )
       OR EXISTS (
           SELECT 1 FROM audit_events
           WHERE resource_type = 'identity_verification_evidence_settlement'
              OR action LIKE 'identity_verification.evidence_settlement.%'
       )
       OR EXISTS (
           SELECT 1 FROM custom_role_revisions
           WHERE permissions @> ARRAY[
               'identity_verification.evidence_settlement.requeue'
           ]::text[]
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'cannot roll back identity verification evidence settlement while facts exist';
    END IF;
END;
$$;

DROP TRIGGER identity_verification_write_requests_validate_settlement_commit
    ON identity_verification_write_requests;
DROP TRIGGER identity_verification_evidence_settlements_validate_commit
    ON identity_verification_evidence_settlements;
DROP TRIGGER identity_verification_cases_validate_settlement_commit
    ON identity_verification_cases;
DROP FUNCTION validate_identity_verification_settlement_commit();

DROP TRIGGER identity_verification_submissions_require_settlement
    ON identity_verification_submissions;
DROP FUNCTION require_identity_verification_settlement_before_submission();
DROP TRIGGER identity_verification_cases_settlement_requirement
    ON identity_verification_cases;
DROP FUNCTION protect_identity_verification_case_settlement_requirement();

DROP TRIGGER identity_verification_evidence_settlements_no_truncate
    ON identity_verification_evidence_settlements;
DROP TRIGGER identity_verification_evidence_settlements_protected
    ON identity_verification_evidence_settlements;
DROP FUNCTION protect_identity_verification_evidence_settlement();
DROP TABLE identity_verification_evidence_settlements;

ALTER TABLE identity_verification_write_requests
    DROP CONSTRAINT identity_verification_write_requests_settlement_binding_key;
ALTER TABLE identity_verification_cases
    DROP CONSTRAINT identity_verification_cases_settlement_binding_key,
    DROP COLUMN evidence_settlement_required;

DELETE FROM custom_rbac_permission_catalog
WHERE permission_name = 'identity_verification.evidence_settlement.requeue';
DELETE FROM role_permissions
WHERE permission_name = 'identity_verification.evidence_settlement.requeue';
DELETE FROM permissions
WHERE name = 'identity_verification.evidence_settlement.requeue';
