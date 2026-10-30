LOCK TABLE identity_verification_evidence_reservations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE audit_events IN SHARE ROW EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM identity_verification_evidence_reservations)
       OR EXISTS (
           SELECT 1 FROM audit_events
           WHERE resource_type = 'identity_verification_evidence_reservation'
              OR action LIKE 'identity_verification.evidence_reservation.%'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'cannot roll back identity verification evidence reservations while facts exist';
    END IF;
END;
$$;

DROP TRIGGER identity_verification_evidence_reservations_require_audit_075
    ON identity_verification_evidence_reservations;
DROP FUNCTION require_identity_verification_evidence_reservation_audit_075();

DROP TRIGGER identity_verification_evidence_reservations_no_truncate_075
    ON identity_verification_evidence_reservations;
DROP TRIGGER identity_verification_evidence_reservations_protected_075
    ON identity_verification_evidence_reservations;
DROP FUNCTION protect_identity_verification_evidence_reservation_075();

DROP TABLE identity_verification_evidence_reservations;
DROP INDEX auth_sessions_identity_evidence_binding_075_idx;
