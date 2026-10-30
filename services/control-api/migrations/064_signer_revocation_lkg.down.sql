LOCK TABLE control_signer_revocation_audit,
           control_signer_revocation_events,
           control_signer_revocation_manifests,
           control_signer_trust_snapshots
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM control_signer_trust_snapshots)
       OR EXISTS (SELECT 1 FROM control_signer_revocation_manifests)
       OR EXISTS (SELECT 1 FROM control_signer_revocation_events)
       OR EXISTS (SELECT 1 FROM control_signer_revocation_audit) THEN
        RAISE EXCEPTION 'cannot roll back signer revocation LKG while 064 facts exist' USING ERRCODE = 'P0001';
    END IF;
END;
$$;

DROP TABLE control_signer_revocation_audit;
DROP TABLE control_signer_revocation_events;
DROP TABLE control_signer_revocation_manifests;
DROP TABLE control_signer_trust_snapshots;

DROP FUNCTION assert_control_signer_snapshot_complete();
DROP FUNCTION validate_control_signer_revocation_manifest();
DROP FUNCTION validate_control_signer_trust_snapshot();
DROP FUNCTION protect_control_signer_revocation_fact();
