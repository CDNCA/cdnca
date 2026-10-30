LOCK TABLE control_signer_checkpoint_audit,
           control_signer_checkpoint_manifests,
           control_signer_checkpoint_snapshots
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM control_signer_checkpoint_snapshots)
       OR EXISTS (SELECT 1 FROM control_signer_checkpoint_manifests)
       OR EXISTS (SELECT 1 FROM control_signer_checkpoint_audit) THEN
        RAISE EXCEPTION 'cannot roll back signer checkpoint LKG while 077 facts exist' USING ERRCODE = '55000';
    END IF;
END;
$$;

DROP TABLE control_signer_checkpoint_audit;
DROP TABLE control_signer_checkpoint_manifests;
DROP TABLE control_signer_checkpoint_snapshots;

DROP FUNCTION validate_control_signer_checkpoint_audit_077();
DROP FUNCTION validate_control_signer_checkpoint_manifest_077();
DROP FUNCTION assert_control_signer_checkpoint_complete_077();
DROP FUNCTION validate_control_signer_checkpoint_snapshot_077();
DROP FUNCTION protect_control_signer_checkpoint_fact_077();
