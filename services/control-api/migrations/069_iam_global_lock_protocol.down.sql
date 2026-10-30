LOCK TABLE iam_global_lock_protocol_claims IN ACCESS EXCLUSIVE MODE;
LOCK TABLE iam_global_lock_authority_grants IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM iam_global_lock_protocol_claims) OR
       EXISTS (SELECT 1 FROM iam_global_lock_authority_grants) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'iam_global_lock_protocol_stage2_facts_prevent_rollback';
    END IF;
END;
$$;

DROP TRIGGER iam_global_lock_authority_grants_immutable_069
    ON iam_global_lock_authority_grants;
DROP TRIGGER iam_global_lock_protocol_claims_immutable_069
    ON iam_global_lock_protocol_claims;
DROP FUNCTION protect_iam_global_lock_protocol_fact_069();

DROP TABLE iam_global_lock_authority_grants;
DROP TABLE iam_global_lock_protocol_claims;

DROP FUNCTION iam_assert_scope_locks_v1(uuid[]);
DROP FUNCTION iam_scope_locks_v1(uuid[]);
DROP FUNCTION iam_global_lock_exclusive_v1();
DROP FUNCTION iam_global_lock_shared_v1();
