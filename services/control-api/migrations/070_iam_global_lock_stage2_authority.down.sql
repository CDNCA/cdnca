LOCK TABLE iam_global_lock_protocol_claims IN ACCESS EXCLUSIVE MODE;
LOCK TABLE iam_global_lock_authority_grants IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM iam_global_lock_protocol_claims
        WHERE component = 'iam-stage2a'
    ) OR EXISTS (
        SELECT 1
        FROM iam_global_lock_authority_grants
        WHERE authority_procedure = 'iam_begin_authority_mutation_v1(text,uuid[])'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'iam_stage2_authority_facts_prevent_rollback';
    END IF;
END;
$$;

DROP FUNCTION iam_begin_authority_mutation_v1(text, uuid[]);
DROP FUNCTION iam_validate_authority_operation_v1(text);
