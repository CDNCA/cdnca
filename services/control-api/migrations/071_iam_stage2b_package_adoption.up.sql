CREATE FUNCTION iam_validate_stage2b_authority_operation_v1(operation text)
RETURNS void
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF operation IS NULL OR NOT operation = ANY (ARRAY[
        'identity.account_recovery.request',
        'identity.account_recovery.reset',
        'mfa.enrollment.begin',
        'mfa.enrollment.activate',
        'mfa.step_up.issue',
        'mfa.step_up.consume',
        'mfa.disable',
        'mfa.reset',
        'identity.impersonation.create',
        'identity.impersonation.exchange',
        'identity.impersonation.revoke'
    ]::text[]) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P7100',
            MESSAGE = 'iam_stage2b_authority_operation_invalid';
    END IF;
END;
$$;

CREATE FUNCTION iam_check_stage2b_authority_operation_state_v1(operation text, bind_state boolean)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    state_relation oid;
    state_is_safe boolean;
    state_row_count bigint;
    held_operation text;
BEGIN
    state_relation := pg_catalog.to_regclass('pg_temp.iam_stage2b_authority_state_v1');
    IF state_relation IS NULL THEN
        IF NOT bind_state THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P7101',
                MESSAGE = 'iam_stage2b_authority_state_required';
        END IF;
        CREATE TEMP TABLE pg_temp.iam_stage2b_authority_state_v1 (
            singleton boolean PRIMARY KEY CHECK (singleton),
            operation text NOT NULL
        ) ON COMMIT DELETE ROWS;
        REVOKE ALL ON TABLE pg_temp.iam_stage2b_authority_state_v1 FROM PUBLIC;
        state_relation := pg_catalog.to_regclass('pg_temp.iam_stage2b_authority_state_v1');
    END IF;

    SELECT
        relation.relowner = owner.oid AND
        relation.relnamespace = pg_catalog.pg_my_temp_schema() AND
        relation.relkind = 'r' AND
        relation.relpersistence = 't' AND
        NOT EXISTS (
            SELECT 1
            FROM pg_catalog.aclexplode(relation.relacl) acl
            WHERE acl.grantee <> relation.relowner
        ) AND
        (
            SELECT pg_catalog.count(*)
            FROM pg_catalog.pg_attribute attribute
            WHERE attribute.attrelid = relation.oid
              AND attribute.attnum > 0
              AND NOT attribute.attisdropped
        ) = 2 AND
        EXISTS (
            SELECT 1
            FROM pg_catalog.pg_attribute attribute
            WHERE attribute.attrelid = relation.oid
              AND attribute.attnum = 1
              AND attribute.attname = 'singleton'
              AND attribute.atttypid = pg_catalog.to_regtype('pg_catalog.bool')
              AND attribute.attnotnull
        ) AND
        EXISTS (
            SELECT 1
            FROM pg_catalog.pg_attribute attribute
            WHERE attribute.attrelid = relation.oid
              AND attribute.attnum = 2
              AND attribute.attname = 'operation'
              AND attribute.atttypid = pg_catalog.to_regtype('pg_catalog.text')
              AND attribute.attnotnull
        ) AND
        (
            SELECT pg_catalog.count(*)
            FROM pg_catalog.pg_constraint constraint_row
            WHERE constraint_row.conrelid = relation.oid
        ) = 2 AND
        EXISTS (
            SELECT 1
            FROM pg_catalog.pg_constraint constraint_row
            WHERE constraint_row.conrelid = relation.oid
              AND constraint_row.contype = 'p'
              AND constraint_row.conkey = ARRAY[1]::smallint[]
        ) AND
        EXISTS (
            SELECT 1
            FROM pg_catalog.pg_constraint constraint_row
            WHERE constraint_row.conrelid = relation.oid
              AND constraint_row.contype = 'c'
              AND constraint_row.conkey = ARRAY[1]::smallint[]
        )
      INTO state_is_safe
    FROM pg_catalog.pg_class relation
    JOIN pg_catalog.pg_roles owner ON owner.rolname = CURRENT_USER
    WHERE relation.oid = state_relation;
    IF NOT COALESCE(state_is_safe, false) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P7101',
            MESSAGE = 'iam_stage2b_authority_state_tampered';
    END IF;

    SELECT pg_catalog.count(*), pg_catalog.min(state.operation)
      INTO state_row_count, held_operation
    FROM pg_temp.iam_stage2b_authority_state_v1 state;
    IF state_row_count = 0 THEN
        IF NOT bind_state THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P7101',
                MESSAGE = 'iam_stage2b_authority_state_required';
        END IF;
        INSERT INTO pg_temp.iam_stage2b_authority_state_v1(singleton, operation)
        VALUES (true, operation);
    ELSIF state_row_count <> 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P7101',
            MESSAGE = 'iam_stage2b_authority_state_tampered';
    ELSIF held_operation <> operation THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P7101',
            MESSAGE = 'iam_stage2b_authority_operation_mismatch';
    END IF;
END;
$$;

CREATE FUNCTION iam_begin_stage2b_authority_mutation_v1(operation text, requested_scopes uuid[])
RETURNS uuid[]
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
BEGIN ATOMIC
    SELECT iam_validate_stage2b_authority_operation_v1(operation);
    SELECT iam_global_lock_exclusive_v1();
    SELECT iam_check_stage2b_authority_operation_state_v1(operation, true);
    SELECT iam_scope_locks_v1(requested_scopes);
END;

CREATE FUNCTION iam_require_stage2b_global_exclusive_v1()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_locks lock
        WHERE lock.pid = pg_catalog.pg_backend_pid()
          AND lock.locktype = 'advisory'
          AND lock.classid = 1229016321::oid
          AND lock.objid = 1::oid
          AND lock.objsubid = 2
          AND lock.mode = 'ExclusiveLock'
          AND lock.granted
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6901',
            MESSAGE = 'iam_stage2b_global_exclusive_required';
    END IF;
END;
$$;

CREATE FUNCTION iam_assert_stage2b_authority_mutation_v1(operation text, required_scopes uuid[])
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
BEGIN ATOMIC
    SELECT iam_validate_stage2b_authority_operation_v1(operation);
    SELECT iam_require_stage2b_global_exclusive_v1();
    SELECT iam_check_stage2b_authority_operation_state_v1(operation, false);
    SELECT iam_assert_scope_locks_v1(required_scopes);
END;

REVOKE ALL ON FUNCTION iam_validate_stage2b_authority_operation_v1(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_check_stage2b_authority_operation_state_v1(text, boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_begin_stage2b_authority_mutation_v1(text, uuid[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_require_stage2b_global_exclusive_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_assert_stage2b_authority_mutation_v1(text, uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_begin_stage2b_authority_mutation_v1(text, uuid[]) TO CURRENT_USER;
GRANT EXECUTE ON FUNCTION iam_assert_stage2b_authority_mutation_v1(text, uuid[]) TO CURRENT_USER;
