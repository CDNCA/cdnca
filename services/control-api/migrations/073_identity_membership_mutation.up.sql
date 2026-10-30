LOCK TABLE identity_write_requests IN ACCESS EXCLUSIVE MODE;

DO $$
DECLARE
    validator oid := pg_catalog.to_regprocedure('iam_validate_authority_operation_v1(text)');
    operation_check_valid boolean;
    operation_check_found boolean;
    operation_check_matches boolean;
    rejected boolean := false;
BEGIN
    IF (SELECT pg_catalog.count(*) FROM schema_migrations) <> 72 OR
       (SELECT pg_catalog.min(version) FROM schema_migrations) <> 1 OR
       (SELECT pg_catalog.max(version) FROM schema_migrations) <> 72 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P7300',
            MESSAGE = 'identity_membership_migration_requires_head_072';
    END IF;
    -- This is the exact prosrc body installed by 070; metadata alone does not constrain its allowlist.
    IF validator IS NULL OR NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc procedure
        WHERE procedure.oid = validator
          AND procedure.proowner = (
              SELECT role.oid FROM pg_catalog.pg_roles role WHERE role.rolname = CURRENT_USER
          )
          AND procedure.provolatile = 'i'
          AND NOT procedure.prosecdef
          AND procedure.proconfig = ARRAY['search_path=pg_catalog, pg_temp']::text[]
          AND procedure.prosrc = $validator_070$
BEGIN
    IF operation IS NULL OR NOT operation = ANY (ARRAY[
        'identity.session.create',
        'identity.session.rotate',
        'identity.session.revoke',
        'identity.bootstrap',
        'identity.user.create',
        'identity.user.update',
        'identity.self.update',
        'identity.password.change',
        'api_key.self.create',
        'api_key.self.update',
        'api_key.self.activate',
        'api_key.self.rotate',
        'api_key.self.revoke',
        'api_key.admin.create_pending',
        'api_key.admin.revoke',
        'identity.custom_role.create',
        'identity.custom_role.rename',
        'identity.custom_role.publish',
        'identity.custom_role.deactivate',
        'identity.custom_role.assign',
        'identity.custom_role.revoke'
    ]::text[]) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P7000',
            MESSAGE = 'iam_authority_operation_invalid';
    END IF;
END;
$validator_070$
          AND NOT EXISTS (
              SELECT 1
              FROM pg_catalog.aclexplode(COALESCE(
                  procedure.proacl,
                  pg_catalog.acldefault('f', procedure.proowner)
              )) privilege
              WHERE privilege.grantee <> procedure.proowner
                 OR privilege.privilege_type <> 'EXECUTE'
          )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P7300',
            MESSAGE = 'identity_membership_authority_validator_state_invalid';
    END IF;

    PERFORM iam_validate_authority_operation_v1('identity.user.create');
    BEGIN
        PERFORM iam_validate_authority_operation_v1('identity.membership.suspend');
    EXCEPTION
        WHEN SQLSTATE 'P7000' THEN rejected := true;
        WHEN OTHERS THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P7300',
                MESSAGE = 'identity_membership_authority_validator_state_invalid';
    END;
    IF NOT rejected THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P7300',
            MESSAGE = 'identity_membership_authority_validator_state_invalid';
    END IF;

    CREATE TEMPORARY TABLE identity_membership_receipt_expected_073
        (LIKE identity_write_requests)
        ON COMMIT DROP;
    ALTER TABLE pg_temp.identity_membership_receipt_expected_073
        ADD CONSTRAINT identity_membership_receipt_expected_073_check CHECK (operation IN (
            'identity.user.create',
            'identity.user.update',
            'identity.self.update'
        ));
    SELECT actual.convalidated,
           pg_catalog.pg_get_expr(actual.conbin, actual.conrelid, false) =
               pg_catalog.pg_get_expr(expected.conbin, expected.conrelid, false)
      INTO operation_check_valid, operation_check_matches
    FROM pg_catalog.pg_constraint actual
    CROSS JOIN pg_catalog.pg_constraint expected
    WHERE actual.conrelid = 'identity_write_requests'::pg_catalog.regclass
      AND actual.conname = 'identity_write_requests_operation_check'
      AND actual.contype = 'c'
      AND expected.conrelid = 'pg_temp.identity_membership_receipt_expected_073'::pg_catalog.regclass
      AND expected.conname = 'identity_membership_receipt_expected_073_check'
      AND expected.contype = 'c';
    operation_check_found := FOUND;
    DROP TABLE pg_temp.identity_membership_receipt_expected_073;
    IF NOT operation_check_found OR operation_check_valid IS DISTINCT FROM true OR
       operation_check_matches IS DISTINCT FROM true THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P7300',
            MESSAGE = 'identity_membership_receipt_constraint_state_invalid';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION iam_validate_authority_operation_v1(operation text)
RETURNS void
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF operation IS NULL OR NOT operation = ANY (ARRAY[
        'identity.session.create',
        'identity.session.rotate',
        'identity.session.revoke',
        'identity.bootstrap',
        'identity.user.create',
        'identity.user.update',
        'identity.self.update',
        'identity.password.change',
        'identity.membership.suspend',
        'api_key.self.create',
        'api_key.self.update',
        'api_key.self.activate',
        'api_key.self.rotate',
        'api_key.self.revoke',
        'api_key.admin.create_pending',
        'api_key.admin.revoke',
        'identity.custom_role.create',
        'identity.custom_role.rename',
        'identity.custom_role.publish',
        'identity.custom_role.deactivate',
        'identity.custom_role.assign',
        'identity.custom_role.revoke'
    ]::text[]) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P7000',
            MESSAGE = 'iam_authority_operation_invalid';
    END IF;
END;
$$;

REVOKE ALL ON FUNCTION iam_validate_authority_operation_v1(text) FROM PUBLIC;

ALTER TABLE identity_write_requests
    DROP CONSTRAINT identity_write_requests_operation_check,
    ADD CONSTRAINT identity_write_requests_operation_check CHECK (operation IN (
        'identity.user.create',
        'identity.user.update',
        'identity.self.update',
        'identity.membership.suspend'
    ));
