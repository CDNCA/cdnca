CREATE FUNCTION iam_validate_authority_operation_v1(operation text)
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

-- BEGIN ATOMIC binds the schema-local 069 helpers when this migration is
-- applied, while the runtime search_path remains restricted.
CREATE FUNCTION iam_begin_authority_mutation_v1(operation text, requested_scopes uuid[])
RETURNS uuid[]
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
BEGIN ATOMIC
    SELECT iam_validate_authority_operation_v1(operation);
    SELECT iam_global_lock_exclusive_v1();
    SELECT iam_scope_locks_v1(requested_scopes);
END;

REVOKE ALL ON FUNCTION iam_validate_authority_operation_v1(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_begin_authority_mutation_v1(text, uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_begin_authority_mutation_v1(text, uuid[]) TO CURRENT_USER;
