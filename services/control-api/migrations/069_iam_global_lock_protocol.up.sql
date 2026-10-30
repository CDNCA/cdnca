CREATE TABLE iam_global_lock_protocol_claims (
    component text NOT NULL CHECK (
        component = lower(btrim(component)) AND
        component ~ '^[a-z][a-z0-9_-]{0,63}$'
    ),
    caller text NOT NULL CHECK (caller = btrim(caller) AND char_length(caller) BETWEEN 1 AND 256),
    authority_table text NOT NULL CHECK (
        authority_table = lower(btrim(authority_table)) AND
        authority_table ~ '^[a-z][a-z0-9_]{0,62}$'
    ),
    mutation_kind text NOT NULL CHECK (mutation_kind IN ('insert', 'update', 'delete')),
    protocol_version smallint NOT NULL DEFAULT 1 CHECK (protocol_version = 1),
    claimed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (component, caller, authority_table, mutation_kind)
);

CREATE TABLE iam_global_lock_authority_grants (
    role_name name NOT NULL,
    authority_procedure text NOT NULL CHECK (
        authority_procedure = btrim(authority_procedure) AND
        char_length(authority_procedure) BETWEEN 1 AND 256
    ),
    base_table text NOT NULL CHECK (
        base_table = lower(btrim(base_table)) AND
        base_table ~ '^[a-z][a-z0-9_]{0,62}$'
    ),
    protocol_version smallint NOT NULL DEFAULT 1 CHECK (protocol_version = 1),
    direct_dml_revoked boolean NOT NULL DEFAULT true CHECK (direct_dml_revoked),
    granted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (role_name, authority_procedure, base_table)
);

CREATE FUNCTION protect_iam_global_lock_protocol_fact_069()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'iam_global_lock_protocol_fact_immutable';
END;
$$;

CREATE TRIGGER iam_global_lock_protocol_claims_immutable_069
BEFORE UPDATE OR DELETE OR TRUNCATE ON iam_global_lock_protocol_claims
FOR EACH STATEMENT EXECUTE FUNCTION protect_iam_global_lock_protocol_fact_069();

CREATE TRIGGER iam_global_lock_authority_grants_immutable_069
BEFORE UPDATE OR DELETE OR TRUNCATE ON iam_global_lock_authority_grants
FOR EACH STATEMENT EXECUTE FUNCTION protect_iam_global_lock_protocol_fact_069();

CREATE FUNCTION iam_global_lock_shared_v1()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    global_shared boolean;
    global_exclusive boolean;
    held_mode text;
    state_relation oid;
    state_is_safe boolean;
BEGIN
    PERFORM pg_catalog.pg_current_xact_id();
    IF pg_catalog.current_setting('transaction_read_only')::boolean THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6900',
            MESSAGE = 'iam_global_lock_read_only_transaction';
    END IF;

    SELECT
        COALESCE(pg_catalog.bool_or(lock.mode = 'ShareLock'), false),
        COALESCE(pg_catalog.bool_or(lock.mode = 'ExclusiveLock'), false)
      INTO global_shared, global_exclusive
    FROM pg_catalog.pg_locks lock
    WHERE lock.pid = pg_catalog.pg_backend_pid()
      AND lock.locktype = 'advisory'
      AND lock.classid = 1229016321::oid
      AND lock.objid = 1::oid
      AND lock.objsubid = 2
      AND lock.granted;

    state_relation := pg_catalog.to_regclass('pg_temp.iam_global_lock_state_v1');
    IF state_relation IS NOT NULL THEN
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
                  AND attribute.attname = 'singleton'
                  AND attribute.atttypid = pg_catalog.to_regtype('pg_catalog.bool')
                  AND attribute.attnotnull
            ) AND
            EXISTS (
                SELECT 1
                FROM pg_catalog.pg_attribute attribute
                WHERE attribute.attrelid = relation.oid
                  AND attribute.attname = 'lock_mode'
                  AND attribute.atttypid = pg_catalog.to_regtype('pg_catalog.text')
                  AND attribute.attnotnull
            )
          INTO state_is_safe
        FROM pg_catalog.pg_class relation
        JOIN pg_catalog.pg_roles owner ON owner.rolname = CURRENT_USER
        WHERE relation.oid = state_relation;
        IF NOT COALESCE(state_is_safe, false) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P6902',
                MESSAGE = 'iam_global_lock_state_tampered';
        END IF;
        SELECT state.lock_mode
          INTO held_mode
        FROM pg_temp.iam_global_lock_state_v1 state
        WHERE state.singleton;
    END IF;

    IF held_mode = 'shared' AND global_shared AND NOT global_exclusive THEN
        RETURN;
    END IF;
    IF held_mode = 'exclusive' AND global_exclusive AND NOT global_shared THEN
        RETURN;
    END IF;
    IF held_mode IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6902',
            MESSAGE = 'iam_global_lock_state_tampered';
    END IF;
    IF global_shared OR global_exclusive THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6902',
            MESSAGE = 'iam_global_lock_not_first_effective_lock';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_locks lock
        WHERE lock.pid = pg_catalog.pg_backend_pid()
          AND lock.locktype = 'advisory'
          AND lock.granted
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_locks lock
        JOIN pg_catalog.pg_class relation ON relation.oid = lock.relation
        JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
        WHERE lock.pid = pg_catalog.pg_backend_pid()
          AND lock.locktype = 'relation'
          AND lock.granted
          AND lock.mode IN (
              'RowShareLock', 'RowExclusiveLock', 'ShareUpdateExclusiveLock',
              'ShareLock', 'ShareRowExclusiveLock', 'ExclusiveLock', 'AccessExclusiveLock'
          )
          AND namespace.nspname <> 'information_schema'
          AND namespace.nspname !~ '^pg_'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6902',
            MESSAGE = 'iam_global_lock_not_first_effective_lock';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock_shared(1229016321, 1);
    IF state_relation IS NULL THEN
        CREATE TEMP TABLE pg_temp.iam_global_lock_state_v1 (
            singleton boolean PRIMARY KEY CHECK (singleton),
            lock_mode text NOT NULL CHECK (lock_mode IN ('shared', 'exclusive'))
        ) ON COMMIT DELETE ROWS;
        REVOKE ALL ON TABLE pg_temp.iam_global_lock_state_v1 FROM PUBLIC;
    END IF;
    INSERT INTO pg_temp.iam_global_lock_state_v1(singleton, lock_mode)
    VALUES (true, 'shared');
END;
$$;

CREATE FUNCTION iam_global_lock_exclusive_v1()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    global_shared boolean;
    global_exclusive boolean;
    held_mode text;
    state_relation oid;
    state_is_safe boolean;
BEGIN
    PERFORM pg_catalog.pg_current_xact_id();
    IF pg_catalog.current_setting('transaction_read_only')::boolean THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6900',
            MESSAGE = 'iam_global_lock_read_only_transaction';
    END IF;

    SELECT
        COALESCE(pg_catalog.bool_or(lock.mode = 'ShareLock'), false),
        COALESCE(pg_catalog.bool_or(lock.mode = 'ExclusiveLock'), false)
      INTO global_shared, global_exclusive
    FROM pg_catalog.pg_locks lock
    WHERE lock.pid = pg_catalog.pg_backend_pid()
      AND lock.locktype = 'advisory'
      AND lock.classid = 1229016321::oid
      AND lock.objid = 1::oid
      AND lock.objsubid = 2
      AND lock.granted;

    state_relation := pg_catalog.to_regclass('pg_temp.iam_global_lock_state_v1');
    IF state_relation IS NOT NULL THEN
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
                  AND attribute.attname = 'singleton'
                  AND attribute.atttypid = pg_catalog.to_regtype('pg_catalog.bool')
                  AND attribute.attnotnull
            ) AND
            EXISTS (
                SELECT 1
                FROM pg_catalog.pg_attribute attribute
                WHERE attribute.attrelid = relation.oid
                  AND attribute.attname = 'lock_mode'
                  AND attribute.atttypid = pg_catalog.to_regtype('pg_catalog.text')
                  AND attribute.attnotnull
            )
          INTO state_is_safe
        FROM pg_catalog.pg_class relation
        JOIN pg_catalog.pg_roles owner ON owner.rolname = CURRENT_USER
        WHERE relation.oid = state_relation;
        IF NOT COALESCE(state_is_safe, false) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P6902',
                MESSAGE = 'iam_global_lock_state_tampered';
        END IF;
        SELECT state.lock_mode
          INTO held_mode
        FROM pg_temp.iam_global_lock_state_v1 state
        WHERE state.singleton;
    END IF;

    IF held_mode = 'exclusive' AND global_exclusive AND NOT global_shared THEN
        RETURN;
    END IF;
    IF held_mode = 'shared' AND global_shared AND NOT global_exclusive THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6903',
            MESSAGE = 'iam_global_lock_upgrade_forbidden';
    END IF;
    IF held_mode IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6902',
            MESSAGE = 'iam_global_lock_state_tampered';
    END IF;
    IF global_shared OR global_exclusive THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6902',
            MESSAGE = 'iam_global_lock_not_first_effective_lock';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_locks lock
        WHERE lock.pid = pg_catalog.pg_backend_pid()
          AND lock.locktype = 'advisory'
          AND lock.granted
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_locks lock
        JOIN pg_catalog.pg_class relation ON relation.oid = lock.relation
        JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
        WHERE lock.pid = pg_catalog.pg_backend_pid()
          AND lock.locktype = 'relation'
          AND lock.granted
          AND lock.mode IN (
              'RowShareLock', 'RowExclusiveLock', 'ShareUpdateExclusiveLock',
              'ShareLock', 'ShareRowExclusiveLock', 'ExclusiveLock', 'AccessExclusiveLock'
          )
          AND namespace.nspname <> 'information_schema'
          AND namespace.nspname !~ '^pg_'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6902',
            MESSAGE = 'iam_global_lock_not_first_effective_lock';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(1229016321, 1);
    IF state_relation IS NULL THEN
        CREATE TEMP TABLE pg_temp.iam_global_lock_state_v1 (
            singleton boolean PRIMARY KEY CHECK (singleton),
            lock_mode text NOT NULL CHECK (lock_mode IN ('shared', 'exclusive'))
        ) ON COMMIT DELETE ROWS;
        REVOKE ALL ON TABLE pg_temp.iam_global_lock_state_v1 FROM PUBLIC;
    END IF;
    INSERT INTO pg_temp.iam_global_lock_state_v1(singleton, lock_mode)
    VALUES (true, 'exclusive');
END;
$$;

CREATE FUNCTION iam_scope_locks_v1(requested_scopes uuid[])
RETURNS uuid[]
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    normalized uuid[];
    scope_id uuid;
    global_shared boolean;
    global_exclusive boolean;
    global_mode text;
    global_state_relation oid;
    global_state_is_safe boolean;
    scope_sentinel boolean;
    canonical_identity text;
    held_identity text;
    state_relation oid;
    state_is_safe boolean;
    acquired_scope_keys integer[] := ARRAY[]::integer[];
    scope_key integer;
BEGIN
    IF requested_scopes IS NULL OR pg_catalog.cardinality(requested_scopes) < 1 OR
       pg_catalog.cardinality(requested_scopes) > 64 OR
       pg_catalog.array_position(requested_scopes, NULL::uuid) IS NOT NULL OR
       pg_catalog.array_position(requested_scopes, '00000000-0000-0000-0000-000000000000'::uuid) IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6900',
            MESSAGE = 'iam_scope_locks_invalid_input';
    END IF;

    SELECT pg_catalog.array_agg(DISTINCT value ORDER BY value)
      INTO normalized
    FROM pg_catalog.unnest(requested_scopes) value;
    canonical_identity := 'v1:' || pg_catalog.array_to_string(normalized, ',');
    IF pg_catalog.char_length(canonical_identity) > 4096 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6900',
            MESSAGE = 'iam_scope_locks_identity_too_large';
    END IF;

    SELECT
        COALESCE(pg_catalog.bool_or(lock.mode = 'ShareLock'), false),
        COALESCE(pg_catalog.bool_or(lock.mode = 'ExclusiveLock'), false)
      INTO global_shared, global_exclusive
    FROM pg_catalog.pg_locks lock
    WHERE lock.pid = pg_catalog.pg_backend_pid()
      AND lock.locktype = 'advisory'
      AND lock.classid = 1229016321::oid
      AND lock.objid = 1::oid
      AND lock.objsubid = 2
      AND lock.granted;

    global_state_relation := pg_catalog.to_regclass('pg_temp.iam_global_lock_state_v1');
    IF global_state_relation IS NULL THEN
        IF global_shared OR global_exclusive THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P6902',
                MESSAGE = 'iam_global_lock_state_tampered';
        END IF;
        RAISE EXCEPTION USING
            ERRCODE = 'P6901',
            MESSAGE = 'iam_global_lock_required';
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
              AND attribute.attname = 'singleton'
              AND attribute.atttypid = pg_catalog.to_regtype('pg_catalog.bool')
              AND attribute.attnotnull
        ) AND
        EXISTS (
            SELECT 1
            FROM pg_catalog.pg_attribute attribute
            WHERE attribute.attrelid = relation.oid
              AND attribute.attname = 'lock_mode'
              AND attribute.atttypid = pg_catalog.to_regtype('pg_catalog.text')
              AND attribute.attnotnull
        )
      INTO global_state_is_safe
    FROM pg_catalog.pg_class relation
    JOIN pg_catalog.pg_roles owner ON owner.rolname = CURRENT_USER
    WHERE relation.oid = global_state_relation;
    IF NOT COALESCE(global_state_is_safe, false) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6902',
            MESSAGE = 'iam_global_lock_state_tampered';
    END IF;
    SELECT state.lock_mode
      INTO global_mode
    FROM pg_temp.iam_global_lock_state_v1 state
    WHERE state.singleton;
    IF global_mode IS NULL AND NOT global_shared AND NOT global_exclusive THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6901',
            MESSAGE = 'iam_global_lock_required';
    END IF;
    IF NOT (
        (global_mode = 'shared' AND global_shared AND NOT global_exclusive) OR
        (global_mode = 'exclusive' AND global_exclusive AND NOT global_shared)
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6902',
            MESSAGE = 'iam_global_lock_state_tampered';
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_locks lock
        WHERE lock.pid = pg_catalog.pg_backend_pid()
          AND lock.locktype = 'advisory'
          AND lock.classid = 1229016321::oid
          AND lock.objid = 2::oid
          AND lock.objsubid = 2
          AND lock.mode = 'ShareLock'
          AND lock.granted
    ) INTO scope_sentinel;

    state_relation := pg_catalog.to_regclass('pg_temp.iam_scope_lock_state_v1');
    IF state_relation IS NULL THEN
        IF scope_sentinel THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P6902',
                MESSAGE = 'iam_scope_lock_state_tampered';
        END IF;
        CREATE TEMP TABLE pg_temp.iam_scope_lock_state_v1 (
            singleton boolean PRIMARY KEY CHECK (singleton),
            canonical_identity text NOT NULL CHECK (
                pg_catalog.char_length(canonical_identity) BETWEEN 4 AND 4096
            )
        ) ON COMMIT DELETE ROWS;
        REVOKE ALL ON TABLE pg_temp.iam_scope_lock_state_v1 FROM PUBLIC;
        state_relation := pg_catalog.to_regclass('pg_temp.iam_scope_lock_state_v1');
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
              AND attribute.attname = 'singleton'
              AND attribute.atttypid = pg_catalog.to_regtype('pg_catalog.bool')
              AND attribute.attnotnull
        ) AND
        EXISTS (
            SELECT 1
            FROM pg_catalog.pg_attribute attribute
            WHERE attribute.attrelid = relation.oid
              AND attribute.attname = 'canonical_identity'
              AND attribute.atttypid = pg_catalog.to_regtype('pg_catalog.text')
              AND attribute.attnotnull
        )
      INTO state_is_safe
    FROM pg_catalog.pg_class relation
    JOIN pg_catalog.pg_roles owner ON owner.rolname = CURRENT_USER
    WHERE relation.oid = state_relation;
    IF NOT COALESCE(state_is_safe, false) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6902',
            MESSAGE = 'iam_scope_lock_state_tampered';
    END IF;

    SELECT state.canonical_identity
      INTO held_identity
    FROM pg_temp.iam_scope_lock_state_v1 state
    WHERE state.singleton;
    IF (held_identity IS NULL AND scope_sentinel) OR
       (held_identity IS NOT NULL AND NOT scope_sentinel) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6902',
            MESSAGE = 'iam_scope_lock_state_tampered';
    END IF;
    IF held_identity IS NOT NULL AND held_identity <> canonical_identity THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6902',
            MESSAGE = 'iam_scope_lock_identity_mismatch';
    END IF;

    IF held_identity IS NULL THEN
        IF EXISTS (
            SELECT 1
            FROM pg_catalog.pg_locks lock
            WHERE lock.pid = pg_catalog.pg_backend_pid()
              AND lock.locktype = 'advisory'
              AND lock.granted
              AND NOT (
                  lock.classid = 1229016321::oid AND lock.objid = 1::oid AND lock.objsubid = 2
              )
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P6902',
                MESSAGE = 'iam_scope_locks_preceded_by_advisory_lock';
        END IF;
        PERFORM pg_catalog.pg_advisory_xact_lock_shared(1229016321, 2);
    END IF;

    FOREACH scope_id IN ARRAY normalized LOOP
        scope_key := pg_catalog.hashtext('iam-scope:v1:' || scope_id::text) & 2147483647;
        IF pg_catalog.array_position(acquired_scope_keys, scope_key) IS NULL THEN
            IF global_exclusive THEN
                PERFORM pg_catalog.pg_advisory_xact_lock(1229016322, scope_key);
            ELSE
                PERFORM pg_catalog.pg_advisory_xact_lock_shared(1229016322, scope_key);
            END IF;
            acquired_scope_keys := pg_catalog.array_append(acquired_scope_keys, scope_key);
        END IF;
    END LOOP;

    FOREACH scope_id IN ARRAY normalized LOOP
        IF global_exclusive THEN
            PERFORM pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtextextended('iam-authz:v1:' || scope_id::text, 0));
        ELSE
            PERFORM pg_catalog.pg_advisory_xact_lock_shared(
                pg_catalog.hashtextextended('iam-authz:v1:' || scope_id::text, 0));
        END IF;
    END LOOP;
    FOREACH scope_id IN ARRAY normalized LOOP
        IF global_exclusive THEN
            PERFORM pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtextextended('custom-rbac-tenant:' || scope_id::text, 0));
        ELSE
            PERFORM pg_catalog.pg_advisory_xact_lock_shared(
                pg_catalog.hashtextextended('custom-rbac-tenant:' || scope_id::text, 0));
        END IF;
    END LOOP;

    IF held_identity IS NULL THEN
        INSERT INTO pg_temp.iam_scope_lock_state_v1(singleton, canonical_identity)
        VALUES (true, canonical_identity);
    END IF;

    RETURN normalized;
END;
$$;

CREATE FUNCTION iam_assert_scope_locks_v1(required_scopes uuid[])
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    normalized uuid[];
    canonical_identity text;
    held_identity text;
    global_shared boolean;
    global_exclusive boolean;
    global_mode text;
    global_state_relation oid;
    global_state_is_safe boolean;
    state_relation oid;
    state_is_safe boolean;
    scope_sentinel boolean;
    scope_id uuid;
    scope_key integer;
BEGIN
    IF required_scopes IS NULL OR pg_catalog.cardinality(required_scopes) < 1 OR
       pg_catalog.cardinality(required_scopes) > 64 OR
       pg_catalog.array_position(required_scopes, NULL::uuid) IS NOT NULL OR
       pg_catalog.array_position(required_scopes, '00000000-0000-0000-0000-000000000000'::uuid) IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6900',
            MESSAGE = 'iam_scope_lock_assertion_invalid_input';
    END IF;
    SELECT pg_catalog.array_agg(DISTINCT value ORDER BY value)
      INTO normalized
    FROM pg_catalog.unnest(required_scopes) value;
    canonical_identity := 'v1:' || pg_catalog.array_to_string(normalized, ',');
    IF pg_catalog.char_length(canonical_identity) > 4096 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6900',
            MESSAGE = 'iam_scope_lock_assertion_identity_too_large';
    END IF;

    SELECT
        COALESCE(pg_catalog.bool_or(lock.mode = 'ShareLock'), false),
        COALESCE(pg_catalog.bool_or(lock.mode = 'ExclusiveLock'), false)
      INTO global_shared, global_exclusive
    FROM pg_catalog.pg_locks lock
    WHERE lock.pid = pg_catalog.pg_backend_pid()
      AND lock.locktype = 'advisory'
      AND lock.classid = 1229016321::oid
      AND lock.objid = 1::oid
      AND lock.objsubid = 2
      AND lock.granted;

    global_state_relation := pg_catalog.to_regclass('pg_temp.iam_global_lock_state_v1');
    IF global_state_relation IS NULL THEN
        IF global_shared OR global_exclusive THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P6902',
                MESSAGE = 'iam_global_lock_state_tampered';
        END IF;
        RAISE EXCEPTION USING
            ERRCODE = 'P6901',
            MESSAGE = 'iam_global_lock_required';
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
              AND attribute.attname = 'singleton'
              AND attribute.atttypid = pg_catalog.to_regtype('pg_catalog.bool')
              AND attribute.attnotnull
        ) AND
        EXISTS (
            SELECT 1
            FROM pg_catalog.pg_attribute attribute
            WHERE attribute.attrelid = relation.oid
              AND attribute.attname = 'lock_mode'
              AND attribute.atttypid = pg_catalog.to_regtype('pg_catalog.text')
              AND attribute.attnotnull
        )
      INTO global_state_is_safe
    FROM pg_catalog.pg_class relation
    JOIN pg_catalog.pg_roles owner ON owner.rolname = CURRENT_USER
    WHERE relation.oid = global_state_relation;
    IF NOT COALESCE(global_state_is_safe, false) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6902',
            MESSAGE = 'iam_global_lock_state_tampered';
    END IF;
    SELECT state.lock_mode
      INTO global_mode
    FROM pg_temp.iam_global_lock_state_v1 state
    WHERE state.singleton;
    IF global_mode IS NULL AND NOT global_shared AND NOT global_exclusive THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6901',
            MESSAGE = 'iam_global_lock_required';
    END IF;
    IF NOT (
        (global_mode = 'shared' AND global_shared AND NOT global_exclusive) OR
        (global_mode = 'exclusive' AND global_exclusive AND NOT global_shared)
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6902',
            MESSAGE = 'iam_global_lock_state_tampered';
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_locks lock
        WHERE lock.pid = pg_catalog.pg_backend_pid()
          AND lock.locktype = 'advisory'
          AND lock.classid = 1229016321::oid
          AND lock.objid = 2::oid
          AND lock.objsubid = 2
          AND lock.mode = 'ShareLock'
          AND lock.granted
    ) INTO scope_sentinel;
    IF NOT scope_sentinel THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6901',
            MESSAGE = 'iam_scope_lock_sentinel_required';
    END IF;

    state_relation := pg_catalog.to_regclass('pg_temp.iam_scope_lock_state_v1');
    IF state_relation IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6902',
            MESSAGE = 'iam_scope_lock_state_tampered';
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
              AND attribute.attname = 'singleton'
              AND attribute.atttypid = pg_catalog.to_regtype('pg_catalog.bool')
              AND attribute.attnotnull
        ) AND
        EXISTS (
            SELECT 1
            FROM pg_catalog.pg_attribute attribute
            WHERE attribute.attrelid = relation.oid
              AND attribute.attname = 'canonical_identity'
              AND attribute.atttypid = pg_catalog.to_regtype('pg_catalog.text')
              AND attribute.attnotnull
        )
      INTO state_is_safe
    FROM pg_catalog.pg_class relation
    JOIN pg_catalog.pg_roles owner ON owner.rolname = CURRENT_USER
    WHERE relation.oid = state_relation;
    IF NOT COALESCE(state_is_safe, false) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6902',
            MESSAGE = 'iam_scope_lock_state_tampered';
    END IF;

    SELECT state.canonical_identity
      INTO held_identity
    FROM pg_temp.iam_scope_lock_state_v1 state
    WHERE state.singleton;
    IF held_identity IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6901',
            MESSAGE = 'iam_scope_lock_identity_required';
    END IF;
    IF held_identity <> canonical_identity THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P6902',
            MESSAGE = 'iam_scope_lock_identity_mismatch';
    END IF;

    FOREACH scope_id IN ARRAY normalized LOOP
        scope_key := pg_catalog.hashtext('iam-scope:v1:' || scope_id::text) & 2147483647;
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_locks lock
            WHERE lock.pid = pg_catalog.pg_backend_pid()
              AND lock.locktype = 'advisory'
              AND lock.classid = 1229016322::oid
              AND lock.objid = scope_key::oid
              AND lock.objsubid = 2
              AND lock.granted
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'P6901',
                MESSAGE = 'iam_scope_lock_required';
        END IF;
    END LOOP;
END;
$$;

REVOKE ALL ON FUNCTION iam_global_lock_shared_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_global_lock_exclusive_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_scope_locks_v1(uuid[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam_assert_scope_locks_v1(uuid[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_iam_global_lock_protocol_fact_069() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_global_lock_shared_v1() TO CURRENT_USER;
GRANT EXECUTE ON FUNCTION iam_global_lock_exclusive_v1() TO CURRENT_USER;
GRANT EXECUTE ON FUNCTION iam_scope_locks_v1(uuid[]) TO CURRENT_USER;
GRANT EXECUTE ON FUNCTION iam_assert_scope_locks_v1(uuid[]) TO CURRENT_USER;

REVOKE ALL ON TABLE iam_global_lock_protocol_claims FROM PUBLIC;
REVOKE ALL ON TABLE iam_global_lock_authority_grants FROM PUBLIC;
GRANT SELECT, INSERT ON TABLE iam_global_lock_protocol_claims TO CURRENT_USER;
GRANT SELECT, INSERT ON TABLE iam_global_lock_authority_grants TO CURRENT_USER;
