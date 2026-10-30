LOCK TABLE access_scopes,
    users,
    memberships,
    roles,
    role_permissions,
    permissions,
    custom_rbac_permission_catalog,
    custom_roles,
    custom_role_revisions,
    custom_role_grants,
    custom_role_grant_revocations,
    role_assignments,
    audit_events,
    control_installation_entitlement,
    entitlement_cached_leases,
    entitlement_signing_keyset_lkg
IN ACCESS EXCLUSIVE MODE;

DO $$
DECLARE
    effective_function oid := to_regprocedure('custom_rbac_effective_permissions(uuid,uuid)');
    guard_function oid := to_regprocedure('guard_system_role_permission_mutation()');
    revision_function oid := to_regprocedure('validate_custom_role_revision()');
    grant_function oid := to_regprocedure('validate_custom_role_grant()');
    control_role oid := to_regrole('cdnca_control_app');
    runtime_role oid := to_regrole('cdnca_plugin_webhook_runtime');
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 83 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 83 THEN
        RAISE EXCEPTION 'plugin webhook control requires frozen migration head 083'
            USING ERRCODE = 'P8400';
    END IF;
    IF control_role IS NULL OR runtime_role IS NULL OR
       (SELECT nspowner FROM pg_namespace
        WHERE oid = current_schema()::regnamespace) <> current_user::regrole OR EXISTS (
        SELECT 1 FROM pg_roles role
        WHERE role.oid IN (control_role, runtime_role) AND (
            role.rolcanlogin OR role.rolsuper OR role.rolcreatedb OR role.rolcreaterole OR
            role.rolreplication OR role.rolbypassrls
        )
    ) OR current_user::regrole IN (control_role, runtime_role) OR
       (SELECT COALESCE(nspacl, acldefault('n', nspowner)) IS DISTINCT FROM
               acldefault('n', nspowner)
        FROM pg_namespace
        WHERE oid = current_schema()::regnamespace) OR EXISTS (
        SELECT 1
        FROM pg_default_acl default_acl
        WHERE default_acl.defaclrole = current_user::regrole
          AND default_acl.defaclnamespace IN (0, current_schema()::regnamespace)
          AND default_acl.defaclobjtype IN ('r', 'S', 'f', 'T')
    ) OR
       has_schema_privilege(control_role, current_schema(), 'CREATE') OR
       has_schema_privilege(runtime_role, current_schema(), 'CREATE') OR
       has_database_privilege(control_role, current_database(), 'CREATE') OR
       has_database_privilege(runtime_role, current_database(), 'CREATE') OR
       pg_has_role(control_role, runtime_role, 'MEMBER') OR
       pg_has_role(runtime_role, control_role, 'MEMBER') OR EXISTS (
        SELECT 1
        FROM pg_namespace namespace
        CROSS JOIN LATERAL aclexplode(namespace.nspacl) acl
        WHERE namespace.oid = current_schema()::regnamespace
          AND acl.grantee IN (control_role, runtime_role)
    ) THEN
        RAISE EXCEPTION 'plugin webhook database role baseline is unavailable or unsafe'
            USING ERRCODE = 'P8400';
    END IF;
    IF effective_function IS NULL OR guard_function IS NULL OR
       (SELECT count(*) FROM pg_proc procedure
        WHERE procedure.pronamespace = current_schema()::regnamespace
          AND procedure.proname = 'validate_custom_role_revision') <> 1 OR
       (SELECT count(*) FROM pg_proc procedure
        WHERE procedure.pronamespace = current_schema()::regnamespace
          AND procedure.proname = 'validate_custom_role_grant') <> 1 OR NOT EXISTS (
        SELECT 1
        FROM pg_proc procedure
        JOIN pg_language language ON language.oid = procedure.prolang
        WHERE procedure.oid = effective_function
          AND encode(sha256(convert_to(procedure.prosrc, 'UTF8')), 'hex') =
              '3351565441f2633e41cb7bf1928dde5236c4803e8437e3aea98713edca1e3d96'
          AND language.lanname = 'sql' AND procedure.provolatile = 's'
          AND procedure.proparallel = 'u' AND NOT procedure.proisstrict
          AND NOT procedure.prosecdef AND NOT procedure.proleakproof
          AND procedure.proretset AND procedure.prokind = 'f'
          AND procedure.proowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
          AND procedure.proacl IS NULL
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_proc procedure
        JOIN pg_language language ON language.oid = procedure.prolang
        WHERE procedure.oid = guard_function
          AND encode(sha256(convert_to(procedure.prosrc, 'UTF8')), 'hex') =
              '509793c50a8c96f1b9eaa043d91056bf6ab45efb32cf051858baadbc05c3a43c'
          AND language.lanname = 'plpgsql' AND procedure.provolatile = 'v'
          AND procedure.proparallel = 'u' AND NOT procedure.proisstrict
          AND NOT procedure.prosecdef AND NOT procedure.proleakproof
          AND NOT procedure.proretset AND procedure.prokind = 'f'
          AND procedure.prorettype = 'trigger'::regtype
          AND procedure.procost = 100 AND procedure.prorows = 0
          AND procedure.prosupport = 0 AND procedure.pronargdefaults = 0
          AND procedure.probin IS NULL AND procedure.proargnames IS NULL
          AND procedure.proargmodes IS NULL AND procedure.proallargtypes IS NULL
          AND procedure.protrftypes IS NULL
          AND procedure.proowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
          AND procedure.proacl IS NULL
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_trigger trigger
        WHERE trigger.tgrelid = 'role_permissions'::regclass
          AND trigger.tgname = 'role_permissions_system_role_guard'
          AND trigger.tgfoid = guard_function AND NOT trigger.tgisinternal
          AND trigger.tgenabled = 'O' AND trigger.tgtype = 31
          AND trigger.tgattr = ''::int2vector AND trigger.tgqual IS NULL
          AND trigger.tgoldtable IS NULL AND trigger.tgnewtable IS NULL
    ) OR revision_function IS NULL OR grant_function IS NULL OR NOT EXISTS (
        SELECT 1
        FROM pg_proc procedure
        JOIN pg_language language ON language.oid = procedure.prolang
        WHERE procedure.oid = revision_function
          AND procedure.pronamespace = current_schema()::regnamespace
          AND procedure.pronargs = 0 AND procedure.proargtypes = ''::oidvector
          AND encode(sha256(convert_to(procedure.prosrc, 'UTF8')), 'hex') =
              'de66b83fa473ac92be83ccb0603d7cd7cde1b96832f6ce56f8ce714375097cf7'
          AND language.lanname = 'plpgsql' AND procedure.provolatile = 'v'
          AND procedure.proparallel = 'u' AND NOT procedure.proisstrict
          AND NOT procedure.prosecdef AND NOT procedure.proleakproof
          AND NOT procedure.proretset AND procedure.prokind = 'f'
          AND procedure.prorettype = 'trigger'::regtype
          AND procedure.procost = 100 AND procedure.prorows = 0
          AND procedure.prosupport = 0 AND procedure.pronargdefaults = 0
          AND procedure.probin IS NULL AND procedure.proargnames IS NULL
          AND procedure.proargmodes IS NULL AND procedure.proallargtypes IS NULL
          AND procedure.protrftypes IS NULL
          AND procedure.proowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
          AND procedure.proacl IS NULL AND procedure.proconfig IS NULL
          AND procedure.procost = 100 AND procedure.prorows = 0
          AND procedure.prosupport = 0 AND procedure.pronargdefaults = 0
          AND procedure.probin IS NULL AND procedure.proargnames IS NULL
          AND procedure.proargmodes IS NULL AND procedure.proallargtypes IS NULL
          AND procedure.protrftypes IS NULL
          AND (SELECT count(*) FROM pg_depend dependency
               WHERE dependency.classid = 'pg_proc'::regclass
                 AND dependency.objid = procedure.oid) = 2
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_proc procedure
        JOIN pg_language language ON language.oid = procedure.prolang
        WHERE procedure.oid = grant_function
          AND procedure.pronamespace = current_schema()::regnamespace
          AND procedure.pronargs = 0 AND procedure.proargtypes = ''::oidvector
          AND encode(sha256(convert_to(procedure.prosrc, 'UTF8')), 'hex') =
              'a0b83206a7be3a095c6a536a6df8820bb1f859ec273e26f543bc6b5c096e8012'
          AND language.lanname = 'plpgsql' AND procedure.provolatile = 'v'
          AND procedure.proparallel = 'u' AND NOT procedure.proisstrict
          AND NOT procedure.prosecdef AND NOT procedure.proleakproof
          AND NOT procedure.proretset AND procedure.prokind = 'f'
          AND procedure.prorettype = 'trigger'::regtype
          AND procedure.proowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
          AND procedure.proacl IS NULL AND procedure.proconfig IS NULL
          AND procedure.procost = 100 AND procedure.prorows = 0
          AND procedure.prosupport = 0 AND procedure.pronargdefaults = 0
          AND procedure.probin IS NULL AND procedure.proargnames IS NULL
          AND procedure.proargmodes IS NULL AND procedure.proallargtypes IS NULL
          AND procedure.protrftypes IS NULL
          AND (SELECT count(*) FROM pg_depend dependency
               WHERE dependency.classid = 'pg_proc'::regclass
                 AND dependency.objid = procedure.oid) = 2
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_trigger trigger
        WHERE trigger.tgrelid = 'custom_role_revisions'::regclass
          AND trigger.tgname = 'custom_role_revisions_validate'
          AND trigger.tgfoid = revision_function AND NOT trigger.tgisinternal
          AND trigger.tgenabled = 'O' AND trigger.tgtype = 7
          AND trigger.tgattr = ''::int2vector AND trigger.tgqual IS NULL
          AND trigger.tgoldtable IS NULL AND trigger.tgnewtable IS NULL
          AND octet_length(trigger.tgargs) = 0
          AND EXISTS (
              SELECT 1 FROM pg_depend dependency
              WHERE dependency.classid = 'pg_trigger'::regclass
                AND dependency.objid = trigger.oid
                AND dependency.refclassid = 'pg_proc'::regclass
                AND dependency.refobjid = revision_function AND dependency.deptype = 'n'
            ) AND EXISTS (
              SELECT 1 FROM pg_depend dependency
              WHERE dependency.classid = 'pg_trigger'::regclass
                AND dependency.objid = trigger.oid
                AND dependency.refclassid = 'pg_class'::regclass
                AND dependency.refobjid = 'custom_role_revisions'::regclass
                AND dependency.deptype = 'a'
            ) AND (SELECT count(*) FROM pg_depend dependency
                   WHERE dependency.classid = 'pg_trigger'::regclass
                     AND dependency.objid = trigger.oid) = 2
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_trigger trigger
        WHERE trigger.tgrelid = 'custom_role_grants'::regclass
          AND trigger.tgname = 'custom_role_grants_validate'
          AND trigger.tgfoid = grant_function AND NOT trigger.tgisinternal
          AND trigger.tgenabled = 'O' AND trigger.tgtype = 7
          AND trigger.tgattr = ''::int2vector AND trigger.tgqual IS NULL
          AND trigger.tgoldtable IS NULL AND trigger.tgnewtable IS NULL
          AND octet_length(trigger.tgargs) = 0
          AND EXISTS (
              SELECT 1 FROM pg_depend dependency
              WHERE dependency.classid = 'pg_trigger'::regclass
                AND dependency.objid = trigger.oid
                AND dependency.refclassid = 'pg_proc'::regclass
                AND dependency.refobjid = grant_function AND dependency.deptype = 'n'
          ) AND EXISTS (
              SELECT 1 FROM pg_depend dependency
              WHERE dependency.classid = 'pg_trigger'::regclass
                AND dependency.objid = trigger.oid
                AND dependency.refclassid = 'pg_class'::regclass
                AND dependency.refobjid = 'custom_role_grants'::regclass
                AND dependency.deptype = 'a'
            ) AND (SELECT count(*) FROM pg_depend dependency
                   WHERE dependency.classid = 'pg_trigger'::regclass
                     AND dependency.objid = trigger.oid) = 2
        ) THEN
        RAISE EXCEPTION 'plugin webhook control RBAC baseline drift'
            USING ERRCODE = 'P8400';
    END IF;
    IF EXISTS (
        SELECT 1 FROM permissions
        WHERE name IN ('plugin_webhooks.read', 'plugin_webhooks.manage')
    ) OR EXISTS (
        SELECT 1 FROM custom_rbac_permission_catalog
        WHERE permission_name IN ('plugin_webhooks.read', 'plugin_webhooks.manage')
    ) OR to_regclass('plugin_webhook_subscriptions') IS NOT NULL OR
       to_regclass('plugin_webhook_secret_versions') IS NOT NULL OR
       to_regclass('plugin_webhook_write_requests') IS NOT NULL OR
       to_regclass('plugin_webhook_events') IS NOT NULL OR
       to_regclass('plugin_webhook_deliveries') IS NOT NULL OR
       to_regclass('plugin_webhook_outbox') IS NOT NULL OR
       to_regclass('plugin_webhook_delivery_attempts') IS NOT NULL OR
       to_regclass('plugin_webhook_dead_letters') IS NOT NULL OR
       to_regclass('plugin_webhook_rate_events') IS NOT NULL OR
       to_regclass('control_entitlement_revocation_lkg') IS NOT NULL OR
       to_regclass('control_entitlement_revoked_serials') IS NOT NULL OR
       to_regclass('entitlement_signing_keyset_current_keys') IS NOT NULL OR
       to_regclass('plugin_webhook_entitlement_decisions') IS NOT NULL OR
       to_regclass('plugin_webhook_runtime_attestation_keys') IS NOT NULL OR
       to_regclass('plugin_webhook_runtime_attestation_head') IS NOT NULL OR
       to_regprocedure('plugin_webhook_u32be_084(integer)') IS NOT NULL OR
       to_regprocedure('plugin_webhook_attestation_frame_084(bytea[])') IS NOT NULL OR
       to_regprocedure('plugin_webhook_outbox_attestation_sha256_084(numeric,text,text,uuid,uuid,uuid,uuid,uuid,uuid,numeric,text,numeric,text,numeric,text,bytea,numeric)') IS NOT NULL OR
       to_regprocedure('plugin_webhook_dead_letter_attestation_sha256_084(numeric,text,text,uuid,uuid,uuid,uuid,uuid,uuid,text,numeric,numeric,numeric,text,numeric,text,numeric,text,bytea,bytea,numeric)') IS NOT NULL OR
       to_regprocedure('guard_plugin_webhook_runtime_attestation_key_084()') IS NOT NULL OR
       to_regprocedure('guard_plugin_webhook_runtime_attestation_head_084()') IS NOT NULL OR
       to_regprocedure('validate_plugin_webhook_runtime_attestation_head_084()') IS NOT NULL OR
       to_regprocedure('prevent_plugin_webhook_runtime_attestation_truncate_084()') IS NOT NULL OR
       to_regprocedure('read_plugin_webhook_secret_envelope_084(uuid,uuid,uuid)') IS NOT NULL OR
       to_regprocedure('read_plugin_webhook_receipt_envelope_084(uuid,uuid,uuid,text)') IS NOT NULL OR
       to_regprocedure('publish_plugin_webhook_outbox_084(uuid,uuid,uuid,uuid,text,text,numeric,text,numeric,text,bytea,numeric,numeric,text,bytea)') IS NOT NULL OR
       to_regprocedure('transition_plugin_webhook_dead_letter_reconcile_084(uuid,uuid,uuid,uuid,text,numeric,numeric,numeric,numeric,uuid,text,numeric,numeric,numeric,numeric)') IS NOT NULL OR
       to_regprocedure('acknowledge_plugin_webhook_dead_letter_084(uuid,uuid,uuid,uuid,text,numeric,numeric,numeric,numeric,text,text,numeric,text,numeric,text,bytea,bytea,numeric,numeric,text,bytea)') IS NOT NULL THEN
        RAISE EXCEPTION 'plugin webhook control baseline is not empty'
            USING ERRCODE = 'P8400';
    END IF;
END;
$$;

CREATE FUNCTION plugin_webhook_mod_084(value numeric, modulus numeric)
RETURNS numeric
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT mod(mod(value, modulus) + modulus, modulus);
$$;

CREATE FUNCTION plugin_webhook_le_numeric_084(value bytea)
RETURNS numeric
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    result numeric := 0;
    factor numeric := 1;
    byte_index integer;
BEGIN
    IF octet_length(value) > 64 THEN
        RETURN NULL;
    END IF;
    FOR byte_index IN 0..octet_length(value) - 1 LOOP
        result := result + get_byte(value, byte_index) * factor;
        factor := factor * 256;
    END LOOP;
    RETURN result;
END;
$$;

CREATE FUNCTION plugin_webhook_mod_pow_084(value numeric, exponent numeric, modulus numeric)
RETURNS numeric
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    result numeric := 1;
    factor numeric := plugin_webhook_mod_084(value, modulus);
    remaining numeric := exponent;
BEGIN
    IF exponent < 0 OR exponent <> trunc(exponent) OR modulus <= 1 THEN
        RETURN NULL;
    END IF;
    WHILE remaining > 0 LOOP
        IF mod(remaining, 2) = 1 THEN
            result := plugin_webhook_mod_084(result * factor, modulus);
        END IF;
        factor := plugin_webhook_mod_084(factor * factor, modulus);
        remaining := div(remaining, 2);
    END LOOP;
    RETURN result;
END;
$$;

CREATE FUNCTION plugin_webhook_ed25519_decode_084(encoded bytea)
RETURNS numeric[]
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    field_modulus constant numeric :=
        57896044618658097711785492504343953926634992332820282019728792003956564819949;
    two_to_255 constant numeric :=
        57896044618658097711785492504343953926634992332820282019728792003956564819968;
    curve_d constant numeric :=
        37095705934669439343138083508754565189542113879843219016388785533085940283555;
    sqrt_minus_one constant numeric :=
        19681161376707505956807079304988542015446066515923890162744021073123829784752;
    compressed numeric;
    sign_bit numeric;
    y numeric;
    y_squared numeric;
    x_squared numeric;
    x numeric;
BEGIN
    IF octet_length(encoded) <> 32 THEN
        RETURN NULL;
    END IF;
    compressed := plugin_webhook_le_numeric_084(encoded);
    sign_bit := trunc(compressed / two_to_255);
    y := mod(compressed, two_to_255);
    IF sign_bit NOT IN (0, 1) OR y >= field_modulus THEN
        RETURN NULL;
    END IF;
    y_squared := plugin_webhook_mod_084(y * y, field_modulus);
    x_squared := plugin_webhook_mod_084(
        (y_squared - 1) * plugin_webhook_mod_pow_084(
            curve_d * y_squared + 1, field_modulus - 2, field_modulus
        ), field_modulus
    );
    x := plugin_webhook_mod_pow_084(
        x_squared, (field_modulus + 3) / 8, field_modulus
    );
    IF plugin_webhook_mod_084(x * x - x_squared, field_modulus) <> 0 THEN
        x := plugin_webhook_mod_084(x * sqrt_minus_one, field_modulus);
    END IF;
    IF plugin_webhook_mod_084(x * x - x_squared, field_modulus) <> 0 OR
       (x = 0 AND sign_bit = 1) THEN
        RETURN NULL;
    END IF;
    IF mod(x, 2) <> sign_bit THEN
        x := field_modulus - x;
    END IF;
    RETURN ARRAY[x, y, 1::numeric, plugin_webhook_mod_084(x * y, field_modulus)];
END;
$$;

CREATE FUNCTION plugin_webhook_ed25519_add_084(left_point numeric[], right_point numeric[])
RETURNS numeric[]
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    field_modulus constant numeric :=
        57896044618658097711785492504343953926634992332820282019728792003956564819949;
    twice_curve_d constant numeric :=
        16295367250680780974490674513165176452449235426866156013048779062215315747161;
    a numeric;
    b numeric;
    c numeric;
    d numeric;
    e numeric;
    f numeric;
    g numeric;
    h numeric;
BEGIN
    IF array_length(left_point, 1) <> 4 OR array_length(right_point, 1) <> 4 THEN
        RETURN NULL;
    END IF;
    a := plugin_webhook_mod_084(
        (left_point[2] - left_point[1]) * (right_point[2] - right_point[1]), field_modulus
    );
    b := plugin_webhook_mod_084(
        (left_point[2] + left_point[1]) * (right_point[2] + right_point[1]), field_modulus
    );
    c := plugin_webhook_mod_084(twice_curve_d * left_point[4] * right_point[4], field_modulus);
    d := plugin_webhook_mod_084(2 * left_point[3] * right_point[3], field_modulus);
    e := plugin_webhook_mod_084(b - a, field_modulus);
    f := plugin_webhook_mod_084(d - c, field_modulus);
    g := plugin_webhook_mod_084(d + c, field_modulus);
    h := plugin_webhook_mod_084(b + a, field_modulus);
    RETURN ARRAY[
        plugin_webhook_mod_084(e * f, field_modulus),
        plugin_webhook_mod_084(g * h, field_modulus),
        plugin_webhook_mod_084(f * g, field_modulus),
        plugin_webhook_mod_084(e * h, field_modulus)
    ];
END;
$$;

CREATE FUNCTION plugin_webhook_ed25519_double_084(point numeric[])
RETURNS numeric[]
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    field_modulus constant numeric :=
        57896044618658097711785492504343953926634992332820282019728792003956564819949;
    a numeric;
    b numeric;
    c numeric;
    d numeric;
    e numeric;
    f numeric;
    g numeric;
    h numeric;
BEGIN
    IF array_length(point, 1) <> 4 THEN
        RETURN NULL;
    END IF;
    a := plugin_webhook_mod_084(point[1] * point[1], field_modulus);
    b := plugin_webhook_mod_084(point[2] * point[2], field_modulus);
    c := plugin_webhook_mod_084(2 * point[3] * point[3], field_modulus);
    d := plugin_webhook_mod_084(-a, field_modulus);
    e := plugin_webhook_mod_084((point[1] + point[2]) * (point[1] + point[2]) - a - b,
        field_modulus);
    g := plugin_webhook_mod_084(d + b, field_modulus);
    f := plugin_webhook_mod_084(g - c, field_modulus);
    h := plugin_webhook_mod_084(d - b, field_modulus);
    RETURN ARRAY[
        plugin_webhook_mod_084(e * f, field_modulus),
        plugin_webhook_mod_084(g * h, field_modulus),
        plugin_webhook_mod_084(f * g, field_modulus),
        plugin_webhook_mod_084(e * h, field_modulus)
    ];
END;
$$;

CREATE FUNCTION plugin_webhook_ed25519_scalarmult_084(point numeric[], scalar numeric)
RETURNS numeric[]
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    result numeric[] := ARRAY[0::numeric, 1::numeric, 1::numeric, 0::numeric];
    factor numeric[] := point;
    remaining numeric := scalar;
BEGIN
    IF array_length(point, 1) <> 4 OR scalar < 0 OR scalar <> trunc(scalar) THEN
        RETURN NULL;
    END IF;
    WHILE remaining > 0 LOOP
        IF mod(remaining, 2) = 1 THEN
            result := plugin_webhook_ed25519_add_084(result, factor);
        END IF;
        factor := plugin_webhook_ed25519_double_084(factor);
        remaining := div(remaining, 2);
    END LOOP;
    RETURN result;
END;
$$;

CREATE FUNCTION plugin_webhook_ed25519_prime_order_point_084(point numeric[])
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    field_modulus constant numeric :=
        57896044618658097711785492504343953926634992332820282019728792003956564819949;
    group_order constant numeric :=
        7237005577332262213973186563042994240857116359379907606001950938285454250989;
    multiplied numeric[];
BEGIN
    IF array_length(point, 1) <> 4 OR
       (plugin_webhook_mod_084(point[1], field_modulus) = 0 AND
        plugin_webhook_mod_084(point[2] - point[3], field_modulus) = 0) THEN
        RETURN false;
    END IF;
    multiplied := plugin_webhook_ed25519_scalarmult_084(point, group_order);
    RETURN multiplied IS NOT NULL AND
        plugin_webhook_mod_084(multiplied[1], field_modulus) = 0 AND
        plugin_webhook_mod_084(multiplied[2] - multiplied[3], field_modulus) = 0;
END;
$$;

CREATE FUNCTION plugin_webhook_ed25519_verify_084(
    public_key bytea,
    message bytea,
    signature bytea
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    field_modulus constant numeric :=
        57896044618658097711785492504343953926634992332820282019728792003956564819949;
    group_order constant numeric :=
        7237005577332262213973186563042994240857116359379907606001950938285454250989;
    base_point constant numeric[] := ARRAY[
        15112221349535400772501151409588531511454012693041857206046113283949847762202,
        46316835694926478169428394003475163141307993866256225615783033603165251855960,
        1,
        46827403850823179245072216630277197565144205554125654976674165829533817101731
    ]::numeric[];
    encoded_r bytea;
    scalar_s numeric;
    challenge numeric;
    public_point numeric[];
    r_point numeric[];
    left_point numeric[];
    right_point numeric[];
BEGIN
    IF octet_length(public_key) <> 32 OR octet_length(signature) <> 64 THEN
        RETURN false;
    END IF;
    encoded_r := substring(signature FROM 1 FOR 32);
    scalar_s := plugin_webhook_le_numeric_084(substring(signature FROM 33 FOR 32));
    IF scalar_s >= group_order THEN
        RETURN false;
    END IF;
    public_point := plugin_webhook_ed25519_decode_084(public_key);
    r_point := plugin_webhook_ed25519_decode_084(encoded_r);
    IF public_point IS NULL OR r_point IS NULL OR
       NOT plugin_webhook_ed25519_prime_order_point_084(public_point) OR
       NOT plugin_webhook_ed25519_prime_order_point_084(r_point) THEN
        RETURN false;
    END IF;
    challenge := mod(plugin_webhook_le_numeric_084(sha512(encoded_r || public_key || message)),
        group_order);
    left_point := plugin_webhook_ed25519_scalarmult_084(base_point, scalar_s);
    right_point := plugin_webhook_ed25519_add_084(
        r_point, plugin_webhook_ed25519_scalarmult_084(public_point, challenge)
    );
    RETURN plugin_webhook_mod_084(
               left_point[1] * right_point[3] - right_point[1] * left_point[3], field_modulus
           ) = 0 AND
           plugin_webhook_mod_084(
               left_point[2] * right_point[3] - right_point[2] * left_point[3], field_modulus
           ) = 0;
END;
$$;

CREATE FUNCTION plugin_webhook_u32be_084(value integer)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT CASE WHEN value < 0 THEN NULL
        ELSE decode(lpad(to_hex(value), 8, '0'), 'hex') END;
$$;

CREATE FUNCTION plugin_webhook_attestation_frame_084(fields bytea[])
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
DECLARE
    field bytea;
    framed bytea := ''::bytea;
BEGIN
    FOREACH field IN ARRAY fields LOOP
        field := COALESCE(field, ''::bytea);
        framed := framed || plugin_webhook_u32be_084(octet_length(field)) || field;
    END LOOP;
    RETURN framed;
END;
$$;

CREATE FUNCTION plugin_webhook_outbox_attestation_sha256_084(
    attestation_generation numeric,
    key_id text,
    nats_domain text,
    tenant_scope_id uuid,
    subscription_id uuid,
    delivery_id uuid,
    event_id uuid,
    outbox_id uuid,
    lease_token uuid,
    publish_attempt numeric,
    stream text,
    stream_created_unix_nano numeric,
    subject text,
    sequence numeric,
    message_id text,
    queue_body_sha256 bytea,
    expected_last_subject_sequence numeric
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT sha256(plugin_webhook_attestation_frame_084(ARRAY[
        convert_to('cdnca.plugin-webhook.nats-publication/outbox/v1', 'UTF8'),
        convert_to(attestation_generation::text, 'UTF8'),
        convert_to(key_id, 'UTF8'),
        convert_to(nats_domain, 'UTF8'),
        convert_to(tenant_scope_id::text, 'UTF8'),
        convert_to(subscription_id::text, 'UTF8'),
        convert_to(delivery_id::text, 'UTF8'),
        convert_to(event_id::text, 'UTF8'),
        convert_to(outbox_id::text, 'UTF8'),
        convert_to(lease_token::text, 'UTF8'),
        convert_to(publish_attempt::text, 'UTF8'),
        convert_to(stream, 'UTF8'),
        convert_to(stream_created_unix_nano::text, 'UTF8'),
        convert_to(subject, 'UTF8'),
        convert_to(sequence::text, 'UTF8'),
        convert_to(message_id, 'UTF8'),
        convert_to(encode(queue_body_sha256, 'hex'), 'UTF8'),
        convert_to(expected_last_subject_sequence::text, 'UTF8')
    ]));
$$;

CREATE FUNCTION plugin_webhook_dead_letter_attestation_sha256_084(
    attestation_generation numeric,
    key_id text,
    nats_domain text,
    tenant_scope_id uuid,
    subscription_id uuid,
    delivery_id uuid,
    event_id uuid,
    dead_letter_id uuid,
    reconcile_generation uuid,
    reconcile_phase text,
    reconcile_high_watermark numeric,
    reconcile_scan_boundary numeric,
    reconcile_cursor numeric,
    stream text,
    stream_created_unix_nano numeric,
    subject text,
    sequence numeric,
    message_id text,
    semantic_payload_sha256 bytea,
    wire_body_sha256 bytea,
    expected_last_stream_sequence numeric
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
    SELECT sha256(plugin_webhook_attestation_frame_084(ARRAY[
        convert_to('cdnca.plugin-webhook.nats-publication/dead-letter/v1', 'UTF8'),
        convert_to(attestation_generation::text, 'UTF8'),
        convert_to(key_id, 'UTF8'),
        convert_to(nats_domain, 'UTF8'),
        convert_to(tenant_scope_id::text, 'UTF8'),
        convert_to(subscription_id::text, 'UTF8'),
        convert_to(delivery_id::text, 'UTF8'),
        convert_to(event_id::text, 'UTF8'),
        convert_to(dead_letter_id::text, 'UTF8'),
        convert_to(reconcile_generation::text, 'UTF8'),
        convert_to(reconcile_phase, 'UTF8'),
        convert_to(COALESCE(reconcile_high_watermark::text, ''), 'UTF8'),
        convert_to(COALESCE(reconcile_scan_boundary::text, ''), 'UTF8'),
        convert_to(COALESCE(reconcile_cursor::text, ''), 'UTF8'),
        convert_to(stream, 'UTF8'),
        convert_to(stream_created_unix_nano::text, 'UTF8'),
        convert_to(subject, 'UTF8'),
        convert_to(sequence::text, 'UTF8'),
        convert_to(message_id, 'UTF8'),
        convert_to(encode(semantic_payload_sha256, 'hex'), 'UTF8'),
        convert_to(encode(wire_body_sha256, 'hex'), 'UTF8'),
        convert_to(expected_last_stream_sequence::text, 'UTF8')
    ]));
$$;

DO $$
DECLARE
    schema_name text := current_schema();
BEGIN
    EXECUTE format(
        'ALTER FUNCTION %I.plugin_webhook_ed25519_verify_084(bytea,bytea,bytea) SET search_path = %I, pg_catalog',
        schema_name, schema_name
    );
    EXECUTE format(
        'ALTER FUNCTION %I.plugin_webhook_attestation_frame_084(bytea[]) SET search_path = %I, pg_catalog',
        schema_name, schema_name
    );
    EXECUTE format(
        'ALTER FUNCTION %I.plugin_webhook_outbox_attestation_sha256_084(numeric,text,text,uuid,uuid,uuid,uuid,uuid,uuid,numeric,text,numeric,text,numeric,text,bytea,numeric) SET search_path = %I, pg_catalog',
        schema_name, schema_name
    );
    EXECUTE format(
        'ALTER FUNCTION %I.plugin_webhook_dead_letter_attestation_sha256_084(numeric,text,text,uuid,uuid,uuid,uuid,uuid,uuid,text,numeric,numeric,numeric,text,numeric,text,numeric,text,bytea,bytea,numeric) SET search_path = %I, pg_catalog',
        schema_name, schema_name
    );
END;
$$;

CREATE TABLE plugin_webhook_runtime_attestation_keys (
    key_generation numeric(20,0) PRIMARY KEY CHECK (
        key_generation = trunc(key_generation) AND key_generation > 0 AND
        key_generation <= 18446744073709551615
    ),
    key_id text NOT NULL UNIQUE CHECK (
        char_length(key_id) BETWEEN 1 AND 128 AND
        key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    public_key bytea NOT NULL CHECK (
        octet_length(public_key) = 32 AND
        COALESCE(plugin_webhook_ed25519_prime_order_point_084(
            plugin_webhook_ed25519_decode_084(public_key)
        ), false)
    ),
    status text NOT NULL CHECK (status IN ('active', 'retired')),
    not_before timestamptz NOT NULL CHECK (isfinite(not_before)),
    expires_at timestamptz NOT NULL CHECK (isfinite(expires_at) AND expires_at > not_before),
    installed_at timestamptz NOT NULL DEFAULT clock_timestamp() CHECK (isfinite(installed_at)),
    retired_at timestamptz CHECK (
        retired_at IS NULL OR (isfinite(retired_at) AND retired_at >= installed_at)
    ),
    UNIQUE (key_generation, key_id),
    UNIQUE (key_generation, key_id, public_key, status, not_before, expires_at),
    CHECK ((status = 'active' AND retired_at IS NULL) OR
           (status = 'retired' AND retired_at IS NOT NULL))
);

CREATE TABLE plugin_webhook_runtime_attestation_head (
    singleton boolean PRIMARY KEY CHECK (singleton),
    key_generation numeric(20,0) NOT NULL UNIQUE CHECK (
        key_generation = trunc(key_generation) AND key_generation > 0 AND
        key_generation <= 18446744073709551615
    ),
    key_id text NOT NULL UNIQUE,
    public_key bytea NOT NULL,
    status text NOT NULL CHECK (status = 'active'),
    not_before timestamptz NOT NULL CHECK (isfinite(not_before)),
    expires_at timestamptz NOT NULL CHECK (isfinite(expires_at) AND expires_at > not_before),
    nats_domain text NOT NULL CHECK (
        octet_length(nats_domain) <= 128 AND nats_domain ~ '^[A-Za-z0-9_-]*$'
    ),
    delivery_stream text NOT NULL CHECK (
        char_length(delivery_stream) BETWEEN 1 AND 128 AND
        delivery_stream ~ '^[A-Za-z0-9_-]+$'
    ),
    delivery_subject_prefix text NOT NULL CHECK (
        char_length(delivery_subject_prefix) BETWEEN 1 AND 240 AND
        delivery_subject_prefix ~ '^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$'
    ),
    dead_letter_stream text NOT NULL CHECK (dead_letter_stream = 'PLUGIN_WEBHOOK_DLQ'),
    dead_letter_subject text NOT NULL CHECK (
        dead_letter_subject = 'cdnca.plugin-webhook.dead-letter.v1'
    ),
    advanced_at timestamptz NOT NULL DEFAULT clock_timestamp() CHECK (isfinite(advanced_at)),
    FOREIGN KEY (key_generation, key_id, public_key, status, not_before, expires_at)
        REFERENCES plugin_webhook_runtime_attestation_keys(
            key_generation, key_id, public_key, status, not_before, expires_at
        ) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE FUNCTION guard_plugin_webhook_runtime_attestation_key_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    head_generation numeric(20,0);
BEGIN
    IF TG_OP = 'INSERT' THEN
        SELECT key_generation INTO head_generation
        FROM plugin_webhook_runtime_attestation_head WHERE singleton = true FOR UPDATE;
        IF NEW.status <> 'active' OR NEW.retired_at IS NOT NULL OR
           NEW.key_generation <> COALESCE(head_generation + 1, 1) THEN
            RAISE EXCEPTION 'plugin webhook runtime attestation key advance is invalid'
                USING ERRCODE = 'P8408';
        END IF;
        NEW.installed_at := clock_timestamp();
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.status = 'active' AND NEW.status = 'retired' AND
       ROW(NEW.key_generation, NEW.key_id, NEW.public_key, NEW.not_before, NEW.expires_at,
           NEW.installed_at) IS NOT DISTINCT FROM
       ROW(OLD.key_generation, OLD.key_id, OLD.public_key, OLD.not_before, OLD.expires_at,
           OLD.installed_at) THEN
        NEW.retired_at := clock_timestamp();
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'plugin webhook runtime attestation key history is immutable'
        USING ERRCODE = 'P8408';
END;
$$;

CREATE FUNCTION guard_plugin_webhook_runtime_attestation_head_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    old_key_status text;
    new_key_status text;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.singleton IS DISTINCT FROM true OR NEW.key_generation <> 1 THEN
            RAISE EXCEPTION 'plugin webhook runtime attestation head bootstrap is invalid'
                USING ERRCODE = 'P8408';
        END IF;
    ELSIF TG_OP = 'UPDATE' THEN
        SELECT status INTO old_key_status FROM plugin_webhook_runtime_attestation_keys
        WHERE key_generation = OLD.key_generation FOR SHARE;
        IF NEW.singleton IS DISTINCT FROM OLD.singleton OR
           NEW.key_generation <> OLD.key_generation + 1 OR
           ROW(NEW.nats_domain, NEW.delivery_stream, NEW.delivery_subject_prefix,
               NEW.dead_letter_stream, NEW.dead_letter_subject) IS DISTINCT FROM
           ROW(OLD.nats_domain, OLD.delivery_stream, OLD.delivery_subject_prefix,
               OLD.dead_letter_stream, OLD.dead_letter_subject) OR
           old_key_status IS DISTINCT FROM 'retired' THEN
            RAISE EXCEPTION 'plugin webhook runtime attestation head advance is invalid'
                USING ERRCODE = 'P8408';
        END IF;
    ELSE
        RAISE EXCEPTION 'plugin webhook runtime attestation head is immutable'
            USING ERRCODE = 'P8408';
    END IF;
    SELECT status INTO new_key_status FROM plugin_webhook_runtime_attestation_keys
    WHERE key_generation = NEW.key_generation AND key_id = NEW.key_id AND
          public_key = NEW.public_key AND not_before = NEW.not_before AND
          expires_at = NEW.expires_at FOR SHARE;
    IF new_key_status IS DISTINCT FROM 'active' THEN
        RAISE EXCEPTION 'plugin webhook runtime attestation head key is not active'
            USING ERRCODE = 'P8408';
    END IF;
    NEW.status := 'active';
    NEW.advanced_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_plugin_webhook_runtime_attestation_head_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    active_count bigint;
    current_generation numeric(20,0);
    maximum_generation numeric(20,0);
BEGIN
    SELECT count(*) FILTER (WHERE status = 'active'), max(key_generation)
      INTO active_count, maximum_generation
    FROM plugin_webhook_runtime_attestation_keys;
    SELECT key_generation INTO current_generation
    FROM plugin_webhook_runtime_attestation_head WHERE singleton = true;
    IF active_count <> 1 OR current_generation IS NULL OR
       current_generation IS DISTINCT FROM maximum_generation OR NOT EXISTS (
           SELECT 1 FROM plugin_webhook_runtime_attestation_keys key
           JOIN plugin_webhook_runtime_attestation_head head
             ON head.key_generation = key.key_generation AND head.key_id = key.key_id
            AND head.public_key = key.public_key AND head.status = key.status
            AND head.not_before = key.not_before AND head.expires_at = key.expires_at
           WHERE head.singleton = true AND key.status = 'active'
       ) THEN
        RAISE EXCEPTION 'plugin webhook runtime attestation head is not exact'
            USING ERRCODE = 'P8408';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION prevent_plugin_webhook_runtime_attestation_truncate_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'plugin webhook runtime attestation trust cannot be truncated'
        USING ERRCODE = 'P8408';
END;
$$;

CREATE TRIGGER plugin_webhook_runtime_attestation_keys_guard_084
BEFORE INSERT OR UPDATE OR DELETE ON plugin_webhook_runtime_attestation_keys
FOR EACH ROW EXECUTE FUNCTION guard_plugin_webhook_runtime_attestation_key_084();
CREATE CONSTRAINT TRIGGER plugin_webhook_runtime_attestation_keys_validate_084
AFTER INSERT OR UPDATE ON plugin_webhook_runtime_attestation_keys
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_runtime_attestation_head_084();
CREATE TRIGGER plugin_webhook_runtime_attestation_keys_truncate_084
BEFORE TRUNCATE ON plugin_webhook_runtime_attestation_keys
FOR EACH STATEMENT EXECUTE FUNCTION prevent_plugin_webhook_runtime_attestation_truncate_084();
CREATE TRIGGER plugin_webhook_runtime_attestation_head_guard_084
BEFORE INSERT OR UPDATE OR DELETE ON plugin_webhook_runtime_attestation_head
FOR EACH ROW EXECUTE FUNCTION guard_plugin_webhook_runtime_attestation_head_084();
CREATE CONSTRAINT TRIGGER plugin_webhook_runtime_attestation_head_validate_084
AFTER INSERT OR UPDATE ON plugin_webhook_runtime_attestation_head
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_runtime_attestation_head_084();
CREATE TRIGGER plugin_webhook_runtime_attestation_head_truncate_084
BEFORE TRUNCATE ON plugin_webhook_runtime_attestation_head
FOR EACH STATEMENT EXECUTE FUNCTION prevent_plugin_webhook_runtime_attestation_truncate_084();

CREATE TABLE entitlement_signing_keyset_current_keys (
    key_id text PRIMARY KEY,
    public_key bytea NOT NULL,
    status text NOT NULL,
    not_before timestamptz,
    sign_until timestamptz,
    verify_until timestamptz,
    keyset_payload_sha256 bytea NOT NULL,
    accepted_at timestamptz NOT NULL,
    CONSTRAINT entitlement_signing_keyset_current_keys_key_id_084 CHECK (
        char_length(key_id) BETWEEN 1 AND 128 AND
        key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    CONSTRAINT entitlement_signing_keyset_current_keys_public_key_084 CHECK (
        octet_length(public_key) = 32 AND
        COALESCE(plugin_webhook_ed25519_prime_order_point_084(
            plugin_webhook_ed25519_decode_084(public_key)
        ), false)
    ),
    CONSTRAINT entitlement_signing_keyset_current_keys_status_084 CHECK (
        status IN ('active', 'verify_only', 'retired')
    ),
    CONSTRAINT entitlement_signing_keyset_current_keys_windows_084 CHECK (
        (not_before IS NULL OR isfinite(not_before)) AND
        (sign_until IS NULL OR isfinite(sign_until)) AND
        (verify_until IS NULL OR isfinite(verify_until)) AND
        (not_before IS NULL OR sign_until IS NULL OR sign_until > not_before) AND
        (sign_until IS NULL OR verify_until IS NULL OR verify_until >= sign_until)
    ),
    CONSTRAINT entitlement_signing_keyset_current_keys_digest_084 CHECK (
        octet_length(keyset_payload_sha256) = 32
    ),
    CONSTRAINT entitlement_signing_keyset_current_keys_accepted_at_084 CHECK (
        isfinite(accepted_at)
    )
);

CREATE FUNCTION plugin_webhook_canonical_u64_token_084(value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT value ~ '^(0|[1-9][0-9]*)$' AND
        (char_length(value) < 20 OR
         (char_length(value) = 20 AND value <= '18446744073709551615'));
$$;

CREATE TABLE control_entitlement_revocation_lkg (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    installation_id text NOT NULL UNIQUE CHECK (
        char_length(installation_id) BETWEEN 1 AND 128 AND
        installation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ) REFERENCES control_installation_entitlement(installation_id) ON DELETE RESTRICT,
    customer_id text NOT NULL CHECK (char_length(customer_id) BETWEEN 1 AND 128),
    license_id text NOT NULL CHECK (char_length(license_id) BETWEEN 1 AND 128),
    revision bigint NOT NULL CHECK (revision > 0),
    key_id text NOT NULL CHECK (
        char_length(key_id) BETWEEN 1 AND 128 AND
        key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    artifact bytea NOT NULL CHECK (octet_length(artifact) BETWEEN 1 AND 1048576),
    artifact_sha256 bytea NOT NULL CHECK (octet_length(artifact_sha256) = 32),
    artifact_etag text NOT NULL CHECK (artifact_etag ~ '^"sha256-[A-Za-z0-9_-]{43}"$'),
    issued_at timestamptz NOT NULL CHECK (isfinite(issued_at)),
    expires_at timestamptz NOT NULL CHECK (isfinite(expires_at) AND expires_at > issued_at),
    accepted_at timestamptz NOT NULL CHECK (isfinite(accepted_at)),
    CHECK (accepted_at >= issued_at AND accepted_at < expires_at)
);

CREATE TABLE control_entitlement_revoked_serials (
    installation_id text NOT NULL
        REFERENCES control_installation_entitlement(installation_id) ON DELETE RESTRICT,
    license_id text NOT NULL CHECK (char_length(license_id) BETWEEN 1 AND 128),
    serial bigint NOT NULL CHECK (serial > 0),
    first_revision bigint NOT NULL CHECK (first_revision > 0),
    first_artifact_sha256 bytea NOT NULL CHECK (octet_length(first_artifact_sha256) = 32),
    recorded_at timestamptz NOT NULL CHECK (isfinite(recorded_at)),
    PRIMARY KEY (installation_id, license_id, serial)
);

CREATE FUNCTION guard_control_entitlement_revocation_lkg_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    installation_row text;
    previous_lkg control_entitlement_revocation_lkg%ROWTYPE;
    document jsonb;
    body jsonb;
    raw_document json;
    raw_body json;
    raw_item json;
    serial_value numeric;
    previous_serial numeric := 0;
    physical_now timestamptz;
    canonical_serials text;
    canonical_body text;
    canonical_artifact bytea;
    signing_document bytea;
    signature_text text;
    signature_bytes bytea;
    revocation_public_key bytea;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'entitlement revocation LKG cannot be deleted'
            USING ERRCODE = 'P8408';
    END IF;
    SELECT installation_id INTO installation_row
    FROM control_installation_entitlement WHERE singleton = true FOR UPDATE;
    IF installation_row IS NULL OR NEW.singleton IS DISTINCT FROM true OR
       NEW.installation_id IS DISTINCT FROM installation_row THEN
        RAISE EXCEPTION 'entitlement revocation LKG installation binding is invalid'
            USING ERRCODE = 'P8408';
    END IF;
    IF sha256(NEW.artifact) IS DISTINCT FROM NEW.artifact_sha256 OR
       NEW.artifact_etag IS DISTINCT FROM '"sha256-' ||
           rtrim(translate(encode(NEW.artifact_sha256, 'base64'), '+/', '-_'), '=') || '"' THEN
        RAISE EXCEPTION 'entitlement revocation LKG artifact digest is invalid'
            USING ERRCODE = 'P8408';
    END IF;
    BEGIN
        raw_document := convert_from(NEW.artifact, 'UTF8')::json;
        raw_body := raw_document->'body';
        document := convert_from(NEW.artifact, 'UTF8')::jsonb;
        body := document->'body';
        IF jsonb_typeof(document) <> 'object' OR
           document->>'algorithm' <> 'Ed25519' OR
           document->>'key_id' IS DISTINCT FROM NEW.key_id OR
           jsonb_typeof(body) <> 'object' OR
           body->>'schema' <> 'cdnca.entitlement.revocation-set/v2' OR
           body->>'audience' <> 'cdnca-control-plane' OR
           body->>'customer_id' IS DISTINCT FROM NEW.customer_id OR
           body->>'installation_id' IS DISTINCT FROM NEW.installation_id OR
           body->>'license_id' IS DISTINCT FROM NEW.license_id OR
           NOT plugin_webhook_canonical_u64_token_084(raw_body->>'revision') OR
           (raw_body->>'revision')::numeric IS DISTINCT FROM NEW.revision OR
           (body->>'issued_at')::numeric IS DISTINCT FROM extract(epoch FROM NEW.issued_at) OR
           (body->>'expires_at')::numeric IS DISTINCT FROM extract(epoch FROM NEW.expires_at) OR
           jsonb_typeof(body->'revoked_serials') <> 'array' OR
           jsonb_array_length(body->'revoked_serials') > 65536 OR
           NEW.customer_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR
           NEW.installation_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR
           NEW.license_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR
           NEW.customer_id = '00000000-0000-0000-0000-000000000000' OR
           NEW.installation_id = '00000000-0000-0000-0000-000000000000' OR
           NEW.license_id = '00000000-0000-0000-0000-000000000000' OR
           NEW.revision > 9223372036854775807 OR
           extract(epoch FROM NEW.issued_at) <= 0 OR
           extract(epoch FROM NEW.expires_at) > 253402300799 OR
           extract(epoch FROM NEW.expires_at) - extract(epoch FROM NEW.issued_at) <> 900 THEN
            RAISE EXCEPTION 'invalid entitlement revocation artifact body';
        END IF;
        FOR raw_item IN SELECT value FROM json_array_elements(raw_body->'revoked_serials') LOOP
            IF json_typeof(raw_item) <> 'number' OR
               NOT plugin_webhook_canonical_u64_token_084(raw_item #>> '{}') THEN
                RAISE EXCEPTION 'invalid entitlement revocation serial';
            END IF;
            serial_value := (raw_item #>> '{}')::numeric;
            IF serial_value <= 0 OR serial_value > 9223372036854775807 OR
               serial_value <= previous_serial OR serial_value <> trunc(serial_value) THEN
                RAISE EXCEPTION 'entitlement revocation serials must be positive and sorted';
            END IF;
            previous_serial := serial_value;
        END LOOP;
        SELECT COALESCE(string_agg(value #>> '{}', ',' ORDER BY ordinality), '')
          INTO canonical_serials
        FROM json_array_elements(raw_body->'revoked_serials') WITH ORDINALITY AS item(value, ordinality);
        canonical_body :=
            '{"schema":' || to_json(body->>'schema')::text ||
            ',"audience":' || to_json(body->>'audience')::text ||
            ',"customer_id":' || to_json(body->>'customer_id')::text ||
            ',"installation_id":' || to_json(body->>'installation_id')::text ||
            ',"license_id":' || to_json(body->>'license_id')::text ||
            ',"revision":' || NEW.revision::text ||
            ',"issued_at":' || extract(epoch FROM NEW.issued_at)::bigint::text ||
            ',"expires_at":' || extract(epoch FROM NEW.expires_at)::bigint::text ||
            ',"revoked_serials":[' || canonical_serials || ']}';
        signature_text := document->>'signature';
        IF signature_text IS NULL OR signature_text !~ '^[A-Za-z0-9_-]{86}$' THEN
            RAISE EXCEPTION 'invalid entitlement revocation signature encoding';
        END IF;
        signature_bytes := decode(translate(signature_text, '-_', '+/') || '==', 'base64');
        IF octet_length(signature_bytes) <> 64 OR
           replace(rtrim(translate(encode(signature_bytes, 'base64'), '+/', '-_'), '='),
               E'\n', '') <> signature_text THEN
            RAISE EXCEPTION 'invalid entitlement revocation signature encoding';
        END IF;
        canonical_artifact := convert_to(
            '{"algorithm":"Ed25519","key_id":' || to_json(NEW.key_id)::text ||
            ',"body":' || canonical_body || ',"signature":' || to_json(signature_text)::text || '}',
            'UTF8'
        );
        IF canonical_artifact IS DISTINCT FROM NEW.artifact THEN
            RAISE EXCEPTION 'entitlement revocation artifact is not canonical';
        END IF;
        signing_document := convert_to(
            '{"domain":"cdnca-entitlement-revocation-set-signature/v2",' ||
            '"algorithm":"Ed25519","key_id":' || to_json(NEW.key_id)::text ||
            ',"body":' || canonical_body || '}', 'UTF8'
        );
        SELECT projected_key.public_key INTO revocation_public_key
        FROM entitlement_signing_keyset_current_keys projected_key
        JOIN entitlement_signing_keyset_lkg keyset
          ON keyset.singleton = true
         AND keyset.payload_sha256 = projected_key.keyset_payload_sha256
         AND keyset.accepted_at = projected_key.accepted_at
        WHERE projected_key.key_id = NEW.key_id
          AND projected_key.status IN ('active', 'verify_only')
          AND projected_key.not_before IS NOT NULL
          AND projected_key.not_before <= NEW.issued_at
          AND (projected_key.sign_until IS NULL OR
               projected_key.sign_until >= NEW.expires_at)
          AND (projected_key.verify_until IS NULL OR
               projected_key.verify_until >= NEW.expires_at)
        FOR SHARE OF projected_key, keyset;
        IF revocation_public_key IS NULL OR NOT plugin_webhook_ed25519_verify_084(
            revocation_public_key, signing_document, signature_bytes
        ) THEN
            RAISE EXCEPTION 'entitlement revocation signature is invalid';
        END IF;
    EXCEPTION WHEN others THEN
        RAISE EXCEPTION 'entitlement revocation LKG artifact is not canonical and valid'
            USING ERRCODE = 'P8408';
    END;
    physical_now := clock_timestamp();
    IF TG_OP = 'UPDATE' THEN
        SELECT * INTO previous_lkg FROM control_entitlement_revocation_lkg
        WHERE singleton = true FOR UPDATE;
        IF NEW.installation_id IS DISTINCT FROM previous_lkg.installation_id OR
           NEW.customer_id IS DISTINCT FROM previous_lkg.customer_id OR
           NEW.license_id IS DISTINCT FROM previous_lkg.license_id OR
           NEW.revision < previous_lkg.revision OR
           (NEW.revision = previous_lkg.revision AND
            (NEW.artifact IS DISTINCT FROM previous_lkg.artifact OR
             NEW.artifact_sha256 IS DISTINCT FROM previous_lkg.artifact_sha256)) OR
           (NEW.revision > previous_lkg.revision AND NEW.issued_at <= previous_lkg.issued_at) THEN
            RAISE EXCEPTION 'entitlement revocation LKG revision is not monotonic'
                USING ERRCODE = 'P8408';
        END IF;
        IF NEW.revision = previous_lkg.revision THEN
            RETURN previous_lkg;
        END IF;
        IF EXISTS (
            SELECT 1 FROM control_entitlement_revoked_serials revoked
            WHERE revoked.installation_id = NEW.installation_id
              AND revoked.license_id = NEW.license_id
              AND NOT EXISTS (
                  SELECT 1 FROM jsonb_array_elements(body->'revoked_serials') value
                  WHERE (value #>> '{}')::numeric = revoked.serial
              )
        ) THEN
            RAISE EXCEPTION 'entitlement revocation LKG cannot shrink its revoked serial set'
                USING ERRCODE = 'P8408';
        END IF;
    END IF;
    IF physical_now < NEW.issued_at OR physical_now >= NEW.expires_at THEN
        RAISE EXCEPTION 'entitlement revocation LKG is outside its physical validity window'
            USING ERRCODE = 'P8408';
    END IF;
    NEW.accepted_at := physical_now;
    RETURN NEW;
END;
$$;

CREATE TRIGGER control_entitlement_revocation_lkg_guard_084
BEFORE INSERT OR UPDATE OR DELETE ON control_entitlement_revocation_lkg
FOR EACH ROW EXECUTE FUNCTION guard_control_entitlement_revocation_lkg_084();

CREATE FUNCTION guard_control_entitlement_revocation_serial_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'entitlement revoked serial facts are append-only'
            USING ERRCODE = 'P8408';
    END IF;
    NEW.recorded_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER control_entitlement_revoked_serials_guard_084
BEFORE INSERT OR UPDATE OR DELETE ON control_entitlement_revoked_serials
FOR EACH ROW EXECUTE FUNCTION guard_control_entitlement_revocation_serial_084();

CREATE FUNCTION assert_control_entitlement_revocation_serial_projection_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    lkg control_entitlement_revocation_lkg%ROWTYPE;
    body jsonb;
BEGIN
    SELECT * INTO lkg FROM control_entitlement_revocation_lkg
    WHERE singleton = true FOR UPDATE;
    IF lkg.singleton IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'entitlement revocation serial projection has no current artifact'
            USING ERRCODE = 'P8408';
    END IF;
    body := (convert_from(lkg.artifact, 'UTF8')::jsonb)->'body';
    IF TG_TABLE_NAME = 'control_entitlement_revoked_serials' AND TG_OP = 'INSERT' THEN
        IF NEW.installation_id IS DISTINCT FROM lkg.installation_id OR
           NEW.license_id IS DISTINCT FROM lkg.license_id OR
           NEW.first_revision IS DISTINCT FROM lkg.revision OR
           NEW.first_artifact_sha256 IS DISTINCT FROM lkg.artifact_sha256 OR
           NOT EXISTS (
               SELECT 1 FROM jsonb_array_elements(body->'revoked_serials') value
               WHERE (value #>> '{}')::numeric = NEW.serial
           ) THEN
            RAISE EXCEPTION 'entitlement revoked serial provenance is invalid'
                USING ERRCODE = 'P8408';
        END IF;
    END IF;
    IF EXISTS (
        SELECT (value #>> '{}')::bigint AS serial
        FROM jsonb_array_elements(body->'revoked_serials') value
        EXCEPT
        SELECT revoked.serial
        FROM control_entitlement_revoked_serials revoked
        WHERE revoked.installation_id = lkg.installation_id
          AND revoked.license_id = lkg.license_id
    ) OR EXISTS (
        SELECT revoked.serial
        FROM control_entitlement_revoked_serials revoked
        EXCEPT
        SELECT (value #>> '{}')::bigint
        FROM jsonb_array_elements(body->'revoked_serials') value
    ) THEN
        RAISE EXCEPTION 'entitlement revocation artifact and serial projection differ'
            USING ERRCODE = 'P8408';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER control_entitlement_revocation_lkg_serials_complete_084
AFTER INSERT OR UPDATE ON control_entitlement_revocation_lkg
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_control_entitlement_revocation_serial_projection_084();
CREATE CONSTRAINT TRIGGER control_entitlement_revoked_serials_complete_084
AFTER INSERT ON control_entitlement_revoked_serials
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_control_entitlement_revocation_serial_projection_084();

CREATE FUNCTION prevent_control_entitlement_revocation_truncate_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'entitlement revocation facts cannot be truncated'
        USING ERRCODE = 'P8408';
END;
$$;

CREATE TRIGGER control_entitlement_revocation_lkg_truncate_084
BEFORE TRUNCATE ON control_entitlement_revocation_lkg
FOR EACH STATEMENT EXECUTE FUNCTION prevent_control_entitlement_revocation_truncate_084();
CREATE TRIGGER control_entitlement_revoked_serials_truncate_084
BEFORE TRUNCATE ON control_entitlement_revoked_serials
FOR EACH STATEMENT EXECUTE FUNCTION prevent_control_entitlement_revocation_truncate_084();

CREATE FUNCTION guard_control_entitlement_cached_lease_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM control_entitlement_revoked_serials revoked
        WHERE revoked.installation_id = NEW.installation_id
          AND revoked.license_id = NEW.license_id
          AND revoked.serial = NEW.serial
    ) AND NEW.status <> 'revoked' THEN
        RAISE EXCEPTION 'revoked entitlement serial cannot be replayed as valid'
            USING ERRCODE = 'P8408';
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.status = 'revoked' AND NEW.status <> 'revoked' THEN
        RAISE EXCEPTION 'revoked entitlement serial cannot be unrevoked'
            USING ERRCODE = 'P8408';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER entitlement_cached_leases_revocation_guard_084
BEFORE INSERT OR UPDATE ON entitlement_cached_leases
FOR EACH ROW EXECUTE FUNCTION guard_control_entitlement_cached_lease_084();

INSERT INTO permissions(name, description) VALUES
    ('plugin_webhooks.read', 'Read tenant outbound webhook subscriptions and deliveries'),
    ('plugin_webhooks.manage', 'Create test rotate replay and revoke tenant outbound webhooks');

CREATE TABLE plugin_webhook_rbac_catalog_additions_084 (
    permission_name text PRIMARY KEY CHECK (
        permission_name IN ('plugin_webhooks.read', 'plugin_webhooks.manage')
    ),
    source_migration smallint NOT NULL DEFAULT 84 CHECK (source_migration = 84),
    FOREIGN KEY (permission_name)
        REFERENCES custom_rbac_permission_catalog(permission_name) ON DELETE RESTRICT
);

WITH additions AS (
    INSERT INTO custom_rbac_permission_catalog(permission_name, step_up_required) VALUES
        ('plugin_webhooks.read', false),
        ('plugin_webhooks.manage', false)
    RETURNING permission_name
)
INSERT INTO plugin_webhook_rbac_catalog_additions_084(permission_name)
SELECT permission_name FROM additions;

CREATE TABLE plugin_webhook_rbac_grant_additions_084 (
    role_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    permission_name text NOT NULL CHECK (
        permission_name IN ('plugin_webhooks.read', 'plugin_webhooks.manage')
    ),
    source_migration smallint NOT NULL DEFAULT 84 CHECK (source_migration = 84),
    PRIMARY KEY (role_id, permission_name),
    FOREIGN KEY (scope_id, role_id)
        REFERENCES roles(scope_id, id) ON DELETE RESTRICT,
    CONSTRAINT plugin_webhook_rbac_grant_role_permission_084_fk
        FOREIGN KEY (role_id, permission_name)
        REFERENCES role_permissions(role_id, permission_name) ON DELETE RESTRICT
);

CREATE OR REPLACE FUNCTION custom_rbac_effective_permissions(requested_scope_id uuid, requested_user_id uuid)
RETURNS TABLE(permission_name text)
LANGUAGE sql
STABLE
AS $$
    SELECT DISTINCT effective.permission_name
    FROM (
        SELECT role_permission.permission_name
        FROM access_scopes scope
        JOIN tenants tenant ON tenant.id = scope.tenant_id AND tenant.status = 'active'
        JOIN memberships membership
          ON membership.scope_id = scope.id AND membership.user_id = requested_user_id
         AND membership.status = 'active'
        JOIN users account ON account.id = membership.user_id AND account.status = 'active'
        JOIN role_assignments assignment
          ON assignment.scope_id = scope.id AND assignment.user_id = membership.user_id
        JOIN roles role ON role.id = assignment.role_id AND role.scope_id = scope.id
        JOIN role_permissions role_permission ON role_permission.role_id = role.id
        WHERE scope.id = requested_scope_id AND scope.kind = 'tenant'
          AND role_permission.permission_name NOT IN (
              'platform.admin', 'identity.impersonation.manage', 'billing.adjustments.manage',
              'api_keys.admin.manage', 'packages.manage', 'nodes.read', 'nodes.manage',
              'control.upgrades.check', 'node_ca.manage', 'system_configuration.read',
              'system_configuration.manage'
          )
          AND (
              role_permission.permission_name NOT IN (
                  'package_subscriptions.read', 'package_subscriptions.manage',
                  'plugin_webhooks.read', 'plugin_webhooks.manage'
              ) OR
              (role.system_role AND role.name = 'tenant_owner') OR
              (role.system_role AND role.name = 'tenant_viewer' AND
               role_permission.permission_name = 'package_subscriptions.read') OR
              (role.system_role AND role.name IN ('tenant_owner', 'tenant_admin') AND
               role_permission.permission_name IN ('plugin_webhooks.read', 'plugin_webhooks.manage')) OR
              (role.system_role AND role.name IN ('tenant_member', 'tenant_viewer') AND
               role_permission.permission_name = 'plugin_webhooks.read')
          )
        UNION ALL
        SELECT custom_permission.permission_name
        FROM access_scopes scope
        JOIN tenants tenant ON tenant.id = scope.tenant_id AND tenant.status = 'active'
        JOIN memberships membership
          ON membership.scope_id = scope.id AND membership.user_id = requested_user_id
         AND membership.status = 'active'
        JOIN users account ON account.id = membership.user_id AND account.status = 'active'
        JOIN custom_role_grants grant_row
          ON grant_row.tenant_scope_id = scope.id AND grant_row.subject_user_id = membership.user_id
        JOIN custom_roles role
          ON role.id = grant_row.role_id AND role.tenant_scope_id = scope.id
         AND role.deactivated_at IS NULL
        JOIN custom_role_revisions revision
          ON revision.role_id = role.id AND revision.revision = role.current_revision
        CROSS JOIN LATERAL unnest(revision.permissions) AS custom_permission(permission_name)
        LEFT JOIN custom_role_grant_revocations revocation ON revocation.grant_id = grant_row.id
        WHERE scope.id = requested_scope_id AND scope.kind = 'tenant' AND revocation.id IS NULL
          AND NOT (
              custom_permission.permission_name = 'package_subscriptions.manage' AND EXISTS (
                  SELECT 1
                  FROM role_assignments viewer_assignment
                  JOIN roles viewer_role
                    ON viewer_role.id = viewer_assignment.role_id
                   AND viewer_role.scope_id = scope.id
                   AND viewer_role.system_role
                   AND viewer_role.name = 'tenant_viewer'
                  WHERE viewer_assignment.scope_id = scope.id
                    AND viewer_assignment.user_id = requested_user_id
              )
          )
          AND NOT (
              custom_permission.permission_name = 'plugin_webhooks.manage' AND EXISTS (
                  SELECT 1
                  FROM role_assignments read_assignment
                  JOIN roles read_role
                    ON read_role.id = read_assignment.role_id
                   AND read_role.scope_id = scope.id
                   AND read_role.system_role
                   AND read_role.name IN ('tenant_member', 'tenant_viewer')
                  WHERE read_assignment.scope_id = scope.id
                    AND read_assignment.user_id = requested_user_id
              )
          )
    ) effective;
$$;

CREATE OR REPLACE FUNCTION guard_system_role_permission_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_role_id uuid;
    target_system_role boolean;
    target_role_name text;
    target_permission_name text;
    scope_kind text;
    protected_permission boolean;
BEGIN
    target_role_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.role_id ELSE NEW.role_id END;
    target_permission_name := CASE
        WHEN TG_OP = 'DELETE' THEN OLD.permission_name ELSE NEW.permission_name
    END;
    SELECT role.system_role, role.name, scope.kind
      INTO target_system_role, target_role_name, scope_kind
    FROM roles role JOIN access_scopes scope ON scope.id = role.scope_id
    WHERE role.id = target_role_id;
    IF NOT target_system_role THEN
        IF EXISTS (SELECT 1 FROM custom_roles WHERE id = target_role_id) AND pg_trigger_depth() < 2 THEN
            RAISE EXCEPTION 'custom role permission projection is protected';
        END IF;
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;
    SELECT EXISTS (
        SELECT 1 FROM custom_rbac_permission_catalog
        WHERE permission_name = target_permission_name
    ) INTO protected_permission;

    IF TG_OP = 'UPDATE' OR (TG_OP = 'DELETE' AND protected_permission) THEN
        RAISE EXCEPTION 'system role permissions are immutable';
    END IF;
    IF TG_OP = 'INSERT' AND scope_kind = 'tenant' AND
       (NEW.permission_name IN (
            'platform.admin', 'identity.impersonation.manage', 'billing.adjustments.manage',
            'api_keys.admin.manage', 'packages.manage', 'nodes.read', 'nodes.manage',
            'control.upgrades.check', 'node_ca.manage', 'system_configuration.read',
            'system_configuration.manage'
        ) OR
        (NEW.permission_name = 'package_subscriptions.read' AND
         target_role_name NOT IN ('tenant_owner', 'tenant_viewer')) OR
        (NEW.permission_name = 'package_subscriptions.manage' AND
         target_role_name <> 'tenant_owner') OR
        (NEW.permission_name = 'plugin_webhooks.read' AND
         target_role_name NOT IN ('tenant_owner', 'tenant_admin', 'tenant_member', 'tenant_viewer')) OR
        (NEW.permission_name = 'plugin_webhooks.manage' AND
         target_role_name NOT IN ('tenant_owner', 'tenant_admin')) OR
        (target_role_name = 'tenant_viewer' AND
         NEW.permission_name NOT LIKE '%.read' AND
         NEW.permission_name NOT IN (
             'identity.self.update', 'identity.password.change', 'api_keys.self.manage',
             'identity_verification.self.manage', 'promotions.quote', 'promotions.redeem'
         ))) THEN
        RAISE EXCEPTION 'invalid tenant system role permission';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

WITH additions AS (
    INSERT INTO role_permissions(role_id, permission_name)
    SELECT role.id, permission.name
    FROM roles role
    JOIN access_scopes scope ON scope.id = role.scope_id
    CROSS JOIN (VALUES ('plugin_webhooks.read'), ('plugin_webhooks.manage')) permission(name)
    WHERE role.system_role AND (
        (scope.kind = 'platform' AND role.name IN ('platform_owner', 'platform_admin')) OR
        (scope.kind = 'tenant' AND role.name IN ('tenant_owner', 'tenant_admin'))
    )
    ON CONFLICT DO NOTHING
    RETURNING role_id, permission_name
)
INSERT INTO plugin_webhook_rbac_grant_additions_084(role_id, scope_id, permission_name)
SELECT addition.role_id, role.scope_id, addition.permission_name
FROM additions addition JOIN roles role ON role.id = addition.role_id;

WITH additions AS (
    INSERT INTO role_permissions(role_id, permission_name)
    SELECT role.id, 'plugin_webhooks.read'
    FROM roles role JOIN access_scopes scope ON scope.id = role.scope_id
    WHERE role.system_role AND scope.kind = 'tenant'
      AND role.name IN ('tenant_member', 'tenant_viewer')
    ON CONFLICT DO NOTHING
    RETURNING role_id, permission_name
)
INSERT INTO plugin_webhook_rbac_grant_additions_084(role_id, scope_id, permission_name)
SELECT addition.role_id, role.scope_id, addition.permission_name
FROM additions addition JOIN roles role ON role.id = addition.role_id;

CREATE FUNCTION project_plugin_webhook_system_role_permissions_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_scope_kind text;
BEGIN
    IF NOT NEW.system_role THEN
        RETURN NEW;
    END IF;
    SELECT kind INTO target_scope_kind FROM access_scopes WHERE id = NEW.scope_id FOR SHARE;
    WITH additions AS (
        INSERT INTO role_permissions(role_id, permission_name)
        SELECT NEW.id, permission.name
        FROM (VALUES ('plugin_webhooks.read'), ('plugin_webhooks.manage')) permission(name)
        WHERE (target_scope_kind = 'platform' AND NEW.name IN ('platform_owner', 'platform_admin'))
           OR (target_scope_kind = 'tenant' AND NEW.name IN ('tenant_owner', 'tenant_admin'))
           OR (target_scope_kind = 'tenant' AND NEW.name IN ('tenant_member', 'tenant_viewer')
               AND permission.name = 'plugin_webhooks.read')
        ON CONFLICT DO NOTHING
        RETURNING role_id, permission_name
    )
    INSERT INTO plugin_webhook_rbac_grant_additions_084(role_id, scope_id, permission_name)
    SELECT role_id, NEW.scope_id, permission_name FROM additions;
    RETURN NEW;
END;
$$;

CREATE TRIGGER roles_project_plugin_webhook_permissions_084
AFTER INSERT ON roles
FOR EACH ROW EXECUTE FUNCTION project_plugin_webhook_system_role_permissions_084();

CREATE FUNCTION protect_plugin_webhook_rbac_provenance_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' AND pg_trigger_depth() >= 2 THEN
        RETURN NULL;
    END IF;
    RAISE EXCEPTION 'plugin webhook RBAC provenance is immutable'
        USING ERRCODE = 'P8403';
END;
$$;

CREATE TRIGGER plugin_webhook_rbac_catalog_protect_084
BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON plugin_webhook_rbac_catalog_additions_084
FOR EACH STATEMENT EXECUTE FUNCTION protect_plugin_webhook_rbac_provenance_084();
CREATE TRIGGER plugin_webhook_rbac_grants_protect_084
BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON plugin_webhook_rbac_grant_additions_084
FOR EACH STATEMENT EXECUTE FUNCTION protect_plugin_webhook_rbac_provenance_084();
ALTER TABLE plugin_webhook_rbac_catalog_additions_084
    ENABLE ALWAYS TRIGGER plugin_webhook_rbac_catalog_protect_084;
ALTER TABLE plugin_webhook_rbac_grant_additions_084
    ENABLE ALWAYS TRIGGER plugin_webhook_rbac_grants_protect_084;

CREATE FUNCTION protect_plugin_webhook_catalog_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.permission_name IN ('plugin_webhooks.read', 'plugin_webhooks.manage') THEN
        RAISE EXCEPTION 'plugin webhook RBAC catalog rows are immutable'
            USING ERRCODE = 'P8403';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER plugin_webhook_rbac_catalog_delete_guard_084
BEFORE DELETE ON custom_rbac_permission_catalog
FOR EACH ROW EXECUTE FUNCTION protect_plugin_webhook_catalog_084();
ALTER TABLE custom_rbac_permission_catalog
    ENABLE ALWAYS TRIGGER plugin_webhook_rbac_catalog_delete_guard_084;

CREATE FUNCTION validate_plugin_webhook_custom_role_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    checked_scope uuid;
    checked_user uuid;
    checked_role uuid;
    checked_revision bigint;
BEGIN
    IF TG_TABLE_NAME = 'custom_role_grants' THEN
        checked_scope := NEW.tenant_scope_id;
        checked_user := NEW.subject_user_id;
        checked_role := NEW.role_id;
        checked_revision := NEW.role_revision;
    ELSIF TG_TABLE_NAME = 'custom_role_revisions' THEN
        IF NOT ('plugin_webhooks.manage' = ANY(NEW.permissions)) THEN
            RETURN NEW;
        END IF;
        IF EXISTS (
            SELECT 1
            FROM custom_role_grants grant_row
            JOIN role_assignments assignment
              ON assignment.scope_id = grant_row.tenant_scope_id
             AND assignment.user_id = grant_row.subject_user_id
            JOIN roles role ON role.id = assignment.role_id AND role.scope_id = assignment.scope_id
            LEFT JOIN custom_role_grant_revocations revocation ON revocation.grant_id = grant_row.id
            WHERE grant_row.tenant_scope_id = NEW.tenant_scope_id
              AND grant_row.role_id = NEW.role_id
              AND revocation.id IS NULL
              AND role.system_role AND role.name IN ('tenant_member', 'tenant_viewer')
        ) THEN
            RAISE EXCEPTION 'read-only tenant role cannot receive plugin webhook management'
                USING ERRCODE = '42501';
        END IF;
        RETURN NEW;
    ELSE
        checked_scope := NEW.scope_id;
        checked_user := NEW.user_id;
        SELECT role.id INTO checked_role
        FROM roles role
        WHERE role.id = NEW.role_id AND role.scope_id = NEW.scope_id
          AND role.system_role AND role.name IN ('tenant_member', 'tenant_viewer');
        IF checked_role IS NULL THEN
            RETURN NEW;
        END IF;
        IF EXISTS (
            SELECT 1
            FROM custom_role_grants grant_row
            JOIN custom_roles custom_role
              ON custom_role.id = grant_row.role_id
             AND custom_role.tenant_scope_id = grant_row.tenant_scope_id
             AND custom_role.deactivated_at IS NULL
            JOIN custom_role_revisions revision
              ON revision.role_id = custom_role.id
             AND revision.revision = custom_role.current_revision
            LEFT JOIN custom_role_grant_revocations revocation ON revocation.grant_id = grant_row.id
            WHERE grant_row.tenant_scope_id = checked_scope
              AND grant_row.subject_user_id = checked_user
              AND revocation.id IS NULL
              AND 'plugin_webhooks.manage' = ANY(revision.permissions)
        ) THEN
            RAISE EXCEPTION 'read-only tenant role cannot receive plugin webhook management'
                USING ERRCODE = '42501';
        END IF;
        RETURN NEW;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM custom_role_revisions revision
        JOIN role_assignments assignment
          ON assignment.scope_id = checked_scope AND assignment.user_id = checked_user
        JOIN roles role ON role.id = assignment.role_id AND role.scope_id = assignment.scope_id
        WHERE revision.role_id = checked_role AND revision.revision = checked_revision
          AND 'plugin_webhooks.manage' = ANY(revision.permissions)
          AND role.system_role AND role.name IN ('tenant_member', 'tenant_viewer')
    ) THEN
        RAISE EXCEPTION 'read-only tenant role cannot receive plugin webhook management'
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER custom_role_revisions_plugin_webhook_guard_084
BEFORE INSERT ON custom_role_revisions
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_custom_role_084();
CREATE TRIGGER custom_role_grants_plugin_webhook_guard_084
BEFORE INSERT ON custom_role_grants
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_custom_role_084();
CREATE TRIGGER role_assignments_plugin_webhook_guard_084
BEFORE INSERT OR UPDATE ON role_assignments
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_custom_role_084();

CREATE FUNCTION plugin_webhook_u64_084(value numeric)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT value BETWEEN 0 AND 18446744073709551615 AND trunc(value) = value;
$$;

CREATE FUNCTION plugin_webhook_text_valid_084(value text, maximum integer)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT value = btrim(value) AND char_length(value) BETWEEN 1 AND maximum
       AND value !~ '[[:cntrl:]]';
$$;

CREATE FUNCTION plugin_webhook_target_host_valid_084(value text)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
DECLARE
    label text;
BEGIN
    IF octet_length(value) NOT BETWEEN 1 AND 253 OR value <> lower(value) OR
       value !~ '^[a-z0-9.-]+$' OR value LIKE '%.%' IS NOT TRUE OR
       value LIKE '%.local' OR value LIKE '%.internal' OR value = 'localhost' OR
       value LIKE 'xn--%' OR value LIKE '%.xn--%' OR value LIKE '%..%' OR
       value ~ '^(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))+$' OR
       left(value, 1) = '.' OR right(value, 1) = '.' THEN
        RETURN false;
    END IF;
    BEGIN
        PERFORM value::inet;
        RETURN false;
    EXCEPTION WHEN invalid_text_representation THEN
        NULL;
    END;
    FOREACH label IN ARRAY string_to_array(value, '.') LOOP
        IF char_length(label) NOT BETWEEN 1 AND 63 OR
           label !~ '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$' THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
END;
$$;

CREATE FUNCTION plugin_webhook_target_path_valid_084(value text)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
DECLARE
    position_value integer := 1;
    value_length integer := char_length(value);
    current_character text;
    encoded_bytes text;
    decoded_value text;
    decoded_character text;
    codepoint integer;
BEGIN
    IF octet_length(value) NOT BETWEEN 1 AND 512 OR left(value, 1) <> '/' OR
       value ~ '(^|/)(\.|\.\.)(/|$)' THEN
        RETURN false;
    END IF;
    WHILE position_value <= value_length LOOP
        current_character := substr(value, position_value, 1);
        IF current_character = '%' THEN
            encoded_bytes := '';
            WHILE position_value <= value_length AND substr(value, position_value, 1) = '%' LOOP
                IF position_value + 2 > value_length OR
                   substr(value, position_value + 1, 2) !~ '^[0-9A-F]{2}$' THEN
                    RETURN false;
                END IF;
                encoded_bytes := encoded_bytes || substr(value, position_value + 1, 2);
                position_value := position_value + 3;
            END LOOP;
            BEGIN
                decoded_value := convert_from(decode(encoded_bytes, 'hex'), 'UTF8');
            EXCEPTION WHEN OTHERS THEN
                RETURN false;
            END;
            FOR decoded_character IN SELECT regexp_split_to_table(decoded_value, '') LOOP
                codepoint := ascii(decoded_character);
                IF codepoint <= 159 OR codepoint = 160 OR codepoint = 5760 OR
                   codepoint BETWEEN 8192 AND 8202 OR codepoint IN (8232, 8233, 8239, 8287, 12288) THEN
                    RETURN false;
                END IF;
            END LOOP;
        ELSE
            IF current_character !~ '^[A-Za-z0-9._~!$&''()*+,;=:@/-]$' THEN
                RETURN false;
            END IF;
            position_value := position_value + 1;
        END IF;
    END LOOP;
    RETURN true;
END;
$$;

CREATE FUNCTION plugin_webhook_secret_aad_sha256_084(
    target_scope_value uuid,
    subscription_value uuid,
    secret_version_value uuid,
    version_value numeric,
    wrapping_key_value text
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT sha256(
        convert_to('cdnca.plugin-webhook.secret/v1', 'UTF8') || decode('00', 'hex') ||
        convert_to(target_scope_value::text, 'UTF8') || decode('00', 'hex') ||
        convert_to(subscription_value::text, 'UTF8') || decode('00', 'hex') ||
        convert_to(secret_version_value::text, 'UTF8') || decode('00', 'hex') ||
        convert_to(version_value::text, 'UTF8') || decode('00', 'hex') ||
        convert_to(wrapping_key_value, 'UTF8')
    );
$$;

CREATE FUNCTION plugin_webhook_receipt_aad_sha256_084(
    target_scope_value uuid,
    actor_scope_value uuid,
    actor_user_value uuid,
    idempotency_key_value text,
    operation_value text,
    resource_value uuid
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT sha256(
        convert_to('cdnca.plugin-webhook.receipt/v1', 'UTF8') || decode('00', 'hex') ||
        convert_to(target_scope_value::text, 'UTF8') || decode('00', 'hex') ||
        convert_to(actor_scope_value::text, 'UTF8') || decode('00', 'hex') ||
        convert_to(actor_user_value::text, 'UTF8') || decode('00', 'hex') ||
        convert_to(idempotency_key_value, 'UTF8') || decode('00', 'hex') ||
        convert_to(operation_value, 'UTF8') || decode('00', 'hex') ||
        convert_to(resource_value::text, 'UTF8')
    );
$$;

CREATE FUNCTION plugin_webhook_sanitized_headers_valid_084(value jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT jsonb_typeof(value) = 'object' AND NOT EXISTS (
        SELECT 1
        FROM jsonb_each(value) header
        CROSS JOIN LATERAL (
            SELECT regexp_replace(lower(header.key), '[^a-z0-9]', '', 'g') AS name
        ) normalized
        WHERE jsonb_typeof(header.value) <> 'string' OR
              header.key !~ '^[A-Za-z0-9!#$%&*+.^_`|~-]{1,128}$' OR
              normalized.name ~ '(authorization|cookie|signature|secret|token|password|credential|apikey|privatekey|signingkey|encryptionkey|webhookkey)' OR
              normalized.name ~ '(^|x)key(id|name|value|version)?$' OR
              char_length(header.value #>> '{}') > 4096 OR
              (header.value #>> '{}') ~ '[[:cntrl:]]' OR
              (header.value #>> '{}') ~* '(bearer[[:space:]]|basic[[:space:]]|signature[=:]|secret|token|password|authorization|cookie|api[-_ ]?key|private[-_ ]?key)'
    );
$$;

CREATE FUNCTION stamp_plugin_webhook_xact_id_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    transition_at timestamptz;
BEGIN
    IF TG_OP = 'UPDATE' AND TG_TABLE_NAME IN (
        'plugin_webhook_secret_versions', 'plugin_webhook_write_requests'
    ) THEN
        NEW.plugin_webhook_physical_created_at := OLD.plugin_webhook_physical_created_at;
    END IF;
    IF TG_OP = 'UPDATE' AND TG_TABLE_NAME = 'plugin_webhook_write_requests' THEN
        IF OLD.completed_at IS NOT NULL THEN
            NEW.plugin_webhook_xact_id := OLD.plugin_webhook_xact_id;
            NEW.plugin_webhook_recorded_at := OLD.plugin_webhook_recorded_at;
            RETURN NEW;
        END IF;
    END IF;
    NEW.plugin_webhook_xact_id := pg_current_xact_id();
    NEW.plugin_webhook_recorded_at := transaction_timestamp();
    IF TG_OP = 'INSERT' AND TG_TABLE_NAME = 'audit_events' THEN
        IF NEW.action = 'plugin_webhook.subscription.revoke' AND
           NEW.resource_type = 'plugin_webhook_subscription' AND
           NEW.resource_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
            PERFORM 1
            FROM plugin_webhook_subscriptions subscription
            WHERE subscription.tenant_scope_id = NEW.scope_id
              AND subscription.id = NEW.resource_id::uuid
            FOR UPDATE;
            IF FOUND THEN
                transition_at := clock_timestamp();
                NEW.plugin_webhook_recorded_at := transition_at;
                NEW.occurred_at := transition_at;
            END IF;
        END IF;
    ELSIF TG_OP = 'INSERT' AND TG_TABLE_NAME = 'plugin_webhook_write_requests' THEN
        IF NEW.completed_at IS NOT NULL AND
           NEW.operation = 'plugin_webhook.subscription.revoke' THEN
            SELECT audit.plugin_webhook_recorded_at INTO transition_at
            FROM audit_events audit
            WHERE audit.id = NEW.audit_event_id
              AND audit.scope_id = NEW.tenant_scope_id
              AND audit.actor_user_id = NEW.actor_user_id
              AND audit.action = NEW.operation
              AND audit.request_id = NEW.idempotency_key
              AND audit.plugin_webhook_xact_id = pg_current_xact_id();
            IF transition_at IS NOT NULL THEN
                NEW.plugin_webhook_recorded_at := transition_at;
                NEW.completed_at := transition_at;
            END IF;
        END IF;
    ELSIF TG_OP = 'UPDATE' THEN
        IF TG_TABLE_NAME = 'plugin_webhook_write_requests' THEN
            IF OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL AND
               NEW.operation = 'plugin_webhook.subscription.revoke' THEN
                SELECT audit.plugin_webhook_recorded_at INTO transition_at
                FROM audit_events audit
                WHERE audit.id = NEW.audit_event_id
                  AND audit.scope_id = NEW.tenant_scope_id
                  AND audit.actor_user_id = NEW.actor_user_id
                  AND audit.action = NEW.operation
                  AND audit.resource_type = 'plugin_webhook_subscription'
                  AND audit.resource_id = NEW.subscription_id::text
                  AND audit.request_id = NEW.idempotency_key
                  AND audit.plugin_webhook_xact_id = pg_current_xact_id();
                IF transition_at IS NULL THEN
                    RAISE EXCEPTION 'plugin webhook revoke physical marker is unavailable'
                        USING ERRCODE = 'P8402';
                END IF;
                NEW.plugin_webhook_recorded_at := transition_at;
                NEW.completed_at := transition_at;
            END IF;
        ELSIF TG_TABLE_NAME = 'plugin_webhook_subscriptions' THEN
            IF OLD.status = 'active' AND NEW.status = 'revoked' THEN
                SELECT request.completed_at INTO transition_at
                FROM plugin_webhook_write_requests request
                WHERE request.tenant_scope_id = NEW.tenant_scope_id
                  AND request.subscription_id = NEW.id
                  AND request.operation = 'plugin_webhook.subscription.revoke'
                  AND request.response_status = 200
                  AND request.plugin_webhook_xact_id = pg_current_xact_id();
                IF transition_at IS NULL THEN
                    RAISE EXCEPTION 'plugin webhook revoke physical marker is unavailable'
                        USING ERRCODE = 'P8402';
                END IF;
                NEW.plugin_webhook_recorded_at := transition_at;
                NEW.updated_at := transition_at;
                NEW.revoked_at := transition_at;
            END IF;
        ELSIF TG_TABLE_NAME = 'plugin_webhook_secret_versions' THEN
            IF NEW.status = 'expired' AND OLD.status IN ('pending', 'retired') THEN
                NEW.plugin_webhook_recorded_at := clock_timestamp();
            ELSIF NEW.status = 'revoked' AND OLD.status <> 'revoked' THEN
                NEW.plugin_webhook_recorded_at := NEW.revoked_at;
            END IF;
        ELSIF TG_TABLE_NAME = 'plugin_webhook_delivery_attempts' THEN
            IF NEW.status = 'revoked' AND OLD.status = 'claimed' THEN
                NEW.plugin_webhook_recorded_at := NEW.completed_at;
            END IF;
        ELSIF TG_TABLE_NAME = 'plugin_webhook_deliveries' THEN
            IF NEW.status = 'revoked' AND OLD.status <> 'revoked' THEN
                NEW.plugin_webhook_recorded_at := NEW.completed_at;
            END IF;
        END IF;
    END IF;
    IF TG_OP = 'UPDATE' AND TG_TABLE_NAME = 'plugin_webhook_write_requests' THEN
        IF OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL AND
           NEW.operation IN ('plugin_webhook.subscription.create', 'plugin_webhook.secret.rotate') AND
           NEW.receipt_ciphertext IS NOT NULL THEN
            NEW.plugin_webhook_physical_created_at := clock_timestamp();
            NEW.receipt_expires_at := NEW.plugin_webhook_physical_created_at + interval '24 hours';
        END IF;
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF TG_TABLE_NAME = 'plugin_webhook_subscriptions' THEN
            NEW.created_at := NEW.plugin_webhook_recorded_at;
            NEW.updated_at := NEW.plugin_webhook_recorded_at;
        ELSIF TG_TABLE_NAME = 'plugin_webhook_secret_versions' THEN
            NEW.plugin_webhook_physical_created_at := clock_timestamp();
            NEW.created_at := NEW.plugin_webhook_recorded_at;
            IF NEW.status = 'pending' THEN
                NEW.expires_at := NEW.plugin_webhook_physical_created_at + interval '24 hours';
            ELSIF NEW.version = 1 AND NEW.status = 'active' THEN
                NEW.activated_at := NEW.plugin_webhook_recorded_at;
            END IF;
        ELSIF TG_TABLE_NAME = 'plugin_webhook_write_requests' THEN
            NEW.plugin_webhook_physical_created_at := clock_timestamp();
            IF NEW.operation IN ('plugin_webhook.subscription.create', 'plugin_webhook.secret.rotate') THEN
                NEW.created_at := NEW.plugin_webhook_recorded_at;
                IF NEW.receipt_expires_at IS NOT NULL THEN
                    NEW.receipt_expires_at := NEW.plugin_webhook_physical_created_at + interval '24 hours';
                END IF;
            END IF;
        ELSIF TG_TABLE_NAME = 'plugin_webhook_rate_events' THEN
            NEW.plugin_webhook_physical_recorded_at := clock_timestamp();
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

ALTER TABLE audit_events
    ADD COLUMN plugin_webhook_xact_id xid8,
    ADD COLUMN plugin_webhook_recorded_at timestamptz;
CREATE TRIGGER audit_events_plugin_webhook_xact_084
BEFORE INSERT ON audit_events
FOR EACH ROW EXECUTE FUNCTION stamp_plugin_webhook_xact_id_084();

CREATE FUNCTION validate_plugin_webhook_actor_target_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_kind text;
    target_status text;
    actor_kind text;
    actor_membership text;
    actor_status text;
    actor_can_manage boolean;
    requires_live_manage boolean;
    requires_active_target boolean := true;
BEGIN
    requires_live_manage := TG_OP = 'INSERT' AND TG_TABLE_NAME IN (
        'plugin_webhook_subscriptions', 'plugin_webhook_secret_versions',
        'plugin_webhook_write_requests', 'plugin_webhook_events',
        'plugin_webhook_deliveries', 'plugin_webhook_outbox', 'plugin_webhook_rate_events'
    );
    IF TG_OP = 'UPDATE' AND
       ROW(NEW.actor_scope_id, NEW.actor_user_id) IS DISTINCT FROM
       ROW(OLD.actor_scope_id, OLD.actor_user_id) THEN
        requires_live_manage := true;
    END IF;
    IF TG_OP = 'UPDATE' AND TG_TABLE_NAME = 'plugin_webhook_write_requests' THEN
        IF OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL THEN
            requires_live_manage := true;
        END IF;
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF TG_TABLE_NAME = 'plugin_webhook_secret_versions' THEN
            IF OLD.status IN ('pending', 'retired') AND NEW.status = 'expired' THEN
                requires_active_target := false;
            END IF;
        ELSIF TG_TABLE_NAME = 'plugin_webhook_write_requests' THEN
            IF OLD.completed_at IS NOT NULL AND OLD.receipt_ciphertext IS NOT NULL AND
               NEW.receipt_ciphertext IS NULL AND NEW.receipt_cleared_at IS NOT NULL THEN
                requires_active_target := false;
            END IF;
        ELSIF TG_TABLE_NAME = 'plugin_webhook_delivery_attempts' THEN
            IF (OLD.status = 'started' AND NEW.status IN (
                   'succeeded', 'temporary_failure', 'permanent_failure'
               )) OR (OLD.status = 'claimed' AND NEW.status = 'revoked') THEN
                requires_active_target := false;
            END IF;
        ELSIF TG_TABLE_NAME = 'plugin_webhook_deliveries' THEN
            IF OLD.status = 'claimed' AND NEW.status IN (
                   'retry_scheduled', 'delivered', 'dead_letter_pending', 'revoked'
               ) OR OLD.status = 'dead_letter_pending' AND NEW.status = 'dead_lettered' THEN
                requires_active_target := false;
            END IF;
        ELSIF TG_TABLE_NAME = 'plugin_webhook_dead_letters' THEN
            requires_active_target := false;
        END IF;
    ELSIF TG_TABLE_NAME = 'plugin_webhook_dead_letters' THEN
        requires_active_target := false;
    END IF;
    IF requires_live_manage THEN
        SELECT scope.kind, tenant.status INTO target_kind, target_status
        FROM access_scopes scope JOIN tenants tenant ON tenant.id = scope.tenant_id
        WHERE scope.id = NEW.tenant_scope_id
        FOR SHARE OF scope, tenant;
        SELECT scope.kind, membership.status, account.status
          INTO actor_kind, actor_membership, actor_status
        FROM access_scopes scope
        JOIN memberships membership ON membership.scope_id = scope.id
        JOIN users account ON account.id = membership.user_id
        WHERE scope.id = NEW.actor_scope_id AND membership.user_id = NEW.actor_user_id
        FOR SHARE OF scope, membership, account;
    ELSE
        SELECT scope.kind, tenant.status INTO target_kind, target_status
        FROM access_scopes scope JOIN tenants tenant ON tenant.id = scope.tenant_id
        WHERE scope.id = NEW.tenant_scope_id;
        SELECT scope.kind, membership.status, account.status
          INTO actor_kind, actor_membership, actor_status
        FROM access_scopes scope
        JOIN memberships membership ON membership.scope_id = scope.id
        JOIN users account ON account.id = membership.user_id
        WHERE scope.id = NEW.actor_scope_id AND membership.user_id = NEW.actor_user_id;
    END IF;
    IF target_kind IS DISTINCT FROM 'tenant' OR
       (requires_active_target AND target_status IS DISTINCT FROM 'active') OR
       actor_kind NOT IN ('platform', 'tenant') OR
       (actor_kind = 'tenant' AND NEW.actor_scope_id <> NEW.tenant_scope_id) THEN
        RAISE EXCEPTION 'plugin webhook actor target boundary is invalid'
            USING ERRCODE = 'P8402';
    END IF;
    IF NOT requires_live_manage THEN
        RETURN NEW;
    END IF;
    PERFORM 1
    FROM role_assignments assignment
    JOIN roles role ON role.id = assignment.role_id AND role.scope_id = assignment.scope_id
    WHERE assignment.scope_id = NEW.actor_scope_id AND assignment.user_id = NEW.actor_user_id
    FOR SHARE OF assignment, role;
    IF actor_kind = 'tenant' THEN
        PERFORM 1
        FROM custom_role_grants grant_row
        JOIN custom_roles role
          ON role.id = grant_row.role_id AND role.tenant_scope_id = grant_row.tenant_scope_id
        WHERE grant_row.tenant_scope_id = NEW.actor_scope_id
          AND grant_row.subject_user_id = NEW.actor_user_id
        FOR SHARE OF grant_row, role;
        SELECT EXISTS (
            SELECT 1 FROM custom_rbac_effective_permissions(
                NEW.actor_scope_id, NEW.actor_user_id
            ) permission
            WHERE permission.permission_name = 'plugin_webhooks.manage'
        ) INTO actor_can_manage;
    ELSIF actor_kind = 'platform' THEN
        SELECT EXISTS (
            SELECT 1
            FROM role_assignments assignment
            JOIN roles role
              ON role.id = assignment.role_id AND role.scope_id = assignment.scope_id
             AND role.system_role
            JOIN role_permissions permission ON permission.role_id = role.id
            WHERE assignment.scope_id = NEW.actor_scope_id
              AND assignment.user_id = NEW.actor_user_id
              AND permission.permission_name = 'plugin_webhooks.manage'
        ) INTO actor_can_manage;
    ELSE
        actor_can_manage := false;
    END IF;
    IF actor_membership IS DISTINCT FROM 'active' OR
       actor_status IS DISTINCT FROM 'active' OR
       actor_can_manage IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'plugin webhook actor target boundary is invalid'
            USING ERRCODE = 'P8402';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION prevent_plugin_webhook_truncate_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'plugin webhook facts cannot be truncated'
        USING ERRCODE = 'P8403';
END;
$$;

CREATE TABLE plugin_webhook_subscriptions (
    id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    name text NOT NULL CHECK (plugin_webhook_text_valid_084(name, 128)),
    target_url text NOT NULL CHECK (octet_length(target_url) BETWEEN 1 AND 2048),
    target_host text NOT NULL CHECK (plugin_webhook_target_host_valid_084(target_host)),
    target_path text NOT NULL CHECK (plugin_webhook_target_path_valid_084(target_path)),
    event_types text[] NOT NULL CHECK (
        event_types = ARRAY['io.cdnca.webhook.v1.test']::text[]
    ),
    active_secret_version_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('active', 'revoked')),
    revision numeric(20,0) NOT NULL CHECK (plugin_webhook_u64_084(revision) AND revision > 0),
    event_sequence numeric(20,0) NOT NULL DEFAULT 0 CHECK (plugin_webhook_u64_084(event_sequence)),
    lifecycle_sequence numeric(20,0) NOT NULL DEFAULT 0 CHECK (plugin_webhook_u64_084(lifecycle_sequence)),
    revoke_sequence numeric(20,0) CHECK (revoke_sequence IS NULL OR plugin_webhook_u64_084(revoke_sequence)),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    revoked_at timestamptz CHECK (revoked_at IS NULL OR isfinite(revoked_at)),
    plugin_webhook_xact_id xid8 NOT NULL,
    plugin_webhook_recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, id),
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (tenant_scope_id, id, active_secret_version_id),
    CHECK (target_url = 'https://' || target_host || target_path),
    CHECK (updated_at >= created_at),
    CHECK (
        (status = 'active' AND revoke_sequence IS NULL AND revoked_at IS NULL) OR
        (status = 'revoked' AND revoke_sequence IS NOT NULL AND revoked_at = updated_at)
    )
);

CREATE TRIGGER plugin_webhook_subscriptions_00_xact_084
BEFORE INSERT OR UPDATE ON plugin_webhook_subscriptions
FOR EACH ROW EXECUTE FUNCTION stamp_plugin_webhook_xact_id_084();

CREATE INDEX plugin_webhook_subscriptions_page_084
    ON plugin_webhook_subscriptions(tenant_scope_id, status, updated_at DESC, id);

CREATE TRIGGER plugin_webhook_subscriptions_actor_target_084
BEFORE INSERT OR UPDATE ON plugin_webhook_subscriptions
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_actor_target_084();

CREATE FUNCTION enforce_plugin_webhook_subscription_quota_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'plugin-webhook-subscription-quota:' || NEW.tenant_scope_id::text, 84));
    IF (SELECT count(*) FROM plugin_webhook_subscriptions
        WHERE tenant_scope_id = NEW.tenant_scope_id AND status = 'active') >= 100 THEN
        RAISE EXCEPTION 'plugin webhook hard subscription quota exceeded'
            USING ERRCODE = 'P8408', DETAIL = 'plugin_webhook.quota_exceeded';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER plugin_webhook_subscriptions_quota_084
BEFORE INSERT ON plugin_webhook_subscriptions
FOR EACH ROW EXECUTE FUNCTION enforce_plugin_webhook_subscription_quota_084();

CREATE FUNCTION guard_plugin_webhook_subscription_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'active' OR NEW.revision <> 1 OR
           NEW.event_sequence <> 0 OR NEW.lifecycle_sequence <> 0 OR
           NEW.revoke_sequence IS NOT NULL OR NEW.revoked_at IS NOT NULL THEN
            RAISE EXCEPTION 'plugin webhook subscription initial state is invalid'
                USING ERRCODE = 'P8404';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'plugin webhook subscriptions cannot be deleted'
            USING ERRCODE = 'P8403';
    END IF;
    IF OLD.status = 'revoked' OR
       ROW(NEW.id, NEW.tenant_scope_id, NEW.actor_scope_id, NEW.actor_user_id,
           NEW.name, NEW.target_url, NEW.target_host, NEW.target_path, NEW.event_types,
           NEW.created_at) IS DISTINCT FROM
       ROW(OLD.id, OLD.tenant_scope_id, OLD.actor_scope_id, OLD.actor_user_id,
           OLD.name, OLD.target_url, OLD.target_host, OLD.target_path, OLD.event_types,
           OLD.created_at) OR
       NEW.event_sequence < OLD.event_sequence OR
       NEW.event_sequence > OLD.event_sequence + 1 OR
       NEW.lifecycle_sequence < OLD.lifecycle_sequence OR
       NEW.lifecycle_sequence > OLD.lifecycle_sequence + 1 OR
       NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'plugin webhook subscription mutation is invalid'
            USING ERRCODE = 'P8404';
    END IF;
    IF NEW.status = 'revoked' THEN
        IF OLD.status <> 'active' OR NEW.revision <> OLD.revision + 1 OR
           NEW.lifecycle_sequence <> OLD.lifecycle_sequence + 1 OR
           NEW.revoke_sequence <> NEW.lifecycle_sequence OR
           NEW.revoked_at <> NEW.updated_at THEN
            RAISE EXCEPTION 'plugin webhook revoke sequence is invalid'
                USING ERRCODE = 'P8404';
        END IF;
    ELSIF NEW.active_secret_version_id IS DISTINCT FROM OLD.active_secret_version_id THEN
        IF NEW.revision <> OLD.revision + 1 OR NEW.lifecycle_sequence <> OLD.lifecycle_sequence + 1 OR
           NEW.status <> 'active' OR NEW.revoke_sequence IS NOT NULL OR NEW.revoked_at IS NOT NULL OR
           NEW.updated_at IS DISTINCT FROM NEW.plugin_webhook_recorded_at THEN
            RAISE EXCEPTION 'plugin webhook secret activation is invalid'
                USING ERRCODE = 'P8404';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM plugin_webhook_write_requests request
            WHERE request.tenant_scope_id = NEW.tenant_scope_id
              AND request.subscription_id = NEW.id
              AND request.operation = 'plugin_webhook.secret.activate'
              AND request.rotation_id = NEW.active_secret_version_id
              AND request.completed_at = NEW.plugin_webhook_recorded_at
              AND request.plugin_webhook_xact_id = pg_current_xact_id()
              AND request.plugin_webhook_recorded_at = NEW.plugin_webhook_recorded_at
        ) THEN
            RAISE EXCEPTION 'plugin webhook activation requires current management authorization'
                USING ERRCODE = 'P8402';
        END IF;
    ELSIF NEW.revision <> OLD.revision OR NEW.status <> OLD.status OR
          NEW.revoke_sequence IS DISTINCT FROM OLD.revoke_sequence OR
          NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
        RAISE EXCEPTION 'plugin webhook revision changed without activation or revoke'
            USING ERRCODE = 'P8404';
    END IF;
    IF NEW.event_sequence = OLD.event_sequence AND
       NEW.lifecycle_sequence = OLD.lifecycle_sequence AND
       NEW.active_secret_version_id = OLD.active_secret_version_id AND
       NEW.status = OLD.status THEN
        RAISE EXCEPTION 'plugin webhook subscription update has no durable transition'
            USING ERRCODE = 'P8404';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER plugin_webhook_subscriptions_guard_084
BEFORE INSERT OR UPDATE OR DELETE ON plugin_webhook_subscriptions
FOR EACH ROW EXECUTE FUNCTION guard_plugin_webhook_subscription_084();
CREATE TRIGGER plugin_webhook_subscriptions_truncate_084
BEFORE TRUNCATE ON plugin_webhook_subscriptions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_plugin_webhook_truncate_084();

CREATE TABLE plugin_webhook_secret_versions (
    id uuid NOT NULL,
    key_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    version numeric(20,0) NOT NULL CHECK (plugin_webhook_u64_084(version) AND version > 0),
    status text NOT NULL CHECK (status IN ('pending', 'active', 'retired', 'expired', 'revoked')),
    wrapping_key_id text NOT NULL CHECK (
        plugin_webhook_text_valid_084(wrapping_key_id, 128) AND
        wrapping_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'
    ),
    aad_sha256 bytea NOT NULL CHECK (
        octet_length(aad_sha256) = 32 AND
        aad_sha256 = plugin_webhook_secret_aad_sha256_084(
            tenant_scope_id, subscription_id, id, version, wrapping_key_id
        )
    ),
    nonce bytea,
    ciphertext bytea,
    secret_sha256 bytea NOT NULL CHECK (octet_length(secret_sha256) = 32),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    activated_at timestamptz CHECK (activated_at IS NULL OR isfinite(activated_at)),
    expires_at timestamptz CHECK (expires_at IS NULL OR isfinite(expires_at)),
    retired_at timestamptz CHECK (retired_at IS NULL OR isfinite(retired_at)),
    revoked_at timestamptz CHECK (revoked_at IS NULL OR isfinite(revoked_at)),
    plugin_webhook_xact_id xid8 NOT NULL,
    plugin_webhook_recorded_at timestamptz NOT NULL,
    plugin_webhook_physical_created_at timestamptz NOT NULL
        CHECK (isfinite(plugin_webhook_physical_created_at)),
    PRIMARY KEY (tenant_scope_id, subscription_id, id),
    FOREIGN KEY (tenant_scope_id, subscription_id)
        REFERENCES plugin_webhook_subscriptions(tenant_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (tenant_scope_id, subscription_id, version),
    UNIQUE (tenant_scope_id, subscription_id, id, status),
    CHECK (key_id = id),
    CHECK (
        (status = 'pending' AND nonce IS NOT NULL AND octet_length(nonce) = 12 AND
         ciphertext IS NOT NULL AND octet_length(ciphertext) = 48 AND activated_at IS NULL AND
         expires_at = plugin_webhook_physical_created_at + interval '24 hours' AND
         retired_at IS NULL AND revoked_at IS NULL) OR
        (status = 'active' AND nonce IS NOT NULL AND octet_length(nonce) = 12 AND
         ciphertext IS NOT NULL AND octet_length(ciphertext) = 48 AND activated_at IS NOT NULL AND
         expires_at IS NULL AND retired_at IS NULL AND revoked_at IS NULL) OR
        (status = 'retired' AND nonce IS NOT NULL AND octet_length(nonce) = 12 AND
         ciphertext IS NOT NULL AND octet_length(ciphertext) = 48 AND activated_at IS NOT NULL AND
         expires_at = retired_at + interval '24 hours' AND retired_at IS NOT NULL AND revoked_at IS NULL) OR
        (status = 'expired' AND nonce IS NULL AND ciphertext IS NULL AND expires_at IS NOT NULL AND
         ((activated_at IS NULL AND retired_at IS NULL) OR
          (activated_at IS NOT NULL AND retired_at IS NOT NULL)) AND revoked_at IS NULL) OR
        (status = 'revoked' AND nonce IS NULL AND ciphertext IS NULL AND revoked_at IS NOT NULL AND (
             (activated_at IS NULL AND retired_at IS NULL AND
              expires_at = plugin_webhook_physical_created_at + interval '24 hours') OR
             (activated_at IS NOT NULL AND retired_at IS NULL AND expires_at IS NULL) OR
             (activated_at IS NOT NULL AND retired_at IS NOT NULL AND
              expires_at = retired_at + interval '24 hours')
        ))
    )
);

CREATE TRIGGER plugin_webhook_secret_versions_00_xact_084
BEFORE INSERT OR UPDATE ON plugin_webhook_secret_versions
FOR EACH ROW EXECUTE FUNCTION stamp_plugin_webhook_xact_id_084();

CREATE UNIQUE INDEX plugin_webhook_secret_active_084
    ON plugin_webhook_secret_versions(tenant_scope_id, subscription_id) WHERE status = 'active';
CREATE UNIQUE INDEX plugin_webhook_secret_pending_084
    ON plugin_webhook_secret_versions(tenant_scope_id, subscription_id) WHERE status = 'pending';

ALTER TABLE plugin_webhook_subscriptions
    ADD CONSTRAINT plugin_webhook_subscriptions_active_secret_084_fk
    FOREIGN KEY (tenant_scope_id, id, active_secret_version_id)
    REFERENCES plugin_webhook_secret_versions(tenant_scope_id, subscription_id, id)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE TRIGGER plugin_webhook_secret_versions_actor_target_084
BEFORE INSERT OR UPDATE ON plugin_webhook_secret_versions
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_actor_target_084();

CREATE FUNCTION validate_plugin_webhook_secret_insert_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    subscription_status text;
    subscription_actor_scope uuid;
    subscription_actor_user uuid;
    subscription_xact_id xid8;
    next_version numeric(20,0);
BEGIN
    SELECT status, actor_scope_id, actor_user_id, plugin_webhook_xact_id
      INTO subscription_status, subscription_actor_scope, subscription_actor_user, subscription_xact_id
    FROM plugin_webhook_subscriptions
    WHERE tenant_scope_id = NEW.tenant_scope_id AND id = NEW.subscription_id
    FOR UPDATE;
    SELECT COALESCE(max(version), 0) + 1 INTO next_version
    FROM plugin_webhook_secret_versions
    WHERE tenant_scope_id = NEW.tenant_scope_id AND subscription_id = NEW.subscription_id;
    IF subscription_status IS DISTINCT FROM 'active' OR NEW.version <> next_version OR
       (NEW.version = 1 AND NEW.status <> 'active') OR
       (NEW.version > 1 AND NEW.status <> 'pending') THEN
        RAISE EXCEPTION 'plugin webhook secret insertion is invalid'
            USING ERRCODE = 'P8406';
    END IF;
    IF NEW.version = 1 AND (
       NEW.actor_scope_id IS DISTINCT FROM subscription_actor_scope OR
       NEW.actor_user_id IS DISTINCT FROM subscription_actor_user OR
       subscription_xact_id IS DISTINCT FROM pg_current_xact_id()
    ) THEN
        RAISE EXCEPTION 'initial plugin webhook secret must inherit create actor provenance'
            USING ERRCODE = 'P8406';
    END IF;
    IF NEW.version > 1 AND NOT EXISTS (
        SELECT 1 FROM plugin_webhook_write_requests request
        WHERE request.tenant_scope_id = NEW.tenant_scope_id
          AND request.subscription_id = NEW.subscription_id
          AND request.rotation_id = NEW.id
          AND request.actor_scope_id = NEW.actor_scope_id
          AND request.actor_user_id = NEW.actor_user_id
          AND request.operation = 'plugin_webhook.secret.rotate'
          AND request.plugin_webhook_xact_id = pg_current_xact_id()
    ) THEN
        RAISE EXCEPTION 'plugin webhook secret rotation requires current management authorization'
            USING ERRCODE = 'P8402';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER plugin_webhook_secret_versions_insert_084
BEFORE INSERT ON plugin_webhook_secret_versions
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_secret_insert_084();

CREATE FUNCTION guard_plugin_webhook_secret_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' OR
       ROW(NEW.id, NEW.key_id, NEW.tenant_scope_id, NEW.subscription_id,
           NEW.actor_scope_id, NEW.actor_user_id, NEW.version, NEW.wrapping_key_id,
           NEW.aad_sha256, NEW.secret_sha256, NEW.created_at,
           NEW.plugin_webhook_physical_created_at) IS DISTINCT FROM
       ROW(OLD.id, OLD.key_id, OLD.tenant_scope_id, OLD.subscription_id,
           OLD.actor_scope_id, OLD.actor_user_id, OLD.version, OLD.wrapping_key_id,
           OLD.aad_sha256, OLD.secret_sha256, OLD.created_at,
           OLD.plugin_webhook_physical_created_at) THEN
        RAISE EXCEPTION 'plugin webhook secret identity is immutable'
            USING ERRCODE = 'P8406';
    END IF;
    IF (OLD.status = 'pending' AND NEW.status NOT IN ('active', 'expired', 'revoked')) OR
       (OLD.status = 'active' AND NEW.status NOT IN ('retired', 'revoked')) OR
       (OLD.status = 'retired' AND NEW.status NOT IN ('expired', 'revoked')) OR
       OLD.status IN ('expired', 'revoked') OR OLD.status = NEW.status THEN
        RAISE EXCEPTION 'plugin webhook secret transition is invalid'
            USING ERRCODE = 'P8406';
    END IF;
    IF NEW.status = 'expired' AND (
       NEW.activated_at IS DISTINCT FROM OLD.activated_at OR
       NEW.expires_at IS DISTINCT FROM OLD.expires_at OR
       NEW.retired_at IS DISTINCT FROM OLD.retired_at OR
       NEW.revoked_at IS DISTINCT FROM OLD.revoked_at OR
       NEW.plugin_webhook_recorded_at < OLD.expires_at OR
       clock_timestamp() < OLD.expires_at
    ) THEN
        RAISE EXCEPTION 'plugin webhook secret cannot expire before its physical lifetime'
            USING ERRCODE = 'P8406';
    END IF;
    IF OLD.status = 'pending' AND NEW.status = 'active' AND (
       NEW.nonce IS DISTINCT FROM OLD.nonce OR
       NEW.ciphertext IS DISTINCT FROM OLD.ciphertext OR
       NEW.retired_at IS DISTINCT FROM OLD.retired_at OR
       NEW.revoked_at IS DISTINCT FROM OLD.revoked_at OR
       NEW.activated_at IS NULL OR NEW.activated_at < OLD.created_at OR
       NEW.activated_at > OLD.expires_at OR
       NEW.activated_at IS DISTINCT FROM NEW.plugin_webhook_recorded_at OR
       clock_timestamp() > OLD.expires_at
    ) THEN
        RAISE EXCEPTION 'plugin webhook secret activation time is invalid'
            USING ERRCODE = 'P8406';
    END IF;
    IF OLD.status = 'pending' AND NEW.status = 'active' AND NOT EXISTS (
        SELECT 1
        FROM plugin_webhook_write_requests request
        JOIN audit_events audit ON audit.id = request.audit_event_id
        WHERE request.tenant_scope_id = NEW.tenant_scope_id
          AND request.subscription_id = NEW.subscription_id
          AND request.operation = 'plugin_webhook.secret.activate'
          AND request.rotation_id = NEW.id
          AND request.completed_at IS NOT NULL
          AND request.completed_at = NEW.activated_at
          AND request.completed_at = request.plugin_webhook_recorded_at
          AND audit.occurred_at = request.completed_at
          AND audit.occurred_at = audit.plugin_webhook_recorded_at
          AND request.plugin_webhook_recorded_at = NEW.plugin_webhook_recorded_at
          AND audit.plugin_webhook_recorded_at = NEW.plugin_webhook_recorded_at
          AND request.plugin_webhook_xact_id = pg_current_xact_id()
          AND audit.plugin_webhook_xact_id = pg_current_xact_id()
    ) THEN
        RAISE EXCEPTION 'plugin webhook secret activation requires exact current management authorization'
            USING ERRCODE = 'P8402';
    END IF;
    IF OLD.status = 'active' AND NEW.status = 'retired' AND NOT EXISTS (
        SELECT 1
        FROM plugin_webhook_write_requests request
        JOIN audit_events audit ON audit.id = request.audit_event_id
        WHERE request.tenant_scope_id = NEW.tenant_scope_id
          AND request.subscription_id = NEW.subscription_id
          AND request.operation = 'plugin_webhook.secret.activate'
          AND request.rotation_id IS NOT NULL
          AND request.completed_at IS NOT NULL
          AND NEW.retired_at = NEW.plugin_webhook_recorded_at
          AND request.completed_at = NEW.retired_at
          AND request.completed_at = request.plugin_webhook_recorded_at
          AND audit.occurred_at = request.completed_at
          AND audit.occurred_at = audit.plugin_webhook_recorded_at
          AND request.plugin_webhook_recorded_at = NEW.plugin_webhook_recorded_at
          AND audit.plugin_webhook_recorded_at = NEW.plugin_webhook_recorded_at
          AND request.plugin_webhook_xact_id = pg_current_xact_id()
    ) THEN
        RAISE EXCEPTION 'plugin webhook secret retirement requires current activation authorization'
            USING ERRCODE = 'P8402';
    END IF;
    IF OLD.status = 'active' AND NEW.status = 'retired' AND (
       NEW.nonce IS DISTINCT FROM OLD.nonce OR
       NEW.ciphertext IS DISTINCT FROM OLD.ciphertext OR
       NEW.activated_at IS DISTINCT FROM OLD.activated_at OR
       NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
    ) THEN
        RAISE EXCEPTION 'plugin webhook secret retirement must preserve envelope and history'
            USING ERRCODE = 'P8406';
    END IF;
    IF NEW.status = 'revoked' AND NOT EXISTS (
        SELECT 1 FROM plugin_webhook_subscriptions subscription
        WHERE subscription.tenant_scope_id = NEW.tenant_scope_id
          AND subscription.id = NEW.subscription_id
          AND subscription.status = 'revoked'
          AND subscription.plugin_webhook_xact_id = pg_current_xact_id()
    ) THEN
        RAISE EXCEPTION 'plugin webhook secret revoke requires current subscription fence'
            USING ERRCODE = 'P8402';
    END IF;
    IF NEW.status = 'revoked' AND
       ROW(NEW.activated_at, NEW.expires_at, NEW.retired_at) IS DISTINCT FROM
       ROW(OLD.activated_at, OLD.expires_at, OLD.retired_at) THEN
        RAISE EXCEPTION 'plugin webhook secret revoke must preserve lifecycle history'
            USING ERRCODE = 'P8406';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION apply_plugin_webhook_secret_expiry_fence_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    subscription_status text;
    subscription_active_secret uuid;
BEGIN
    IF OLD.status <> 'retired' OR NEW.status <> 'expired' THEN
        RETURN NULL;
    END IF;
    SELECT status, active_secret_version_id
      INTO subscription_status, subscription_active_secret
    FROM plugin_webhook_subscriptions
    WHERE tenant_scope_id = NEW.tenant_scope_id AND id = NEW.subscription_id
    FOR SHARE;
    UPDATE plugin_webhook_delivery_attempts
    SET status = 'revoked', completed_at = NEW.plugin_webhook_recorded_at
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND subscription_id = NEW.subscription_id
      AND secret_version_id = NEW.id AND status = 'claimed';
    UPDATE plugin_webhook_deliveries delivery
    SET status = CASE
            WHEN subscription_status = 'active' AND subscription_active_secret <> NEW.id
                THEN 'retry_scheduled'
            ELSE 'revoked'
        END,
        completed_at = CASE
            WHEN subscription_status = 'active' AND subscription_active_secret <> NEW.id
                THEN NULL
            ELSE NEW.plugin_webhook_recorded_at
        END,
        next_attempt_at = CASE
            WHEN subscription_status = 'active' AND subscription_active_secret <> NEW.id
                THEN NEW.plugin_webhook_recorded_at
            ELSE NULL
        END
    WHERE delivery.tenant_scope_id = NEW.tenant_scope_id
      AND delivery.subscription_id = NEW.subscription_id AND delivery.status = 'claimed'
      AND EXISTS (
          SELECT 1 FROM plugin_webhook_delivery_attempts attempt
          WHERE attempt.tenant_scope_id = delivery.tenant_scope_id
            AND attempt.subscription_id = delivery.subscription_id
            AND attempt.delivery_id = delivery.id AND attempt.secret_version_id = NEW.id
            AND attempt.status = 'revoked'
            AND attempt.completed_at = NEW.plugin_webhook_recorded_at
      );
    RETURN NULL;
END;
$$;

CREATE TRIGGER plugin_webhook_secret_versions_guard_084
BEFORE UPDATE OR DELETE ON plugin_webhook_secret_versions
FOR EACH ROW EXECUTE FUNCTION guard_plugin_webhook_secret_084();
CREATE TRIGGER plugin_webhook_secret_versions_expiry_fence_084
AFTER UPDATE ON plugin_webhook_secret_versions
FOR EACH ROW EXECUTE FUNCTION apply_plugin_webhook_secret_expiry_fence_084();
CREATE TRIGGER plugin_webhook_secret_versions_truncate_084
BEFORE TRUNCATE ON plugin_webhook_secret_versions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_plugin_webhook_truncate_084();

CREATE FUNCTION validate_plugin_webhook_active_secret_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    checked_scope uuid;
    checked_subscription uuid;
BEGIN
    checked_scope := NEW.tenant_scope_id;
    IF TG_TABLE_NAME = 'plugin_webhook_subscriptions' THEN
        checked_subscription := NEW.id;
    ELSE
        checked_subscription := NEW.subscription_id;
    END IF;
    IF EXISTS (
        SELECT 1
        FROM plugin_webhook_subscriptions subscription
        WHERE subscription.tenant_scope_id = checked_scope
          AND subscription.id = checked_subscription
          AND subscription.status = 'active'
          AND NOT EXISTS (
              SELECT 1 FROM plugin_webhook_secret_versions secret
              WHERE secret.tenant_scope_id = subscription.tenant_scope_id
                AND secret.subscription_id = subscription.id
                AND secret.id = subscription.active_secret_version_id
                AND secret.status = 'active'
          )
    ) THEN
        RAISE EXCEPTION 'active plugin webhook subscription requires its active secret'
            USING ERRCODE = 'P8406';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM plugin_webhook_secret_versions secret
        WHERE secret.tenant_scope_id = checked_scope
          AND secret.subscription_id = checked_subscription
          AND secret.version > 1 AND secret.status = 'active'
          AND secret.plugin_webhook_xact_id = pg_current_xact_id()
          AND clock_timestamp() > secret.created_at + interval '24 hours'
    ) THEN
        RAISE EXCEPTION 'plugin webhook secret activation missed its physical deadline'
            USING ERRCODE = 'P8406';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER plugin_webhook_subscriptions_active_secret_check_084
AFTER INSERT OR UPDATE ON plugin_webhook_subscriptions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_active_secret_084();
CREATE CONSTRAINT TRIGGER plugin_webhook_secret_versions_active_check_084
AFTER INSERT OR UPDATE ON plugin_webhook_secret_versions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_active_secret_084();

CREATE TABLE plugin_webhook_write_requests (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation IN (
        'plugin_webhook.subscription.create',
        'plugin_webhook.test_delivery.create',
        'plugin_webhook.delivery.replay',
        'plugin_webhook.secret.rotate',
        'plugin_webhook.secret.activate',
        'plugin_webhook.subscription.revoke'
    )),
    idempotency_key text NOT NULL CHECK (
        idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    subscription_id uuid NOT NULL,
    delivery_id uuid,
    rotation_id uuid,
    response_status integer CHECK (
        response_status IS NULL OR response_status = CASE
            WHEN operation IN ('plugin_webhook.subscription.create', 'plugin_webhook.secret.rotate') THEN 201
            WHEN operation IN ('plugin_webhook.test_delivery.create', 'plugin_webhook.delivery.replay') THEN 202
            ELSE 200
        END
    ),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    receipt_wrapping_key_id text,
    receipt_aad_sha256 bytea,
    receipt_nonce bytea,
    receipt_ciphertext bytea,
    receipt_expires_at timestamptz,
    receipt_cleared_at timestamptz,
    receipt_cleared_reason text CHECK (
        receipt_cleared_reason IS NULL OR receipt_cleared_reason IN ('expired', 'subscription_revoked')
    ),
    audit_event_id uuid,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    completed_at timestamptz CHECK (completed_at IS NULL OR isfinite(completed_at)),
    plugin_webhook_xact_id xid8 NOT NULL,
    plugin_webhook_recorded_at timestamptz NOT NULL,
    plugin_webhook_physical_created_at timestamptz NOT NULL
        CHECK (isfinite(plugin_webhook_physical_created_at)),
    FOREIGN KEY (tenant_scope_id, subscription_id)
        REFERENCES plugin_webhook_subscriptions(tenant_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (audit_event_id) REFERENCES audit_events(id) ON DELETE RESTRICT,
    UNIQUE (tenant_scope_id, actor_scope_id, actor_user_id, idempotency_key),
    CHECK (completed_at IS NULL OR completed_at >= created_at),
    CHECK (
        (operation = 'plugin_webhook.subscription.create' AND delivery_id IS NULL AND rotation_id IS NULL) OR
        (operation IN ('plugin_webhook.test_delivery.create', 'plugin_webhook.delivery.replay') AND
         delivery_id IS NOT NULL AND rotation_id IS NULL) OR
        (operation IN ('plugin_webhook.secret.rotate', 'plugin_webhook.secret.activate') AND
         delivery_id IS NULL AND rotation_id IS NOT NULL) OR
        (operation = 'plugin_webhook.subscription.revoke' AND delivery_id IS NULL AND rotation_id IS NULL)
    ),
    CHECK (
        response_body IS NULL OR
        (operation IN ('plugin_webhook.subscription.create', 'plugin_webhook.subscription.revoke') AND
         response_body = jsonb_build_object('subscription_id', subscription_id::text)) OR
        (operation = 'plugin_webhook.secret.activate' AND response_body = jsonb_build_object(
             'subscription_id', subscription_id::text, 'rotation_id', rotation_id::text
         )) OR
        (operation IN ('plugin_webhook.test_delivery.create', 'plugin_webhook.delivery.replay') AND
         response_body = jsonb_build_object(
             'subscription_id', subscription_id::text, 'delivery_id', delivery_id::text
         )) OR
        (operation = 'plugin_webhook.secret.rotate' AND response_body = jsonb_build_object(
             'subscription_id', subscription_id::text, 'rotation_id', rotation_id::text
         ))
    ),
    CHECK (
        (completed_at IS NULL AND response_status IS NULL AND response_body IS NULL AND
         audit_event_id IS NULL AND receipt_wrapping_key_id IS NULL AND receipt_aad_sha256 IS NULL AND
         receipt_nonce IS NULL AND receipt_ciphertext IS NULL AND receipt_expires_at IS NULL AND
         receipt_cleared_at IS NULL AND receipt_cleared_reason IS NULL) OR
        (completed_at IS NOT NULL AND response_status IS NOT NULL AND response_body IS NOT NULL AND
         audit_event_id IS NOT NULL AND (
             (operation IN ('plugin_webhook.subscription.create', 'plugin_webhook.secret.rotate') AND
             receipt_wrapping_key_id IS NOT NULL AND plugin_webhook_text_valid_084(receipt_wrapping_key_id, 128) AND
              receipt_aad_sha256 IS NOT NULL AND octet_length(receipt_aad_sha256) = 32 AND
              receipt_aad_sha256 = plugin_webhook_receipt_aad_sha256_084(
                  tenant_scope_id, actor_scope_id, actor_user_id, idempotency_key, operation,
                  CASE WHEN operation = 'plugin_webhook.secret.rotate' THEN rotation_id ELSE subscription_id END
              ) AND
              ((receipt_cleared_at IS NULL AND receipt_nonce IS NOT NULL AND octet_length(receipt_nonce) = 12 AND
                receipt_ciphertext IS NOT NULL AND octet_length(receipt_ciphertext) BETWEEN 17 AND 4096 AND
                receipt_expires_at = plugin_webhook_physical_created_at + interval '24 hours' AND
                receipt_cleared_reason IS NULL) OR
               (receipt_cleared_at IS NOT NULL AND receipt_nonce IS NULL AND receipt_ciphertext IS NULL AND (
                    (receipt_cleared_reason = 'expired' AND receipt_cleared_at >= receipt_expires_at) OR
                    receipt_cleared_reason = 'subscription_revoked'
               )))) OR
             (operation NOT IN ('plugin_webhook.subscription.create', 'plugin_webhook.secret.rotate') AND
              receipt_wrapping_key_id IS NULL AND receipt_aad_sha256 IS NULL AND receipt_nonce IS NULL AND
              receipt_ciphertext IS NULL AND receipt_expires_at IS NULL AND receipt_cleared_at IS NULL AND
              receipt_cleared_reason IS NULL)
         ))
    )
);

CREATE TRIGGER plugin_webhook_write_requests_00_xact_084
BEFORE INSERT OR UPDATE ON plugin_webhook_write_requests
FOR EACH ROW EXECUTE FUNCTION stamp_plugin_webhook_xact_id_084();

CREATE INDEX plugin_webhook_write_request_receipts_084
    ON plugin_webhook_write_requests(receipt_expires_at)
    WHERE receipt_ciphertext IS NOT NULL;
CREATE UNIQUE INDEX plugin_webhook_write_request_activation_084
    ON plugin_webhook_write_requests(tenant_scope_id, subscription_id, rotation_id)
    WHERE operation = 'plugin_webhook.secret.activate';
CREATE UNIQUE INDEX plugin_webhook_write_request_audit_084
    ON plugin_webhook_write_requests(audit_event_id)
    WHERE audit_event_id IS NOT NULL;

CREATE TABLE plugin_webhook_entitlement_decisions (
    request_id uuid PRIMARY KEY
        REFERENCES plugin_webhook_write_requests(id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    operation text NOT NULL,
    subscription_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    feature_key text NOT NULL CHECK (feature_key = 'extensions.webhooks'),
    lease_installation_id text NOT NULL,
    lease_customer_id text NOT NULL,
    lease_license_id text NOT NULL,
    lease_serial bigint NOT NULL CHECK (lease_serial > 0),
    lease_sha256 bytea NOT NULL CHECK (octet_length(lease_sha256) = 32),
    lease_status text NOT NULL CHECK (lease_status IN ('valid', 'grace')),
    lease_not_before timestamptz NOT NULL CHECK (isfinite(lease_not_before)),
    lease_expires_at timestamptz NOT NULL CHECK (isfinite(lease_expires_at)),
    lease_grace_until timestamptz NOT NULL CHECK (isfinite(lease_grace_until)),
    revocation_revision bigint NOT NULL CHECK (revocation_revision > 0),
    revocation_sha256 bytea NOT NULL CHECK (octet_length(revocation_sha256) = 32),
    revocation_key_id text NOT NULL,
    revocation_issued_at timestamptz NOT NULL CHECK (isfinite(revocation_issued_at)),
    revocation_expires_at timestamptz NOT NULL CHECK (isfinite(revocation_expires_at)),
    evaluated_at timestamptz NOT NULL CHECK (isfinite(evaluated_at)),
    quota_code text NOT NULL CHECK (quota_code = 'extensions.webhooks.count'),
    quota_limit bigint NOT NULL CHECK (quota_limit >= -1),
    quota_current bigint NOT NULL CHECK (quota_current >= 0),
    quota_allowed boolean NOT NULL,
    reason_code text NOT NULL CHECK (reason_code IN ('accepted_feature', 'accepted_quota')),
    plugin_webhook_xact_id xid8 NOT NULL,
    UNIQUE (tenant_scope_id, request_digest),
    FOREIGN KEY (tenant_scope_id, subscription_id)
        REFERENCES plugin_webhook_subscriptions(tenant_scope_id, id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED
);

CREATE FUNCTION record_plugin_webhook_entitlement_decision_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    installation_id_value text;
    lease_serial_value bigint;
    lease_signed bytea;
    lease_status_value text;
    lease_not_before_value timestamptz;
    lease_expires_value timestamptz;
    lease_grace_value timestamptz;
    lkg control_entitlement_revocation_lkg%ROWTYPE;
    lease_document jsonb;
    lease_body jsonb;
    lease_feature boolean;
    quota_value bigint := -1;
    active_count bigint;
    projected_count bigint;
    evaluated_at_value timestamptz;
    resource_value uuid;
    reason_value text;
BEGIN
    IF NEW.completed_at IS NULL OR NEW.operation NOT IN (
        'plugin_webhook.subscription.create',
        'plugin_webhook.test_delivery.create',
        'plugin_webhook.delivery.replay',
        'plugin_webhook.secret.rotate',
        'plugin_webhook.secret.activate'
    ) OR EXISTS (
        SELECT 1 FROM plugin_webhook_entitlement_decisions decision
        WHERE decision.request_id = NEW.id
    ) THEN
        RETURN NEW;
    END IF;
    SELECT installation.installation_id, lease.serial, lease.signed_lease, lease.status,
           lease.not_before, lease.expires_at, lease.grace_until
      INTO installation_id_value, lease_serial_value, lease_signed, lease_status_value,
           lease_not_before_value, lease_expires_value, lease_grace_value
    FROM control_installation_entitlement installation
    LEFT JOIN entitlement_cached_leases lease
      ON lease.serial = installation.current_serial
    WHERE installation.singleton = true
    FOR UPDATE OF installation;
    SELECT * INTO lkg FROM control_entitlement_revocation_lkg
    WHERE singleton = true FOR SHARE;
    evaluated_at_value := clock_timestamp();
    IF installation_id_value IS NULL OR lease_serial_value IS NULL OR lease_signed IS NULL OR
       lease_status_value NOT IN ('valid', 'grace') OR lkg.singleton IS DISTINCT FROM true OR
       evaluated_at_value < lease_not_before_value OR evaluated_at_value >= lease_grace_value OR
       evaluated_at_value < lkg.issued_at THEN
        RAISE EXCEPTION 'plugin webhook entitlement decision is unavailable or expired'
            USING ERRCODE = 'P8408', DETAIL = 'plugin_webhook.entitlement_denied';
    END IF;
    IF EXISTS (
        SELECT 1 FROM control_entitlement_revoked_serials revoked
        WHERE revoked.installation_id = installation_id_value
          AND revoked.license_id = lkg.license_id
          AND revoked.serial = lease_serial_value
    ) OR lkg.installation_id IS DISTINCT FROM installation_id_value OR
       lkg.license_id IS DISTINCT FROM (SELECT license_id FROM entitlement_cached_leases WHERE serial = lease_serial_value) THEN
        RAISE EXCEPTION 'plugin webhook entitlement decision lease or revocation binding is invalid'
            USING ERRCODE = 'P8408', DETAIL = 'plugin_webhook.invariant_violation';
    END IF;
    BEGIN
        lease_document := convert_from(lease_signed, 'UTF8')::jsonb;
        lease_body := lease_document->'lease';
        IF jsonb_typeof(lease_document) <> 'object' OR
           lease_document->>'algorithm' <> 'Ed25519' OR
           lease_document->>'key_id' IS DISTINCT FROM (SELECT key_id FROM entitlement_cached_leases WHERE serial = lease_serial_value) OR
           jsonb_typeof(lease_body) <> 'object' OR
           lease_body->>'schema' <> 'cdnca.entitlement.lease/v1' OR
           lease_body->>'audience' <> 'cdnca-control-plane' OR
           lease_body->>'installation_id' IS DISTINCT FROM installation_id_value OR
           lease_body->>'customer_id' IS DISTINCT FROM (SELECT customer_id FROM entitlement_cached_leases WHERE serial = lease_serial_value) OR
           lease_body->>'license_id' IS DISTINCT FROM (SELECT license_id FROM entitlement_cached_leases WHERE serial = lease_serial_value) OR
           (lease_body->>'serial')::bigint IS DISTINCT FROM lease_serial_value OR
           (lease_body->>'not_before')::numeric IS DISTINCT FROM extract(epoch FROM lease_not_before_value) OR
           (lease_body->>'expires_at')::numeric IS DISTINCT FROM extract(epoch FROM lease_expires_value) OR
           (lease_body->>'grace_until')::numeric IS DISTINCT FROM extract(epoch FROM lease_grace_value) THEN
            RAISE EXCEPTION 'invalid signed entitlement lease body';
        END IF;
        lease_feature := EXISTS (
            SELECT 1 FROM jsonb_array_elements(lease_body->'features') feature
            WHERE feature->>'code' = 'extensions.webhooks'
        );
        SELECT (quota->>'limit')::bigint INTO quota_value
        FROM jsonb_array_elements(lease_body->'quotas') quota
        WHERE quota->>'code' = 'extensions.webhooks.count';
    EXCEPTION WHEN others THEN
        RAISE EXCEPTION 'plugin webhook entitlement lease is invalid'
            USING ERRCODE = 'P8408', DETAIL = 'plugin_webhook.invariant_violation';
    END;
    IF NOT lease_feature THEN
        RAISE EXCEPTION 'plugin webhook entitlement feature is denied'
            USING ERRCODE = 'P8408', DETAIL = 'plugin_webhook.entitlement_denied';
    END IF;
    IF NEW.operation = 'plugin_webhook.subscription.create' THEN
        resource_value := NEW.subscription_id;
        SELECT count(*) INTO active_count
        FROM plugin_webhook_subscriptions subscription
        WHERE subscription.tenant_scope_id = NEW.tenant_scope_id
          AND subscription.status = 'active';
        projected_count := active_count;
        IF NOT EXISTS (
            SELECT 1 FROM plugin_webhook_subscriptions subscription
            WHERE subscription.tenant_scope_id = NEW.tenant_scope_id
              AND subscription.id = NEW.subscription_id
        ) THEN
            projected_count := projected_count + 1;
        END IF;
        IF quota_value < 0 OR projected_count > LEAST(quota_value, 100) THEN
            RAISE EXCEPTION 'plugin webhook entitlement quota is exhausted'
                USING ERRCODE = 'P8408', DETAIL = 'plugin_webhook.quota_exceeded';
        END IF;
        reason_value := 'accepted_quota';
    ELSIF NEW.operation IN ('plugin_webhook.test_delivery.create', 'plugin_webhook.delivery.replay') THEN
        resource_value := NEW.delivery_id;
        SELECT count(*) INTO projected_count
        FROM plugin_webhook_subscriptions subscription
        WHERE subscription.tenant_scope_id = NEW.tenant_scope_id
          AND subscription.status = 'active';
        reason_value := 'accepted_feature';
    ELSE
        resource_value := NEW.rotation_id;
        SELECT count(*) INTO projected_count
        FROM plugin_webhook_subscriptions subscription
        WHERE subscription.tenant_scope_id = NEW.tenant_scope_id
          AND subscription.status = 'active';
        reason_value := 'accepted_feature';
    END IF;
    INSERT INTO plugin_webhook_entitlement_decisions(
        request_id,tenant_scope_id,actor_scope_id,actor_user_id,operation,subscription_id,resource_id,
        request_digest,feature_key,lease_installation_id,lease_customer_id,lease_license_id,lease_serial,
        lease_sha256,lease_status,lease_not_before,lease_expires_at,lease_grace_until,
        revocation_revision,revocation_sha256,revocation_key_id,revocation_issued_at,revocation_expires_at,
        evaluated_at,quota_code,quota_limit,quota_current,quota_allowed,reason_code,plugin_webhook_xact_id
    ) VALUES (
        NEW.id,NEW.tenant_scope_id,NEW.actor_scope_id,NEW.actor_user_id,NEW.operation,NEW.subscription_id,resource_value,
        NEW.request_digest,'extensions.webhooks',installation_id_value,
        (lease_body->>'customer_id'),(lease_body->>'license_id'),lease_serial_value,sha256(lease_signed),
        lease_status_value,lease_not_before_value,lease_expires_value,lease_grace_value,
        lkg.revision,lkg.artifact_sha256,lkg.key_id,lkg.issued_at,lkg.expires_at,
        evaluated_at_value,'extensions.webhooks.count',quota_value,projected_count,true,reason_value,pg_current_xact_id()
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER plugin_webhook_write_requests_entitlement_084
AFTER INSERT OR UPDATE OF completed_at ON plugin_webhook_write_requests
FOR EACH ROW WHEN (NEW.operation <> 'plugin_webhook.secret.activate')
EXECUTE FUNCTION record_plugin_webhook_entitlement_decision_084();

CREATE FUNCTION prevent_plugin_webhook_entitlement_decision_mutation_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'plugin webhook entitlement decisions are immutable'
        USING ERRCODE = 'P8403';
END;
$$;

CREATE FUNCTION prevent_plugin_webhook_entitlement_decision_truncate_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'plugin webhook entitlement decisions cannot be truncated'
        USING ERRCODE = 'P8403';
END;
$$;

CREATE TRIGGER plugin_webhook_entitlement_decisions_immutable_084
BEFORE UPDATE OR DELETE ON plugin_webhook_entitlement_decisions
FOR EACH ROW EXECUTE FUNCTION prevent_plugin_webhook_entitlement_decision_mutation_084();
CREATE TRIGGER plugin_webhook_entitlement_decisions_truncate_084
BEFORE TRUNCATE ON plugin_webhook_entitlement_decisions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_plugin_webhook_entitlement_decision_truncate_084();

CREATE TRIGGER plugin_webhook_write_requests_actor_target_084
BEFORE INSERT OR UPDATE ON plugin_webhook_write_requests
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_actor_target_084();

CREATE FUNCTION guard_plugin_webhook_write_request_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'plugin webhook idempotency facts cannot be deleted'
            USING ERRCODE = 'P8403';
    END IF;
    IF ROW(NEW.id, NEW.tenant_scope_id, NEW.actor_scope_id, NEW.actor_user_id,
           NEW.operation, NEW.idempotency_key, NEW.request_digest, NEW.subscription_id,
           NEW.delivery_id, NEW.rotation_id, NEW.created_at) IS DISTINCT FROM
       ROW(OLD.id, OLD.tenant_scope_id, OLD.actor_scope_id, OLD.actor_user_id,
           OLD.operation, OLD.idempotency_key, OLD.request_digest, OLD.subscription_id,
           OLD.delivery_id, OLD.rotation_id, OLD.created_at) THEN
        RAISE EXCEPTION 'plugin webhook idempotency identity is immutable'
            USING ERRCODE = 'P8403';
    END IF;
    IF OLD.completed_at IS NULL THEN
        IF NEW.completed_at IS NULL OR NEW.receipt_cleared_at IS NOT NULL THEN
            RAISE EXCEPTION 'plugin webhook idempotency completion is invalid'
                USING ERRCODE = 'P8404';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.receipt_ciphertext IS NOT NULL AND NEW.receipt_ciphertext IS NULL AND
       NEW.receipt_nonce IS NULL AND NEW.receipt_cleared_at IS NOT NULL AND
       ROW(NEW.response_status, NEW.response_body, NEW.receipt_wrapping_key_id,
           NEW.receipt_aad_sha256, NEW.receipt_expires_at, NEW.audit_event_id, NEW.completed_at) =
       ROW(OLD.response_status, OLD.response_body, OLD.receipt_wrapping_key_id,
           OLD.receipt_aad_sha256, OLD.receipt_expires_at, OLD.audit_event_id, OLD.completed_at) THEN
        IF NEW.receipt_cleared_reason = 'expired' THEN
            NEW.receipt_cleared_at := clock_timestamp();
            IF NEW.receipt_cleared_at < OLD.receipt_expires_at OR
               clock_timestamp() < OLD.receipt_expires_at THEN
                RAISE EXCEPTION 'plugin webhook receipt cannot clear before physical expiry'
                    USING ERRCODE = 'P8404';
            END IF;
        ELSIF NEW.receipt_cleared_reason = 'subscription_revoked' AND EXISTS (
            SELECT 1 FROM plugin_webhook_subscriptions subscription
            WHERE subscription.tenant_scope_id = NEW.tenant_scope_id
              AND subscription.id = NEW.subscription_id AND subscription.status = 'revoked'
              AND subscription.revoked_at = NEW.receipt_cleared_at
              AND subscription.plugin_webhook_xact_id = pg_current_xact_id()
        ) THEN
            NULL;
        ELSE
            RAISE EXCEPTION 'plugin webhook receipt cleanup is not fenced'
                USING ERRCODE = 'P8404';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'completed plugin webhook idempotency fact is immutable'
        USING ERRCODE = 'P8403';
END;
$$;

CREATE TRIGGER plugin_webhook_write_requests_guard_084
BEFORE UPDATE OR DELETE ON plugin_webhook_write_requests
FOR EACH ROW EXECUTE FUNCTION guard_plugin_webhook_write_request_084();
CREATE TRIGGER plugin_webhook_write_requests_truncate_084
BEFORE TRUNCATE ON plugin_webhook_write_requests
FOR EACH STATEMENT EXECUTE FUNCTION prevent_plugin_webhook_truncate_084();

CREATE FUNCTION validate_plugin_webhook_physical_cleanup_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_TABLE_NAME = 'plugin_webhook_secret_versions' THEN
        IF NEW.status IN ('pending', 'retired') AND NEW.ciphertext IS NOT NULL AND
           clock_timestamp() >= NEW.expires_at THEN
            RAISE EXCEPTION 'plugin webhook secret ciphertext cannot outlive its physical lifetime'
                USING ERRCODE = 'P8406';
        ELSIF NEW.status = 'expired' AND (
           NEW.plugin_webhook_recorded_at < NEW.expires_at OR
           clock_timestamp() < NEW.expires_at
        ) THEN
            RAISE EXCEPTION 'plugin webhook secret cannot expire before its physical lifetime'
                USING ERRCODE = 'P8406';
        END IF;
    ELSIF TG_TABLE_NAME = 'plugin_webhook_write_requests' THEN
        IF NEW.receipt_ciphertext IS NOT NULL AND
           clock_timestamp() >= NEW.receipt_expires_at THEN
            RAISE EXCEPTION 'plugin webhook receipt ciphertext cannot outlive its physical lifetime'
                USING ERRCODE = 'P8404';
        ELSIF NEW.receipt_cleared_reason = 'expired' AND (
             NEW.receipt_cleared_at < NEW.receipt_expires_at OR
             clock_timestamp() < NEW.receipt_expires_at
           ) OR NEW.receipt_cleared_reason = 'subscription_revoked' AND NOT EXISTS (
               SELECT 1 FROM plugin_webhook_subscriptions subscription
               WHERE subscription.tenant_scope_id = NEW.tenant_scope_id
                 AND subscription.id = NEW.subscription_id AND subscription.status = 'revoked'
                 AND subscription.revoked_at = NEW.receipt_cleared_at
                 AND subscription.plugin_webhook_xact_id = pg_current_xact_id()
           ) THEN
            RAISE EXCEPTION 'plugin webhook receipt cannot clear before physical expiry'
                USING ERRCODE = 'P8404';
        END IF;
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER plugin_webhook_secret_versions_physical_cleanup_084
AFTER INSERT OR UPDATE ON plugin_webhook_secret_versions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_physical_cleanup_084();
CREATE CONSTRAINT TRIGGER plugin_webhook_write_requests_physical_cleanup_084
AFTER INSERT OR UPDATE ON plugin_webhook_write_requests
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_physical_cleanup_084();

DO $create$
BEGIN
    EXECUTE format($function$
CREATE FUNCTION %1$I.read_plugin_webhook_secret_envelope_084(
    target_scope_id uuid,
    target_subscription_id uuid,
    target_secret_version_id uuid
)
RETURNS TABLE(
    status text,
    fresh boolean,
    version_text text,
    wrapping_key_id text,
    aad_sha256 bytea,
    nonce bytea,
    ciphertext bytea,
    secret_sha256 bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, %1$I
AS $body$
DECLARE
    cleaned_secret_id uuid;
BEGIN
    IF pg_has_role(session_user, to_regrole('cdnca_plugin_webhook_runtime'), 'MEMBER')
           IS NOT TRUE OR
       pg_has_role(session_user, to_regrole('cdnca_control_app'), 'MEMBER') IS TRUE THEN
        RAISE EXCEPTION 'plugin webhook trusted runtime identity is required'
            USING ERRCODE = 'P8408',
                  DETAIL = 'plugin_webhook.runtime_identity_required';
    END IF;
    UPDATE %1$I.plugin_webhook_secret_versions secret
    SET status = 'expired', nonce = NULL, ciphertext = NULL
    WHERE secret.tenant_scope_id = target_scope_id
      AND secret.subscription_id = target_subscription_id
      AND secret.id = target_secret_version_id
      AND secret.status IN ('pending', 'retired')
      AND secret.expires_at IS NOT NULL AND secret.expires_at <= clock_timestamp()
    RETURNING secret.id INTO cleaned_secret_id;
    IF cleaned_secret_id IS NOT NULL THEN
        SET CONSTRAINTS plugin_webhook_secret_versions_active_check_084,
            plugin_webhook_secret_versions_physical_cleanup_084 IMMEDIATE;
        SET CONSTRAINTS plugin_webhook_secret_versions_active_check_084,
            plugin_webhook_secret_versions_physical_cleanup_084 DEFERRED;
        RETURN;
    END IF;
    SELECT secret.status, true, secret.version::text, secret.wrapping_key_id,
           secret.aad_sha256, secret.nonce, secret.ciphertext, secret.secret_sha256
      INTO status, fresh, version_text, wrapping_key_id, aad_sha256,
           nonce, ciphertext, secret_sha256
    FROM %1$I.plugin_webhook_secret_versions secret
    WHERE secret.tenant_scope_id = target_scope_id
      AND secret.subscription_id = target_subscription_id
      AND secret.id = target_secret_version_id
      AND (
          secret.status = 'active' OR
          secret.status = 'retired' AND secret.expires_at > clock_timestamp()
      )
      AND secret.nonce IS NOT NULL AND secret.ciphertext IS NOT NULL
    FOR SHARE;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    RETURN NEXT;
END;
$body$;
$function$, current_schema());
    EXECUTE format($function$
CREATE FUNCTION %1$I.read_plugin_webhook_receipt_envelope_084(
    target_scope_id uuid,
    target_actor_scope_id uuid,
    target_actor_user_id uuid,
    target_idempotency_key text
)
RETURNS TABLE(
    id uuid,
    operation text,
    request_digest bytea,
    subscription_id uuid,
    delivery_id uuid,
    rotation_id uuid,
    response_status integer,
    receipt_wrapping_key_id text,
    receipt_nonce bytea,
    receipt_ciphertext bytea,
    receipt_expires_at timestamptz,
    receipt_cleared_at timestamptz,
    completed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, %1$I
AS $body$
DECLARE
    locked_request_id uuid;
    locked_receipt_expires_at timestamptz;
    physical_now timestamptz;
BEGIN
    IF pg_has_role(session_user, to_regrole('cdnca_control_app'), 'MEMBER')
           IS NOT TRUE OR
       pg_has_role(session_user, to_regrole('cdnca_plugin_webhook_runtime'), 'MEMBER')
           IS TRUE THEN
        RAISE EXCEPTION 'plugin webhook trusted control identity is required'
            USING ERRCODE = 'P8408',
                  DETAIL = 'plugin_webhook.control_identity_required';
    END IF;
    SELECT request.id, request.operation, request.request_digest, request.subscription_id,
           request.delivery_id, request.rotation_id, request.response_status,
           request.receipt_wrapping_key_id, request.receipt_nonce, request.receipt_ciphertext,
           request.receipt_expires_at, request.receipt_cleared_at, request.completed_at
      INTO locked_request_id, operation, request_digest, subscription_id, delivery_id,
           rotation_id, response_status, receipt_wrapping_key_id, receipt_nonce,
           receipt_ciphertext, locked_receipt_expires_at, receipt_cleared_at, completed_at
    FROM %1$I.plugin_webhook_write_requests request
    WHERE request.tenant_scope_id = target_scope_id
      AND request.actor_scope_id = target_actor_scope_id
      AND request.actor_user_id = target_actor_user_id
      AND request.idempotency_key = target_idempotency_key
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    id := locked_request_id;
    receipt_expires_at := locked_receipt_expires_at;
    physical_now := clock_timestamp();
    IF receipt_cleared_at IS NULL AND receipt_ciphertext IS NOT NULL AND
       locked_receipt_expires_at IS NOT NULL AND physical_now >= locked_receipt_expires_at THEN
        UPDATE %1$I.plugin_webhook_write_requests request
        SET receipt_nonce = NULL, receipt_ciphertext = NULL,
            receipt_cleared_at = physical_now, receipt_cleared_reason = 'expired'
        WHERE request.id = locked_request_id AND request.receipt_cleared_at IS NULL
          AND request.receipt_expires_at = locked_receipt_expires_at;
        SET CONSTRAINTS plugin_webhook_write_requests_physical_cleanup_084,
            plugin_webhook_write_requests_audit_084,
            plugin_webhook_write_requests_result_084 IMMEDIATE;
        SET CONSTRAINTS plugin_webhook_write_requests_physical_cleanup_084,
            plugin_webhook_write_requests_audit_084,
            plugin_webhook_write_requests_result_084 DEFERRED;
        receipt_nonce := NULL;
        receipt_ciphertext := NULL;
        receipt_cleared_at := physical_now;
    END IF;
    RETURN NEXT;
END;
$body$;
$function$, current_schema());
END
$create$;

CREATE FUNCTION plugin_webhook_canonical_body_084(
    event_id_value uuid,
    tenant_id_value uuid,
    event_type_value text,
    subject_value text,
    event_time_value timestamptz,
    request_id_value text,
    traceparent_value text,
    sequence_value numeric,
    data_value jsonb
)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
AS $$
DECLARE
    event_time_text text;
BEGIN
    event_time_text := to_char(
        event_time_value AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS'
    );
    IF to_char(event_time_value AT TIME ZONE 'UTC', 'US') = '000000' THEN
        event_time_text := event_time_text || 'Z';
    ELSE
        event_time_text := event_time_text || '.' ||
            rtrim(to_char(event_time_value AT TIME ZONE 'UTC', 'US'), '0') || 'Z';
    END IF;
    RETURN convert_to(
        '{"specversion":"1.0","id":' || to_jsonb(event_id_value::text)::text ||
        ',"source":"/control-plane/plugin-webhooks","type":' || to_jsonb(event_type_value)::text ||
        ',"subject":' || to_jsonb(subject_value)::text ||
        ',"time":' || to_jsonb(event_time_text)::text ||
        ',"datacontenttype":"application/json"' ||
        ',"dataschema":"https://schemas.cdnca.example/marketplace/v1/webhook-test-event.schema.json"' ||
        ',"tenant_id":' || to_jsonb(tenant_id_value::text)::text ||
        ',"request_id":' || to_jsonb(request_id_value)::text ||
        CASE WHEN traceparent_value IS NULL THEN '' ELSE
            ',"traceparent":' || to_jsonb(traceparent_value)::text
        END ||
        ',"sequence":' || sequence_value::text ||
        ',"data":{"subscription_id":' ||
            to_jsonb(data_value ->> 'subscription_id')::text ||
            ',"test":' || (data_value -> 'test')::text || '}}',
        'UTF8'
    );
END;
$$;

CREATE FUNCTION validate_plugin_webhook_event_body_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    event_tenant_id uuid;
    parsed_body jsonb;
    expected_body bytea;
    expected_json jsonb;
BEGIN
    SELECT scope.tenant_id INTO event_tenant_id
    FROM access_scopes scope
    WHERE scope.id = NEW.tenant_scope_id AND scope.kind = 'tenant'
    FOR SHARE;
    BEGIN
        parsed_body := convert_from(NEW.canonical_body, 'UTF8')::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'plugin webhook canonical body is not valid UTF-8 JSON'
            USING ERRCODE = 'P8404';
    END;
    expected_body := plugin_webhook_canonical_body_084(
        NEW.id, event_tenant_id, NEW.event_type, NEW.subject, NEW.event_time,
        NEW.request_id, NEW.traceparent, NEW.sequence, NEW.data
    );
    expected_json := convert_from(expected_body, 'UTF8')::jsonb;
    IF event_tenant_id IS NULL OR parsed_body IS DISTINCT FROM expected_json OR
       NEW.canonical_body IS DISTINCT FROM expected_body OR
       NEW.body_sha256 IS DISTINCT FROM sha256(NEW.canonical_body) THEN
        RAISE EXCEPTION 'plugin webhook canonical body does not match the event fact'
            USING ERRCODE = 'P8404';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TABLE plugin_webhook_events (
    id uuid NOT NULL CHECK (
        id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    tenant_scope_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    sequence numeric(20,0) NOT NULL CHECK (plugin_webhook_u64_084(sequence) AND sequence > 0),
    event_type text NOT NULL CHECK (event_type = 'io.cdnca.webhook.v1.test'),
    subject text NOT NULL,
    request_id text NOT NULL CHECK (
        request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    traceparent text CHECK (
        traceparent IS NULL OR (
            traceparent ~ '^00-[0-9a-f]{32}-[0-9a-f]{16}-(00|01)$' AND
            substr(traceparent, 4, 32) <> repeat('0', 32) AND
            substr(traceparent, 37, 16) <> repeat('0', 16)
        )
    ),
    event_time timestamptz NOT NULL CHECK (isfinite(event_time)),
    data jsonb NOT NULL CHECK (jsonb_typeof(data) = 'object'),
    canonical_body bytea NOT NULL CHECK (octet_length(canonical_body) BETWEEN 2 AND 262144),
    body_sha256 bytea NOT NULL CHECK (octet_length(body_sha256) = 32),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    plugin_webhook_xact_id xid8 NOT NULL,
    plugin_webhook_recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, subscription_id, id),
    FOREIGN KEY (tenant_scope_id, subscription_id)
        REFERENCES plugin_webhook_subscriptions(tenant_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (tenant_scope_id, subscription_id, sequence),
    CHECK (subject = 'webhook_subscription/' || subscription_id::text),
    CHECK (data = jsonb_build_object('subscription_id', subscription_id::text, 'test', true)),
    CHECK (body_sha256 = sha256(canonical_body)),
    CHECK (date_trunc('microseconds', event_time) = event_time),
    CHECK (created_at = event_time)
);

CREATE TRIGGER plugin_webhook_events_00_xact_084
BEFORE INSERT OR UPDATE ON plugin_webhook_events
FOR EACH ROW EXECUTE FUNCTION stamp_plugin_webhook_xact_id_084();

CREATE TRIGGER plugin_webhook_events_actor_target_084
BEFORE INSERT OR UPDATE ON plugin_webhook_events
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_actor_target_084();

CREATE TRIGGER plugin_webhook_events_body_084
BEFORE INSERT ON plugin_webhook_events
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_event_body_084();

CREATE FUNCTION advance_plugin_webhook_event_sequence_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    subscription_status text;
    current_sequence numeric(20,0);
BEGIN
    SELECT status, event_sequence INTO subscription_status, current_sequence
    FROM plugin_webhook_subscriptions
    WHERE tenant_scope_id = NEW.tenant_scope_id AND id = NEW.subscription_id
    FOR UPDATE;
    IF subscription_status IS DISTINCT FROM 'active' OR NEW.sequence <> current_sequence + 1 THEN
        RAISE EXCEPTION 'plugin webhook event sequence is invalid'
            USING ERRCODE = 'P8404';
    END IF;
    UPDATE plugin_webhook_subscriptions
    SET event_sequence = NEW.sequence, updated_at = GREATEST(updated_at, NEW.created_at)
    WHERE tenant_scope_id = NEW.tenant_scope_id AND id = NEW.subscription_id;
    RETURN NEW;
END;
$$;

CREATE TRIGGER plugin_webhook_events_sequence_084
BEFORE INSERT ON plugin_webhook_events
FOR EACH ROW EXECUTE FUNCTION advance_plugin_webhook_event_sequence_084();

CREATE FUNCTION prevent_plugin_webhook_append_mutation_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'plugin webhook append-only fact is immutable'
        USING ERRCODE = 'P8403';
END;
$$;

CREATE TRIGGER plugin_webhook_events_append_only_084
BEFORE UPDATE OR DELETE ON plugin_webhook_events
FOR EACH ROW EXECUTE FUNCTION prevent_plugin_webhook_append_mutation_084();
CREATE TRIGGER plugin_webhook_events_truncate_084
BEFORE TRUNCATE ON plugin_webhook_events
FOR EACH STATEMENT EXECUTE FUNCTION prevent_plugin_webhook_truncate_084();

CREATE TABLE plugin_webhook_deliveries (
    id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    event_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    replay_of uuid,
    delivery_idempotency_key text NOT NULL CHECK (
        delivery_idempotency_key ~ '^plugin-webhook-v2-[0-9a-f]{64}$'
    ),
    target_url text NOT NULL,
    target_host text NOT NULL CHECK (plugin_webhook_target_host_valid_084(target_host)),
    target_path text NOT NULL CHECK (plugin_webhook_target_path_valid_084(target_path)),
    status text NOT NULL CHECK (status IN (
        'pending', 'queued', 'claimed', 'retry_scheduled',
        'delivered', 'dead_letter_pending', 'dead_lettered', 'revoked'
    )),
    subscription_revision numeric(20,0) NOT NULL CHECK (
        plugin_webhook_u64_084(subscription_revision) AND subscription_revision > 0
    ),
    nats_stream_sequence numeric(20,0) CHECK (
        nats_stream_sequence IS NULL OR
        (plugin_webhook_u64_084(nats_stream_sequence) AND nats_stream_sequence > 0)
    ),
    nats_stream_created_unix_nano numeric(20,0) CHECK (
        nats_stream_created_unix_nano IS NULL OR
        (nats_stream_created_unix_nano > 0 AND
         nats_stream_created_unix_nano <= 9223372036854775807)
    ),
    attempt_count numeric(20,0) NOT NULL DEFAULT 0 CHECK (
        plugin_webhook_u64_084(attempt_count) AND attempt_count <= 5
    ),
    next_attempt_at timestamptz CHECK (next_attempt_at IS NULL OR isfinite(next_attempt_at)),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    queued_at timestamptz CHECK (queued_at IS NULL OR isfinite(queued_at)),
    claimed_at timestamptz CHECK (claimed_at IS NULL OR isfinite(claimed_at)),
    completed_at timestamptz CHECK (completed_at IS NULL OR isfinite(completed_at)),
    plugin_webhook_xact_id xid8 NOT NULL,
    plugin_webhook_recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, subscription_id, id),
    FOREIGN KEY (tenant_scope_id, subscription_id, event_id)
        REFERENCES plugin_webhook_events(tenant_scope_id, subscription_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, subscription_id, replay_of)
        REFERENCES plugin_webhook_deliveries(tenant_scope_id, subscription_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    UNIQUE (tenant_scope_id, subscription_id, delivery_idempotency_key),
    CHECK (replay_of IS NULL OR replay_of <> id),
    CHECK (target_url = 'https://' || target_host || target_path),
    CHECK (
        (status = 'pending' AND queued_at IS NULL AND claimed_at IS NULL AND
         completed_at IS NULL AND next_attempt_at IS NULL AND nats_stream_sequence IS NULL AND
         nats_stream_created_unix_nano IS NULL) OR
        (status = 'queued' AND queued_at IS NOT NULL AND claimed_at IS NULL AND
         completed_at IS NULL AND next_attempt_at IS NULL AND nats_stream_sequence IS NOT NULL AND
         nats_stream_created_unix_nano IS NOT NULL) OR
        (status = 'claimed' AND queued_at IS NOT NULL AND claimed_at IS NOT NULL AND
         completed_at IS NULL AND next_attempt_at IS NULL AND nats_stream_sequence IS NOT NULL AND
         nats_stream_created_unix_nano IS NOT NULL) OR
        (status = 'retry_scheduled' AND queued_at IS NOT NULL AND claimed_at IS NOT NULL AND
         completed_at IS NULL AND next_attempt_at IS NOT NULL AND nats_stream_sequence IS NOT NULL AND
         nats_stream_created_unix_nano IS NOT NULL) OR
        (status IN ('delivered', 'dead_letter_pending', 'dead_lettered') AND
         completed_at IS NOT NULL AND nats_stream_sequence IS NOT NULL AND
         nats_stream_created_unix_nano IS NOT NULL) OR
        (status = 'revoked' AND completed_at IS NOT NULL AND
         ((nats_stream_sequence IS NULL AND nats_stream_created_unix_nano IS NULL) OR
          (nats_stream_sequence IS NOT NULL AND nats_stream_created_unix_nano IS NOT NULL)))
    )
);

CREATE TRIGGER plugin_webhook_deliveries_00_xact_084
BEFORE INSERT OR UPDATE ON plugin_webhook_deliveries
FOR EACH ROW EXECUTE FUNCTION stamp_plugin_webhook_xact_id_084();

CREATE UNIQUE INDEX plugin_webhook_deliveries_fresh_event_084
    ON plugin_webhook_deliveries(tenant_scope_id, subscription_id, event_id)
    WHERE replay_of IS NULL;

CREATE INDEX plugin_webhook_deliveries_page_084
    ON plugin_webhook_deliveries(tenant_scope_id, subscription_id, status, created_at DESC, id);
CREATE INDEX plugin_webhook_deliveries_retry_084
    ON plugin_webhook_deliveries(next_attempt_at, id) WHERE status = 'retry_scheduled';
CREATE UNIQUE INDEX plugin_webhook_deliveries_nats_identity_084
    ON plugin_webhook_deliveries(nats_stream_created_unix_nano, nats_stream_sequence)
    WHERE nats_stream_created_unix_nano IS NOT NULL AND nats_stream_sequence IS NOT NULL;

CREATE TRIGGER plugin_webhook_deliveries_actor_target_084
BEFORE INSERT OR UPDATE ON plugin_webhook_deliveries
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_actor_target_084();

CREATE FUNCTION guard_plugin_webhook_delivery_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    subscription_status text;
    subscription_revoke_sequence numeric(20,0);
    secret_expiry_fenced boolean;
    attempt_rebound boolean;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'pending' OR NEW.attempt_count <> 0 OR
           NEW.nats_stream_sequence IS NOT NULL OR
           NEW.nats_stream_created_unix_nano IS NOT NULL OR NEW.next_attempt_at IS NOT NULL OR
           NEW.queued_at IS NOT NULL OR NEW.claimed_at IS NOT NULL OR
           NEW.completed_at IS NOT NULL THEN
            RAISE EXCEPTION 'plugin webhook delivery must start pending and unclaimed'
                USING ERRCODE = 'P8404';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.status <> 'revoked' AND pg_has_role(
        session_user,
        to_regrole('cdnca_plugin_webhook_runtime'),
        'MEMBER'
    ) IS NOT TRUE THEN
        RAISE EXCEPTION 'plugin webhook trusted runtime identity is required'
            USING ERRCODE = 'P8408',
                  DETAIL = 'plugin_webhook.runtime_identity_required';
    END IF;
    IF OLD.status = 'pending' AND NEW.status = 'queued' AND
       current_user::regrole IS DISTINCT FROM (
           SELECT relation.relowner FROM pg_class relation WHERE relation.oid = TG_RELID
       ) THEN
        RAISE EXCEPTION 'plugin webhook queue publication transition is restricted'
            USING ERRCODE = 'P8404';
    END IF;
    IF TG_OP = 'DELETE' OR
       ROW(NEW.id, NEW.tenant_scope_id, NEW.subscription_id, NEW.event_id,
           NEW.actor_scope_id, NEW.actor_user_id, NEW.replay_of,
           NEW.delivery_idempotency_key, NEW.target_url, NEW.target_host, NEW.target_path,
           NEW.subscription_revision, NEW.created_at) IS DISTINCT FROM
       ROW(OLD.id, OLD.tenant_scope_id, OLD.subscription_id, OLD.event_id,
           OLD.actor_scope_id, OLD.actor_user_id, OLD.replay_of,
           OLD.delivery_idempotency_key, OLD.target_url, OLD.target_host, OLD.target_path,
           OLD.subscription_revision, OLD.created_at) OR
       (OLD.nats_stream_sequence IS NOT NULL AND
        ROW(NEW.nats_stream_created_unix_nano, NEW.nats_stream_sequence) IS DISTINCT FROM
        ROW(OLD.nats_stream_created_unix_nano, OLD.nats_stream_sequence)) OR
       OLD.status IN ('delivered', 'dead_lettered', 'revoked') THEN
        RAISE EXCEPTION 'plugin webhook delivery identity or terminal state is immutable'
            USING ERRCODE = 'P8404';
    END IF;
    IF NOT ((OLD.status = 'pending' AND NEW.status IN ('queued', 'revoked')) OR
            (OLD.status = 'queued' AND NEW.status IN ('claimed', 'revoked')) OR
            (OLD.status = 'claimed' AND NEW.status IN (
                'claimed', 'retry_scheduled', 'delivered', 'dead_letter_pending', 'revoked'
            )) OR
            (OLD.status = 'retry_scheduled' AND NEW.status IN ('claimed', 'revoked')) OR
            (OLD.status = 'dead_letter_pending' AND NEW.status = 'dead_lettered')) THEN
        RAISE EXCEPTION 'plugin webhook delivery transition is invalid'
            USING ERRCODE = 'P8404';
    END IF;
    IF NEW.attempt_count < OLD.attempt_count OR NEW.attempt_count > OLD.attempt_count + 1 OR
       NEW.attempt_count > 5 OR
       (NEW.status = 'claimed' AND (
            (OLD.status = 'claimed' AND NEW.attempt_count <> OLD.attempt_count) OR
            (OLD.status <> 'claimed' AND NEW.attempt_count <> OLD.attempt_count + 1)
       )) OR
       (NEW.status <> 'claimed' AND NEW.attempt_count <> OLD.attempt_count) THEN
        RAISE EXCEPTION 'plugin webhook delivery attempt counter is invalid'
            USING ERRCODE = 'P8404';
    END IF;
    IF OLD.status = 'claimed' AND NEW.status = 'claimed' THEN
        SELECT EXISTS (
            SELECT 1 FROM plugin_webhook_delivery_attempts attempt
            WHERE attempt.tenant_scope_id = NEW.tenant_scope_id
              AND attempt.subscription_id = NEW.subscription_id
              AND attempt.delivery_id = NEW.id
              AND attempt.attempt_number = NEW.attempt_count
              AND attempt.status = 'claimed'
              AND attempt.claimed_at = NEW.claimed_at
              AND attempt.plugin_webhook_xact_id = pg_current_xact_id()
        ) INTO attempt_rebound;
        IF NEW.claimed_at IS NOT DISTINCT FROM OLD.claimed_at OR NOT attempt_rebound THEN
            RAISE EXCEPTION 'plugin webhook delivery rebind requires its current transaction attempt'
                USING ERRCODE = 'P8404';
        END IF;
    END IF;
    IF NEW.status IN ('queued', 'revoked') THEN
        SELECT status, revoke_sequence INTO subscription_status, subscription_revoke_sequence
        FROM plugin_webhook_subscriptions
        WHERE tenant_scope_id = NEW.tenant_scope_id AND id = NEW.subscription_id
        FOR SHARE;
    END IF;
    IF NEW.status = 'queued' THEN
        IF subscription_status IS DISTINCT FROM 'active' THEN
            RAISE EXCEPTION 'plugin webhook queue lost the active subscription fence'
                USING ERRCODE = 'P8404';
        END IF;
    ELSIF NEW.status = 'revoked' THEN
        SELECT EXISTS (
            SELECT 1 FROM plugin_webhook_delivery_attempts attempt
            JOIN plugin_webhook_secret_versions secret
              ON secret.tenant_scope_id = attempt.tenant_scope_id
             AND secret.subscription_id = attempt.subscription_id
             AND secret.id = attempt.secret_version_id
            WHERE attempt.tenant_scope_id = NEW.tenant_scope_id
              AND attempt.subscription_id = NEW.subscription_id
              AND attempt.delivery_id = NEW.id AND attempt.status = 'revoked'
              AND attempt.completed_at = NEW.completed_at
              AND secret.status IN ('expired', 'revoked')
              AND secret.expires_at <= NEW.completed_at
              AND clock_timestamp() >= secret.expires_at
        ) INTO secret_expiry_fenced;
        IF (subscription_status IS DISTINCT FROM 'revoked' OR subscription_revoke_sequence IS NULL) AND
           NOT secret_expiry_fenced THEN
            RAISE EXCEPTION 'plugin webhook delivery revoke lost the subscription fence'
                USING ERRCODE = 'P8407';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER plugin_webhook_deliveries_guard_084
BEFORE INSERT OR UPDATE OR DELETE ON plugin_webhook_deliveries
FOR EACH ROW EXECUTE FUNCTION guard_plugin_webhook_delivery_084();
CREATE TRIGGER plugin_webhook_deliveries_truncate_084
BEFORE TRUNCATE ON plugin_webhook_deliveries
FOR EACH STATEMENT EXECUTE FUNCTION prevent_plugin_webhook_truncate_084();

CREATE FUNCTION validate_plugin_webhook_replay_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    subscription_status text;
    subscription_revision numeric(20,0);
    subscription_target_url text;
    subscription_target_host text;
    subscription_target_path text;
    original_status text;
    original_event_id uuid;
BEGIN
    SELECT status, revision, target_url, target_host, target_path
      INTO subscription_status, subscription_revision, subscription_target_url,
           subscription_target_host, subscription_target_path
    FROM plugin_webhook_subscriptions
    WHERE tenant_scope_id = NEW.tenant_scope_id AND id = NEW.subscription_id
    FOR SHARE;
    IF NEW.target_url <> 'https://' || NEW.target_host || NEW.target_path THEN
        RETURN NEW;
    END IF;
    IF subscription_status IS DISTINCT FROM 'active' OR
       NEW.subscription_revision <> subscription_revision OR
       ROW(NEW.target_url, NEW.target_host, NEW.target_path) IS DISTINCT FROM
       ROW(subscription_target_url, subscription_target_host, subscription_target_path) OR
       NEW.delivery_idempotency_key <> 'plugin-webhook-v2-' ||
           encode(sha256(convert_to(NEW.id::text, 'UTF8')), 'hex') THEN
        RAISE EXCEPTION 'plugin webhook delivery is outside the active subscription fence'
            USING ERRCODE = 'P8404';
    END IF;
    IF NEW.replay_of IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT status, event_id INTO original_status, original_event_id
    FROM plugin_webhook_deliveries
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND subscription_id = NEW.subscription_id AND id = NEW.replay_of
    FOR SHARE;
    IF original_status NOT IN ('delivered', 'dead_lettered') OR
       NEW.event_id IS DISTINCT FROM original_event_id OR
       (original_status = 'dead_lettered' AND NOT EXISTS (
           SELECT 1 FROM plugin_webhook_dead_letters dead_letter
           WHERE dead_letter.tenant_scope_id = NEW.tenant_scope_id
             AND dead_letter.subscription_id = NEW.subscription_id
             AND dead_letter.delivery_id = NEW.replay_of
             AND dead_letter.publish_state = 'acknowledged'
       )) THEN
        RAISE EXCEPTION 'plugin webhook delivery is not replayable'
            USING ERRCODE = 'P8404';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER plugin_webhook_deliveries_replay_084
BEFORE INSERT ON plugin_webhook_deliveries
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_replay_084();

CREATE TABLE plugin_webhook_outbox (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    event_id uuid NOT NULL,
    delivery_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    queue_schema text NOT NULL CHECK (queue_schema = 'cdnca.plugin-webhook.queue/v2'),
    queue_body bytea NOT NULL CHECK (octet_length(queue_body) BETWEEN 2 AND 262144),
    queue_body_sha256 bytea NOT NULL CHECK (octet_length(queue_body_sha256) = 32),
    message_id text NOT NULL CHECK (message_id ~ '^plugin-webhook-v2-[0-9a-f]{64}$'),
    status text NOT NULL CHECK (status IN ('pending', 'leased', 'published', 'revoked')),
    lease_token uuid,
    lease_expires_at timestamptz CHECK (lease_expires_at IS NULL OR isfinite(lease_expires_at)),
    publish_attempt numeric(20,0) NOT NULL DEFAULT 0 CHECK (plugin_webhook_u64_084(publish_attempt)),
    available_at timestamptz NOT NULL CHECK (isfinite(available_at)),
    leased_at timestamptz CHECK (leased_at IS NULL OR isfinite(leased_at)),
    published_at timestamptz CHECK (published_at IS NULL OR isfinite(published_at)),
    publication_lease_token uuid,
    publication_publish_attempt numeric(20,0) CHECK (
        publication_publish_attempt IS NULL OR
        (plugin_webhook_u64_084(publication_publish_attempt) AND publication_publish_attempt > 0)
    ),
    publication_nats_domain text CHECK (
        publication_nats_domain IS NULL OR
        (octet_length(publication_nats_domain) <= 128 AND
         publication_nats_domain ~ '^[A-Za-z0-9_-]*$')
    ),
    publication_nats_stream text CHECK (
        publication_nats_stream IS NULL OR
        (char_length(publication_nats_stream) BETWEEN 1 AND 128 AND
         publication_nats_stream ~ '^[A-Za-z0-9_-]+$')
    ),
    publication_stream_created_unix_nano numeric(20,0) CHECK (
        publication_stream_created_unix_nano IS NULL OR
        (publication_stream_created_unix_nano > 0 AND
         publication_stream_created_unix_nano <= 9223372036854775807)
    ),
    publication_nats_subject text CHECK (
        publication_nats_subject IS NULL OR
        (char_length(publication_nats_subject) BETWEEN 1 AND 512 AND
         publication_nats_subject ~ '^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$')
    ),
    publication_nats_sequence numeric(20,0) CHECK (
        publication_nats_sequence IS NULL OR
        (plugin_webhook_u64_084(publication_nats_sequence) AND
         publication_nats_sequence > 0)
    ),
    publication_expected_last_subject_sequence numeric(20,0) CHECK (
        publication_expected_last_subject_sequence IS NULL OR
        publication_expected_last_subject_sequence = 0
    ),
    publication_attestation_generation numeric(20,0),
    publication_attestation_key_id text,
    publication_attestation_sha256 bytea CHECK (
        publication_attestation_sha256 IS NULL OR
        octet_length(publication_attestation_sha256) = 32
    ),
    publication_attestation_signature bytea CHECK (
        publication_attestation_signature IS NULL OR
        octet_length(publication_attestation_signature) = 64
    ),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    FOREIGN KEY (tenant_scope_id, subscription_id, event_id)
        REFERENCES plugin_webhook_events(tenant_scope_id, subscription_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, subscription_id, delivery_id)
        REFERENCES plugin_webhook_deliveries(tenant_scope_id, subscription_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (publication_attestation_generation, publication_attestation_key_id)
        REFERENCES plugin_webhook_runtime_attestation_keys(key_generation, key_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    UNIQUE (tenant_scope_id, subscription_id, delivery_id),
    UNIQUE (message_id),
    UNIQUE (publication_nats_domain, publication_nats_stream,
        publication_stream_created_unix_nano, publication_nats_sequence),
    CHECK (queue_body_sha256 = sha256(queue_body)),
    CHECK (
        (status = 'pending' AND lease_token IS NULL AND lease_expires_at IS NULL AND
         leased_at IS NULL AND published_at IS NULL AND
         publication_lease_token IS NULL AND publication_publish_attempt IS NULL AND
         publication_nats_domain IS NULL AND publication_nats_stream IS NULL AND
         publication_stream_created_unix_nano IS NULL AND publication_nats_subject IS NULL AND
         publication_nats_sequence IS NULL AND
         publication_expected_last_subject_sequence IS NULL AND
         publication_attestation_generation IS NULL AND publication_attestation_key_id IS NULL AND
         publication_attestation_sha256 IS NULL AND publication_attestation_signature IS NULL) OR
        (status = 'leased' AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL AND
         leased_at IS NOT NULL AND published_at IS NULL AND
         publication_lease_token IS NULL AND publication_publish_attempt IS NULL AND
         publication_nats_domain IS NULL AND publication_nats_stream IS NULL AND
         publication_stream_created_unix_nano IS NULL AND publication_nats_subject IS NULL AND
         publication_nats_sequence IS NULL AND
         publication_expected_last_subject_sequence IS NULL AND
         publication_attestation_generation IS NULL AND publication_attestation_key_id IS NULL AND
         publication_attestation_sha256 IS NULL AND publication_attestation_signature IS NULL) OR
        (status = 'published' AND lease_token IS NULL AND lease_expires_at IS NULL AND
         leased_at IS NOT NULL AND published_at IS NOT NULL AND
         publication_lease_token IS NOT NULL AND publication_publish_attempt = publish_attempt AND
         publication_nats_domain IS NOT NULL AND publication_nats_stream IS NOT NULL AND
         publication_stream_created_unix_nano IS NOT NULL AND publication_nats_subject IS NOT NULL AND
         publication_nats_sequence IS NOT NULL AND
         publication_expected_last_subject_sequence = 0 AND
         publication_attestation_generation IS NOT NULL AND publication_attestation_key_id IS NOT NULL AND
         publication_attestation_sha256 IS NOT NULL AND publication_attestation_signature IS NOT NULL) OR
        (status = 'revoked' AND lease_token IS NULL AND lease_expires_at IS NULL AND
         published_at IS NULL AND publication_lease_token IS NULL AND
         publication_publish_attempt IS NULL AND publication_nats_domain IS NULL AND
         publication_nats_stream IS NULL AND publication_stream_created_unix_nano IS NULL AND
         publication_nats_subject IS NULL AND publication_nats_sequence IS NULL AND
         publication_expected_last_subject_sequence IS NULL AND
         publication_attestation_generation IS NULL AND publication_attestation_key_id IS NULL AND
         publication_attestation_sha256 IS NULL AND publication_attestation_signature IS NULL)
    )
);

CREATE INDEX plugin_webhook_outbox_pending_084
    ON plugin_webhook_outbox(available_at, id) WHERE status = 'pending';
CREATE INDEX plugin_webhook_outbox_leases_084
    ON plugin_webhook_outbox(lease_expires_at, id) WHERE status = 'leased';

CREATE TRIGGER plugin_webhook_outbox_actor_target_084
BEFORE INSERT OR UPDATE ON plugin_webhook_outbox
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_actor_target_084();

CREATE FUNCTION guard_plugin_webhook_outbox_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    subscription_status text;
    delivery_event_id uuid;
    delivery_status text;
    delivery_actor_scope uuid;
    delivery_actor_user uuid;
    delivery_replay_of uuid;
    event_body bytea;
    event_digest bytea;
    event_actor_scope uuid;
    event_actor_user uuid;
    physical_now timestamptz;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'pending' OR NEW.publish_attempt <> 0 OR
           NEW.lease_token IS NOT NULL OR NEW.lease_expires_at IS NOT NULL OR
           NEW.leased_at IS NOT NULL OR NEW.published_at IS NOT NULL THEN
            RAISE EXCEPTION 'plugin webhook outbox must start pending and unleased'
                USING ERRCODE = 'P8404';
        END IF;
        SELECT status INTO subscription_status
        FROM plugin_webhook_subscriptions
        WHERE tenant_scope_id = NEW.tenant_scope_id AND id = NEW.subscription_id
        FOR SHARE;
        SELECT event_id, status, actor_scope_id, actor_user_id, replay_of
          INTO delivery_event_id, delivery_status, delivery_actor_scope,
               delivery_actor_user, delivery_replay_of
        FROM plugin_webhook_deliveries
        WHERE tenant_scope_id = NEW.tenant_scope_id
          AND subscription_id = NEW.subscription_id AND id = NEW.delivery_id
        FOR SHARE;
        SELECT canonical_body, body_sha256, actor_scope_id, actor_user_id
          INTO event_body, event_digest, event_actor_scope, event_actor_user
        FROM plugin_webhook_events
        WHERE tenant_scope_id = NEW.tenant_scope_id
          AND subscription_id = NEW.subscription_id AND id = NEW.event_id
        FOR SHARE;
        IF subscription_status IS DISTINCT FROM 'active' OR delivery_status <> 'pending' OR
           delivery_event_id IS DISTINCT FROM NEW.event_id OR
           NEW.actor_scope_id IS DISTINCT FROM delivery_actor_scope OR
           NEW.actor_user_id IS DISTINCT FROM delivery_actor_user OR
           (delivery_replay_of IS NULL AND (
               event_actor_scope IS DISTINCT FROM delivery_actor_scope OR
               event_actor_user IS DISTINCT FROM delivery_actor_user
           )) OR
           event_body IS DISTINCT FROM NEW.queue_body OR
           event_digest IS DISTINCT FROM NEW.queue_body_sha256 OR
           NEW.queue_body_sha256 IS DISTINCT FROM sha256(NEW.queue_body) OR
           NEW.message_id <> 'plugin-webhook-v2-' ||
               encode(sha256(convert_to('msg-' || NEW.delivery_id::text, 'UTF8')), 'hex') THEN
            RAISE EXCEPTION 'plugin webhook outbox identity is outside the active delivery fence'
                USING ERRCODE = 'P8404';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.status <> 'revoked' AND pg_has_role(
        session_user,
        to_regrole('cdnca_plugin_webhook_runtime'),
        'MEMBER'
    ) IS NOT TRUE THEN
        RAISE EXCEPTION 'plugin webhook trusted runtime identity is required'
            USING ERRCODE = 'P8408',
                  DETAIL = 'plugin_webhook.runtime_identity_required';
    END IF;
    IF TG_OP = 'DELETE' OR
       ROW(NEW.id, NEW.tenant_scope_id, NEW.subscription_id, NEW.event_id,
           NEW.delivery_id, NEW.actor_scope_id, NEW.actor_user_id, NEW.queue_schema,
           NEW.queue_body, NEW.queue_body_sha256, NEW.message_id, NEW.available_at,
           NEW.created_at) IS DISTINCT FROM
       ROW(OLD.id, OLD.tenant_scope_id, OLD.subscription_id, OLD.event_id,
           OLD.delivery_id, OLD.actor_scope_id, OLD.actor_user_id, OLD.queue_schema,
           OLD.queue_body, OLD.queue_body_sha256, OLD.message_id, OLD.available_at,
           OLD.created_at) OR
       OLD.status IN ('published', 'revoked') THEN
        RAISE EXCEPTION 'plugin webhook outbox identity or terminal state is immutable'
            USING ERRCODE = 'P8404';
    END IF;
    physical_now := clock_timestamp();
    IF OLD.status = 'pending' AND NEW.status = 'leased' THEN
        IF OLD.available_at > physical_now OR
           NEW.publish_attempt <> OLD.publish_attempt + 1 OR
           NEW.lease_token IS NULL OR NEW.lease_expires_at IS NULL OR
           NEW.lease_expires_at <= physical_now OR
           NEW.lease_expires_at > physical_now + interval '5 minutes' THEN
            RAISE EXCEPTION 'plugin webhook outbox lease is invalid or not due'
                USING ERRCODE = 'P8404';
        END IF;
        NEW.leased_at := physical_now;
    ELSIF OLD.status = 'leased' AND NEW.status = 'pending' THEN
        IF physical_now < OLD.lease_expires_at OR
           NEW.publish_attempt <> OLD.publish_attempt THEN
            RAISE EXCEPTION 'plugin webhook outbox lease is not physically recoverable'
                USING ERRCODE = 'P8404';
        END IF;
    ELSIF OLD.status = 'leased' AND NEW.status = 'published' THEN
        IF physical_now >= OLD.lease_expires_at OR
           NEW.publish_attempt <> OLD.publish_attempt OR
           NEW.leased_at IS DISTINCT FROM OLD.leased_at OR
           current_user::regrole IS DISTINCT FROM (
               SELECT relation.relowner FROM pg_class relation WHERE relation.oid = TG_RELID
           ) OR NEW.publication_lease_token IS DISTINCT FROM OLD.lease_token OR
           NEW.publication_publish_attempt IS DISTINCT FROM OLD.publish_attempt THEN
            RAISE EXCEPTION 'plugin webhook outbox publication lacks a valid lease'
                USING ERRCODE = 'P8404';
        END IF;
        NEW.published_at := physical_now;
    ELSIF ((OLD.status = 'pending' OR OLD.status = 'leased') AND NEW.status = 'revoked') THEN
        IF NEW.publish_attempt <> OLD.publish_attempt THEN
            RAISE EXCEPTION 'plugin webhook revoked outbox changed its publish attempt'
                USING ERRCODE = 'P8404';
        END IF;
    ELSE
        RAISE EXCEPTION 'plugin webhook outbox transition is invalid'
            USING ERRCODE = 'P8404';
    END IF;
    IF NEW.status IN ('leased', 'published') THEN
        SELECT status INTO subscription_status
        FROM plugin_webhook_subscriptions
        WHERE tenant_scope_id = NEW.tenant_scope_id AND id = NEW.subscription_id
        FOR SHARE;
        SELECT event_id, status INTO delivery_event_id, delivery_status
        FROM plugin_webhook_deliveries
        WHERE tenant_scope_id = NEW.tenant_scope_id
          AND subscription_id = NEW.subscription_id AND id = NEW.delivery_id
        FOR SHARE;
        IF subscription_status IS DISTINCT FROM 'active' OR
           delivery_event_id IS DISTINCT FROM NEW.event_id OR
           (NEW.status = 'leased' AND delivery_status IS DISTINCT FROM 'pending') OR
           (NEW.status = 'published' AND delivery_status IS DISTINCT FROM 'queued') THEN
            RAISE EXCEPTION 'plugin webhook publish lost the active subscription fence'
                USING ERRCODE = 'P8404';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DO $create$
BEGIN
    EXECUTE format($function$
CREATE FUNCTION %1$I.publish_plugin_webhook_outbox_084(
    target_scope_id uuid,
    target_subscription_id uuid,
    target_delivery_id uuid,
    caller_lease_token uuid,
    broker_nats_domain text,
    broker_stream text,
    broker_stream_created_unix_nano numeric,
    broker_subject text,
    broker_sequence numeric,
    broker_message_id text,
    broker_queue_body_sha256 bytea,
    broker_expected_last_subject_sequence numeric,
    attestation_generation numeric,
    attestation_key_id text,
    attestation_signature bytea
)
RETURNS timestamptz
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $body$
DECLARE
    head_record record;
    delivery_record record;
    outbox_record record;
    subscription_status text;
    publication_time timestamptz;
    attestation_digest bytea;
    expected_subject text;
BEGIN
    IF pg_has_role(
        session_user,
        to_regrole('cdnca_plugin_webhook_runtime'),
        'MEMBER'
    ) IS NOT TRUE THEN
        RAISE EXCEPTION 'plugin webhook trusted runtime identity is required'
            USING ERRCODE = 'P8408',
                  DETAIL = 'plugin_webhook.runtime_identity_required';
    END IF;
    SELECT * INTO head_record
    FROM %1$I.plugin_webhook_runtime_attestation_head
    WHERE singleton = true
    FOR SHARE;
    SELECT status INTO subscription_status
    FROM %1$I.plugin_webhook_subscriptions
    WHERE tenant_scope_id = target_scope_id AND id = target_subscription_id
    FOR SHARE;
    SELECT id, event_id, status INTO delivery_record
    FROM %1$I.plugin_webhook_deliveries
    WHERE tenant_scope_id = target_scope_id AND subscription_id = target_subscription_id
      AND id = target_delivery_id
    FOR UPDATE;
    SELECT * INTO outbox_record
    FROM %1$I.plugin_webhook_outbox
    WHERE tenant_scope_id = target_scope_id AND subscription_id = target_subscription_id
      AND delivery_id = target_delivery_id
    FOR UPDATE;
    publication_time := clock_timestamp();
    expected_subject := head_record.delivery_subject_prefix || '.' || target_scope_id::text ||
        '.' || target_subscription_id::text || '_' || target_delivery_id::text;
    IF head_record.singleton IS DISTINCT FROM true OR head_record.status IS DISTINCT FROM 'active' OR
       publication_time < head_record.not_before OR publication_time >= head_record.expires_at OR
       subscription_status IS DISTINCT FROM 'active' OR delivery_record.id IS NULL OR
       delivery_record.status IS DISTINCT FROM 'pending' OR outbox_record.id IS NULL OR
       outbox_record.status IS DISTINCT FROM 'leased' OR caller_lease_token IS NULL OR
       outbox_record.lease_token IS DISTINCT FROM caller_lease_token OR
       outbox_record.lease_expires_at <= publication_time OR outbox_record.publish_attempt <= 0 OR
       broker_nats_domain IS DISTINCT FROM head_record.nats_domain OR
       broker_stream IS DISTINCT FROM head_record.delivery_stream OR
       broker_stream_created_unix_nano IS NULL OR broker_stream_created_unix_nano <= 0 OR
       broker_stream_created_unix_nano > 9223372036854775807 OR
       broker_subject IS DISTINCT FROM expected_subject OR
       broker_sequence IS NULL OR broker_sequence <= 0 OR
       NOT %1$I.plugin_webhook_u64_084(broker_sequence) OR
       broker_message_id IS DISTINCT FROM outbox_record.message_id OR
       broker_queue_body_sha256 IS DISTINCT FROM outbox_record.queue_body_sha256 OR
       broker_expected_last_subject_sequence IS DISTINCT FROM 0 OR
       attestation_generation IS DISTINCT FROM head_record.key_generation OR
       attestation_key_id IS DISTINCT FROM head_record.key_id OR
       octet_length(attestation_signature) IS DISTINCT FROM 64 THEN
        RAISE EXCEPTION 'plugin webhook outbox publication attestation is invalid'
            USING ERRCODE = 'P8404';
    END IF;
    attestation_digest := %1$I.plugin_webhook_outbox_attestation_sha256_084(
        attestation_generation, attestation_key_id, broker_nats_domain,
        target_scope_id, target_subscription_id, target_delivery_id,
        delivery_record.event_id, outbox_record.id, caller_lease_token,
        outbox_record.publish_attempt, broker_stream, broker_stream_created_unix_nano,
        broker_subject, broker_sequence, broker_message_id, broker_queue_body_sha256,
        broker_expected_last_subject_sequence
    );
    IF NOT %1$I.plugin_webhook_ed25519_verify_084(
        head_record.public_key, attestation_digest, attestation_signature
    ) THEN
        RAISE EXCEPTION 'plugin webhook outbox publication attestation is invalid'
            USING ERRCODE = 'P8404';
    END IF;
    UPDATE %1$I.plugin_webhook_deliveries
    SET status = 'queued', queued_at = publication_time,
        nats_stream_created_unix_nano = broker_stream_created_unix_nano,
        nats_stream_sequence = broker_sequence
    WHERE tenant_scope_id = target_scope_id AND subscription_id = target_subscription_id
      AND id = target_delivery_id AND status = 'pending';
    UPDATE %1$I.plugin_webhook_outbox
    SET status = 'published', lease_token = NULL, lease_expires_at = NULL,
        publication_lease_token = caller_lease_token,
        publication_publish_attempt = outbox_record.publish_attempt,
        publication_nats_domain = broker_nats_domain,
        publication_nats_stream = broker_stream,
        publication_stream_created_unix_nano = broker_stream_created_unix_nano,
        publication_nats_subject = broker_subject,
        publication_nats_sequence = broker_sequence,
        publication_expected_last_subject_sequence = broker_expected_last_subject_sequence,
        publication_attestation_generation = attestation_generation,
        publication_attestation_key_id = attestation_key_id,
        publication_attestation_sha256 = attestation_digest,
        publication_attestation_signature = attestation_signature
    WHERE id = outbox_record.id AND status = 'leased' AND lease_token = caller_lease_token
    RETURNING published_at INTO publication_time;
    IF publication_time IS NULL THEN
        RAISE EXCEPTION 'plugin webhook outbox publication lease is stale'
            USING ERRCODE = 'P8404';
    END IF;
    RETURN publication_time;
END;
$body$;
$function$, current_schema());
END;
$create$;

CREATE TRIGGER plugin_webhook_outbox_guard_084
BEFORE INSERT OR UPDATE OR DELETE ON plugin_webhook_outbox
FOR EACH ROW EXECUTE FUNCTION guard_plugin_webhook_outbox_084();
CREATE TRIGGER plugin_webhook_outbox_truncate_084
BEFORE TRUNCATE ON plugin_webhook_outbox
FOR EACH STATEMENT EXECUTE FUNCTION prevent_plugin_webhook_truncate_084();

CREATE FUNCTION validate_plugin_webhook_delivery_outbox_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    delivery_id_value uuid;
    delivery_event_id uuid;
    delivery_status text;
    outbox_event_id uuid;
    outbox_status text;
BEGIN
    IF TG_TABLE_NAME = 'plugin_webhook_deliveries' THEN
        delivery_id_value := NEW.id;
    ELSE
        delivery_id_value := NEW.delivery_id;
    END IF;
    SELECT event_id, status INTO delivery_event_id, delivery_status
    FROM plugin_webhook_deliveries
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND subscription_id = NEW.subscription_id AND id = delivery_id_value
    FOR SHARE;
    SELECT event_id, status INTO outbox_event_id, outbox_status
    FROM plugin_webhook_outbox
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND subscription_id = NEW.subscription_id AND delivery_id = delivery_id_value
    FOR SHARE;
    IF delivery_event_id IS NULL OR outbox_event_id IS NULL OR
       delivery_event_id IS DISTINCT FROM outbox_event_id OR
       NOT (
           (delivery_status = 'pending' AND outbox_status IN ('pending', 'leased')) OR
           (delivery_status = 'queued' AND outbox_status = 'published') OR
           (delivery_status IN (
                'claimed', 'retry_scheduled', 'delivered', 'dead_letter_pending', 'dead_lettered'
            ) AND
            outbox_status = 'published') OR
           (delivery_status = 'revoked' AND outbox_status IN ('revoked', 'published'))
       ) THEN
        RAISE EXCEPTION 'plugin webhook delivery and durable outbox states are inconsistent'
            USING ERRCODE = 'P8404';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER plugin_webhook_deliveries_outbox_084
AFTER INSERT OR UPDATE ON plugin_webhook_deliveries
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_delivery_outbox_084();

CREATE CONSTRAINT TRIGGER plugin_webhook_outbox_delivery_084
AFTER INSERT OR UPDATE ON plugin_webhook_outbox
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_delivery_outbox_084();

CREATE FUNCTION plugin_webhook_retry_delay_seconds_084(
    delivery_value uuid,
    attempt_value numeric,
    completed_value timestamptz,
    retry_after_value integer
)
RETURNS integer
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
AS $$
DECLARE
    ceiling_seconds integer;
    floor_seconds integer;
    jitter_seed integer;
    digest_value bytea;
BEGIN
    IF retry_after_value IS NOT NULL THEN
        IF retry_after_value < 0 OR retry_after_value > 300 THEN
            RAISE EXCEPTION 'plugin webhook Retry-After is outside the five minute bound'
                USING ERRCODE = 'P8404';
        END IF;
        RETURN retry_after_value;
    END IF;
    ceiling_seconds := CASE attempt_value::integer
        WHEN 1 THEN 60
        WHEN 2 THEN 120
        WHEN 3 THEN 240
        WHEN 4 THEN 480
        WHEN 5 THEN 900
        ELSE NULL
    END;
    IF ceiling_seconds IS NULL OR attempt_value <> trunc(attempt_value) OR completed_value IS NULL THEN
        RAISE EXCEPTION 'plugin webhook retry backoff identity is invalid'
            USING ERRCODE = 'P8404';
    END IF;
    floor_seconds := ceiling_seconds * 3 / 4;
    digest_value := sha256(
        convert_to(delivery_value::text, 'UTF8') || decode('00', 'hex') ||
        convert_to(attempt_value::text, 'UTF8') || decode('00', 'hex') ||
        convert_to(extract(epoch FROM completed_value)::numeric::text, 'UTF8')
    );
    jitter_seed := get_byte(digest_value, 0) * 256 + get_byte(digest_value, 1);
    RETURN floor_seconds + mod(jitter_seed, ceiling_seconds - floor_seconds + 1);
END;
$$;

CREATE TABLE plugin_webhook_delivery_attempts (
    tenant_scope_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    delivery_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    attempt_number numeric(20,0) NOT NULL CHECK (
        plugin_webhook_u64_084(attempt_number) AND attempt_number BETWEEN 1 AND 5
    ),
    claim_token uuid NOT NULL,
    claim_sequence numeric(20,0) NOT NULL CHECK (
        plugin_webhook_u64_084(claim_sequence) AND claim_sequence > 0
    ),
    claimed_subscription_revision numeric(20,0) NOT NULL CHECK (
        plugin_webhook_u64_084(claimed_subscription_revision) AND claimed_subscription_revision > 0
    ),
    secret_version_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN (
        'claimed', 'started', 'succeeded', 'temporary_failure', 'permanent_failure', 'revoked'
    )),
    claimed_at timestamptz NOT NULL CHECK (isfinite(claimed_at)),
    started_at timestamptz CHECK (started_at IS NULL OR isfinite(started_at)),
    completed_at timestamptz CHECK (completed_at IS NULL OR isfinite(completed_at)),
    http_status integer CHECK (http_status BETWEEN 100 AND 599),
    failure_code text CHECK (
        failure_code IS NULL OR (
            plugin_webhook_text_valid_084(failure_code, 128) AND
            failure_code ~ '^[a-z][a-z0-9_]{0,127}$'
        )
    ),
    retry_after_seconds integer CHECK (retry_after_seconds BETWEEN 0 AND 300),
    retry_delay_seconds integer CHECK (retry_delay_seconds BETWEEN 0 AND 900),
    request_sha256 bytea CHECK (request_sha256 IS NULL OR octet_length(request_sha256) = 32),
    response_sha256 bytea CHECK (response_sha256 IS NULL OR octet_length(response_sha256) = 32),
    response_bytes integer CHECK (response_bytes BETWEEN 0 AND 65536),
    response_preview bytea CHECK (response_preview IS NULL OR response_preview = ''::bytea),
    sanitized_headers jsonb CHECK (
        sanitized_headers IS NULL OR plugin_webhook_sanitized_headers_valid_084(sanitized_headers)
    ),
    plugin_webhook_xact_id xid8 NOT NULL,
    plugin_webhook_recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, subscription_id, delivery_id, attempt_number),
    FOREIGN KEY (tenant_scope_id, subscription_id, delivery_id)
        REFERENCES plugin_webhook_deliveries(tenant_scope_id, subscription_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, subscription_id, secret_version_id)
        REFERENCES plugin_webhook_secret_versions(tenant_scope_id, subscription_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (claim_token),
    CHECK (
        (status = 'claimed' AND started_at IS NULL AND completed_at IS NULL AND
         http_status IS NULL AND failure_code IS NULL AND retry_after_seconds IS NULL AND
         retry_delay_seconds IS NULL AND
         request_sha256 IS NULL AND response_sha256 IS NULL AND response_bytes IS NULL AND
         response_preview IS NULL AND sanitized_headers IS NULL) OR
        (status = 'started' AND started_at IS NOT NULL AND completed_at IS NULL AND
         http_status IS NULL AND failure_code IS NULL AND retry_after_seconds IS NULL AND
         retry_delay_seconds IS NULL AND
         request_sha256 IS NOT NULL AND response_sha256 IS NULL AND response_bytes IS NULL AND
         response_preview IS NULL AND sanitized_headers IS NULL) OR
        (status = 'succeeded' AND
         started_at IS NOT NULL AND completed_at IS NOT NULL AND completed_at >= started_at AND
         http_status BETWEEN 200 AND 299 AND failure_code IS NULL AND retry_after_seconds IS NULL AND
         retry_delay_seconds IS NULL AND
         request_sha256 IS NOT NULL AND response_bytes IS NOT NULL AND sanitized_headers IS NOT NULL) OR
        (status IN ('temporary_failure', 'permanent_failure') AND
         started_at IS NOT NULL AND completed_at IS NOT NULL AND completed_at >= started_at AND
         (http_status IS NULL OR http_status NOT BETWEEN 200 AND 299) AND failure_code IS NOT NULL AND
         (status = 'temporary_failure' OR retry_after_seconds IS NULL) AND
         ((status = 'temporary_failure' AND retry_delay_seconds = plugin_webhook_retry_delay_seconds_084(
              delivery_id, attempt_number, completed_at, retry_after_seconds
          )) OR (status = 'permanent_failure' AND retry_delay_seconds IS NULL)) AND
         request_sha256 IS NOT NULL AND response_bytes IS NOT NULL AND sanitized_headers IS NOT NULL) OR
        (status = 'revoked' AND started_at IS NULL AND completed_at IS NOT NULL AND
         http_status IS NULL AND failure_code IS NULL AND retry_after_seconds IS NULL AND
         retry_delay_seconds IS NULL AND
         request_sha256 IS NULL AND response_sha256 IS NULL AND response_bytes IS NULL AND
         response_preview IS NULL AND sanitized_headers IS NULL)
    )
);

CREATE TRIGGER plugin_webhook_attempts_00_xact_084
BEFORE INSERT OR UPDATE ON plugin_webhook_delivery_attempts
FOR EACH ROW EXECUTE FUNCTION stamp_plugin_webhook_xact_id_084();

CREATE INDEX plugin_webhook_attempt_claims_084
    ON plugin_webhook_delivery_attempts(claimed_at, claim_token)
    WHERE status IN ('claimed', 'started');

CREATE TRIGGER plugin_webhook_attempts_actor_target_084
BEFORE INSERT OR UPDATE ON plugin_webhook_delivery_attempts
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_actor_target_084();

CREATE FUNCTION claim_plugin_webhook_attempt_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    subscription_status text;
    subscription_revision numeric(20,0);
    subscription_secret uuid;
    subscription_lifecycle numeric(20,0);
    delivery_status text;
    delivery_attempts numeric(20,0);
    delivery_actor_scope uuid;
    delivery_actor_user uuid;
    delivery_next_attempt_at timestamptz;
    transition_at timestamptz;
BEGIN
    IF pg_has_role(
        session_user,
        to_regrole('cdnca_plugin_webhook_runtime'),
        'MEMBER'
    ) IS NOT TRUE THEN
        RAISE EXCEPTION 'plugin webhook trusted runtime identity is required'
            USING ERRCODE = 'P8408',
                  DETAIL = 'plugin_webhook.runtime_identity_required';
    END IF;
    SELECT status, revision, active_secret_version_id, lifecycle_sequence
      INTO subscription_status, subscription_revision, subscription_secret, subscription_lifecycle
    FROM plugin_webhook_subscriptions
    WHERE tenant_scope_id = NEW.tenant_scope_id AND id = NEW.subscription_id
    FOR UPDATE;
    SELECT status, attempt_count, actor_scope_id, actor_user_id, next_attempt_at
      INTO delivery_status, delivery_attempts, delivery_actor_scope, delivery_actor_user,
           delivery_next_attempt_at
    FROM plugin_webhook_deliveries
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND subscription_id = NEW.subscription_id AND id = NEW.delivery_id
    FOR UPDATE;
    transition_at := clock_timestamp();
    NEW.plugin_webhook_recorded_at := transition_at;
    IF NEW.actor_scope_id IS DISTINCT FROM delivery_actor_scope OR
       NEW.actor_user_id IS DISTINCT FROM delivery_actor_user THEN
        RAISE EXCEPTION 'plugin webhook attempt actor does not match delivery provenance'
            USING ERRCODE = 'P8402';
    END IF;
    NEW.claimed_at := transition_at;
    IF subscription_status IS DISTINCT FROM 'active' OR
       NEW.claimed_subscription_revision <> subscription_revision OR
       NEW.secret_version_id <> subscription_secret OR
       delivery_status NOT IN ('queued', 'retry_scheduled') OR
       (delivery_status = 'retry_scheduled' AND (
            delivery_next_attempt_at IS NULL OR
            NEW.plugin_webhook_recorded_at < delivery_next_attempt_at
       )) OR
       delivery_attempts >= 5 OR
       NEW.attempt_number <> delivery_attempts + 1 OR
       NEW.claim_sequence <> subscription_lifecycle + 1 OR NEW.status <> 'claimed' THEN
        RAISE EXCEPTION 'plugin webhook claim is outside the active subscription fence'
            USING ERRCODE = 'P8407';
    END IF;
    UPDATE plugin_webhook_subscriptions
    SET lifecycle_sequence = NEW.claim_sequence,
        updated_at = GREATEST(updated_at, NEW.claimed_at)
    WHERE tenant_scope_id = NEW.tenant_scope_id AND id = NEW.subscription_id;
    UPDATE plugin_webhook_deliveries
    SET status = 'claimed', attempt_count = attempt_count + 1,
        claimed_at = NEW.claimed_at, next_attempt_at = NULL
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND subscription_id = NEW.subscription_id AND id = NEW.delivery_id;
    RETURN NEW;
END;
$$;

CREATE TRIGGER plugin_webhook_attempts_claim_084
BEFORE INSERT ON plugin_webhook_delivery_attempts
FOR EACH ROW EXECUTE FUNCTION claim_plugin_webhook_attempt_084();

CREATE FUNCTION guard_plugin_webhook_attempt_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    subscription_status text;
    subscription_revision numeric(20,0);
    subscription_secret uuid;
    subscription_lifecycle numeric(20,0);
    subscription_revoke_sequence numeric(20,0);
    subscription_revoked_at timestamptz;
    delivery_status text;
    delivery_attempts numeric(20,0);
    delivery_claimed_at timestamptz;
    claimed_secret_status text;
    claimed_secret_expires_at timestamptz;
    claimed_secret_available boolean;
    event_request_sha256 bytea;
    outbox_request_sha256 bytea;
    transition_at timestamptz;
BEGIN
    IF NOT (OLD.status = 'claimed' AND NEW.status = 'revoked') AND pg_has_role(
        session_user,
        to_regrole('cdnca_plugin_webhook_runtime'),
        'MEMBER'
    ) IS NOT TRUE THEN
        RAISE EXCEPTION 'plugin webhook trusted runtime identity is required'
            USING ERRCODE = 'P8408',
                  DETAIL = 'plugin_webhook.runtime_identity_required';
    END IF;
    IF TG_OP = 'DELETE' OR
       ROW(NEW.tenant_scope_id, NEW.subscription_id, NEW.delivery_id,
           NEW.actor_scope_id, NEW.actor_user_id, NEW.attempt_number,
           NEW.claim_token) IS DISTINCT FROM
       ROW(OLD.tenant_scope_id, OLD.subscription_id, OLD.delivery_id,
           OLD.actor_scope_id, OLD.actor_user_id, OLD.attempt_number,
           OLD.claim_token) OR
       (NOT (OLD.status = 'claimed' AND NEW.status = 'claimed') AND
        ROW(NEW.claim_sequence, NEW.claimed_subscription_revision,
            NEW.secret_version_id, NEW.claimed_at) IS DISTINCT FROM
        ROW(OLD.claim_sequence, OLD.claimed_subscription_revision,
            OLD.secret_version_id, OLD.claimed_at)) OR
       OLD.status IN ('succeeded', 'temporary_failure', 'permanent_failure', 'revoked') THEN
        RAISE EXCEPTION 'plugin webhook attempt identity or terminal state is immutable'
            USING ERRCODE = 'P8404';
    END IF;
    IF OLD.status = 'claimed' AND NEW.status = 'started' THEN
        SELECT secret.status, secret.expires_at,
               secret.status IN ('active', 'retired')
          INTO claimed_secret_status, claimed_secret_expires_at, claimed_secret_available
        FROM plugin_webhook_secret_versions secret
        WHERE secret.tenant_scope_id = NEW.tenant_scope_id
          AND secret.subscription_id = NEW.subscription_id AND secret.id = NEW.secret_version_id
        FOR SHARE;
    END IF;
    SELECT status, revision, active_secret_version_id, lifecycle_sequence,
           revoke_sequence, revoked_at
      INTO subscription_status, subscription_revision, subscription_secret,
           subscription_lifecycle, subscription_revoke_sequence, subscription_revoked_at
    FROM plugin_webhook_subscriptions
    WHERE tenant_scope_id = NEW.tenant_scope_id AND id = NEW.subscription_id
    FOR UPDATE;
    IF OLD.status = 'claimed' AND NEW.status = 'claimed' THEN
        SELECT status, attempt_count, claimed_at
          INTO delivery_status, delivery_attempts, delivery_claimed_at
        FROM plugin_webhook_deliveries
        WHERE tenant_scope_id = NEW.tenant_scope_id
          AND subscription_id = NEW.subscription_id AND id = NEW.delivery_id
        FOR UPDATE;
        transition_at := clock_timestamp();
        NEW.plugin_webhook_recorded_at := transition_at;
        NEW.claimed_at := transition_at;
        IF subscription_status <> 'active' OR
           subscription_revision <= OLD.claimed_subscription_revision OR
           ROW(OLD.claimed_subscription_revision, OLD.secret_version_id) IS NOT DISTINCT FROM
               ROW(subscription_revision, subscription_secret) OR
           ROW(NEW.claimed_subscription_revision, NEW.secret_version_id) IS DISTINCT FROM
               ROW(subscription_revision, subscription_secret) OR
           NEW.claim_sequence <> subscription_lifecycle + 1 OR
           NEW.claim_sequence <= OLD.claim_sequence OR
           delivery_status <> 'claimed' OR delivery_attempts <> NEW.attempt_number OR
           delivery_claimed_at IS DISTINCT FROM OLD.claimed_at THEN
            RAISE EXCEPTION 'plugin webhook attempt rebind lost the active subscription fence'
                USING ERRCODE = 'P8407';
        END IF;
        UPDATE plugin_webhook_subscriptions
        SET lifecycle_sequence = NEW.claim_sequence,
            updated_at = GREATEST(updated_at, NEW.claimed_at)
        WHERE tenant_scope_id = NEW.tenant_scope_id AND id = NEW.subscription_id;
        RETURN NEW;
    END IF;
    IF OLD.status = 'claimed' AND NEW.status = 'started' THEN
        SELECT event.body_sha256, outbox.queue_body_sha256
          INTO event_request_sha256, outbox_request_sha256
        FROM plugin_webhook_deliveries delivery
        JOIN plugin_webhook_events event
          ON event.tenant_scope_id = delivery.tenant_scope_id
         AND event.subscription_id = delivery.subscription_id AND event.id = delivery.event_id
        JOIN plugin_webhook_outbox outbox
          ON outbox.tenant_scope_id = delivery.tenant_scope_id
         AND outbox.subscription_id = delivery.subscription_id AND outbox.delivery_id = delivery.id
        WHERE delivery.tenant_scope_id = NEW.tenant_scope_id
          AND delivery.subscription_id = NEW.subscription_id AND delivery.id = NEW.delivery_id
        FOR SHARE OF delivery, event, outbox;
        transition_at := clock_timestamp();
        NEW.plugin_webhook_recorded_at := transition_at;
        NEW.started_at := transition_at;
        IF subscription_status <> 'active' OR NOT (
               (subscription_revision = NEW.claimed_subscription_revision AND
                subscription_secret = NEW.secret_version_id) OR
               (claimed_secret_status = 'retired' AND claimed_secret_available AND
                claimed_secret_expires_at > NEW.plugin_webhook_recorded_at AND
                claimed_secret_expires_at > clock_timestamp())
           ) OR NEW.request_sha256 IS DISTINCT FROM event_request_sha256 OR
              NEW.request_sha256 IS DISTINCT FROM outbox_request_sha256 THEN
            RAISE EXCEPTION 'plugin webhook start lost the subscription fence'
                USING ERRCODE = 'P8407';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.status = 'claimed' AND NEW.status = 'revoked' THEN
        SELECT status INTO delivery_status
        FROM plugin_webhook_deliveries
        WHERE tenant_scope_id = NEW.tenant_scope_id
          AND subscription_id = NEW.subscription_id AND id = NEW.delivery_id
        FOR UPDATE;
        SELECT status, expires_at INTO claimed_secret_status, claimed_secret_expires_at
        FROM plugin_webhook_secret_versions
        WHERE tenant_scope_id = NEW.tenant_scope_id
          AND subscription_id = NEW.subscription_id AND id = NEW.secret_version_id
        FOR SHARE;
        IF NOT (
            (subscription_status = 'revoked' AND subscription_revoke_sequence IS NOT NULL AND
             subscription_revoke_sequence > NEW.claim_sequence AND
             subscription_revoked_at = NEW.completed_at) OR
            (claimed_secret_status IN ('expired', 'revoked') AND
             claimed_secret_expires_at <= NEW.completed_at AND
             NEW.completed_at = NEW.plugin_webhook_recorded_at AND
             clock_timestamp() >= claimed_secret_expires_at)
        ) THEN
            RAISE EXCEPTION 'plugin webhook attempt revoke lost the subscription fence'
                USING ERRCODE = 'P8407';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.status = 'started' AND NEW.status IN (
        'succeeded', 'temporary_failure', 'permanent_failure'
    ) THEN
        transition_at := clock_timestamp();
        NEW.plugin_webhook_recorded_at := transition_at;
        NEW.completed_at := transition_at;
        IF NEW.status = 'temporary_failure' THEN
            IF NEW.retry_delay_seconds IS NOT NULL THEN
                RAISE EXCEPTION 'plugin webhook retry delay is database generated'
                    USING ERRCODE = 'P8404';
            END IF;
            NEW.retry_delay_seconds := plugin_webhook_retry_delay_seconds_084(
                NEW.delivery_id, NEW.attempt_number, NEW.completed_at, NEW.retry_after_seconds
            );
        ELSIF NEW.retry_delay_seconds IS NOT NULL THEN
            RAISE EXCEPTION 'plugin webhook retry delay is invalid for a terminal outcome'
                USING ERRCODE = 'P8404';
        END IF;
        NEW.response_preview := CASE
            WHEN NEW.response_preview IS NULL THEN NULL
            ELSE ''::bytea
        END;
        IF NEW.started_at IS DISTINCT FROM OLD.started_at OR
           NEW.request_sha256 IS DISTINCT FROM OLD.request_sha256 THEN
            RAISE EXCEPTION 'plugin webhook HTTP start identity is immutable after start'
                USING ERRCODE = 'P8404';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'plugin webhook attempt transition is invalid'
        USING ERRCODE = 'P8404';
END;
$$;

CREATE TRIGGER plugin_webhook_attempts_guard_084
BEFORE UPDATE OR DELETE ON plugin_webhook_delivery_attempts
FOR EACH ROW EXECUTE FUNCTION guard_plugin_webhook_attempt_084();
CREATE TRIGGER plugin_webhook_attempts_truncate_084
BEFORE TRUNCATE ON plugin_webhook_delivery_attempts
FOR EACH STATEMENT EXECUTE FUNCTION prevent_plugin_webhook_truncate_084();

CREATE FUNCTION project_plugin_webhook_attempt_outcome_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    subscription_status text;
    subscription_revoke_sequence numeric(20,0);
BEGIN
    IF OLD.status = 'claimed' AND NEW.status = 'claimed' THEN
        UPDATE plugin_webhook_deliveries
        SET claimed_at = NEW.claimed_at
        WHERE tenant_scope_id = NEW.tenant_scope_id
          AND subscription_id = NEW.subscription_id AND id = NEW.delivery_id
          AND status = 'claimed' AND attempt_count = NEW.attempt_number
          AND claimed_at = OLD.claimed_at;
        RETURN NULL;
    END IF;
    IF OLD.status <> 'started' OR NEW.status NOT IN (
        'succeeded', 'temporary_failure', 'permanent_failure'
    ) THEN
        RETURN NULL;
    END IF;
    SELECT status, revoke_sequence INTO subscription_status, subscription_revoke_sequence
    FROM plugin_webhook_subscriptions
    WHERE tenant_scope_id = NEW.tenant_scope_id AND id = NEW.subscription_id
    FOR UPDATE;
    IF subscription_status = 'revoked' AND subscription_revoke_sequence > NEW.claim_sequence THEN
        UPDATE plugin_webhook_deliveries
        SET status = CASE WHEN NEW.status = 'succeeded' THEN 'delivered' ELSE 'revoked' END,
            completed_at = NEW.plugin_webhook_recorded_at, next_attempt_at = NULL
        WHERE tenant_scope_id = NEW.tenant_scope_id
          AND subscription_id = NEW.subscription_id AND id = NEW.delivery_id;
    ELSIF NEW.status = 'succeeded' THEN
        UPDATE plugin_webhook_deliveries
        SET status = 'delivered', completed_at = NEW.plugin_webhook_recorded_at, next_attempt_at = NULL
        WHERE tenant_scope_id = NEW.tenant_scope_id
          AND subscription_id = NEW.subscription_id AND id = NEW.delivery_id;
    ELSIF NEW.status = 'temporary_failure' AND NEW.attempt_number < 5 THEN
        UPDATE plugin_webhook_deliveries
        SET status = 'retry_scheduled', next_attempt_at = NEW.plugin_webhook_recorded_at +
            make_interval(secs => NEW.retry_delay_seconds)
        WHERE tenant_scope_id = NEW.tenant_scope_id
          AND subscription_id = NEW.subscription_id AND id = NEW.delivery_id;
    ELSE
        UPDATE plugin_webhook_deliveries
        SET status = 'dead_letter_pending', completed_at = NEW.plugin_webhook_recorded_at,
            next_attempt_at = NULL
        WHERE tenant_scope_id = NEW.tenant_scope_id
          AND subscription_id = NEW.subscription_id AND id = NEW.delivery_id;
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER plugin_webhook_attempts_outcome_084
AFTER UPDATE ON plugin_webhook_delivery_attempts
FOR EACH ROW EXECUTE FUNCTION project_plugin_webhook_attempt_outcome_084();

CREATE FUNCTION validate_plugin_webhook_delivery_attempt_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    checked_scope uuid;
    checked_subscription uuid;
    checked_delivery uuid;
    delivery_status text;
    delivery_attempt_count numeric(20,0);
    delivery_actor_scope uuid;
    delivery_actor_user uuid;
    delivery_claimed_at timestamptz;
    delivery_completed_at timestamptz;
    delivery_next_attempt_at timestamptz;
    subscription_revoked_at timestamptz;
    subscription_status text;
    subscription_active_secret uuid;
    attempt_status text;
    latest_attempt_number numeric(20,0);
    attempt_actor_scope uuid;
    attempt_actor_user uuid;
    attempt_claimed_at timestamptz;
    attempt_completed_at timestamptz;
    attempt_retry_after integer;
    attempt_retry_delay integer;
    attempt_secret_status text;
    attempt_secret_expires_at timestamptz;
    attempt_failure_code text;
    attempt_http_status integer;
    attempt_request_sha256 bytea;
    attempt_response_sha256 bytea;
    attempt_response_bytes integer;
    attempt_secret_version uuid;
    dead_letter_state text;
BEGIN
    checked_scope := NEW.tenant_scope_id;
    checked_subscription := NEW.subscription_id;
    IF TG_TABLE_NAME = 'plugin_webhook_deliveries' THEN
        checked_delivery := NEW.id;
    ELSE
        checked_delivery := NEW.delivery_id;
    END IF;
    SELECT delivery.status, delivery.attempt_count, delivery.actor_scope_id,
           delivery.actor_user_id, delivery.claimed_at, delivery.completed_at,
           delivery.next_attempt_at, subscription.revoked_at, subscription.status,
           subscription.active_secret_version_id
      INTO delivery_status, delivery_attempt_count, delivery_actor_scope,
           delivery_actor_user, delivery_claimed_at, delivery_completed_at,
           delivery_next_attempt_at, subscription_revoked_at, subscription_status,
           subscription_active_secret
    FROM plugin_webhook_deliveries delivery
    JOIN plugin_webhook_subscriptions subscription
      ON subscription.tenant_scope_id = delivery.tenant_scope_id
     AND subscription.id = delivery.subscription_id
    WHERE delivery.tenant_scope_id = checked_scope
      AND delivery.subscription_id = checked_subscription AND delivery.id = checked_delivery
    FOR SHARE OF delivery, subscription;
    SELECT attempt.status, attempt.attempt_number, attempt.actor_scope_id,
           attempt.actor_user_id, attempt.claimed_at, attempt.completed_at,
           attempt.retry_after_seconds, attempt.retry_delay_seconds, attempt.failure_code,
           attempt.http_status, attempt.request_sha256, attempt.response_sha256,
           attempt.response_bytes, attempt.secret_version_id
      INTO attempt_status, latest_attempt_number, attempt_actor_scope, attempt_actor_user,
           attempt_claimed_at, attempt_completed_at, attempt_retry_after, attempt_retry_delay,
           attempt_failure_code, attempt_http_status, attempt_request_sha256,
           attempt_response_sha256, attempt_response_bytes, attempt_secret_version
    FROM plugin_webhook_delivery_attempts attempt
    WHERE attempt.tenant_scope_id = checked_scope
      AND attempt.subscription_id = checked_subscription
      AND attempt.delivery_id = checked_delivery
    ORDER BY attempt.attempt_number DESC
    LIMIT 1
    FOR SHARE;
    IF latest_attempt_number IS NOT NULL THEN
        SELECT secret.status, secret.expires_at
          INTO attempt_secret_status, attempt_secret_expires_at
        FROM plugin_webhook_delivery_attempts attempt
        JOIN plugin_webhook_secret_versions secret
          ON secret.tenant_scope_id = attempt.tenant_scope_id
         AND secret.subscription_id = attempt.subscription_id
         AND secret.id = attempt.secret_version_id
        WHERE attempt.tenant_scope_id = checked_scope
          AND attempt.subscription_id = checked_subscription
          AND attempt.delivery_id = checked_delivery
            AND attempt.attempt_number = latest_attempt_number
        FOR SHARE OF secret;
    END IF;
    IF delivery_status IN ('dead_letter_pending', 'dead_lettered') THEN
        SELECT dead_letter.publish_state INTO dead_letter_state
        FROM plugin_webhook_dead_letters dead_letter
        WHERE dead_letter.tenant_scope_id = checked_scope
          AND dead_letter.subscription_id = checked_subscription
          AND dead_letter.delivery_id = checked_delivery
          AND dead_letter.actor_scope_id = delivery_actor_scope
          AND dead_letter.actor_user_id = delivery_actor_user
          AND dead_letter.final_attempt_number = latest_attempt_number
          AND dead_letter.failed_at = attempt_completed_at
          AND dead_letter.reason_code = attempt_failure_code
          AND dead_letter.http_status IS NOT DISTINCT FROM attempt_http_status
          AND dead_letter.request_sha256 = attempt_request_sha256
          AND dead_letter.response_sha256 IS NOT DISTINCT FROM attempt_response_sha256
          AND dead_letter.response_bytes = attempt_response_bytes
        FOR SHARE;
    END IF;
    IF TG_TABLE_NAME = 'plugin_webhook_delivery_attempts' AND TG_OP = 'UPDATE' THEN
        IF OLD.status = 'claimed' AND NEW.status = 'started' AND
           (NEW.started_at IS DISTINCT FROM NEW.plugin_webhook_recorded_at OR
            (attempt_secret_status = 'retired' AND (
                attempt_secret_expires_at IS NULL OR
                NEW.plugin_webhook_recorded_at >= attempt_secret_expires_at OR
                clock_timestamp() >= attempt_secret_expires_at
            ))) THEN
            RAISE EXCEPTION 'plugin webhook start exceeded the claim-bound secret lifetime'
                USING ERRCODE = 'P8407';
        END IF;
    END IF;
    IF delivery_status IS NULL OR
       (delivery_attempt_count = 0 AND latest_attempt_number IS NOT NULL) OR
       (delivery_attempt_count > 0 AND latest_attempt_number IS DISTINCT FROM delivery_attempt_count) OR
       (latest_attempt_number IS NOT NULL AND (
            attempt_actor_scope IS DISTINCT FROM delivery_actor_scope OR
            attempt_actor_user IS DISTINCT FROM delivery_actor_user OR
            attempt_claimed_at IS DISTINCT FROM delivery_claimed_at
       )) OR NOT (
           (delivery_status IN ('pending', 'queued') AND delivery_attempt_count = 0 AND
            latest_attempt_number IS NULL) OR
           (delivery_status = 'claimed' AND attempt_status IN ('claimed', 'started')) OR
           (delivery_status = 'delivered' AND attempt_status = 'succeeded' AND
            delivery_completed_at = attempt_completed_at) OR
           (delivery_status = 'retry_scheduled' AND attempt_status = 'temporary_failure' AND
            latest_attempt_number < 5 AND delivery_next_attempt_at = attempt_completed_at +
                make_interval(secs => attempt_retry_delay) AND
            attempt_retry_delay = plugin_webhook_retry_delay_seconds_084(
                checked_delivery, latest_attempt_number, attempt_completed_at, attempt_retry_after
            )) OR
           (delivery_status = 'retry_scheduled' AND attempt_status = 'revoked' AND
            attempt_secret_status = 'expired' AND subscription_status = 'active' AND
            subscription_active_secret IS DISTINCT FROM attempt_secret_version AND
            delivery_next_attempt_at = attempt_completed_at) OR
           (delivery_status = 'dead_letter_pending' AND
            (attempt_status = 'permanent_failure' OR
             (attempt_status = 'temporary_failure' AND latest_attempt_number = 5)) AND
            delivery_completed_at = attempt_completed_at AND
            dead_letter_state IS NOT DISTINCT FROM 'pending') OR
           (delivery_status = 'dead_lettered' AND
            (attempt_status = 'permanent_failure' OR
             (attempt_status = 'temporary_failure' AND latest_attempt_number = 5)) AND
            delivery_completed_at = attempt_completed_at AND
            dead_letter_state IS NOT DISTINCT FROM 'acknowledged') OR
           (delivery_status = 'revoked' AND (
                (delivery_attempt_count = 0 AND latest_attempt_number IS NULL) OR
                (attempt_status = 'revoked' AND delivery_completed_at = attempt_completed_at AND (
                    delivery_completed_at = subscription_revoked_at OR
                    (attempt_secret_status IN ('expired', 'revoked') AND
                     delivery_completed_at >= attempt_secret_expires_at)
                )) OR
                (attempt_status IN ('temporary_failure', 'permanent_failure') AND
                 (delivery_completed_at = attempt_completed_at OR
                  delivery_completed_at = subscription_revoked_at))
           ))
       ) THEN
        RAISE EXCEPTION 'plugin webhook delivery and attempt facts are inconsistent'
            USING ERRCODE = 'P8404';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER plugin_webhook_deliveries_attempt_084
AFTER INSERT OR UPDATE ON plugin_webhook_deliveries
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_delivery_attempt_084();
CREATE CONSTRAINT TRIGGER plugin_webhook_attempts_delivery_084
AFTER INSERT OR UPDATE ON plugin_webhook_delivery_attempts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_delivery_attempt_084();

CREATE FUNCTION validate_plugin_webhook_subscription_sequence_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.event_sequence IS DISTINCT FROM OLD.event_sequence AND NOT EXISTS (
        SELECT 1 FROM plugin_webhook_events event
        WHERE event.tenant_scope_id = NEW.tenant_scope_id
          AND event.subscription_id = NEW.id AND event.sequence = NEW.event_sequence
          AND event.plugin_webhook_xact_id = pg_current_xact_id()
    ) THEN
        RAISE EXCEPTION 'plugin webhook event sequence requires its current transaction event'
            USING ERRCODE = 'P8404';
    END IF;
    IF NEW.lifecycle_sequence IS DISTINCT FROM OLD.lifecycle_sequence AND
       OLD.status = 'active' AND NEW.status = 'revoked' AND NOT EXISTS (
           SELECT 1
           FROM plugin_webhook_write_requests request
           JOIN audit_events audit ON audit.id = request.audit_event_id
           WHERE request.tenant_scope_id = NEW.tenant_scope_id
             AND request.subscription_id = NEW.id
             AND request.operation = 'plugin_webhook.subscription.revoke'
             AND request.completed_at = NEW.revoked_at
             AND request.response_status = 200
             AND request.response_body = jsonb_build_object('subscription_id', NEW.id::text)
             AND request.plugin_webhook_xact_id = pg_current_xact_id()
             AND audit.plugin_webhook_xact_id = pg_current_xact_id()
             AND audit.scope_id = NEW.tenant_scope_id
             AND audit.actor_user_id = request.actor_user_id
             AND audit.action = request.operation AND audit.result = 'success'
             AND audit.resource_type = 'plugin_webhook_subscription'
             AND audit.resource_id = NEW.id::text
             AND audit.request_id = request.idempotency_key
             AND audit.occurred_at = request.completed_at
             AND audit.payload = jsonb_build_object(
                 'actor_scope_id', request.actor_scope_id::text,
                 'target_scope_id', request.tenant_scope_id::text,
                 'operation', request.operation,
                 'reason', 'accepted'
             )
       ) THEN
        RAISE EXCEPTION 'plugin webhook revoke requires exact current management authorization'
            USING ERRCODE = 'P8402';
    END IF;
    IF NEW.lifecycle_sequence IS DISTINCT FROM OLD.lifecycle_sequence AND NOT (
        EXISTS (
            SELECT 1 FROM plugin_webhook_delivery_attempts attempt
            WHERE attempt.tenant_scope_id = NEW.tenant_scope_id
              AND attempt.subscription_id = NEW.id
              AND attempt.claim_sequence = NEW.lifecycle_sequence
              AND attempt.plugin_webhook_xact_id = pg_current_xact_id()
        ) OR (
            NEW.active_secret_version_id IS DISTINCT FROM OLD.active_secret_version_id AND
            EXISTS (
                SELECT 1 FROM plugin_webhook_write_requests request
                WHERE request.tenant_scope_id = NEW.tenant_scope_id
                  AND request.subscription_id = NEW.id
                  AND request.operation = 'plugin_webhook.secret.activate'
                  AND request.rotation_id = NEW.active_secret_version_id
                  AND request.completed_at IS NOT NULL
                  AND request.plugin_webhook_xact_id = pg_current_xact_id()
            )
        ) OR (OLD.status = 'active' AND NEW.status = 'revoked')
    ) THEN
        RAISE EXCEPTION 'plugin webhook lifecycle sequence requires its current transaction fact'
            USING ERRCODE = 'P8404';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER plugin_webhook_subscriptions_sequence_084
AFTER UPDATE ON plugin_webhook_subscriptions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_subscription_sequence_084();

CREATE FUNCTION apply_plugin_webhook_revoke_fence_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status <> 'active' OR NEW.status <> 'revoked' THEN
        RETURN NULL;
    END IF;
    UPDATE plugin_webhook_deliveries delivery
    SET status = 'revoked', completed_at = NEW.revoked_at, next_attempt_at = NULL
    WHERE delivery.tenant_scope_id = NEW.tenant_scope_id
      AND delivery.subscription_id = NEW.id
      AND delivery.status IN ('pending', 'queued', 'retry_scheduled', 'claimed')
      AND NOT EXISTS (
          SELECT 1 FROM plugin_webhook_delivery_attempts attempt
          WHERE attempt.tenant_scope_id = delivery.tenant_scope_id
            AND attempt.subscription_id = delivery.subscription_id
            AND attempt.delivery_id = delivery.id AND attempt.status = 'started'
      );
    UPDATE plugin_webhook_delivery_attempts
    SET status = 'revoked', completed_at = NEW.revoked_at
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND subscription_id = NEW.id AND status = 'claimed';
    UPDATE plugin_webhook_outbox
    SET status = 'revoked', lease_token = NULL, lease_expires_at = NULL
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND subscription_id = NEW.id AND status IN ('pending', 'leased');
    UPDATE plugin_webhook_secret_versions
    SET status = 'revoked', nonce = NULL, ciphertext = NULL, revoked_at = NEW.revoked_at
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND subscription_id = NEW.id AND status IN ('pending', 'active', 'retired');
    UPDATE plugin_webhook_write_requests
    SET receipt_nonce = NULL, receipt_ciphertext = NULL,
        receipt_cleared_at = NEW.revoked_at, receipt_cleared_reason = 'subscription_revoked'
    WHERE tenant_scope_id = NEW.tenant_scope_id AND subscription_id = NEW.id
      AND operation IN ('plugin_webhook.subscription.create', 'plugin_webhook.secret.rotate')
      AND receipt_expires_at IS NOT NULL AND receipt_cleared_at IS NULL;
    RETURN NULL;
END;
$$;

CREATE TRIGGER plugin_webhook_subscriptions_revoke_fence_084
AFTER UPDATE ON plugin_webhook_subscriptions
FOR EACH ROW EXECUTE FUNCTION apply_plugin_webhook_revoke_fence_084();

CREATE FUNCTION plugin_webhook_dead_letter_payload_sha256_084(
    target_scope_id uuid,
    subscription_id uuid,
    delivery_id uuid,
    event_id uuid,
    attempt_number numeric,
    reason_code text,
    http_status integer,
    request_sha256 bytea,
    response_sha256 bytea,
    response_bytes integer
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT sha256(
        convert_to('cdnca.plugin-webhook.dead-letter/v1', 'UTF8') || decode('00', 'hex') ||
        convert_to(target_scope_id::text, 'UTF8') || decode('00', 'hex') ||
        convert_to(subscription_id::text, 'UTF8') || decode('00', 'hex') ||
        convert_to(delivery_id::text, 'UTF8') || decode('00', 'hex') ||
        convert_to(event_id::text, 'UTF8') || decode('00', 'hex') ||
        convert_to(attempt_number::text, 'UTF8') || decode('00', 'hex') ||
        convert_to(reason_code, 'UTF8') || decode('00', 'hex') ||
        convert_to(COALESCE(http_status::text, '-'), 'UTF8') || decode('00', 'hex') ||
        convert_to(encode(request_sha256, 'hex'), 'UTF8') || decode('00', 'hex') ||
        convert_to(COALESCE(encode(response_sha256, 'hex'), '-'), 'UTF8') || decode('00', 'hex') ||
        convert_to(response_bytes::text, 'UTF8')
    );
$$;

CREATE TABLE plugin_webhook_dead_letters (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    delivery_id uuid NOT NULL,
    event_id uuid NOT NULL,
    final_attempt_number numeric(20,0) NOT NULL CHECK (
        plugin_webhook_u64_084(final_attempt_number) AND final_attempt_number BETWEEN 1 AND 5
    ),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    nats_stream text NOT NULL CHECK (nats_stream = 'PLUGIN_WEBHOOK_DLQ'),
    nats_subject text NOT NULL CHECK (nats_subject = 'cdnca.plugin-webhook.dead-letter.v1'),
    nats_message_id text NOT NULL,
    CONSTRAINT plugin_webhook_dead_letters_message_id_084_check CHECK (
        nats_message_id = 'plugin-webhook-dlq-v1-' || encode(sha256(convert_to(
            delivery_id::text || ':' || final_attempt_number::text, 'UTF8'
        )), 'hex')
    ),
    payload_sha256 bytea NOT NULL CHECK (octet_length(payload_sha256) = 32),
    publish_state text NOT NULL CHECK (publish_state IN ('pending', 'acknowledged')),
    reconcile_phase text NOT NULL DEFAULT 'uninitialized',
    reconcile_generation uuid NOT NULL DEFAULT gen_random_uuid(),
    reconcile_stream_created_unix_nano numeric(20,0),
    reconcile_high_watermark numeric(20,0),
    reconcile_scan_boundary numeric(20,0),
    reconcile_cursor numeric(20,0),
    nats_dlq_stream_created_unix_nano numeric(20,0) CHECK (
        nats_dlq_stream_created_unix_nano IS NULL OR
        (nats_dlq_stream_created_unix_nano > 0 AND
         nats_dlq_stream_created_unix_nano <= 9223372036854775807)
    ),
    nats_dlq_sequence numeric(20,0) CHECK (
        nats_dlq_sequence IS NULL OR
        (plugin_webhook_u64_084(nats_dlq_sequence) AND nats_dlq_sequence > 0)
    ),
    nats_ack_id text CHECK (nats_ack_id IS NULL OR plugin_webhook_text_valid_084(nats_ack_id, 160)),
    nats_domain text CHECK (
        nats_domain IS NULL OR
        (octet_length(nats_domain) <= 128 AND nats_domain ~ '^[A-Za-z0-9_-]*$')
    ),
    wire_body_sha256 bytea CHECK (
        wire_body_sha256 IS NULL OR octet_length(wire_body_sha256) = 32
    ),
    expected_last_stream_sequence numeric(20,0) CHECK (
        expected_last_stream_sequence IS NULL OR
        plugin_webhook_u64_084(expected_last_stream_sequence)
    ),
    publication_attestation_generation numeric(20,0),
    publication_attestation_key_id text,
    publication_attestation_sha256 bytea CHECK (
        publication_attestation_sha256 IS NULL OR
        octet_length(publication_attestation_sha256) = 32
    ),
    publication_attestation_signature bytea CHECK (
        publication_attestation_signature IS NULL OR
        octet_length(publication_attestation_signature) = 64
    ),
    acknowledged_at timestamptz CHECK (acknowledged_at IS NULL OR isfinite(acknowledged_at)),
    reason_code text NOT NULL CHECK (plugin_webhook_text_valid_084(reason_code, 128)),
    http_status integer CHECK (http_status BETWEEN 100 AND 599),
    request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
    response_sha256 bytea CHECK (response_sha256 IS NULL OR octet_length(response_sha256) = 32),
    response_bytes integer NOT NULL CHECK (response_bytes BETWEEN 0 AND 65536),
    failed_at timestamptz NOT NULL CHECK (isfinite(failed_at)),
    plugin_webhook_xact_id xid8 NOT NULL,
    plugin_webhook_recorded_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_scope_id, subscription_id, delivery_id)
        REFERENCES plugin_webhook_deliveries(tenant_scope_id, subscription_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, subscription_id, event_id)
        REFERENCES plugin_webhook_events(tenant_scope_id, subscription_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, subscription_id, delivery_id, final_attempt_number)
        REFERENCES plugin_webhook_delivery_attempts(
            tenant_scope_id, subscription_id, delivery_id, attempt_number
        ) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (publication_attestation_generation, publication_attestation_key_id)
        REFERENCES plugin_webhook_runtime_attestation_keys(key_generation, key_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    UNIQUE (tenant_scope_id, subscription_id, delivery_id),
    UNIQUE (nats_message_id),
    CONSTRAINT plugin_webhook_dead_letters_broker_identity_084_key UNIQUE (
        nats_stream, nats_dlq_stream_created_unix_nano, nats_dlq_sequence
    ),
    CONSTRAINT plugin_webhook_dead_letters_payload_084_check CHECK (
        payload_sha256 = plugin_webhook_dead_letter_payload_sha256_084(
        tenant_scope_id, subscription_id, delivery_id, event_id, final_attempt_number,
        reason_code, http_status, request_sha256, response_sha256, response_bytes
    )),
    CONSTRAINT plugin_webhook_dead_letters_reconcile_084_check CHECK (
        (publish_state = 'pending' AND nats_dlq_stream_created_unix_nano IS NULL AND
         nats_dlq_sequence IS NULL AND
         nats_ack_id IS NULL AND nats_domain IS NULL AND wire_body_sha256 IS NULL AND
         expected_last_stream_sequence IS NULL AND
         publication_attestation_generation IS NULL AND publication_attestation_key_id IS NULL AND
         publication_attestation_sha256 IS NULL AND publication_attestation_signature IS NULL AND
         acknowledged_at IS NULL AND (
            (reconcile_phase = 'uninitialized' AND
             reconcile_stream_created_unix_nano IS NULL AND
             reconcile_high_watermark IS NULL AND reconcile_scan_boundary IS NULL AND
             reconcile_cursor IS NULL) OR
            (reconcile_phase = 'reverse_scan' AND
             reconcile_stream_created_unix_nano IS NOT NULL AND
             reconcile_stream_created_unix_nano > 0 AND
             reconcile_stream_created_unix_nano <= 9223372036854775807 AND
             reconcile_high_watermark IS NOT NULL AND reconcile_high_watermark > 0 AND
             plugin_webhook_u64_084(reconcile_high_watermark) AND
             reconcile_scan_boundary IS NOT NULL AND reconcile_scan_boundary > 0 AND
             plugin_webhook_u64_084(reconcile_scan_boundary) AND
             reconcile_cursor IS NOT NULL AND reconcile_cursor > 0 AND
             plugin_webhook_u64_084(reconcile_cursor) AND
             reconcile_scan_boundary <= reconcile_cursor AND
             reconcile_cursor <= reconcile_high_watermark) OR
            (reconcile_phase = 'publish_ready' AND
             reconcile_stream_created_unix_nano IS NOT NULL AND
             reconcile_stream_created_unix_nano > 0 AND
             reconcile_stream_created_unix_nano <= 9223372036854775807 AND
             reconcile_high_watermark IS NOT NULL AND
             plugin_webhook_u64_084(reconcile_high_watermark) AND
             reconcile_scan_boundary IS NULL AND
             reconcile_cursor IS NULL) OR
            (reconcile_phase = 'forward_scan' AND
             reconcile_stream_created_unix_nano IS NOT NULL AND
             reconcile_stream_created_unix_nano > 0 AND
             reconcile_stream_created_unix_nano <= 9223372036854775807 AND
             reconcile_high_watermark IS NOT NULL AND reconcile_high_watermark > 0 AND
             plugin_webhook_u64_084(reconcile_high_watermark) AND
             reconcile_scan_boundary IS NOT NULL AND reconcile_scan_boundary > 0 AND
             plugin_webhook_u64_084(reconcile_scan_boundary) AND
             reconcile_cursor IS NOT NULL AND reconcile_cursor > 0 AND
             plugin_webhook_u64_084(reconcile_cursor) AND
             reconcile_scan_boundary <= reconcile_cursor AND
             reconcile_cursor <= reconcile_high_watermark)
         )) OR
        (publish_state = 'acknowledged' AND reconcile_phase = 'complete' AND
         reconcile_stream_created_unix_nano IS NULL AND
         reconcile_high_watermark IS NULL AND reconcile_scan_boundary IS NULL AND
         reconcile_cursor IS NULL AND
         nats_dlq_stream_created_unix_nano IS NOT NULL AND
         nats_dlq_sequence IS NOT NULL AND
         nats_ack_id = nats_stream || ':' || nats_dlq_sequence::text AND
         nats_domain IS NOT NULL AND wire_body_sha256 IS NOT NULL AND
         expected_last_stream_sequence = nats_dlq_sequence - 1 AND
         publication_attestation_generation IS NOT NULL AND
         publication_attestation_key_id IS NOT NULL AND
         publication_attestation_sha256 IS NOT NULL AND
         publication_attestation_signature IS NOT NULL AND
         acknowledged_at IS NOT NULL)
    )
);

CREATE TRIGGER plugin_webhook_dead_letters_00_xact_084
BEFORE INSERT OR UPDATE ON plugin_webhook_dead_letters
FOR EACH ROW EXECUTE FUNCTION stamp_plugin_webhook_xact_id_084();

CREATE FUNCTION guard_plugin_webhook_dead_letter_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    epoch_changed boolean;
BEGIN
    IF pg_has_role(
        session_user,
        to_regrole('cdnca_plugin_webhook_runtime'),
        'MEMBER'
    ) IS NOT TRUE THEN
        RAISE EXCEPTION 'plugin webhook trusted runtime identity is required'
            USING ERRCODE = 'P8408',
                  DETAIL = 'plugin_webhook.runtime_identity_required';
    END IF;
    IF TG_OP = 'INSERT' THEN
        NEW.reconcile_generation := gen_random_uuid();
        IF NEW.publish_state <> 'pending' OR NEW.reconcile_phase <> 'uninitialized' OR
           NEW.reconcile_stream_created_unix_nano IS NOT NULL OR
           NEW.reconcile_high_watermark IS NOT NULL OR
           NEW.reconcile_scan_boundary IS NOT NULL OR NEW.reconcile_cursor IS NOT NULL OR
           NEW.nats_dlq_stream_created_unix_nano IS NOT NULL OR
           NEW.nats_dlq_sequence IS NOT NULL OR NEW.nats_ack_id IS NOT NULL OR
           NEW.nats_domain IS NOT NULL OR NEW.wire_body_sha256 IS NOT NULL OR
           NEW.expected_last_stream_sequence IS NOT NULL OR
           NEW.publication_attestation_generation IS NOT NULL OR
           NEW.publication_attestation_key_id IS NOT NULL OR
           NEW.publication_attestation_sha256 IS NOT NULL OR
           NEW.publication_attestation_signature IS NOT NULL OR
           NEW.acknowledged_at IS NOT NULL THEN
            RAISE EXCEPTION 'plugin webhook dead letter must start pending and unreconciled'
                USING ERRCODE = 'P8403';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND current_user::regrole IS DISTINCT FROM (
        SELECT relation.relowner FROM pg_class relation WHERE relation.oid = TG_RELID
    ) THEN
        RAISE EXCEPTION 'plugin webhook dead letter transition is restricted'
            USING ERRCODE = 'P8403';
    END IF;
    IF TG_OP = 'DELETE' OR
       ROW(NEW.id, NEW.tenant_scope_id, NEW.subscription_id, NEW.delivery_id,
           NEW.event_id, NEW.final_attempt_number, NEW.actor_scope_id, NEW.actor_user_id,
           NEW.nats_stream, NEW.nats_subject, NEW.nats_message_id, NEW.payload_sha256,
           NEW.reason_code, NEW.http_status, NEW.request_sha256, NEW.response_sha256,
           NEW.response_bytes, NEW.failed_at) IS DISTINCT FROM
       ROW(OLD.id, OLD.tenant_scope_id, OLD.subscription_id, OLD.delivery_id,
           OLD.event_id, OLD.final_attempt_number, OLD.actor_scope_id, OLD.actor_user_id,
           OLD.nats_stream, OLD.nats_subject, OLD.nats_message_id, OLD.payload_sha256,
           OLD.reason_code, OLD.http_status, OLD.request_sha256, OLD.response_sha256,
           OLD.response_bytes, OLD.failed_at) THEN
        RAISE EXCEPTION 'plugin webhook dead letter identity is immutable'
            USING ERRCODE = 'P8403';
    END IF;
    IF OLD.publish_state <> 'pending' THEN
        RAISE EXCEPTION 'plugin webhook dead letter acknowledgement is terminal'
            USING ERRCODE = 'P8403';
    ELSIF NEW.publish_state = 'acknowledged' THEN
        IF NEW.reconcile_generation IS DISTINCT FROM OLD.reconcile_generation OR
           NEW.reconcile_phase <> 'complete' OR
           NEW.reconcile_stream_created_unix_nano IS NOT NULL OR
           NEW.reconcile_high_watermark IS NOT NULL OR
           NEW.reconcile_scan_boundary IS NOT NULL OR NEW.reconcile_cursor IS NOT NULL OR
           NEW.nats_dlq_stream_created_unix_nano IS DISTINCT FROM
               OLD.reconcile_stream_created_unix_nano OR
           OLD.reconcile_phase = 'uninitialized' OR
           (OLD.reconcile_phase IN ('reverse_scan', 'forward_scan') AND
            NEW.nats_dlq_sequence IS DISTINCT FROM OLD.reconcile_cursor) OR
           (OLD.reconcile_phase = 'publish_ready' AND (
                OLD.reconcile_high_watermark >= 18446744073709551615 OR
                NEW.nats_dlq_sequence IS DISTINCT FROM OLD.reconcile_high_watermark + 1
           )) THEN
            RAISE EXCEPTION 'plugin webhook dead letter acknowledgement lacks an exact wire hit'
                USING ERRCODE = 'P8403';
        END IF;
        NEW.acknowledged_at := clock_timestamp();
    ELSIF NEW.publish_state = 'pending' THEN
        epoch_changed := NEW.reconcile_stream_created_unix_nano IS DISTINCT FROM
            OLD.reconcile_stream_created_unix_nano;
        IF epoch_changed THEN
            IF NEW.reconcile_generation IS NOT DISTINCT FROM OLD.reconcile_generation THEN
                NEW.reconcile_generation := gen_random_uuid();
            END IF;
            IF NEW.reconcile_stream_created_unix_nano IS NULL OR NOT (
                (NEW.reconcile_phase = 'reverse_scan' AND
                 NEW.reconcile_high_watermark IS NOT NULL AND
                 NEW.reconcile_high_watermark > 0 AND NEW.reconcile_cursor IS NOT NULL AND
                 NEW.reconcile_scan_boundary IS NOT NULL AND
                 NEW.reconcile_scan_boundary <= NEW.reconcile_high_watermark AND
                 NEW.reconcile_cursor = NEW.reconcile_high_watermark) OR
                (NEW.reconcile_phase = 'publish_ready' AND
                 NEW.reconcile_high_watermark = 0 AND
                 NEW.reconcile_scan_boundary IS NULL AND NEW.reconcile_cursor IS NULL)
            ) THEN
                RAISE EXCEPTION 'plugin webhook dead letter stream reset is invalid'
                    USING ERRCODE = 'P8403';
            END IF;
        ELSIF NEW.reconcile_generation IS DISTINCT FROM OLD.reconcile_generation THEN
            RAISE EXCEPTION 'plugin webhook dead letter generation changed without stream reset'
                USING ERRCODE = 'P8403';
        ELSIF OLD.reconcile_phase = 'reverse_scan' THEN
            IF NOT (
                (NEW.reconcile_phase = 'reverse_scan' AND
                 NEW.reconcile_high_watermark = OLD.reconcile_high_watermark AND
                 NEW.reconcile_scan_boundary = OLD.reconcile_scan_boundary AND
                 NEW.reconcile_cursor < OLD.reconcile_cursor AND
                 OLD.reconcile_cursor - NEW.reconcile_cursor BETWEEN 1 AND 32) OR
                (NEW.reconcile_phase = 'publish_ready' AND
                 NEW.reconcile_high_watermark = OLD.reconcile_high_watermark AND
                 NEW.reconcile_scan_boundary IS NULL AND NEW.reconcile_cursor IS NULL AND
                 OLD.reconcile_cursor = OLD.reconcile_scan_boundary)
            ) THEN
                RAISE EXCEPTION 'plugin webhook dead letter reverse scan is not monotonic'
                    USING ERRCODE = 'P8403';
            END IF;
        ELSIF OLD.reconcile_phase = 'publish_ready' THEN
            IF NOT (NEW.reconcile_phase = 'forward_scan' AND
                    OLD.reconcile_high_watermark < 18446744073709551615 AND
                    NEW.reconcile_high_watermark > OLD.reconcile_high_watermark AND
                    NEW.reconcile_scan_boundary = OLD.reconcile_high_watermark + 1 AND
                    NEW.reconcile_cursor = NEW.reconcile_scan_boundary) THEN
                RAISE EXCEPTION 'plugin webhook dead letter forward scan start is invalid'
                    USING ERRCODE = 'P8403';
            END IF;
        ELSIF OLD.reconcile_phase = 'forward_scan' THEN
            IF NOT (
                (NEW.reconcile_phase = 'forward_scan' AND
                 NEW.reconcile_high_watermark = OLD.reconcile_high_watermark AND
                 NEW.reconcile_scan_boundary = OLD.reconcile_scan_boundary AND
                 NEW.reconcile_cursor > OLD.reconcile_cursor AND
                 NEW.reconcile_cursor - OLD.reconcile_cursor BETWEEN 1 AND 32) OR
                (NEW.reconcile_phase = 'publish_ready' AND
                 NEW.reconcile_high_watermark = OLD.reconcile_high_watermark AND
                 NEW.reconcile_scan_boundary IS NULL AND NEW.reconcile_cursor IS NULL AND
                 OLD.reconcile_cursor = OLD.reconcile_high_watermark)
            ) THEN
                RAISE EXCEPTION 'plugin webhook dead letter forward scan is not monotonic'
                    USING ERRCODE = 'P8403';
            END IF;
        ELSE
            RAISE EXCEPTION 'plugin webhook dead letter reconciliation transition is invalid'
                USING ERRCODE = 'P8403';
        END IF;
    ELSE
        RAISE EXCEPTION 'plugin webhook dead letter publish state transition is invalid'
            USING ERRCODE = 'P8403';
    END IF;
    RETURN NEW;
END;
$$;

DO $create$
BEGIN
    EXECUTE format($function$
CREATE FUNCTION %1$I.transition_plugin_webhook_dead_letter_reconcile_084(
    target_scope_id uuid,
    target_subscription_id uuid,
    target_delivery_id uuid,
    expected_reconcile_generation uuid,
    expected_reconcile_phase text,
    expected_stream_created_unix_nano numeric,
    expected_high_watermark numeric,
    expected_scan_boundary numeric,
    expected_cursor numeric,
    new_reconcile_generation uuid,
    new_reconcile_phase text,
    new_stream_created_unix_nano numeric,
    new_high_watermark numeric,
    new_scan_boundary numeric,
    new_cursor numeric
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $body$
DECLARE
    current_record record;
    resulting_generation uuid;
BEGIN
    IF pg_has_role(
        session_user,
        to_regrole('cdnca_plugin_webhook_runtime'),
        'MEMBER'
    ) IS NOT TRUE THEN
        RAISE EXCEPTION 'plugin webhook trusted runtime identity is required'
            USING ERRCODE = 'P8408',
                  DETAIL = 'plugin_webhook.runtime_identity_required';
    END IF;
    PERFORM 1
    FROM %1$I.plugin_webhook_deliveries
    WHERE tenant_scope_id = target_scope_id AND subscription_id = target_subscription_id
      AND id = target_delivery_id
    FOR SHARE;
    SELECT publish_state, reconcile_generation, reconcile_phase,
           reconcile_stream_created_unix_nano, reconcile_high_watermark,
           reconcile_scan_boundary, reconcile_cursor
      INTO current_record
    FROM %1$I.plugin_webhook_dead_letters
    WHERE tenant_scope_id = target_scope_id AND subscription_id = target_subscription_id
      AND delivery_id = target_delivery_id
    FOR UPDATE;
    IF current_record.publish_state IS DISTINCT FROM 'pending' OR
       expected_reconcile_generation IS NULL OR new_reconcile_generation IS NULL OR
       current_record.reconcile_generation IS DISTINCT FROM expected_reconcile_generation OR
       ROW(current_record.reconcile_phase,
           current_record.reconcile_stream_created_unix_nano,
           current_record.reconcile_high_watermark,
           current_record.reconcile_scan_boundary,
           current_record.reconcile_cursor) IS DISTINCT FROM
       ROW(expected_reconcile_phase,
           expected_stream_created_unix_nano,
           expected_high_watermark,
           expected_scan_boundary,
           expected_cursor) OR
       ((new_stream_created_unix_nano IS DISTINCT FROM
             current_record.reconcile_stream_created_unix_nano) =
        (new_reconcile_generation IS NOT DISTINCT FROM expected_reconcile_generation)) THEN
        RAISE EXCEPTION 'plugin webhook dead letter reconcile generation is stale'
            USING ERRCODE = 'P8403';
    END IF;
    UPDATE %1$I.plugin_webhook_dead_letters
    SET reconcile_generation = new_reconcile_generation,
        reconcile_phase = new_reconcile_phase,
        reconcile_stream_created_unix_nano = new_stream_created_unix_nano,
        reconcile_high_watermark = new_high_watermark,
        reconcile_scan_boundary = new_scan_boundary,
        reconcile_cursor = new_cursor
    WHERE tenant_scope_id = target_scope_id AND subscription_id = target_subscription_id
      AND delivery_id = target_delivery_id AND publish_state = 'pending'
      AND reconcile_generation = expected_reconcile_generation
      AND reconcile_phase IS NOT DISTINCT FROM expected_reconcile_phase
      AND reconcile_stream_created_unix_nano IS NOT DISTINCT FROM
          expected_stream_created_unix_nano
      AND reconcile_high_watermark IS NOT DISTINCT FROM expected_high_watermark
      AND reconcile_scan_boundary IS NOT DISTINCT FROM expected_scan_boundary
      AND reconcile_cursor IS NOT DISTINCT FROM expected_cursor
    RETURNING reconcile_generation INTO resulting_generation;
    IF resulting_generation IS NULL THEN
        RAISE EXCEPTION 'plugin webhook dead letter reconcile generation is stale'
            USING ERRCODE = 'P8403';
    END IF;
    RETURN resulting_generation;
END;
$body$;
$function$, current_schema());
END;
$create$;

DO $create$
BEGIN
    EXECUTE format($function$
CREATE FUNCTION %1$I.acknowledge_plugin_webhook_dead_letter_084(
    target_scope_id uuid,
    target_subscription_id uuid,
    target_delivery_id uuid,
    expected_reconcile_generation uuid,
    expected_reconcile_phase text,
    expected_stream_created_unix_nano numeric,
    expected_high_watermark numeric,
    expected_scan_boundary numeric,
    expected_cursor numeric,
    broker_nats_domain text,
    broker_stream text,
    broker_stream_created_unix_nano numeric,
    broker_subject text,
    broker_sequence numeric,
    broker_message_id text,
    broker_semantic_payload_sha256 bytea,
    broker_wire_body_sha256 bytea,
    broker_expected_last_stream_sequence numeric,
    attestation_generation numeric,
    attestation_key_id text,
    attestation_signature bytea
)
RETURNS timestamptz
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $body$
DECLARE
    head_record record;
    delivery_record record;
    dead_letter_record record;
    subscription_found boolean;
    attestation_digest bytea;
    acknowledgement_time timestamptz;
BEGIN
    IF pg_has_role(
        session_user,
        to_regrole('cdnca_plugin_webhook_runtime'),
        'MEMBER'
    ) IS NOT TRUE THEN
        RAISE EXCEPTION 'plugin webhook trusted runtime identity is required'
            USING ERRCODE = 'P8408',
                  DETAIL = 'plugin_webhook.runtime_identity_required';
    END IF;
    SELECT * INTO head_record
    FROM %1$I.plugin_webhook_runtime_attestation_head
    WHERE singleton = true
    FOR SHARE;
    SELECT true INTO subscription_found
    FROM %1$I.plugin_webhook_subscriptions
    WHERE tenant_scope_id = target_scope_id AND id = target_subscription_id
    FOR SHARE;
    SELECT id, event_id, status INTO delivery_record
    FROM %1$I.plugin_webhook_deliveries
    WHERE tenant_scope_id = target_scope_id AND subscription_id = target_subscription_id
      AND id = target_delivery_id
    FOR UPDATE;
    SELECT * INTO dead_letter_record
    FROM %1$I.plugin_webhook_dead_letters
    WHERE tenant_scope_id = target_scope_id AND subscription_id = target_subscription_id
      AND delivery_id = target_delivery_id
    FOR UPDATE;
    acknowledgement_time := clock_timestamp();
    IF head_record.singleton IS DISTINCT FROM true OR head_record.status IS DISTINCT FROM 'active' OR
       acknowledgement_time < head_record.not_before OR acknowledgement_time >= head_record.expires_at OR
       subscription_found IS DISTINCT FROM true OR delivery_record.id IS NULL OR
       delivery_record.status IS DISTINCT FROM 'dead_letter_pending' OR
       dead_letter_record.id IS NULL OR dead_letter_record.publish_state IS DISTINCT FROM 'pending' OR
       dead_letter_record.reconcile_generation IS DISTINCT FROM expected_reconcile_generation OR
       ROW(dead_letter_record.reconcile_phase,
           dead_letter_record.reconcile_stream_created_unix_nano,
           dead_letter_record.reconcile_high_watermark,
           dead_letter_record.reconcile_scan_boundary,
           dead_letter_record.reconcile_cursor) IS DISTINCT FROM
       ROW(expected_reconcile_phase,
           expected_stream_created_unix_nano,
           expected_high_watermark,
           expected_scan_boundary,
           expected_cursor) OR
       dead_letter_record.reconcile_phase NOT IN ('reverse_scan', 'publish_ready', 'forward_scan') OR
       broker_nats_domain IS DISTINCT FROM head_record.nats_domain OR
       broker_stream IS DISTINCT FROM head_record.dead_letter_stream OR
       broker_stream IS DISTINCT FROM dead_letter_record.nats_stream OR
       broker_stream_created_unix_nano IS DISTINCT FROM
           dead_letter_record.reconcile_stream_created_unix_nano OR
       broker_subject IS DISTINCT FROM head_record.dead_letter_subject OR
       broker_subject IS DISTINCT FROM dead_letter_record.nats_subject OR
       broker_sequence IS NULL OR broker_sequence <= 0 OR
       NOT %1$I.plugin_webhook_u64_084(broker_sequence) OR
       broker_expected_last_stream_sequence IS DISTINCT FROM broker_sequence - 1 OR
       broker_message_id IS DISTINCT FROM dead_letter_record.nats_message_id OR
       broker_semantic_payload_sha256 IS DISTINCT FROM dead_letter_record.payload_sha256 OR
       octet_length(broker_wire_body_sha256) IS DISTINCT FROM 32 OR
       attestation_generation IS DISTINCT FROM head_record.key_generation OR
       attestation_key_id IS DISTINCT FROM head_record.key_id OR
       octet_length(attestation_signature) IS DISTINCT FROM 64 OR NOT (
           (dead_letter_record.reconcile_phase IN ('reverse_scan', 'forward_scan') AND
            broker_sequence = dead_letter_record.reconcile_cursor) OR
           (dead_letter_record.reconcile_phase = 'publish_ready' AND
            dead_letter_record.reconcile_high_watermark < 18446744073709551615 AND
            broker_sequence = dead_letter_record.reconcile_high_watermark + 1)
       ) THEN
        RAISE EXCEPTION 'plugin webhook dead letter publication attestation is invalid'
            USING ERRCODE = 'P8403';
    END IF;
    attestation_digest := %1$I.plugin_webhook_dead_letter_attestation_sha256_084(
        attestation_generation, attestation_key_id, broker_nats_domain,
        target_scope_id, target_subscription_id, target_delivery_id,
        delivery_record.event_id, dead_letter_record.id,
        dead_letter_record.reconcile_generation, dead_letter_record.reconcile_phase,
        dead_letter_record.reconcile_high_watermark,
        dead_letter_record.reconcile_scan_boundary, dead_letter_record.reconcile_cursor,
        broker_stream, broker_stream_created_unix_nano, broker_subject, broker_sequence,
        broker_message_id, broker_semantic_payload_sha256, broker_wire_body_sha256,
        broker_expected_last_stream_sequence
    );
    IF NOT %1$I.plugin_webhook_ed25519_verify_084(
        head_record.public_key, attestation_digest, attestation_signature
    ) THEN
        RAISE EXCEPTION 'plugin webhook dead letter publication attestation is invalid'
            USING ERRCODE = 'P8403';
    END IF;
    UPDATE %1$I.plugin_webhook_dead_letters
    SET publish_state = 'acknowledged', reconcile_phase = 'complete',
        reconcile_stream_created_unix_nano = NULL, reconcile_high_watermark = NULL,
        reconcile_scan_boundary = NULL, reconcile_cursor = NULL,
        nats_dlq_stream_created_unix_nano = broker_stream_created_unix_nano,
        nats_dlq_sequence = broker_sequence,
        nats_ack_id = broker_stream || ':' || broker_sequence::text,
        nats_domain = broker_nats_domain,
        wire_body_sha256 = broker_wire_body_sha256,
        expected_last_stream_sequence = broker_expected_last_stream_sequence,
        publication_attestation_generation = attestation_generation,
        publication_attestation_key_id = attestation_key_id,
        publication_attestation_sha256 = attestation_digest,
        publication_attestation_signature = attestation_signature,
        acknowledged_at = acknowledgement_time
    WHERE id = dead_letter_record.id AND publish_state = 'pending'
      AND reconcile_generation = expected_reconcile_generation
      AND reconcile_phase IS NOT DISTINCT FROM expected_reconcile_phase
      AND reconcile_stream_created_unix_nano IS NOT DISTINCT FROM
          expected_stream_created_unix_nano
      AND reconcile_high_watermark IS NOT DISTINCT FROM expected_high_watermark
      AND reconcile_scan_boundary IS NOT DISTINCT FROM expected_scan_boundary
      AND reconcile_cursor IS NOT DISTINCT FROM expected_cursor
    RETURNING acknowledged_at INTO acknowledgement_time;
    IF acknowledgement_time IS NULL THEN
        RAISE EXCEPTION 'plugin webhook dead letter reconcile generation is stale'
            USING ERRCODE = 'P8403';
    END IF;
    RETURN acknowledgement_time;
END;
$body$;
$function$, current_schema());
END;
$create$;

CREATE FUNCTION validate_plugin_webhook_dead_letter_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_publish_state text;
    current_reconcile_phase text;
    current_reconcile_generation uuid;
    current_reconcile_epoch numeric(20,0);
    current_reconcile_high numeric(20,0);
    current_reconcile_boundary numeric(20,0);
    current_reconcile_cursor numeric(20,0);
    current_nats_stream_epoch numeric(20,0);
    current_nats_sequence numeric(20,0);
    current_nats_ack_id text;
    current_nats_domain text;
    current_wire_body_sha256 bytea;
    current_expected_last_stream_sequence numeric(20,0);
    current_attestation_generation numeric(20,0);
    current_attestation_key_id text;
    current_attestation_sha256 bytea;
    current_attestation_signature bytea;
    current_acknowledged_at timestamptz;
    delivery_status text;
    delivery_attempt_count numeric(20,0);
    delivery_completed_at timestamptz;
    delivery_actor_scope uuid;
    delivery_actor_user uuid;
    attempt_status text;
    attempt_completed_at timestamptz;
    attempt_actor_scope uuid;
    attempt_actor_user uuid;
    attempt_failure_code text;
    attempt_http_status integer;
    attempt_request_sha256 bytea;
    attempt_response_sha256 bytea;
    attempt_response_bytes integer;
    delivery_event_id uuid;
    terminal_attempt_found boolean;
BEGIN
    SELECT publish_state, reconcile_phase, reconcile_generation,
           reconcile_stream_created_unix_nano,
           reconcile_high_watermark, reconcile_scan_boundary, reconcile_cursor,
           nats_dlq_stream_created_unix_nano, nats_dlq_sequence, nats_ack_id,
           nats_domain, wire_body_sha256, expected_last_stream_sequence,
           publication_attestation_generation, publication_attestation_key_id,
           publication_attestation_sha256, publication_attestation_signature,
           acknowledged_at
      INTO current_publish_state, current_reconcile_phase, current_reconcile_generation,
           current_reconcile_epoch,
           current_reconcile_high, current_reconcile_boundary, current_reconcile_cursor,
           current_nats_stream_epoch, current_nats_sequence,
           current_nats_ack_id, current_nats_domain, current_wire_body_sha256,
           current_expected_last_stream_sequence, current_attestation_generation,
           current_attestation_key_id, current_attestation_sha256,
           current_attestation_signature, current_acknowledged_at
    FROM plugin_webhook_dead_letters
    WHERE id = NEW.id;
    IF NOT FOUND OR
       ROW(current_publish_state, current_reconcile_phase, current_reconcile_generation,
           current_reconcile_epoch,
           current_reconcile_high, current_reconcile_boundary, current_reconcile_cursor,
           current_nats_stream_epoch, current_nats_sequence,
           current_nats_ack_id, current_nats_domain, current_wire_body_sha256,
           current_expected_last_stream_sequence, current_attestation_generation,
           current_attestation_key_id, current_attestation_sha256,
           current_attestation_signature, current_acknowledged_at) IS DISTINCT FROM
       ROW(NEW.publish_state, NEW.reconcile_phase, NEW.reconcile_generation,
           NEW.reconcile_stream_created_unix_nano,
           NEW.reconcile_high_watermark, NEW.reconcile_scan_boundary, NEW.reconcile_cursor,
           NEW.nats_dlq_stream_created_unix_nano, NEW.nats_dlq_sequence,
           NEW.nats_ack_id, NEW.nats_domain, NEW.wire_body_sha256,
           NEW.expected_last_stream_sequence, NEW.publication_attestation_generation,
           NEW.publication_attestation_key_id, NEW.publication_attestation_sha256,
           NEW.publication_attestation_signature, NEW.acknowledged_at) THEN
        RETURN NEW;
    END IF;
    SELECT status, attempt_count, completed_at, actor_scope_id, actor_user_id, event_id
      INTO delivery_status, delivery_attempt_count, delivery_completed_at,
           delivery_actor_scope, delivery_actor_user, delivery_event_id
    FROM plugin_webhook_deliveries
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND subscription_id = NEW.subscription_id AND id = NEW.delivery_id
    FOR SHARE;
    SELECT status, completed_at, actor_scope_id, actor_user_id, failure_code, http_status,
           request_sha256, response_sha256, response_bytes
      INTO attempt_status, attempt_completed_at, attempt_actor_scope, attempt_actor_user,
           attempt_failure_code, attempt_http_status, attempt_request_sha256,
           attempt_response_sha256, attempt_response_bytes
    FROM plugin_webhook_delivery_attempts
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND subscription_id = NEW.subscription_id AND delivery_id = NEW.delivery_id
      AND attempt_number = delivery_attempt_count
    FOR SHARE;
    terminal_attempt_found := FOUND;
    IF delivery_status IS DISTINCT FROM (CASE NEW.publish_state
           WHEN 'pending' THEN 'dead_letter_pending' ELSE 'dead_lettered' END) OR
       NOT terminal_attempt_found OR
       NEW.event_id IS DISTINCT FROM delivery_event_id OR
       NEW.final_attempt_number IS DISTINCT FROM delivery_attempt_count OR
       NEW.actor_scope_id IS DISTINCT FROM delivery_actor_scope OR
       NEW.actor_user_id IS DISTINCT FROM delivery_actor_user OR
       NEW.actor_scope_id IS DISTINCT FROM attempt_actor_scope OR
       NEW.actor_user_id IS DISTINCT FROM attempt_actor_user OR
       attempt_status NOT IN ('temporary_failure', 'permanent_failure') OR
       delivery_completed_at IS DISTINCT FROM attempt_completed_at OR
       NEW.failed_at IS DISTINCT FROM attempt_completed_at OR
       NEW.reason_code IS DISTINCT FROM attempt_failure_code OR
       NEW.http_status IS DISTINCT FROM attempt_http_status OR
       NEW.request_sha256 IS DISTINCT FROM attempt_request_sha256 OR
       NEW.response_sha256 IS DISTINCT FROM attempt_response_sha256 OR
       NEW.response_bytes IS DISTINCT FROM attempt_response_bytes THEN
        RAISE EXCEPTION 'plugin webhook dead letter is not bound to the terminal attempt'
            USING ERRCODE = 'P8404';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION project_plugin_webhook_dead_letter_ack_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.publish_state = 'pending' AND NEW.publish_state = 'acknowledged' THEN
        UPDATE plugin_webhook_deliveries
        SET status = 'dead_lettered'
        WHERE tenant_scope_id = NEW.tenant_scope_id
          AND subscription_id = NEW.subscription_id AND id = NEW.delivery_id
          AND status = 'dead_letter_pending';
    END IF;
    RETURN NULL;
END;
$$;

CREATE INDEX plugin_webhook_dead_letters_page_084
    ON plugin_webhook_dead_letters(tenant_scope_id, failed_at DESC, id);
CREATE INDEX plugin_webhook_dead_letters_reconcile_084
    ON plugin_webhook_dead_letters(failed_at, id)
    WHERE publish_state = 'pending';
CREATE TRIGGER plugin_webhook_dead_letters_actor_target_084
BEFORE INSERT OR UPDATE ON plugin_webhook_dead_letters
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_actor_target_084();
CREATE TRIGGER plugin_webhook_dead_letters_guard_084
BEFORE INSERT OR UPDATE OR DELETE ON plugin_webhook_dead_letters
FOR EACH ROW EXECUTE FUNCTION guard_plugin_webhook_dead_letter_084();
CREATE TRIGGER plugin_webhook_dead_letters_delivery_084
AFTER UPDATE ON plugin_webhook_dead_letters
FOR EACH ROW EXECUTE FUNCTION project_plugin_webhook_dead_letter_ack_084();
CREATE CONSTRAINT TRIGGER plugin_webhook_dead_letters_terminal_084
AFTER INSERT OR UPDATE ON plugin_webhook_dead_letters
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_dead_letter_084();
CREATE TRIGGER plugin_webhook_dead_letters_truncate_084
BEFORE TRUNCATE ON plugin_webhook_dead_letters
FOR EACH STATEMENT EXECUTE FUNCTION prevent_plugin_webhook_truncate_084();

CREATE TABLE plugin_webhook_rate_events (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    subscription_id uuid,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation IN (
        'plugin_webhook.subscription.create',
        'plugin_webhook.test_delivery.create',
        'plugin_webhook.delivery.replay',
        'plugin_webhook.secret.rotate'
    )),
    outcome text NOT NULL CHECK (outcome IN ('allowed', 'denied')),
    reason_code text NOT NULL CHECK (plugin_webhook_text_valid_084(reason_code, 128)),
    audit_event_id uuid NOT NULL REFERENCES audit_events(id) ON DELETE RESTRICT,
    occurred_at timestamptz NOT NULL CHECK (isfinite(occurred_at)),
    plugin_webhook_xact_id xid8 NOT NULL,
    plugin_webhook_recorded_at timestamptz NOT NULL,
    plugin_webhook_physical_recorded_at timestamptz NOT NULL
        CHECK (isfinite(plugin_webhook_physical_recorded_at)),
    FOREIGN KEY (tenant_scope_id, subscription_id)
        REFERENCES plugin_webhook_subscriptions(tenant_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (
        (operation = 'plugin_webhook.subscription.create' AND subscription_id IS NULL) OR
        (operation <> 'plugin_webhook.subscription.create' AND subscription_id IS NOT NULL)
    )
);

CREATE TRIGGER plugin_webhook_rate_events_00_xact_084
BEFORE INSERT OR UPDATE ON plugin_webhook_rate_events
FOR EACH ROW EXECUTE FUNCTION stamp_plugin_webhook_xact_id_084();

CREATE INDEX plugin_webhook_rate_tenant_084
    ON plugin_webhook_rate_events(
        tenant_scope_id, operation, plugin_webhook_physical_recorded_at DESC
    );
CREATE INDEX plugin_webhook_rate_subscription_084
    ON plugin_webhook_rate_events(
        tenant_scope_id, subscription_id, operation, plugin_webhook_physical_recorded_at DESC
    )
    WHERE subscription_id IS NOT NULL;
CREATE UNIQUE INDEX plugin_webhook_rate_audit_084
    ON plugin_webhook_rate_events(audit_event_id);
CREATE TRIGGER plugin_webhook_rate_events_actor_target_084
BEFORE INSERT OR UPDATE ON plugin_webhook_rate_events
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_actor_target_084();

CREATE FUNCTION enforce_plugin_webhook_rate_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    tenant_allowed bigint;
    subscription_allowed bigint;
    boundary_now timestamptz;
BEGIN
    IF NEW.occurred_at IS DISTINCT FROM NEW.plugin_webhook_recorded_at THEN
        RAISE EXCEPTION 'plugin webhook rate time must be database generated'
            USING ERRCODE = 'P8408', DETAIL = 'plugin_webhook.invariant_violation';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'plugin-webhook-rate-tenant:' || NEW.tenant_scope_id::text || ':' || NEW.operation, 84));
    IF NEW.subscription_id IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(hashtextextended(
            'plugin-webhook-rate-subscription:' || NEW.tenant_scope_id::text || ':' ||
            NEW.subscription_id::text || ':' || NEW.operation, 84));
    END IF;
    boundary_now := clock_timestamp();
    NEW.plugin_webhook_physical_recorded_at := boundary_now;
    IF NEW.outcome = 'denied' THEN
        RETURN NEW;
    END IF;
    IF NEW.operation = 'plugin_webhook.subscription.create' THEN
        SELECT count(*) INTO tenant_allowed FROM plugin_webhook_rate_events
        WHERE tenant_scope_id = NEW.tenant_scope_id AND operation = NEW.operation
          AND outcome = 'allowed'
          AND plugin_webhook_physical_recorded_at > boundary_now - interval '1 hour';
        IF tenant_allowed >= 10 THEN
            RAISE EXCEPTION 'plugin webhook create rate exceeded'
                USING ERRCODE = 'P8408', DETAIL = 'plugin_webhook.rate_limited';
        END IF;
    ELSIF NEW.operation = 'plugin_webhook.test_delivery.create' THEN
        SELECT count(*) INTO tenant_allowed FROM plugin_webhook_rate_events
        WHERE tenant_scope_id = NEW.tenant_scope_id AND operation = NEW.operation
          AND outcome = 'allowed'
          AND plugin_webhook_physical_recorded_at > boundary_now - interval '1 minute';
        SELECT count(*) INTO subscription_allowed FROM plugin_webhook_rate_events
        WHERE tenant_scope_id = NEW.tenant_scope_id AND subscription_id = NEW.subscription_id
          AND operation = NEW.operation AND outcome = 'allowed'
          AND plugin_webhook_physical_recorded_at > boundary_now - interval '1 minute';
        IF tenant_allowed >= 30 OR subscription_allowed >= 5 THEN
            RAISE EXCEPTION 'plugin webhook test rate exceeded'
                USING ERRCODE = 'P8408', DETAIL = 'plugin_webhook.rate_limited';
        END IF;
    ELSIF NEW.operation = 'plugin_webhook.delivery.replay' THEN
        SELECT count(*) INTO tenant_allowed FROM plugin_webhook_rate_events
        WHERE tenant_scope_id = NEW.tenant_scope_id AND operation = NEW.operation
          AND outcome = 'allowed'
          AND plugin_webhook_physical_recorded_at > boundary_now - interval '1 minute';
        SELECT count(*) INTO subscription_allowed FROM plugin_webhook_rate_events
        WHERE tenant_scope_id = NEW.tenant_scope_id AND subscription_id = NEW.subscription_id
          AND operation = NEW.operation AND outcome = 'allowed'
          AND plugin_webhook_physical_recorded_at > boundary_now - interval '1 minute';
        IF tenant_allowed >= 10 OR subscription_allowed >= 5 THEN
            RAISE EXCEPTION 'plugin webhook replay rate exceeded'
                USING ERRCODE = 'P8408', DETAIL = 'plugin_webhook.rate_limited';
        END IF;
    ELSE
        SELECT count(*) INTO subscription_allowed FROM plugin_webhook_rate_events
        WHERE tenant_scope_id = NEW.tenant_scope_id AND subscription_id = NEW.subscription_id
          AND operation = NEW.operation AND outcome = 'allowed'
          AND plugin_webhook_physical_recorded_at > boundary_now - interval '1 hour';
        IF subscription_allowed >= 5 THEN
            RAISE EXCEPTION 'plugin webhook rotation rate exceeded'
                USING ERRCODE = 'P8408', DETAIL = 'plugin_webhook.rate_limited';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER plugin_webhook_rate_events_limit_084
BEFORE INSERT ON plugin_webhook_rate_events
FOR EACH ROW EXECUTE FUNCTION enforce_plugin_webhook_rate_084();
CREATE TRIGGER plugin_webhook_rate_events_append_only_084
BEFORE UPDATE OR DELETE ON plugin_webhook_rate_events
FOR EACH ROW EXECUTE FUNCTION prevent_plugin_webhook_append_mutation_084();
CREATE TRIGGER plugin_webhook_rate_events_truncate_084
BEFORE TRUNCATE ON plugin_webhook_rate_events
FOR EACH STATEMENT EXECUTE FUNCTION prevent_plugin_webhook_truncate_084();

CREATE FUNCTION validate_plugin_webhook_audit_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    event_id uuid;
    event_action text;
    event_result text;
    event_scope uuid;
    event_actor uuid;
    event_resource_type text;
    event_resource_id text;
    event_request_id text;
    event_payload jsonb;
    event_occurred_at timestamptz;
    event_recorded_at timestamptz;
    expected_resource_type text;
    expected_resource_id text;
    expected_request_id text;
    linked_operation text;
    linked_subscription uuid;
    linked_delivery uuid;
    linked_rotation uuid;
    linked_request_id text;
    linked_request_found boolean;
BEGIN
    event_id := NEW.audit_event_id;
    IF event_id IS NULL THEN
        IF TG_TABLE_NAME = 'plugin_webhook_write_requests' AND NEW.completed_at IS NULL THEN
            RETURN NULL;
        END IF;
        RAISE EXCEPTION 'plugin webhook durable fact requires audit'
            USING ERRCODE = 'P8405';
    END IF;
    SELECT action, result, scope_id, actor_user_id, resource_type, resource_id, request_id, payload,
           occurred_at, plugin_webhook_recorded_at
      INTO event_action, event_result, event_scope, event_actor, event_resource_type,
           event_resource_id, event_request_id, event_payload, event_occurred_at, event_recorded_at
    FROM audit_events WHERE id = event_id;
    IF TG_TABLE_NAME = 'plugin_webhook_write_requests' THEN
        expected_resource_type := CASE
            WHEN NEW.operation IN ('plugin_webhook.subscription.create', 'plugin_webhook.subscription.revoke')
                THEN 'plugin_webhook_subscription'
            WHEN NEW.operation IN ('plugin_webhook.test_delivery.create', 'plugin_webhook.delivery.replay')
                THEN 'plugin_webhook_delivery'
            ELSE 'plugin_webhook_secret_version'
        END;
        expected_resource_id := CASE
            WHEN NEW.operation IN ('plugin_webhook.test_delivery.create', 'plugin_webhook.delivery.replay')
                THEN NEW.delivery_id::text
            WHEN NEW.operation IN ('plugin_webhook.secret.rotate', 'plugin_webhook.secret.activate')
                THEN NEW.rotation_id::text
            ELSE NEW.subscription_id::text
        END;
        expected_request_id := NEW.idempotency_key;
    ELSE
        SELECT request.operation, request.subscription_id, request.delivery_id, request.rotation_id,
               request.idempotency_key
          INTO linked_operation, linked_subscription, linked_delivery, linked_rotation, linked_request_id
        FROM plugin_webhook_write_requests request
        WHERE request.audit_event_id = NEW.audit_event_id;
        linked_request_found := FOUND;
        IF linked_request_found THEN
            expected_resource_type := CASE
                WHEN linked_operation IN ('plugin_webhook.subscription.create', 'plugin_webhook.subscription.revoke')
                    THEN 'plugin_webhook_subscription'
                WHEN linked_operation IN ('plugin_webhook.test_delivery.create', 'plugin_webhook.delivery.replay')
                    THEN 'plugin_webhook_delivery'
                ELSE 'plugin_webhook_secret_version'
            END;
            expected_resource_id := CASE
                WHEN linked_operation IN ('plugin_webhook.test_delivery.create', 'plugin_webhook.delivery.replay')
                    THEN linked_delivery::text
                WHEN linked_operation IN ('plugin_webhook.secret.rotate', 'plugin_webhook.secret.activate')
                    THEN linked_rotation::text
                ELSE linked_subscription::text
            END;
            expected_request_id := linked_request_id;
        ELSE
            expected_resource_type := CASE WHEN NEW.subscription_id IS NULL
                THEN 'plugin_webhook_tenant' ELSE 'plugin_webhook_subscription' END;
            expected_resource_id := COALESCE(NEW.subscription_id, NEW.tenant_scope_id)::text;
            expected_request_id := 'rate-' || NEW.id::text;
        END IF;
    END IF;
    IF event_scope IS DISTINCT FROM NEW.tenant_scope_id OR
       event_actor IS DISTINCT FROM NEW.actor_user_id OR event_action IS DISTINCT FROM NEW.operation OR
       event_resource_type IS DISTINCT FROM expected_resource_type OR
       event_resource_id IS DISTINCT FROM expected_resource_id OR
       event_request_id IS DISTINCT FROM expected_request_id OR
       event_occurred_at IS DISTINCT FROM NEW.plugin_webhook_recorded_at OR
       event_recorded_at IS DISTINCT FROM NEW.plugin_webhook_recorded_at OR
       NOT COALESCE(plugin_webhook_text_valid_084(event_payload->>'reason', 128), false) OR
       event_payload IS DISTINCT FROM jsonb_build_object(
           'actor_scope_id', NEW.actor_scope_id::text,
           'target_scope_id', NEW.tenant_scope_id::text,
           'operation', NEW.operation,
           'reason', event_payload->>'reason'
       ) THEN
        RAISE EXCEPTION 'plugin webhook audit identity is invalid'
            USING ERRCODE = 'P8405';
    END IF;
    IF TG_TABLE_NAME = 'plugin_webhook_rate_events' THEN
        IF event_result IS DISTINCT FROM (CASE
               WHEN NEW.outcome = 'denied' THEN 'denied' ELSE 'success' END) OR
           event_payload->>'reason' IS DISTINCT FROM NEW.reason_code THEN
            RAISE EXCEPTION 'plugin webhook rate audit outcome is invalid'
                USING ERRCODE = 'P8405';
        END IF;
    ELSIF event_result <> 'success' THEN
        RAISE EXCEPTION 'plugin webhook write audit outcome is invalid'
            USING ERRCODE = 'P8405';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER plugin_webhook_write_requests_audit_084
AFTER INSERT OR UPDATE ON plugin_webhook_write_requests
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_audit_084();
CREATE CONSTRAINT TRIGGER plugin_webhook_rate_events_audit_084
AFTER INSERT ON plugin_webhook_rate_events
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_audit_084();

CREATE FUNCTION validate_plugin_webhook_command_facts_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    checked_scope uuid;
    checked_subscription uuid;
    checked_delivery uuid;
    checked_event uuid;
    checked_replay uuid;
    checked_actor_scope uuid;
    checked_actor_user uuid;
    checked_operation text;
    checked_created_at timestamptz;
    checked_recorded_at timestamptz;
    matching_facts bigint;
BEGIN
    checked_scope := NEW.tenant_scope_id;
    checked_actor_scope := NEW.actor_scope_id;
    checked_actor_user := NEW.actor_user_id;
    checked_created_at := NEW.created_at;
    checked_recorded_at := NEW.plugin_webhook_recorded_at;
    IF TG_TABLE_NAME = 'plugin_webhook_subscriptions' THEN
        checked_subscription := NEW.id;
        checked_delivery := NULL;
        checked_operation := 'plugin_webhook.subscription.create';
    ELSE
        checked_subscription := NEW.subscription_id;
        checked_delivery := NEW.id;
        checked_event := NEW.event_id;
        checked_replay := NEW.replay_of;
        checked_operation := CASE WHEN NEW.replay_of IS NULL THEN
            'plugin_webhook.test_delivery.create'
        ELSE
            'plugin_webhook.delivery.replay'
        END;
    END IF;
    IF TG_TABLE_NAME = 'plugin_webhook_deliveries' AND checked_replay IS NULL AND NOT EXISTS (
        SELECT 1 FROM plugin_webhook_events event
        WHERE event.tenant_scope_id = checked_scope
          AND event.subscription_id = checked_subscription AND event.id = checked_event
          AND event.actor_scope_id = checked_actor_scope
          AND event.actor_user_id = checked_actor_user
          AND event.created_at = checked_created_at
          AND event.plugin_webhook_recorded_at = checked_recorded_at
          AND event.plugin_webhook_xact_id = pg_current_xact_id()
    ) THEN
        RAISE EXCEPTION 'non-replay plugin webhook delivery requires its fresh current transaction event'
            USING ERRCODE = 'P8405';
    END IF;
    SELECT count(*) INTO matching_facts
    FROM plugin_webhook_write_requests request
    JOIN plugin_webhook_entitlement_decisions decision
      ON decision.request_id = request.id
     AND decision.tenant_scope_id = request.tenant_scope_id
     AND decision.actor_scope_id = request.actor_scope_id
     AND decision.actor_user_id = request.actor_user_id
     AND decision.operation = request.operation
     AND decision.request_digest = request.request_digest
     AND decision.plugin_webhook_xact_id = pg_current_xact_id()
    JOIN plugin_webhook_rate_events rate
      ON rate.audit_event_id = request.audit_event_id
     AND rate.tenant_scope_id = request.tenant_scope_id
     AND rate.actor_scope_id = request.actor_scope_id
     AND rate.actor_user_id = request.actor_user_id
     AND rate.operation = request.operation
    JOIN audit_events audit ON audit.id = request.audit_event_id
    WHERE request.tenant_scope_id = checked_scope
      AND request.subscription_id = checked_subscription
      AND request.delivery_id IS NOT DISTINCT FROM checked_delivery
      AND request.actor_scope_id = checked_actor_scope
      AND request.actor_user_id = checked_actor_user
      AND request.operation = checked_operation
      AND request.completed_at = checked_recorded_at
      AND request.created_at = checked_created_at
      AND rate.outcome = 'allowed' AND rate.reason_code = 'accepted'
      AND rate.occurred_at = checked_recorded_at
      AND ((checked_operation = 'plugin_webhook.subscription.create' AND
            rate.subscription_id IS NULL) OR
           (checked_operation <> 'plugin_webhook.subscription.create' AND
            rate.subscription_id = checked_subscription))
      AND audit.scope_id = checked_scope
      AND audit.actor_user_id = checked_actor_user
      AND audit.action = checked_operation AND audit.result = 'success'
      AND audit.occurred_at = checked_recorded_at
      AND audit.payload = jsonb_build_object(
          'actor_scope_id', checked_actor_scope::text,
          'target_scope_id', checked_scope::text,
          'operation', checked_operation,
          'reason', 'accepted'
      )
      AND request.plugin_webhook_xact_id = pg_current_xact_id()
      AND decision.quota_allowed
      AND rate.plugin_webhook_xact_id = pg_current_xact_id()
      AND audit.plugin_webhook_xact_id = pg_current_xact_id()
      AND request.plugin_webhook_recorded_at = checked_recorded_at
      AND rate.plugin_webhook_recorded_at = checked_recorded_at
      AND audit.plugin_webhook_recorded_at = checked_recorded_at;
    IF matching_facts <> 1 THEN
        RAISE EXCEPTION 'plugin webhook command result requires one current transaction fact bundle'
            USING ERRCODE = 'P8405';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION validate_plugin_webhook_event_command_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM plugin_webhook_deliveries delivery
        WHERE delivery.tenant_scope_id = NEW.tenant_scope_id
          AND delivery.subscription_id = NEW.subscription_id
          AND delivery.event_id = NEW.id AND delivery.replay_of IS NULL
          AND delivery.actor_scope_id = NEW.actor_scope_id
          AND delivery.actor_user_id = NEW.actor_user_id
          AND delivery.created_at = NEW.created_at
          AND delivery.plugin_webhook_recorded_at = NEW.plugin_webhook_recorded_at
          AND delivery.plugin_webhook_xact_id = pg_current_xact_id()
    ) THEN
        RAISE EXCEPTION 'plugin webhook event requires its current transaction command delivery'
            USING ERRCODE = 'P8405';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION validate_plugin_webhook_secret_command_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    matching_facts bigint;
BEGIN
    IF NEW.version = 1 THEN
        RETURN NULL;
    END IF;
    SELECT count(*) INTO matching_facts
    FROM plugin_webhook_write_requests request
    JOIN plugin_webhook_entitlement_decisions decision
      ON decision.request_id = request.id
     AND decision.request_digest = request.request_digest
     AND decision.plugin_webhook_xact_id = pg_current_xact_id()
    JOIN plugin_webhook_rate_events rate
      ON rate.audit_event_id = request.audit_event_id
     AND rate.tenant_scope_id = request.tenant_scope_id
     AND rate.subscription_id = request.subscription_id
     AND rate.actor_scope_id = request.actor_scope_id
     AND rate.actor_user_id = request.actor_user_id
     AND rate.operation = request.operation
    JOIN audit_events audit ON audit.id = request.audit_event_id
    WHERE request.tenant_scope_id = NEW.tenant_scope_id
      AND request.subscription_id = NEW.subscription_id
      AND request.rotation_id = NEW.id
      AND request.actor_scope_id = NEW.actor_scope_id
      AND request.actor_user_id = NEW.actor_user_id
      AND request.operation = 'plugin_webhook.secret.rotate'
      AND request.completed_at = NEW.plugin_webhook_recorded_at
      AND request.created_at = NEW.created_at
      AND rate.outcome = 'allowed' AND rate.reason_code = 'accepted'
      AND rate.occurred_at = NEW.plugin_webhook_recorded_at
      AND audit.scope_id = NEW.tenant_scope_id
      AND audit.actor_user_id = NEW.actor_user_id
      AND audit.action = request.operation AND audit.result = 'success'
      AND audit.occurred_at = NEW.plugin_webhook_recorded_at
      AND request.plugin_webhook_xact_id = pg_current_xact_id()
      AND decision.quota_allowed
      AND rate.plugin_webhook_xact_id = pg_current_xact_id()
      AND audit.plugin_webhook_xact_id = pg_current_xact_id()
      AND request.plugin_webhook_recorded_at = NEW.plugin_webhook_recorded_at
      AND rate.plugin_webhook_recorded_at = NEW.plugin_webhook_recorded_at
      AND audit.plugin_webhook_recorded_at = NEW.plugin_webhook_recorded_at;
    IF matching_facts <> 1 THEN
        RAISE EXCEPTION 'plugin webhook rotation requires one current transaction command rate bundle'
            USING ERRCODE = 'P8405';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION validate_plugin_webhook_write_request_result_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    matching_results bigint;
BEGIN
    IF NEW.completed_at IS NULL OR (TG_OP = 'UPDATE' AND OLD.completed_at IS NOT NULL) THEN
        RETURN NULL;
    END IF;
    IF NEW.completed_at IS DISTINCT FROM NEW.plugin_webhook_recorded_at THEN
        RAISE EXCEPTION 'plugin webhook command completion time must be database generated'
            USING ERRCODE = 'P8405';
    END IF;
    IF NEW.operation IN (
        'plugin_webhook.subscription.create',
        'plugin_webhook.test_delivery.create',
        'plugin_webhook.delivery.replay',
        'plugin_webhook.secret.rotate'
    ) AND NOT EXISTS (
        SELECT 1 FROM plugin_webhook_entitlement_decisions decision
        WHERE decision.request_id = NEW.id
          AND decision.tenant_scope_id = NEW.tenant_scope_id
          AND decision.actor_scope_id = NEW.actor_scope_id
          AND decision.actor_user_id = NEW.actor_user_id
          AND decision.operation = NEW.operation
          AND decision.subscription_id = NEW.subscription_id
          AND decision.request_digest = NEW.request_digest
          AND decision.plugin_webhook_xact_id = pg_current_xact_id()
    ) THEN
        RAISE EXCEPTION 'plugin webhook command requires a current entitlement decision'
            USING ERRCODE = 'P8405';
    END IF;
    IF NEW.operation = 'plugin_webhook.subscription.create' THEN
        SELECT count(*) INTO matching_results
        FROM plugin_webhook_subscriptions subscription
        JOIN plugin_webhook_secret_versions secret
          ON secret.tenant_scope_id = subscription.tenant_scope_id
         AND secret.subscription_id = subscription.id
         AND secret.id = subscription.active_secret_version_id
        WHERE subscription.tenant_scope_id = NEW.tenant_scope_id
          AND subscription.id = NEW.subscription_id
          AND subscription.actor_scope_id = NEW.actor_scope_id
          AND subscription.actor_user_id = NEW.actor_user_id
          AND subscription.created_at = NEW.created_at
          AND subscription.status = 'active'
          AND secret.version = 1 AND secret.status = 'active'
          AND secret.actor_scope_id = NEW.actor_scope_id
          AND secret.actor_user_id = NEW.actor_user_id
          AND secret.created_at = NEW.created_at
          AND subscription.plugin_webhook_recorded_at = NEW.plugin_webhook_recorded_at
          AND secret.plugin_webhook_recorded_at = NEW.plugin_webhook_recorded_at
          AND subscription.plugin_webhook_xact_id = pg_current_xact_id()
          AND secret.plugin_webhook_xact_id = pg_current_xact_id();
    ELSIF NEW.operation IN ('plugin_webhook.test_delivery.create', 'plugin_webhook.delivery.replay') THEN
        SELECT count(*) INTO matching_results
        FROM plugin_webhook_deliveries delivery
        WHERE delivery.tenant_scope_id = NEW.tenant_scope_id
          AND delivery.subscription_id = NEW.subscription_id AND delivery.id = NEW.delivery_id
          AND delivery.actor_scope_id = NEW.actor_scope_id
          AND delivery.actor_user_id = NEW.actor_user_id
          AND delivery.created_at = NEW.created_at
          AND ((NEW.operation = 'plugin_webhook.test_delivery.create' AND delivery.replay_of IS NULL) OR
               (NEW.operation = 'plugin_webhook.delivery.replay' AND delivery.replay_of IS NOT NULL))
          AND delivery.plugin_webhook_xact_id = pg_current_xact_id()
          AND delivery.plugin_webhook_recorded_at = NEW.plugin_webhook_recorded_at;
    ELSIF NEW.operation = 'plugin_webhook.secret.rotate' THEN
        SELECT count(*) INTO matching_results
        FROM plugin_webhook_secret_versions secret
        WHERE secret.tenant_scope_id = NEW.tenant_scope_id
          AND secret.subscription_id = NEW.subscription_id AND secret.id = NEW.rotation_id
          AND secret.actor_scope_id = NEW.actor_scope_id
          AND secret.actor_user_id = NEW.actor_user_id
          AND secret.version > 1 AND secret.status IN ('pending', 'active')
          AND secret.created_at = NEW.created_at
          AND secret.plugin_webhook_xact_id = pg_current_xact_id()
          AND secret.plugin_webhook_recorded_at = NEW.plugin_webhook_recorded_at;
    ELSIF NEW.operation = 'plugin_webhook.secret.activate' THEN
        SELECT count(*) INTO matching_results
        FROM plugin_webhook_subscriptions subscription
        JOIN plugin_webhook_secret_versions secret
          ON secret.tenant_scope_id = subscription.tenant_scope_id
         AND secret.subscription_id = subscription.id AND secret.id = NEW.rotation_id
        WHERE subscription.tenant_scope_id = NEW.tenant_scope_id
          AND subscription.id = NEW.subscription_id
          AND subscription.active_secret_version_id = NEW.rotation_id
          AND subscription.status = 'active' AND secret.status = 'active'
          AND subscription.plugin_webhook_xact_id = pg_current_xact_id()
          AND secret.plugin_webhook_xact_id = pg_current_xact_id()
          AND subscription.plugin_webhook_recorded_at = NEW.plugin_webhook_recorded_at
          AND secret.plugin_webhook_recorded_at = NEW.plugin_webhook_recorded_at;
    ELSE
        SELECT count(*) INTO matching_results
        FROM plugin_webhook_subscriptions subscription
        WHERE subscription.tenant_scope_id = NEW.tenant_scope_id
          AND subscription.id = NEW.subscription_id AND subscription.status = 'revoked'
          AND subscription.plugin_webhook_xact_id = pg_current_xact_id()
          AND subscription.plugin_webhook_recorded_at = NEW.plugin_webhook_recorded_at;
    END IF;
    IF matching_results <> 1 THEN
        RAISE EXCEPTION 'successful plugin webhook request is not bound to its exact result fact'
            USING ERRCODE = 'P8405';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION validate_plugin_webhook_entitlement_decision_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    request plugin_webhook_write_requests%ROWTYPE;
    installation_id_value text;
    current_serial_value bigint;
    lease_signed bytea;
    lease_status_value text;
    lease_not_before_value timestamptz;
    lease_expires_value timestamptz;
    lease_grace_value timestamptz;
    lkg control_entitlement_revocation_lkg%ROWTYPE;
    active_count bigint;
    expected_resource uuid;
    commit_physical_now timestamptz;
BEGIN
    SELECT * INTO request FROM plugin_webhook_write_requests
    WHERE id = NEW.request_id;
    IF request.id IS NULL OR request.completed_at IS NULL OR
       NEW.plugin_webhook_xact_id <> pg_current_xact_id() OR
       NEW.evaluated_at < request.plugin_webhook_physical_created_at OR
       ROW(NEW.tenant_scope_id, NEW.actor_scope_id, NEW.actor_user_id,
           NEW.operation, NEW.subscription_id, NEW.request_digest) IS DISTINCT FROM
       ROW(request.tenant_scope_id, request.actor_scope_id, request.actor_user_id,
           request.operation, request.subscription_id, request.request_digest) THEN
        RAISE EXCEPTION 'plugin webhook entitlement decision request binding is invalid'
            USING ERRCODE = 'P8408', DETAIL = 'plugin_webhook.invariant_violation';
    END IF;
    expected_resource := CASE
        WHEN request.operation = 'plugin_webhook.subscription.create' THEN request.subscription_id
        WHEN request.operation IN ('plugin_webhook.test_delivery.create', 'plugin_webhook.delivery.replay') THEN request.delivery_id
        ELSE request.rotation_id
    END;
    IF NEW.resource_id IS DISTINCT FROM expected_resource THEN
        RAISE EXCEPTION 'plugin webhook entitlement decision resource binding is invalid'
            USING ERRCODE = 'P8408', DETAIL = 'plugin_webhook.invariant_violation';
    END IF;
    SELECT installation.installation_id, installation.current_serial,
           lease.signed_lease, lease.status, lease.not_before, lease.expires_at, lease.grace_until
      INTO installation_id_value, current_serial_value,
           lease_signed, lease_status_value, lease_not_before_value, lease_expires_value, lease_grace_value
    FROM control_installation_entitlement installation
    LEFT JOIN entitlement_cached_leases lease ON lease.serial = installation.current_serial
    WHERE installation.singleton = true
    FOR SHARE OF installation;
    SELECT * INTO lkg FROM control_entitlement_revocation_lkg
    WHERE singleton = true FOR SHARE;
    commit_physical_now := clock_timestamp();
    IF installation_id_value IS DISTINCT FROM NEW.lease_installation_id OR
       current_serial_value IS DISTINCT FROM NEW.lease_serial OR
       sha256(lease_signed) IS DISTINCT FROM NEW.lease_sha256 OR
       lease_status_value IS DISTINCT FROM NEW.lease_status OR
       lease_not_before_value IS DISTINCT FROM NEW.lease_not_before OR
       lease_expires_value IS DISTINCT FROM NEW.lease_expires_at OR
       lease_grace_value IS DISTINCT FROM NEW.lease_grace_until OR
       lkg.revision IS DISTINCT FROM NEW.revocation_revision OR
       lkg.artifact_sha256 IS DISTINCT FROM NEW.revocation_sha256 OR
       lkg.key_id IS DISTINCT FROM NEW.revocation_key_id OR
       lkg.issued_at IS DISTINCT FROM NEW.revocation_issued_at OR
       lkg.expires_at IS DISTINCT FROM NEW.revocation_expires_at OR
       NEW.evaluated_at < NEW.lease_not_before OR NEW.evaluated_at >= NEW.lease_grace_until OR
       NEW.evaluated_at < NEW.revocation_issued_at OR
       commit_physical_now < NEW.evaluated_at OR
       commit_physical_now < NEW.lease_not_before OR
       commit_physical_now >= NEW.lease_grace_until OR
       commit_physical_now < NEW.revocation_issued_at OR
       EXISTS (
           SELECT 1 FROM control_entitlement_revoked_serials revoked
           WHERE revoked.installation_id = NEW.lease_installation_id
             AND revoked.license_id = NEW.lease_license_id
             AND revoked.serial = NEW.lease_serial
       ) THEN
        RAISE EXCEPTION 'plugin webhook entitlement decision is no longer current'
            USING ERRCODE = 'P8408', DETAIL = 'plugin_webhook.entitlement_denied';
    END IF;
    SELECT count(*) INTO active_count
    FROM plugin_webhook_subscriptions subscription
    WHERE subscription.tenant_scope_id = NEW.tenant_scope_id
      AND subscription.status = 'active';
    IF active_count <> NEW.quota_current OR NOT NEW.quota_allowed OR
       (NEW.operation = 'plugin_webhook.subscription.create' AND (
           NEW.reason_code <> 'accepted_quota' OR NEW.quota_limit < 0 OR
           active_count > LEAST(NEW.quota_limit, 100)
       )) OR
       (NEW.operation <> 'plugin_webhook.subscription.create' AND
        NEW.reason_code <> 'accepted_feature') THEN
        RAISE EXCEPTION 'plugin webhook entitlement quota decision is invalid'
            USING ERRCODE = 'P8408', DETAIL = 'plugin_webhook.invariant_violation';
    END IF;
    RETURN NULL;
END;
$$;

ALTER TABLE plugin_webhook_write_requests
    ADD CONSTRAINT plugin_webhook_write_requests_delivery_084_fk
    FOREIGN KEY (tenant_scope_id, subscription_id, delivery_id)
    REFERENCES plugin_webhook_deliveries(tenant_scope_id, subscription_id, id)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT plugin_webhook_write_requests_rotation_084_fk
    FOREIGN KEY (tenant_scope_id, subscription_id, rotation_id)
    REFERENCES plugin_webhook_secret_versions(tenant_scope_id, subscription_id, id)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE CONSTRAINT TRIGGER plugin_webhook_subscriptions_command_facts_084
AFTER INSERT ON plugin_webhook_subscriptions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_command_facts_084();
CREATE CONSTRAINT TRIGGER plugin_webhook_deliveries_command_facts_084
AFTER INSERT ON plugin_webhook_deliveries
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_command_facts_084();
CREATE CONSTRAINT TRIGGER plugin_webhook_events_command_facts_084
AFTER INSERT ON plugin_webhook_events
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_event_command_084();
CREATE CONSTRAINT TRIGGER plugin_webhook_secret_versions_command_facts_084
AFTER INSERT ON plugin_webhook_secret_versions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_secret_command_084();
CREATE CONSTRAINT TRIGGER plugin_webhook_write_requests_result_084
AFTER INSERT OR UPDATE ON plugin_webhook_write_requests
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_write_request_result_084();
CREATE CONSTRAINT TRIGGER plugin_webhook_entitlement_decisions_validate_084
AFTER INSERT ON plugin_webhook_entitlement_decisions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_entitlement_decision_084();

DO $$
DECLARE
    schema_name text := current_schema();
    function_name text;
    privileged_function_name text;
BEGIN
    FOREACH function_name IN ARRAY ARRAY[
        'validate_plugin_webhook_actor_target_084',
        'guard_plugin_webhook_delivery_084',
        'guard_plugin_webhook_outbox_084',
        'validate_plugin_webhook_delivery_outbox_084',
        'claim_plugin_webhook_attempt_084',
        'guard_plugin_webhook_attempt_084',
        'project_plugin_webhook_attempt_outcome_084',
        'validate_plugin_webhook_delivery_attempt_084',
        'guard_plugin_webhook_dead_letter_084',
        'validate_plugin_webhook_dead_letter_084',
        'project_plugin_webhook_dead_letter_ack_084'
    ] LOOP
        EXECUTE format(
            'ALTER FUNCTION %I.%I() SET search_path = %I, pg_catalog',
            schema_name, function_name, schema_name
        );
    END LOOP;
    FOREACH privileged_function_name IN ARRAY ARRAY[
        'validate_plugin_webhook_actor_target_084',
        'claim_plugin_webhook_attempt_084',
        'guard_plugin_webhook_attempt_084',
        'project_plugin_webhook_attempt_outcome_084',
        'validate_plugin_webhook_delivery_attempt_084',
        'guard_plugin_webhook_dead_letter_084',
        'validate_plugin_webhook_dead_letter_084',
        'project_plugin_webhook_dead_letter_ack_084'
    ] LOOP
        EXECUTE format(
            'ALTER FUNCTION %I.%I() SECURITY DEFINER',
            schema_name, privileged_function_name
        );
    END LOOP;
END;
$$;

DO $$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'plugin_webhook_subscriptions', 'plugin_webhook_secret_versions',
        'plugin_webhook_write_requests', 'plugin_webhook_events',
        'plugin_webhook_deliveries', 'plugin_webhook_outbox',
        'plugin_webhook_delivery_attempts', 'plugin_webhook_dead_letters',
        'plugin_webhook_rate_events', 'plugin_webhook_rbac_catalog_additions_084',
        'plugin_webhook_rbac_grant_additions_084',
        'plugin_webhook_entitlement_decisions',
        'control_entitlement_revocation_lkg', 'control_entitlement_revoked_serials',
        'entitlement_signing_keyset_current_keys',
        'plugin_webhook_runtime_attestation_keys',
        'plugin_webhook_runtime_attestation_head'
    ] LOOP
        EXECUTE format('REVOKE ALL ON TABLE %I FROM PUBLIC', table_name);
    END LOOP;
END;
$$;

REVOKE ALL ON FUNCTION project_plugin_webhook_system_role_permissions_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_mod_084(numeric, numeric) FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_le_numeric_084(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_mod_pow_084(numeric, numeric, numeric) FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_ed25519_decode_084(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_ed25519_add_084(numeric[], numeric[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_ed25519_double_084(numeric[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_ed25519_scalarmult_084(numeric[], numeric) FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_ed25519_prime_order_point_084(numeric[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_ed25519_verify_084(bytea, bytea, bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_u32be_084(integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_attestation_frame_084(bytea[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_outbox_attestation_sha256_084(
    numeric, text, text, uuid, uuid, uuid, uuid, uuid, uuid, numeric, text, numeric,
    text, numeric, text, bytea, numeric
) FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_dead_letter_attestation_sha256_084(
    numeric, text, text, uuid, uuid, uuid, uuid, uuid, uuid, text, numeric, numeric,
    numeric, text, numeric, text, numeric, text, bytea, bytea, numeric
) FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_plugin_webhook_runtime_attestation_key_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_plugin_webhook_runtime_attestation_head_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_plugin_webhook_runtime_attestation_head_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_plugin_webhook_runtime_attestation_truncate_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_canonical_u64_token_084(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_control_entitlement_revocation_lkg_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_control_entitlement_revocation_serial_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION assert_control_entitlement_revocation_serial_projection_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_control_entitlement_revocation_truncate_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_control_entitlement_cached_lease_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_plugin_webhook_rbac_provenance_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_plugin_webhook_catalog_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_plugin_webhook_custom_role_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_u64_084(numeric) FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_text_valid_084(text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_target_host_valid_084(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_target_path_valid_084(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_secret_aad_sha256_084(uuid, uuid, uuid, numeric, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_receipt_aad_sha256_084(uuid, uuid, uuid, text, text, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_sanitized_headers_valid_084(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION stamp_plugin_webhook_xact_id_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_plugin_webhook_physical_cleanup_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION read_plugin_webhook_secret_envelope_084(uuid, uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION read_plugin_webhook_receipt_envelope_084(uuid, uuid, uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_canonical_body_084(uuid, uuid, text, text, timestamptz, text, text, numeric, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_plugin_webhook_event_body_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_plugin_webhook_actor_target_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_plugin_webhook_truncate_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_plugin_webhook_subscription_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_plugin_webhook_subscription_quota_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_plugin_webhook_secret_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION apply_plugin_webhook_secret_expiry_fence_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_plugin_webhook_secret_insert_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_plugin_webhook_active_secret_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_plugin_webhook_write_request_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION record_plugin_webhook_entitlement_decision_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_plugin_webhook_entitlement_decision_mutation_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_plugin_webhook_entitlement_decision_truncate_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_plugin_webhook_append_mutation_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION advance_plugin_webhook_event_sequence_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_plugin_webhook_delivery_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_plugin_webhook_replay_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_plugin_webhook_outbox_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION publish_plugin_webhook_outbox_084(
    uuid, uuid, uuid, uuid, text, text, numeric, text, numeric, text, bytea, numeric,
    numeric, text, bytea
) FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_plugin_webhook_delivery_outbox_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_retry_delay_seconds_084(uuid, numeric, timestamptz, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION claim_plugin_webhook_attempt_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_plugin_webhook_attempt_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION project_plugin_webhook_attempt_outcome_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_plugin_webhook_delivery_attempt_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_plugin_webhook_subscription_sequence_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION apply_plugin_webhook_revoke_fence_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_dead_letter_payload_sha256_084(uuid, uuid, uuid, uuid, numeric, text, integer, bytea, bytea, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_plugin_webhook_dead_letter_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION transition_plugin_webhook_dead_letter_reconcile_084(
    uuid, uuid, uuid, uuid, text, numeric, numeric, numeric, numeric,
    uuid, text, numeric, numeric, numeric, numeric
) FROM PUBLIC;
REVOKE ALL ON FUNCTION acknowledge_plugin_webhook_dead_letter_084(
    uuid, uuid, uuid, uuid, text, numeric, numeric, numeric, numeric,
    text, text, numeric, text, numeric, text, bytea, bytea, numeric, numeric, text, bytea
) FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_plugin_webhook_dead_letter_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION project_plugin_webhook_dead_letter_ack_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_plugin_webhook_audit_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_plugin_webhook_command_facts_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_plugin_webhook_event_command_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_plugin_webhook_secret_command_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_plugin_webhook_write_request_result_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_plugin_webhook_entitlement_decision_084() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_plugin_webhook_rate_084() FROM PUBLIC;

DO $$
DECLARE
    table_name text;
    procedure_name text;
    column_list text;
BEGIN
    EXECUTE format(
        'GRANT USAGE ON SCHEMA %I TO cdnca_control_app,cdnca_plugin_webhook_runtime',
        current_schema()
    );
    FOREACH table_name IN ARRAY ARRAY[
        'plugin_webhook_subscriptions', 'plugin_webhook_events',
        'plugin_webhook_deliveries', 'plugin_webhook_outbox',
        'plugin_webhook_delivery_attempts', 'plugin_webhook_dead_letters',
        'plugin_webhook_rate_events', 'plugin_webhook_rbac_catalog_additions_084',
        'plugin_webhook_rbac_grant_additions_084', 'plugin_webhook_entitlement_decisions',
        'control_entitlement_revocation_lkg', 'control_entitlement_revoked_serials',
        'entitlement_signing_keyset_current_keys',
        'plugin_webhook_runtime_attestation_keys',
        'plugin_webhook_runtime_attestation_head'
    ] LOOP
        EXECUTE format(
            'GRANT SELECT ON TABLE %I TO cdnca_control_app,cdnca_plugin_webhook_runtime',
            table_name
        );
    END LOOP;
    SELECT string_agg(format('%I', attribute.attname), ',' ORDER BY attribute.attnum)
      INTO column_list
    FROM pg_attribute attribute
    WHERE attribute.attrelid = format('%I.%I', current_schema(),
                                      'plugin_webhook_secret_versions')::regclass
      AND attribute.attnum > 0 AND NOT attribute.attisdropped
      AND attribute.attname NOT IN ('nonce', 'ciphertext');
    EXECUTE format(
        'GRANT SELECT (%s) ON TABLE %I TO cdnca_control_app,cdnca_plugin_webhook_runtime',
        column_list, 'plugin_webhook_secret_versions'
    );
    SELECT string_agg(format('%I', attribute.attname), ',' ORDER BY attribute.attnum)
      INTO column_list
    FROM pg_attribute attribute
    WHERE attribute.attrelid = format('%I.%I', current_schema(),
                                      'plugin_webhook_write_requests')::regclass
      AND attribute.attnum > 0 AND NOT attribute.attisdropped
      AND attribute.attname NOT IN ('receipt_nonce', 'receipt_ciphertext');
    EXECUTE format(
        'GRANT SELECT (%s) ON TABLE %I TO cdnca_control_app,cdnca_plugin_webhook_runtime',
        column_list, 'plugin_webhook_write_requests'
    );
    GRANT INSERT, UPDATE ON TABLE plugin_webhook_subscriptions,
        plugin_webhook_secret_versions, plugin_webhook_write_requests,
        plugin_webhook_deliveries, plugin_webhook_outbox
        TO cdnca_control_app;
    GRANT INSERT ON TABLE plugin_webhook_events, plugin_webhook_rate_events,
        plugin_webhook_entitlement_decisions TO cdnca_control_app;
    GRANT UPDATE ON TABLE plugin_webhook_subscriptions, plugin_webhook_deliveries,
        plugin_webhook_outbox, plugin_webhook_delivery_attempts
        TO cdnca_plugin_webhook_runtime;
    GRANT UPDATE ON TABLE plugin_webhook_delivery_attempts TO cdnca_control_app;
    GRANT INSERT ON TABLE plugin_webhook_delivery_attempts, plugin_webhook_dead_letters
        TO cdnca_plugin_webhook_runtime;
    FOR procedure_name IN
        SELECT procedure.oid::regprocedure::text
        FROM pg_proc procedure
        WHERE procedure.pronamespace = current_schema()::regnamespace
          AND procedure.proname LIKE '%\_084' ESCAPE '\'
    LOOP
        EXECUTE format(
            'GRANT EXECUTE ON FUNCTION %s TO cdnca_control_app,cdnca_plugin_webhook_runtime',
            procedure_name
        );
    END LOOP;
    REVOKE EXECUTE ON FUNCTION publish_plugin_webhook_outbox_084(
        uuid, uuid, uuid, uuid, text, text, numeric, text, numeric, text, bytea, numeric,
        numeric, text, bytea
    ) FROM cdnca_control_app;
    REVOKE EXECUTE ON FUNCTION transition_plugin_webhook_dead_letter_reconcile_084(
        uuid, uuid, uuid, uuid, text, numeric, numeric, numeric, numeric,
        uuid, text, numeric, numeric, numeric, numeric
    ) FROM cdnca_control_app;
    REVOKE EXECUTE ON FUNCTION acknowledge_plugin_webhook_dead_letter_084(
        uuid, uuid, uuid, uuid, text, numeric, numeric, numeric, numeric,
        text, text, numeric, text, numeric, text, bytea, bytea, numeric, numeric, text, bytea
    ) FROM cdnca_control_app;
    REVOKE EXECUTE ON FUNCTION read_plugin_webhook_secret_envelope_084(uuid, uuid, uuid)
        FROM cdnca_control_app;
    REVOKE EXECUTE ON FUNCTION read_plugin_webhook_receipt_envelope_084(
        uuid, uuid, uuid, text
    ) FROM cdnca_plugin_webhook_runtime;
END;
$$;
