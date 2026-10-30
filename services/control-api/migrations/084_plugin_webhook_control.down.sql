DO $$
DECLARE
    required_tables text[] := ARRAY[
        'schema_migrations',
        'access_scopes',
        'audit_events',
        'tenants',
        'memberships',
        'users',
        'roles',
        'role_permissions',
        'role_assignments',
        'permissions',
        'custom_rbac_permission_catalog',
        'custom_roles',
        'custom_role_revisions',
        'custom_role_grants',
        'custom_role_grant_revocations',
        'plugin_webhook_rbac_catalog_additions_084',
        'plugin_webhook_rbac_grant_additions_084',
        'plugin_webhook_subscriptions',
        'plugin_webhook_secret_versions',
        'plugin_webhook_write_requests',
        'plugin_webhook_events',
        'plugin_webhook_deliveries',
        'plugin_webhook_outbox',
        'plugin_webhook_delivery_attempts',
        'plugin_webhook_dead_letters',
        'plugin_webhook_rate_events',
        'plugin_webhook_entitlement_decisions',
        'control_entitlement_revocation_lkg',
        'control_entitlement_revoked_serials',
        'entitlement_signing_keyset_current_keys',
        'plugin_webhook_runtime_attestation_keys',
        'plugin_webhook_runtime_attestation_head',
        'control_installation_entitlement',
        'entitlement_cached_leases'
    ];
    control_role oid := to_regrole('cdnca_control_app');
    runtime_role oid := to_regrole('cdnca_plugin_webhook_runtime');
BEGIN
    IF EXISTS (
        SELECT 1
        FROM unnest(required_tables) AS expected(table_name)
        LEFT JOIN pg_class relation
          ON relation.oid = to_regclass(format('%I.%I', current_schema(), expected.table_name))
        WHERE relation.oid IS NULL
           OR relation.relnamespace <> current_schema()::regnamespace
           OR relation.relkind <> 'r'
    ) THEN
        RAISE EXCEPTION 'migration 084 rollback required table is missing'
            USING ERRCODE = 'P8401';
    END IF;
    IF control_role IS NULL OR runtime_role IS NULL OR
       current_user::regrole IN (control_role, runtime_role) OR
       (SELECT nspowner FROM pg_namespace
        WHERE oid = current_schema()::regnamespace) <> current_user::regrole OR EXISTS (
        SELECT 1 FROM pg_roles role
        WHERE role.oid IN (control_role, runtime_role) AND (
            role.rolcanlogin OR role.rolsuper OR role.rolcreatedb OR role.rolcreaterole OR
            role.rolreplication OR role.rolbypassrls
        )
    ) OR has_schema_privilege(control_role, current_schema(), 'CREATE') OR
       has_schema_privilege(runtime_role, current_schema(), 'CREATE') OR
       has_database_privilege(control_role, current_database(), 'CREATE') OR
       has_database_privilege(runtime_role, current_database(), 'CREATE') OR
       pg_has_role(control_role, runtime_role, 'MEMBER') OR
       pg_has_role(runtime_role, control_role, 'MEMBER') OR
       (SELECT count(*)
        FROM pg_namespace namespace
        CROSS JOIN LATERAL aclexplode(namespace.nspacl) acl
        WHERE namespace.oid = current_schema()::regnamespace) <> 4 OR EXISTS (
        SELECT 1
        FROM pg_namespace namespace
        CROSS JOIN LATERAL aclexplode(namespace.nspacl) acl
        WHERE namespace.oid = current_schema()::regnamespace
          AND (acl.grantor <> current_user::regrole OR acl.is_grantable OR NOT (
              (acl.grantee = current_user::regrole AND
               acl.privilege_type IN ('CREATE', 'USAGE')) OR
              (acl.grantee IN (control_role, runtime_role) AND
               acl.privilege_type = 'USAGE')
          ))
    ) THEN
        RAISE EXCEPTION 'migration 084 rollback database role or schema ACL drift'
            USING ERRCODE = 'P8401';
    END IF;
END;
$$;

LOCK TABLE schema_migrations,
    access_scopes,
    audit_events,
    tenants,
    memberships,
    users,
    roles,
    role_permissions,
    role_assignments,
    permissions,
    custom_rbac_permission_catalog,
    custom_roles,
    custom_role_revisions,
    custom_role_grants,
    custom_role_grant_revocations,
    plugin_webhook_rbac_catalog_additions_084,
    plugin_webhook_rbac_grant_additions_084,
    plugin_webhook_subscriptions,
    plugin_webhook_secret_versions,
    plugin_webhook_write_requests,
    plugin_webhook_events,
    plugin_webhook_deliveries,
    plugin_webhook_outbox,
    plugin_webhook_delivery_attempts,
    plugin_webhook_dead_letters,
    plugin_webhook_rate_events,
    plugin_webhook_entitlement_decisions,
    control_entitlement_revocation_lkg,
    control_entitlement_revoked_serials,
    entitlement_signing_keyset_current_keys,
    plugin_webhook_runtime_attestation_keys,
    plugin_webhook_runtime_attestation_head,
    control_installation_entitlement,
    entitlement_cached_leases
IN ACCESS EXCLUSIVE MODE;

DO $$
DECLARE
    catalog_hash text;
    catalog_counts integer[];
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 84 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 84 THEN
        RAISE EXCEPTION 'plugin webhook rollback requires frozen migration head 084'
            USING ERRCODE = 'P8401';
    END IF;
    PERFORM set_config(
        'search_path',
        quote_ident(current_schema()) || ',pg_catalog',
        true
    );
    WITH
    owned_names(relation_name) AS (VALUES
        ('entitlement_signing_keyset_current_keys'),
        ('control_entitlement_revocation_lkg'),
        ('control_entitlement_revoked_serials'),
        ('plugin_webhook_rbac_catalog_additions_084'),
        ('plugin_webhook_rbac_grant_additions_084'),
        ('plugin_webhook_subscriptions'),
        ('plugin_webhook_secret_versions'),
        ('plugin_webhook_write_requests'),
        ('plugin_webhook_entitlement_decisions'),
        ('plugin_webhook_events'),
        ('plugin_webhook_deliveries'),
        ('plugin_webhook_outbox'),
        ('plugin_webhook_delivery_attempts'),
        ('plugin_webhook_dead_letters'),
        ('plugin_webhook_rate_events'),
        ('plugin_webhook_runtime_attestation_keys'),
        ('plugin_webhook_runtime_attestation_head')
    ),
    base_triggers(relation_name, trigger_name) AS (VALUES
        ('audit_events', 'audit_events_plugin_webhook_xact_084'),
        ('entitlement_cached_leases', 'entitlement_cached_leases_revocation_guard_084'),
        ('role_assignments', 'role_assignments_plugin_webhook_guard_084'),
        ('custom_role_grants', 'custom_role_grants_plugin_webhook_guard_084'),
        ('custom_role_revisions', 'custom_role_revisions_plugin_webhook_guard_084'),
        ('roles', 'roles_project_plugin_webhook_permissions_084'),
        ('custom_rbac_permission_catalog', 'plugin_webhook_rbac_catalog_delete_guard_084'),
        ('role_permissions', 'role_permissions_system_role_guard')
    ),
    owned_relations AS (
        SELECT relation.*
        FROM owned_names expected
        JOIN pg_class relation
          ON relation.relnamespace = current_schema()::regnamespace
         AND relation.relname = expected.relation_name
    ),
    function_objects AS (
        SELECT procedure.*, language.lanname
        FROM pg_proc procedure
        JOIN pg_language language ON language.oid = procedure.prolang
        WHERE procedure.pronamespace = current_schema()::regnamespace
          AND (
              procedure.proname LIKE '%\_084' ESCAPE '\'
              OR procedure.oid IN (
                  to_regprocedure('custom_rbac_effective_permissions(uuid,uuid)'),
                  to_regprocedure('guard_system_role_permission_mutation()')
              )
          )
    ),
    function_manifest AS (
        SELECT
            'function'::text AS object_kind,
            format('@schema.%I(%s)', procedure.proname,
                pg_get_function_identity_arguments(procedure.oid)) AS object_identity,
            jsonb_build_object(
                'definition', replace(
                    pg_get_functiondef(procedure.oid), current_schema(), '@schema'
                ),
                'owner', CASE WHEN procedure.proowner = current_user::regrole
                    THEN '@owner' ELSE pg_get_userbyid(procedure.proowner) END,
                'acl_is_null', procedure.proacl IS NULL,
                'acl', (
                    SELECT COALESCE(jsonb_agg(jsonb_build_object(
                        'grantor', CASE WHEN acl.grantor = current_user::regrole
                            THEN '@owner' ELSE pg_get_userbyid(acl.grantor) END,
                        'grantee', CASE WHEN acl.grantee = 0 THEN 'PUBLIC'
                            WHEN acl.grantee = current_user::regrole THEN '@owner'
                            ELSE pg_get_userbyid(acl.grantee) END,
                        'privilege', acl.privilege_type,
                        'grantable', acl.is_grantable
                    ) ORDER BY acl.grantor, acl.grantee, acl.privilege_type,
                        acl.is_grantable), '[]'::jsonb)
                    FROM aclexplode(COALESCE(procedure.proacl,
                        acldefault('f', procedure.proowner))) acl
                ),
                'language', procedure.lanname,
                'kind', procedure.prokind,
                'volatile', procedure.provolatile,
                'parallel', procedure.proparallel,
                'strict', procedure.proisstrict,
                'security_definer', procedure.prosecdef,
                'leakproof', procedure.proleakproof,
                'returns_set', procedure.proretset,
                'cost', procedure.procost,
                'rows', procedure.prorows,
                'support', CASE
                    WHEN procedure.prosupport = 0 THEN NULL
                    ELSE procedure.prosupport::regprocedure::text
                END,
                'config', CASE WHEN procedure.proconfig IS NULL THEN NULL ELSE (
                    SELECT jsonb_agg(replace(setting, current_schema(), '@schema') ORDER BY ordinal)
                    FROM unnest(procedure.proconfig) WITH ORDINALITY config(setting, ordinal)
                ) END,
                'binary', procedure.probin,
                'transform_types', CASE WHEN procedure.protrftypes IS NULL THEN NULL ELSE (
                    SELECT jsonb_agg(format_type(transform_type, NULL) ORDER BY ordinal)
                    FROM unnest(procedure.protrftypes) WITH ORDINALITY
                        transform(transform_type, ordinal)
                ) END,
                'sql_body', procedure.prosqlbody::text,
                'comment', obj_description(procedure.oid, 'pg_proc'),
                'dependencies', (
                    SELECT COALESCE(jsonb_agg(
                        jsonb_build_object(
                            'type', dependency.deptype,
                            'reference', CASE WHEN
                                dependency.refclassid = 'pg_namespace'::regclass AND
                                dependency.refobjid = current_schema()::regnamespace
                            THEN 'schema @schema' ELSE replace(pg_describe_object(
                                dependency.refclassid,
                                dependency.refobjid,
                                dependency.refobjsubid
                            ), current_schema() || '.', '@schema.') END
                        )
                        ORDER BY dependency.deptype,
                            CASE WHEN dependency.refclassid = 'pg_namespace'::regclass AND
                                dependency.refobjid = current_schema()::regnamespace
                            THEN 'schema @schema' ELSE replace(pg_describe_object(
                                dependency.refclassid,
                                dependency.refobjid,
                                dependency.refobjsubid
                            ), current_schema() || '.', '@schema.') END
                    ), '[]'::jsonb)
                    FROM pg_depend dependency
                    WHERE dependency.classid = 'pg_proc'::regclass
                      AND dependency.objid = procedure.oid
                      AND dependency.objsubid = 0
                )
            )::text AS object_payload
        FROM function_objects procedure
    ),
    trigger_objects AS (
        SELECT trigger_row.*, relation.relname, namespace.nspname
        FROM pg_trigger trigger_row
        JOIN pg_class relation ON relation.oid = trigger_row.tgrelid
        JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
        WHERE NOT trigger_row.tgisinternal
          AND relation.relnamespace = current_schema()::regnamespace
          AND (
              EXISTS (
                  SELECT 1 FROM owned_relations owned
                  WHERE owned.oid = relation.oid
              )
              OR EXISTS (
                  SELECT 1 FROM base_triggers expected
                  WHERE expected.relation_name = relation.relname
                    AND expected.trigger_name = trigger_row.tgname
              )
          )
    ),
    trigger_manifest AS (
        SELECT
            'trigger'::text AS object_kind,
            format('@schema.%I/%I', trigger_row.relname, trigger_row.tgname)
                AS object_identity,
            jsonb_build_object(
                'definition', replace(replace(
                    pg_get_triggerdef(trigger_row.oid, false),
                    format(' ON %I.', current_schema()), ' ON @schema.'
                ), format(' FUNCTION %I.', current_schema()), ' FUNCTION @schema.'),
                'enabled', trigger_row.tgenabled,
                'type', trigger_row.tgtype,
                'attributes', trigger_row.tgattr::text,
                'arguments', encode(trigger_row.tgargs, 'hex'),
                'old_table', trigger_row.tgoldtable,
                'new_table', trigger_row.tgnewtable,
                'deferrable', trigger_row.tgdeferrable,
                'initially_deferred', trigger_row.tginitdeferred,
                'comment', obj_description(trigger_row.oid, 'pg_trigger'),
                'dependencies', (
                    SELECT COALESCE(jsonb_agg(
                        jsonb_build_object(
                            'type', dependency.deptype,
                            'reference', CASE WHEN
                                dependency.refclassid = 'pg_namespace'::regclass AND
                                dependency.refobjid = current_schema()::regnamespace
                            THEN 'schema @schema' ELSE replace(pg_describe_object(
                                dependency.refclassid,
                                dependency.refobjid,
                                dependency.refobjsubid
                            ), current_schema() || '.', '@schema.') END
                        )
                        ORDER BY dependency.deptype,
                            CASE WHEN dependency.refclassid = 'pg_namespace'::regclass AND
                                dependency.refobjid = current_schema()::regnamespace
                            THEN 'schema @schema' ELSE replace(pg_describe_object(
                                dependency.refclassid,
                                dependency.refobjid,
                                dependency.refobjsubid
                            ), current_schema() || '.', '@schema.') END
                    ), '[]'::jsonb)
                    FROM pg_depend dependency
                    WHERE dependency.classid = 'pg_trigger'::regclass
                      AND dependency.objid = trigger_row.oid
                      AND dependency.objsubid = 0
                )
            )::text AS object_payload
        FROM trigger_objects trigger_row
    ),
    table_manifest AS (
        SELECT
            'table'::text AS object_kind,
            format('@schema.%I', relation.relname) AS object_identity,
            jsonb_build_object(
                'kind', relation.relkind,
                'persistence', relation.relpersistence,
                'owner', CASE WHEN relation.relowner = current_user::regrole
                    THEN '@owner' ELSE pg_get_userbyid(relation.relowner) END,
                'acl_is_null', relation.relacl IS NULL,
                'acl', (
                    SELECT COALESCE(jsonb_agg(jsonb_build_object(
                        'grantor', CASE WHEN acl.grantor = current_user::regrole
                            THEN '@owner' ELSE pg_get_userbyid(acl.grantor) END,
                        'grantee', CASE WHEN acl.grantee = 0 THEN 'PUBLIC'
                            WHEN acl.grantee = current_user::regrole THEN '@owner'
                            ELSE pg_get_userbyid(acl.grantee) END,
                        'privilege', acl.privilege_type,
                        'grantable', acl.is_grantable
                    ) ORDER BY acl.grantor, acl.grantee, acl.privilege_type,
                        acl.is_grantable), '[]'::jsonb)
                    FROM aclexplode(COALESCE(relation.relacl,
                        acldefault('r', relation.relowner))) acl
                ),
                'access_method', access_method.amname,
                'tablespace', tablespace.spcname,
                'options', relation.reloptions,
                'replica_identity', relation.relreplident,
                'row_security', relation.relrowsecurity,
                'force_row_security', relation.relforcerowsecurity,
                'attribute_count', relation.relnatts,
                'check_count', relation.relchecks,
                'has_index', relation.relhasindex,
                'has_rules', relation.relhasrules,
                'has_triggers', relation.relhastriggers,
                'is_populated', relation.relispopulated,
                'of_type', CASE WHEN relation.reloftype = 0 THEN NULL
                    ELSE format_type(relation.reloftype, NULL) END,
                'is_partition', relation.relispartition,
                'partition_key', pg_get_partkeydef(relation.oid),
                'partition_bound', pg_get_expr(
                    relation.relpartbound, relation.oid, false
                ),
                'comment', obj_description(relation.oid, 'pg_class'),
                'dependencies', (
                    SELECT COALESCE(jsonb_agg(
                        jsonb_build_object(
                            'type', dependency.deptype,
                            'reference', CASE WHEN
                                dependency.refclassid = 'pg_namespace'::regclass AND
                                dependency.refobjid = current_schema()::regnamespace
                            THEN 'schema @schema' ELSE replace(pg_describe_object(
                                dependency.refclassid,
                                dependency.refobjid,
                                dependency.refobjsubid
                            ), current_schema() || '.', '@schema.') END
                        )
                        ORDER BY dependency.deptype,
                            CASE WHEN dependency.refclassid = 'pg_namespace'::regclass AND
                                dependency.refobjid = current_schema()::regnamespace
                            THEN 'schema @schema' ELSE replace(pg_describe_object(
                                dependency.refclassid,
                                dependency.refobjid,
                                dependency.refobjsubid
                            ), current_schema() || '.', '@schema.') END
                    ), '[]'::jsonb)
                    FROM pg_depend dependency
                    WHERE dependency.classid = 'pg_class'::regclass
                      AND dependency.objid = relation.oid
                      AND dependency.objsubid = 0
                )
            )::text AS object_payload
        FROM owned_relations relation
        JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
        LEFT JOIN pg_am access_method ON access_method.oid = relation.relam
        LEFT JOIN pg_tablespace tablespace ON tablespace.oid = relation.reltablespace
    ),
    type_objects AS (
        SELECT composite.*
        FROM pg_type composite
        JOIN owned_relations relation ON relation.oid = composite.typrelid
        UNION
        SELECT array_type.*
        FROM pg_type composite
        JOIN owned_relations relation ON relation.oid = composite.typrelid
        JOIN pg_type array_type ON array_type.oid = composite.typarray
    ),
    type_manifest AS (
        SELECT
            'type'::text AS object_kind,
            format('@schema.%I', type_row.typname) AS object_identity,
            jsonb_build_object(
                'kind', type_row.typtype,
                'category', type_row.typcategory,
                'preferred', type_row.typispreferred,
                'defined', type_row.typisdefined,
                'delimiter', type_row.typdelim,
                'owner', CASE WHEN type_row.typowner = current_user::regrole
                    THEN '@owner' ELSE pg_get_userbyid(type_row.typowner) END,
                'acl_is_null', type_row.typacl IS NULL,
                'acl', (
                    SELECT COALESCE(jsonb_agg(jsonb_build_object(
                        'grantor', CASE WHEN acl.grantor = current_user::regrole
                            THEN '@owner' ELSE pg_get_userbyid(acl.grantor) END,
                        'grantee', CASE WHEN acl.grantee = 0 THEN 'PUBLIC'
                            WHEN acl.grantee = current_user::regrole THEN '@owner'
                            ELSE pg_get_userbyid(acl.grantee) END,
                        'privilege', acl.privilege_type,
                        'grantable', acl.is_grantable
                    ) ORDER BY acl.grantor, acl.grantee, acl.privilege_type,
                        acl.is_grantable), '[]'::jsonb)
                    FROM aclexplode(COALESCE(type_row.typacl,
                        acldefault('T', type_row.typowner))) acl
                ),
                'relation', CASE WHEN type_row.typrelid = 0 THEN NULL
                    ELSE type_row.typrelid::regclass::text END,
                'element', CASE WHEN type_row.typelem = 0 THEN NULL
                    ELSE format_type(type_row.typelem, NULL) END,
                'array', CASE WHEN type_row.typarray = 0 THEN NULL
                    ELSE format_type(type_row.typarray, NULL) END,
                'base', CASE WHEN type_row.typbasetype = 0 THEN NULL
                    ELSE format_type(type_row.typbasetype, type_row.typtypmod) END,
                'not_null', type_row.typnotnull,
                'alignment', type_row.typalign,
                'storage', type_row.typstorage,
                'length', type_row.typlen,
                'by_value', type_row.typbyval,
                'collation', CASE WHEN type_row.typcollation = 0 THEN NULL
                    ELSE type_row.typcollation::regcollation::text END,
                'input', type_row.typinput::regprocedure::text,
                'output', type_row.typoutput::regprocedure::text,
                'receive', type_row.typreceive::regprocedure::text,
                'send', type_row.typsend::regprocedure::text,
                'modifier_in', type_row.typmodin::regprocedure::text,
                'modifier_out', type_row.typmodout::regprocedure::text,
                'analyze', type_row.typanalyze::regprocedure::text,
                'subscript', type_row.typsubscript::regprocedure::text,
                'default', type_row.typdefault,
                'default_binary', type_row.typdefaultbin,
                'comment', obj_description(type_row.oid, 'pg_type'),
                'dependencies', (
                    SELECT COALESCE(jsonb_agg(jsonb_build_object(
                        'type', dependency.deptype,
                        'reference', replace(pg_describe_object(dependency.refclassid,
                            dependency.refobjid, dependency.refobjsubid),
                            current_schema() || '.', '@schema.')
                    ) ORDER BY dependency.deptype,
                        replace(pg_describe_object(dependency.refclassid,
                            dependency.refobjid, dependency.refobjsubid),
                            current_schema() || '.', '@schema.')), '[]'::jsonb)
                    FROM pg_depend dependency
                    WHERE dependency.classid = 'pg_type'::regclass
                      AND dependency.objid = type_row.oid
                      AND dependency.objsubid = 0
                )
            )::text AS object_payload
        FROM type_objects type_row
        JOIN pg_namespace namespace ON namespace.oid = type_row.typnamespace
    ),
    policy_relations AS (
        SELECT * FROM owned_relations
        UNION ALL
        SELECT relation.* FROM pg_class relation
        WHERE relation.oid = 'audit_events'::regclass
    ),
    policy_manifest AS (
        SELECT
            'policy'::text AS object_kind,
            format('@schema.%I/%I', relation.relname, policy.polname)
                AS object_identity,
            jsonb_build_object(
                'command', policy.polcmd,
                'permissive', policy.polpermissive,
                'roles', (
                    SELECT jsonb_agg(CASE WHEN role_oid = 0 THEN 'PUBLIC'
                        WHEN role_oid = current_user::regrole THEN '@owner'
                        ELSE pg_get_userbyid(role_oid) END ORDER BY
                        CASE WHEN role_oid = 0 THEN 'PUBLIC'
                            WHEN role_oid = current_user::regrole THEN '@owner'
                            ELSE pg_get_userbyid(role_oid) END)
                    FROM unnest(policy.polroles) role(role_oid)
                ),
                'using', pg_get_expr(policy.polqual, policy.polrelid, false),
                'with_check', pg_get_expr(policy.polwithcheck, policy.polrelid, false),
                'comment', obj_description(policy.oid, 'pg_policy'),
                'dependencies', (
                    SELECT COALESCE(jsonb_agg(jsonb_build_object(
                        'type', dependency.deptype,
                        'reference', replace(pg_describe_object(dependency.refclassid,
                            dependency.refobjid, dependency.refobjsubid),
                            current_schema() || '.', '@schema.')
                    ) ORDER BY dependency.deptype,
                        replace(pg_describe_object(dependency.refclassid,
                            dependency.refobjid, dependency.refobjsubid),
                            current_schema() || '.', '@schema.')), '[]'::jsonb)
                    FROM pg_depend dependency
                    WHERE dependency.classid = 'pg_policy'::regclass
                      AND dependency.objid = policy.oid
                      AND dependency.objsubid = 0
                )
            )::text AS object_payload
        FROM pg_policy policy
        JOIN policy_relations relation ON relation.oid = policy.polrelid
        JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    ),
    rule_manifest AS (
        SELECT
            'rule'::text AS object_kind,
            format('@schema.%I/%I', relation.relname, rewrite.rulename)
                AS object_identity,
            jsonb_build_object(
                'definition', pg_get_ruledef(rewrite.oid, false),
                'event', rewrite.ev_type,
                'enabled', rewrite.ev_enabled,
                'instead', rewrite.is_instead,
                'comment', obj_description(rewrite.oid, 'pg_rewrite'),
                'dependencies', (
                    SELECT COALESCE(jsonb_agg(jsonb_build_object(
                        'type', dependency.deptype,
                        'reference', replace(pg_describe_object(dependency.refclassid,
                            dependency.refobjid, dependency.refobjsubid),
                            current_schema() || '.', '@schema.')
                    ) ORDER BY dependency.deptype,
                        replace(pg_describe_object(dependency.refclassid,
                            dependency.refobjid, dependency.refobjsubid),
                            current_schema() || '.', '@schema.')), '[]'::jsonb)
                    FROM pg_depend dependency
                    WHERE dependency.classid = 'pg_rewrite'::regclass
                      AND dependency.objid = rewrite.oid
                      AND dependency.objsubid = 0
                )
            )::text AS object_payload
        FROM pg_rewrite rewrite
        JOIN policy_relations relation ON relation.oid = rewrite.ev_class
        JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
        WHERE rewrite.rulename <> '_RETURN'
    ),
    column_objects AS (
        SELECT relation.oid AS relation_oid, relation.relname,
            namespace.nspname, attribute.*
        FROM owned_relations relation
        JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
        JOIN pg_attribute attribute ON attribute.attrelid = relation.oid
        WHERE attribute.attnum > 0
        UNION ALL
        SELECT relation.oid, relation.relname, namespace.nspname, attribute.*
        FROM pg_class relation
        JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
        JOIN pg_attribute attribute ON attribute.attrelid = relation.oid
        WHERE relation.oid = 'audit_events'::regclass
          AND attribute.attname IN (
              'plugin_webhook_xact_id',
              'plugin_webhook_recorded_at'
          )
          AND attribute.attnum > 0
    ),
    column_manifest AS (
        SELECT
            'column'::text AS object_kind,
            format('@schema.%I.%I', column_row.relname, column_row.attname)
                AS object_identity,
            jsonb_build_object(
                'number', column_row.attnum,
                'dropped', column_row.attisdropped,
                'type', CASE
                    WHEN column_row.attisdropped THEN NULL
                    ELSE format_type(column_row.atttypid, column_row.atttypmod)
                END,
                'dimensions', column_row.attndims,
                'not_null', column_row.attnotnull,
                'identity', column_row.attidentity,
                'generated', column_row.attgenerated,
                'storage', column_row.attstorage,
                'compression', column_row.attcompression,
                'collation', CASE
                    WHEN column_row.attcollation = 0 THEN NULL
                    ELSE column_row.attcollation::regcollation::text
                END,
                'statistics_target', column_row.attstattarget,
                'options', column_row.attoptions,
                'fdw_options', column_row.attfdwoptions,
                'acl_is_null', column_row.attacl IS NULL,
                'acl', (
                    SELECT COALESCE(jsonb_agg(jsonb_build_object(
                        'grantor', CASE WHEN acl.grantor = current_user::regrole
                            THEN '@owner' ELSE pg_get_userbyid(acl.grantor) END,
                        'grantee', CASE WHEN acl.grantee = 0 THEN 'PUBLIC'
                            WHEN acl.grantee = current_user::regrole THEN '@owner'
                            ELSE pg_get_userbyid(acl.grantee) END,
                        'privilege', acl.privilege_type,
                        'grantable', acl.is_grantable
                    ) ORDER BY acl.grantor, acl.grantee, acl.privilege_type,
                        acl.is_grantable), '[]'::jsonb)
                    FROM aclexplode(column_row.attacl) acl
                ),
                'has_default', column_row.atthasdef,
                'default', (
                    SELECT pg_get_expr(default_row.adbin, default_row.adrelid, false)
                    FROM pg_attrdef default_row
                    WHERE default_row.adrelid = column_row.relation_oid
                      AND default_row.adnum = column_row.attnum
                ),
                'has_missing', column_row.atthasmissing,
                'missing_value', column_row.attmissingval::text,
                'comment', col_description(
                    column_row.relation_oid, column_row.attnum
                ),
                'dependencies', (
                    SELECT COALESCE(jsonb_agg(
                        jsonb_build_object(
                            'type', dependency.deptype,
                            'reference', replace(pg_describe_object(
                                dependency.refclassid,
                                dependency.refobjid,
                                dependency.refobjsubid
                            ), current_schema() || '.', '@schema.')
                        )
                        ORDER BY dependency.deptype,
                            replace(pg_describe_object(
                                dependency.refclassid,
                                dependency.refobjid,
                                dependency.refobjsubid
                            ), current_schema() || '.', '@schema.')
                    ), '[]'::jsonb)
                    FROM pg_depend dependency
                    WHERE dependency.classid = 'pg_class'::regclass
                      AND dependency.objid = column_row.relation_oid
                      AND dependency.objsubid = column_row.attnum
                )
            )::text AS object_payload
        FROM column_objects column_row
    ),
    constraint_manifest AS (
        SELECT
            'constraint'::text AS object_kind,
            format('@schema.%I/%I', relation.relname, constraint_row.conname)
                AS object_identity,
            jsonb_build_object(
                'definition', pg_get_constraintdef(constraint_row.oid, false),
                'type', constraint_row.contype,
                'deferrable', constraint_row.condeferrable,
                'initially_deferred', constraint_row.condeferred,
                'validated', constraint_row.convalidated,
                'no_inherit', constraint_row.connoinherit,
                'local', constraint_row.conislocal,
                'inheritance_count', constraint_row.coninhcount,
                'parent', CASE
                    WHEN constraint_row.conparentid = 0 THEN NULL
                    ELSE pg_describe_object(
                        'pg_constraint'::regclass,
                        constraint_row.conparentid,
                        0
                    )
                END,
                'foreign_relation', CASE
                    WHEN constraint_row.confrelid = 0 THEN NULL
                    ELSE constraint_row.confrelid::regclass::text
                END,
                'foreign_match', constraint_row.confmatchtype,
                'foreign_update', constraint_row.confupdtype,
                'foreign_delete', constraint_row.confdeltype,
                'local_keys', constraint_row.conkey::text,
                'foreign_keys', constraint_row.confkey::text,
                'comment', obj_description(constraint_row.oid, 'pg_constraint'),
                'dependencies', (
                    SELECT COALESCE(jsonb_agg(
                        jsonb_build_object(
                            'type', dependency.deptype,
                            'reference', replace(pg_describe_object(
                                dependency.refclassid,
                                dependency.refobjid,
                                dependency.refobjsubid
                            ), current_schema() || '.', '@schema.')
                        )
                        ORDER BY dependency.deptype,
                            replace(pg_describe_object(
                                dependency.refclassid,
                                dependency.refobjid,
                                dependency.refobjsubid
                            ), current_schema() || '.', '@schema.')
                    ), '[]'::jsonb)
                    FROM pg_depend dependency
                    WHERE dependency.classid = 'pg_constraint'::regclass
                      AND dependency.objid = constraint_row.oid
                      AND dependency.objsubid = 0
                )
            )::text AS object_payload
        FROM pg_constraint constraint_row
        JOIN owned_relations relation ON relation.oid = constraint_row.conrelid
        JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    ),
    index_manifest AS (
        SELECT
            'index'::text AS object_kind,
            format('@schema.%I', index_relation.relname) AS object_identity,
            jsonb_build_object(
                'definition', replace(pg_get_indexdef(index_row.indexrelid, 0, false),
                    format(' ON %I.', current_schema()), ' ON @schema.'),
                'owner', CASE WHEN index_relation.relowner = current_user::regrole
                    THEN '@owner' ELSE pg_get_userbyid(index_relation.relowner) END,
                'acl_is_null', index_relation.relacl IS NULL,
                'acl', (
                    SELECT COALESCE(jsonb_agg(jsonb_build_object(
                        'grantor', CASE WHEN acl.grantor = current_user::regrole
                            THEN '@owner' ELSE pg_get_userbyid(acl.grantor) END,
                        'grantee', CASE WHEN acl.grantee = 0 THEN 'PUBLIC'
                            WHEN acl.grantee = current_user::regrole THEN '@owner'
                            ELSE pg_get_userbyid(acl.grantee) END,
                        'privilege', acl.privilege_type,
                        'grantable', acl.is_grantable
                    ) ORDER BY acl.grantor, acl.grantee, acl.privilege_type,
                        acl.is_grantable), '[]'::jsonb)
                    FROM aclexplode(index_relation.relacl) acl
                ),
                'access_method', access_method.amname,
                'tablespace', tablespace.spcname,
                'options', index_relation.reloptions,
                'unique', index_row.indisunique,
                'primary', index_row.indisprimary,
                'exclusion', index_row.indisexclusion,
                'immediate', index_row.indimmediate,
                'clustered', index_row.indisclustered,
                'valid', index_row.indisvalid,
                'check_xmin', index_row.indcheckxmin,
                'ready', index_row.indisready,
                'live', index_row.indislive,
                'replica_identity', index_row.indisreplident,
                'keys', index_row.indkey::text,
                'collations', (
                    SELECT jsonb_agg(CASE WHEN collation_oid = 0 THEN NULL
                        ELSE collation_oid::regcollation::text END ORDER BY ordinal)
                    FROM unnest(index_row.indcollation::oid[]) WITH ORDINALITY
                        collation_item(collation_oid, ordinal)
                ),
                'operator_classes', (
                    SELECT jsonb_agg(format('%I.%I/%I', namespace.nspname,
                        operator_class.opcname, access_method.amname) ORDER BY ordinal)
                    FROM unnest(index_row.indclass::oid[]) WITH ORDINALITY
                        class(class_oid, ordinal)
                    JOIN pg_opclass operator_class ON operator_class.oid = class.class_oid
                    JOIN pg_namespace namespace ON namespace.oid = operator_class.opcnamespace
                    JOIN pg_am access_method ON access_method.oid = operator_class.opcmethod
                ),
                'options_vector', index_row.indoption::text,
                'key_count', index_row.indnkeyatts,
                'attribute_count', index_row.indnatts,
                'nulls_not_distinct', index_row.indnullsnotdistinct,
                'predicate', pg_get_expr(
                    index_row.indpred, index_row.indrelid, false
                ),
                'comment', obj_description(index_relation.oid, 'pg_class'),
                'dependencies', (
                    SELECT COALESCE(jsonb_agg(
                        jsonb_build_object(
                            'type', dependency.deptype,
                            'reference', replace(pg_describe_object(
                                dependency.refclassid,
                                dependency.refobjid,
                                dependency.refobjsubid
                            ), current_schema() || '.', '@schema.')
                        )
                        ORDER BY dependency.deptype,
                            replace(pg_describe_object(
                                dependency.refclassid,
                                dependency.refobjid,
                                dependency.refobjsubid
                            ), current_schema() || '.', '@schema.')
                    ), '[]'::jsonb)
                    FROM pg_depend dependency
                    WHERE dependency.classid = 'pg_class'::regclass
                      AND dependency.objid = index_row.indexrelid
                      AND dependency.objsubid = 0
                )
            )::text AS object_payload
        FROM pg_index index_row
        JOIN pg_class index_relation ON index_relation.oid = index_row.indexrelid
        JOIN pg_namespace namespace ON namespace.oid = index_relation.relnamespace
        JOIN owned_relations relation ON relation.oid = index_row.indrelid
        JOIN pg_am access_method ON access_method.oid = index_relation.relam
        LEFT JOIN pg_tablespace tablespace
          ON tablespace.oid = index_relation.reltablespace
    ),
    catalog_manifest AS (
        SELECT * FROM function_manifest
        UNION ALL SELECT * FROM trigger_manifest
        UNION ALL SELECT * FROM table_manifest
        UNION ALL SELECT * FROM type_manifest
        UNION ALL SELECT * FROM policy_manifest
        UNION ALL SELECT * FROM rule_manifest
        UNION ALL SELECT * FROM column_manifest
        UNION ALL SELECT * FROM constraint_manifest
        UNION ALL SELECT * FROM index_manifest
    ),
    normalized_manifest AS (
        SELECT object_kind, object_identity, object_payload
        FROM catalog_manifest
    )
    SELECT
        encode(sha256(convert_to(string_agg(
            object_kind || chr(31) || object_identity || chr(31) || object_payload,
            E'\n'
            ORDER BY object_kind, object_identity, object_payload
        ), 'UTF8')), 'hex'),
        ARRAY[
            count(*) FILTER (WHERE object_kind = 'function'),
            count(*) FILTER (WHERE object_kind = 'trigger'),
            count(*) FILTER (WHERE object_kind = 'table'),
            count(*) FILTER (WHERE object_kind = 'column'),
            count(*) FILTER (WHERE object_kind = 'constraint'),
            count(*) FILTER (WHERE object_kind = 'index'),
            count(*) FILTER (WHERE object_kind = 'type'),
            count(*) FILTER (WHERE object_kind = 'policy'),
            count(*) FILTER (WHERE object_kind = 'rule'),
            count(*)
        ]::integer[]
    INTO catalog_hash, catalog_counts
    FROM normalized_manifest;

    IF catalog_hash <> '0570741079353a3dd00111840988c8cc6dfea096f4b285361891010b298febd3'
       OR catalog_counts <> ARRAY[81, 89, 17, 298, 303, 55, 34, 0, 0, 877]::integer[] THEN
        RAISE EXCEPTION 'migration 084 rollback catalog drift'
            USING ERRCODE = 'P8401';
    END IF;
    IF EXISTS (SELECT 1 FROM plugin_webhook_subscriptions) OR
       EXISTS (SELECT 1 FROM plugin_webhook_secret_versions) OR
       EXISTS (SELECT 1 FROM plugin_webhook_write_requests) OR
       EXISTS (SELECT 1 FROM plugin_webhook_events) OR
       EXISTS (SELECT 1 FROM plugin_webhook_deliveries) OR
       EXISTS (SELECT 1 FROM plugin_webhook_outbox) OR
       EXISTS (SELECT 1 FROM plugin_webhook_delivery_attempts) OR
       EXISTS (SELECT 1 FROM plugin_webhook_dead_letters) OR
       EXISTS (SELECT 1 FROM plugin_webhook_rate_events) OR
       EXISTS (SELECT 1 FROM plugin_webhook_entitlement_decisions) OR
       EXISTS (SELECT 1 FROM control_entitlement_revocation_lkg) OR
       EXISTS (SELECT 1 FROM control_entitlement_revoked_serials) OR
       EXISTS (SELECT 1 FROM entitlement_signing_keyset_current_keys) OR
       EXISTS (SELECT 1 FROM plugin_webhook_runtime_attestation_keys) OR
       EXISTS (SELECT 1 FROM plugin_webhook_runtime_attestation_head) OR
       EXISTS (
           SELECT 1 FROM custom_role_revisions
           WHERE permissions && ARRAY['plugin_webhooks.read', 'plugin_webhooks.manage']::text[]
       ) OR
       (SELECT count(*) FROM plugin_webhook_rbac_catalog_additions_084
        WHERE source_migration = 84) <> 2 OR
       EXISTS (
           (SELECT permission_name FROM plugin_webhook_rbac_catalog_additions_084)
           EXCEPT (VALUES ('plugin_webhooks.read'), ('plugin_webhooks.manage'))
       ) OR EXISTS (
           (VALUES ('plugin_webhooks.read'), ('plugin_webhooks.manage'))
           EXCEPT (SELECT permission_name FROM plugin_webhook_rbac_catalog_additions_084)
       ) OR
       (SELECT count(*) FROM custom_rbac_permission_catalog
        WHERE permission_name IN ('plugin_webhooks.read', 'plugin_webhooks.manage')
          AND NOT step_up_required) <> 2 OR
       (SELECT count(*) FROM permissions
        WHERE name IN ('plugin_webhooks.read', 'plugin_webhooks.manage')) <> 2 OR
       EXISTS (
           SELECT 1
           FROM role_permissions permission
           JOIN roles role ON role.id = permission.role_id
           JOIN access_scopes scope ON scope.id = role.scope_id
           LEFT JOIN plugin_webhook_rbac_grant_additions_084 addition
             ON addition.role_id = permission.role_id
            AND addition.permission_name = permission.permission_name
            AND addition.scope_id = role.scope_id
            AND addition.source_migration = 84
           WHERE permission.permission_name IN ('plugin_webhooks.read', 'plugin_webhooks.manage')
             AND addition.role_id IS NULL
       ) OR EXISTS (
           SELECT 1
           FROM plugin_webhook_rbac_grant_additions_084 addition
           JOIN roles role ON role.id = addition.role_id AND role.scope_id = addition.scope_id
           JOIN access_scopes scope ON scope.id = role.scope_id
           JOIN role_permissions permission
             ON permission.role_id = addition.role_id
            AND permission.permission_name = addition.permission_name
           WHERE addition.source_migration <> 84 OR NOT role.system_role OR NOT (
               (scope.kind = 'platform' AND role.name IN ('platform_owner', 'platform_admin') AND
                addition.permission_name IN ('plugin_webhooks.read', 'plugin_webhooks.manage')) OR
               (scope.kind = 'tenant' AND role.name IN ('tenant_owner', 'tenant_admin') AND
                addition.permission_name IN ('plugin_webhooks.read', 'plugin_webhooks.manage')) OR
               (scope.kind = 'tenant' AND role.name IN ('tenant_member', 'tenant_viewer') AND
                addition.permission_name = 'plugin_webhooks.read')
           )
       ) OR EXISTS (
           SELECT 1 FROM plugin_webhook_rbac_grant_additions_084 addition
           LEFT JOIN role_permissions permission
             ON permission.role_id = addition.role_id
            AND permission.permission_name = addition.permission_name
           WHERE permission.role_id IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 084 rollback cannot represent plugin webhook facts or RBAC drift'
            USING ERRCODE = 'P8401';
    END IF;
END;
$$;

DROP TRIGGER plugin_webhook_entitlement_decisions_validate_084 ON plugin_webhook_entitlement_decisions;
DROP FUNCTION validate_plugin_webhook_entitlement_decision_084();
DROP TRIGGER plugin_webhook_write_requests_entitlement_084 ON plugin_webhook_write_requests;
DROP FUNCTION record_plugin_webhook_entitlement_decision_084();
DROP TRIGGER plugin_webhook_entitlement_decisions_truncate_084 ON plugin_webhook_entitlement_decisions;
DROP FUNCTION prevent_plugin_webhook_entitlement_decision_truncate_084();
DROP TRIGGER plugin_webhook_entitlement_decisions_immutable_084 ON plugin_webhook_entitlement_decisions;
DROP FUNCTION prevent_plugin_webhook_entitlement_decision_mutation_084();
DROP TABLE plugin_webhook_entitlement_decisions;

DROP TRIGGER plugin_webhook_write_requests_result_084 ON plugin_webhook_write_requests;
DROP FUNCTION validate_plugin_webhook_write_request_result_084();
ALTER TABLE plugin_webhook_write_requests
    DROP CONSTRAINT plugin_webhook_write_requests_delivery_084_fk,
    DROP CONSTRAINT plugin_webhook_write_requests_rotation_084_fk;
DROP TRIGGER plugin_webhook_secret_versions_command_facts_084 ON plugin_webhook_secret_versions;
DROP FUNCTION validate_plugin_webhook_secret_command_084();
DROP TRIGGER plugin_webhook_events_command_facts_084 ON plugin_webhook_events;
DROP FUNCTION validate_plugin_webhook_event_command_084();
DROP TRIGGER plugin_webhook_deliveries_command_facts_084 ON plugin_webhook_deliveries;
DROP TRIGGER plugin_webhook_subscriptions_command_facts_084 ON plugin_webhook_subscriptions;
DROP FUNCTION validate_plugin_webhook_command_facts_084();
DROP TRIGGER plugin_webhook_rate_events_audit_084 ON plugin_webhook_rate_events;
DROP TRIGGER plugin_webhook_write_requests_audit_084 ON plugin_webhook_write_requests;
DROP FUNCTION validate_plugin_webhook_audit_084();

DROP TRIGGER plugin_webhook_rate_events_truncate_084 ON plugin_webhook_rate_events;
DROP TRIGGER plugin_webhook_rate_events_append_only_084 ON plugin_webhook_rate_events;
DROP TRIGGER plugin_webhook_rate_events_limit_084 ON plugin_webhook_rate_events;
DROP FUNCTION enforce_plugin_webhook_rate_084();
DROP TRIGGER plugin_webhook_rate_events_actor_target_084 ON plugin_webhook_rate_events;
DROP TABLE plugin_webhook_rate_events;

DROP FUNCTION transition_plugin_webhook_dead_letter_reconcile_084(
    uuid, uuid, uuid, uuid, text, numeric, numeric, numeric, numeric,
    uuid, text, numeric, numeric, numeric, numeric
);
DROP FUNCTION acknowledge_plugin_webhook_dead_letter_084(
    uuid, uuid, uuid, uuid, text, numeric, numeric, numeric, numeric,
    text, text, numeric, text, numeric, text, bytea, bytea, numeric, numeric, text, bytea
);
DROP TRIGGER plugin_webhook_dead_letters_truncate_084 ON plugin_webhook_dead_letters;
DROP TRIGGER plugin_webhook_dead_letters_terminal_084 ON plugin_webhook_dead_letters;
DROP FUNCTION validate_plugin_webhook_dead_letter_084();
DROP TRIGGER plugin_webhook_dead_letters_delivery_084 ON plugin_webhook_dead_letters;
DROP FUNCTION project_plugin_webhook_dead_letter_ack_084();
DROP TRIGGER plugin_webhook_dead_letters_guard_084 ON plugin_webhook_dead_letters;
DROP FUNCTION guard_plugin_webhook_dead_letter_084();
DROP TRIGGER plugin_webhook_dead_letters_actor_target_084 ON plugin_webhook_dead_letters;
DROP TRIGGER plugin_webhook_dead_letters_00_xact_084 ON plugin_webhook_dead_letters;
DROP TABLE plugin_webhook_dead_letters;
DROP FUNCTION plugin_webhook_dead_letter_payload_sha256_084(
    uuid, uuid, uuid, uuid, numeric, text, integer, bytea, bytea, integer
);
DROP FUNCTION plugin_webhook_dead_letter_attestation_sha256_084(
    numeric, text, text, uuid, uuid, uuid, uuid, uuid, uuid, text, numeric, numeric,
    numeric, text, numeric, text, numeric, text, bytea, bytea, numeric
);

DROP TRIGGER plugin_webhook_attempts_delivery_084 ON plugin_webhook_delivery_attempts;
DROP TRIGGER plugin_webhook_deliveries_attempt_084 ON plugin_webhook_deliveries;
DROP FUNCTION validate_plugin_webhook_delivery_attempt_084();
DROP TRIGGER plugin_webhook_attempts_outcome_084 ON plugin_webhook_delivery_attempts;
DROP FUNCTION project_plugin_webhook_attempt_outcome_084();
DROP TRIGGER plugin_webhook_attempts_truncate_084 ON plugin_webhook_delivery_attempts;
DROP TRIGGER plugin_webhook_attempts_guard_084 ON plugin_webhook_delivery_attempts;
DROP FUNCTION guard_plugin_webhook_attempt_084();
DROP TRIGGER plugin_webhook_attempts_claim_084 ON plugin_webhook_delivery_attempts;
DROP FUNCTION claim_plugin_webhook_attempt_084();
DROP TRIGGER plugin_webhook_attempts_actor_target_084 ON plugin_webhook_delivery_attempts;
DROP TABLE plugin_webhook_delivery_attempts;
DROP FUNCTION plugin_webhook_retry_delay_seconds_084(uuid, numeric, timestamptz, integer);
DROP FUNCTION plugin_webhook_sanitized_headers_valid_084(jsonb);

DROP TRIGGER plugin_webhook_outbox_delivery_084 ON plugin_webhook_outbox;
DROP TRIGGER plugin_webhook_deliveries_outbox_084 ON plugin_webhook_deliveries;
DROP FUNCTION validate_plugin_webhook_delivery_outbox_084();
DROP TRIGGER plugin_webhook_outbox_truncate_084 ON plugin_webhook_outbox;
DROP TRIGGER plugin_webhook_outbox_guard_084 ON plugin_webhook_outbox;
DROP FUNCTION guard_plugin_webhook_outbox_084();
DROP FUNCTION publish_plugin_webhook_outbox_084(
    uuid, uuid, uuid, uuid, text, text, numeric, text, numeric, text, bytea, numeric,
    numeric, text, bytea
);
DROP TRIGGER plugin_webhook_outbox_actor_target_084 ON plugin_webhook_outbox;
DROP TABLE plugin_webhook_outbox;
DROP FUNCTION plugin_webhook_outbox_attestation_sha256_084(
    numeric, text, text, uuid, uuid, uuid, uuid, uuid, uuid, numeric, text, numeric,
    text, numeric, text, bytea, numeric
);

DROP TRIGGER plugin_webhook_runtime_attestation_head_truncate_084
    ON plugin_webhook_runtime_attestation_head;
DROP TRIGGER plugin_webhook_runtime_attestation_head_validate_084
    ON plugin_webhook_runtime_attestation_head;
DROP TRIGGER plugin_webhook_runtime_attestation_head_guard_084
    ON plugin_webhook_runtime_attestation_head;
DROP TABLE plugin_webhook_runtime_attestation_head;
DROP TRIGGER plugin_webhook_runtime_attestation_keys_truncate_084
    ON plugin_webhook_runtime_attestation_keys;
DROP TRIGGER plugin_webhook_runtime_attestation_keys_validate_084
    ON plugin_webhook_runtime_attestation_keys;
DROP TRIGGER plugin_webhook_runtime_attestation_keys_guard_084
    ON plugin_webhook_runtime_attestation_keys;
DROP TABLE plugin_webhook_runtime_attestation_keys;
DROP FUNCTION guard_plugin_webhook_runtime_attestation_head_084();
DROP FUNCTION guard_plugin_webhook_runtime_attestation_key_084();
DROP FUNCTION validate_plugin_webhook_runtime_attestation_head_084();
DROP FUNCTION prevent_plugin_webhook_runtime_attestation_truncate_084();
DROP FUNCTION plugin_webhook_attestation_frame_084(bytea[]);
DROP FUNCTION plugin_webhook_u32be_084(integer);

DROP TRIGGER plugin_webhook_deliveries_replay_084 ON plugin_webhook_deliveries;
DROP FUNCTION validate_plugin_webhook_replay_084();
DROP TRIGGER plugin_webhook_deliveries_truncate_084 ON plugin_webhook_deliveries;
DROP TRIGGER plugin_webhook_deliveries_guard_084 ON plugin_webhook_deliveries;
DROP FUNCTION guard_plugin_webhook_delivery_084();
DROP TRIGGER plugin_webhook_deliveries_actor_target_084 ON plugin_webhook_deliveries;
DROP TABLE plugin_webhook_deliveries;

DROP TRIGGER plugin_webhook_events_body_084 ON plugin_webhook_events;
DROP FUNCTION validate_plugin_webhook_event_body_084();
DROP TRIGGER plugin_webhook_events_truncate_084 ON plugin_webhook_events;
DROP TRIGGER plugin_webhook_events_append_only_084 ON plugin_webhook_events;
DROP TRIGGER plugin_webhook_events_sequence_084 ON plugin_webhook_events;
DROP FUNCTION advance_plugin_webhook_event_sequence_084();
DROP TRIGGER plugin_webhook_events_actor_target_084 ON plugin_webhook_events;
DROP TABLE plugin_webhook_events;
DROP FUNCTION plugin_webhook_canonical_body_084(
    uuid, uuid, text, text, timestamptz, text, text, numeric, jsonb
);
DROP FUNCTION prevent_plugin_webhook_append_mutation_084();

DROP FUNCTION read_plugin_webhook_receipt_envelope_084(uuid, uuid, uuid, text);
DROP FUNCTION read_plugin_webhook_secret_envelope_084(uuid, uuid, uuid);
DROP TRIGGER plugin_webhook_write_requests_truncate_084 ON plugin_webhook_write_requests;
DROP TRIGGER plugin_webhook_write_requests_physical_cleanup_084 ON plugin_webhook_write_requests;
DROP TRIGGER plugin_webhook_secret_versions_physical_cleanup_084 ON plugin_webhook_secret_versions;
DROP FUNCTION validate_plugin_webhook_physical_cleanup_084();
DROP TRIGGER plugin_webhook_write_requests_guard_084 ON plugin_webhook_write_requests;
DROP FUNCTION guard_plugin_webhook_write_request_084();
DROP TRIGGER plugin_webhook_write_requests_actor_target_084 ON plugin_webhook_write_requests;
DROP TABLE plugin_webhook_write_requests;
DROP FUNCTION plugin_webhook_receipt_aad_sha256_084(uuid, uuid, uuid, text, text, uuid);

DROP TRIGGER plugin_webhook_subscriptions_revoke_fence_084 ON plugin_webhook_subscriptions;
DROP FUNCTION apply_plugin_webhook_revoke_fence_084();
DROP TRIGGER plugin_webhook_subscriptions_sequence_084 ON plugin_webhook_subscriptions;
DROP FUNCTION validate_plugin_webhook_subscription_sequence_084();
DROP TRIGGER plugin_webhook_secret_versions_active_check_084 ON plugin_webhook_secret_versions;
DROP TRIGGER plugin_webhook_subscriptions_active_secret_check_084 ON plugin_webhook_subscriptions;
DROP FUNCTION validate_plugin_webhook_active_secret_084();
ALTER TABLE plugin_webhook_subscriptions
    DROP CONSTRAINT plugin_webhook_subscriptions_active_secret_084_fk;
DROP TRIGGER plugin_webhook_secret_versions_truncate_084 ON plugin_webhook_secret_versions;
DROP TRIGGER plugin_webhook_secret_versions_expiry_fence_084 ON plugin_webhook_secret_versions;
DROP FUNCTION apply_plugin_webhook_secret_expiry_fence_084();
DROP TRIGGER plugin_webhook_secret_versions_guard_084 ON plugin_webhook_secret_versions;
DROP FUNCTION guard_plugin_webhook_secret_084();
DROP TRIGGER plugin_webhook_secret_versions_insert_084 ON plugin_webhook_secret_versions;
DROP FUNCTION validate_plugin_webhook_secret_insert_084();
DROP TRIGGER plugin_webhook_secret_versions_actor_target_084 ON plugin_webhook_secret_versions;
DROP TABLE plugin_webhook_secret_versions;
DROP FUNCTION plugin_webhook_secret_aad_sha256_084(uuid, uuid, uuid, numeric, text);

DROP TRIGGER plugin_webhook_subscriptions_truncate_084 ON plugin_webhook_subscriptions;
DROP TRIGGER plugin_webhook_subscriptions_guard_084 ON plugin_webhook_subscriptions;
DROP FUNCTION guard_plugin_webhook_subscription_084();
DROP TRIGGER plugin_webhook_subscriptions_quota_084 ON plugin_webhook_subscriptions;
DROP FUNCTION enforce_plugin_webhook_subscription_quota_084();
DROP TRIGGER plugin_webhook_subscriptions_actor_target_084 ON plugin_webhook_subscriptions;
DROP TABLE plugin_webhook_subscriptions;

DROP TRIGGER audit_events_plugin_webhook_xact_084 ON audit_events;
ALTER TABLE audit_events
    DROP COLUMN plugin_webhook_xact_id,
    DROP COLUMN plugin_webhook_recorded_at;
DROP FUNCTION stamp_plugin_webhook_xact_id_084();

DROP FUNCTION prevent_plugin_webhook_truncate_084();
DROP FUNCTION validate_plugin_webhook_actor_target_084();
DROP FUNCTION plugin_webhook_target_path_valid_084(text);
DROP FUNCTION plugin_webhook_target_host_valid_084(text);
DROP FUNCTION plugin_webhook_text_valid_084(text, integer);
DROP FUNCTION plugin_webhook_u64_084(numeric);

DROP TRIGGER entitlement_cached_leases_revocation_guard_084 ON entitlement_cached_leases;
DROP FUNCTION guard_control_entitlement_cached_lease_084();
DROP TRIGGER control_entitlement_revoked_serials_complete_084 ON control_entitlement_revoked_serials;
DROP TRIGGER control_entitlement_revoked_serials_truncate_084 ON control_entitlement_revoked_serials;
DROP TRIGGER control_entitlement_revoked_serials_guard_084 ON control_entitlement_revoked_serials;
DROP FUNCTION guard_control_entitlement_revocation_serial_084();
DROP TABLE control_entitlement_revoked_serials;
DROP TRIGGER control_entitlement_revocation_lkg_serials_complete_084 ON control_entitlement_revocation_lkg;
DROP TRIGGER control_entitlement_revocation_lkg_truncate_084 ON control_entitlement_revocation_lkg;
DROP TRIGGER control_entitlement_revocation_lkg_guard_084 ON control_entitlement_revocation_lkg;
DROP FUNCTION guard_control_entitlement_revocation_lkg_084();
DROP TABLE control_entitlement_revocation_lkg;
DROP FUNCTION assert_control_entitlement_revocation_serial_projection_084();
DROP TABLE entitlement_signing_keyset_current_keys;
DROP FUNCTION prevent_control_entitlement_revocation_truncate_084();
DROP FUNCTION plugin_webhook_canonical_u64_token_084(text);
DROP FUNCTION plugin_webhook_ed25519_verify_084(bytea, bytea, bytea);
DROP FUNCTION plugin_webhook_ed25519_prime_order_point_084(numeric[]);
DROP FUNCTION plugin_webhook_ed25519_scalarmult_084(numeric[], numeric);
DROP FUNCTION plugin_webhook_ed25519_double_084(numeric[]);
DROP FUNCTION plugin_webhook_ed25519_add_084(numeric[], numeric[]);
DROP FUNCTION plugin_webhook_ed25519_decode_084(bytea);
DROP FUNCTION plugin_webhook_mod_pow_084(numeric, numeric, numeric);
DROP FUNCTION plugin_webhook_le_numeric_084(bytea);
DROP FUNCTION plugin_webhook_mod_084(numeric, numeric);

DROP TRIGGER role_assignments_plugin_webhook_guard_084 ON role_assignments;
DROP TRIGGER custom_role_grants_plugin_webhook_guard_084 ON custom_role_grants;
DROP TRIGGER custom_role_revisions_plugin_webhook_guard_084 ON custom_role_revisions;
DROP FUNCTION validate_plugin_webhook_custom_role_084();

DROP TRIGGER roles_project_plugin_webhook_permissions_084 ON roles;
DROP FUNCTION project_plugin_webhook_system_role_permissions_084();

DROP TRIGGER plugin_webhook_rbac_catalog_delete_guard_084 ON custom_rbac_permission_catalog;
DROP FUNCTION protect_plugin_webhook_catalog_084();
DROP TRIGGER plugin_webhook_rbac_grants_protect_084 ON plugin_webhook_rbac_grant_additions_084;
DROP TRIGGER plugin_webhook_rbac_catalog_protect_084 ON plugin_webhook_rbac_catalog_additions_084;
DROP FUNCTION protect_plugin_webhook_rbac_provenance_084();

ALTER TABLE plugin_webhook_rbac_grant_additions_084
    DROP CONSTRAINT plugin_webhook_rbac_grant_role_permission_084_fk;
ALTER TABLE role_permissions DISABLE TRIGGER role_permissions_system_role_guard;
DELETE FROM role_permissions permission
USING plugin_webhook_rbac_grant_additions_084 addition
WHERE permission.role_id = addition.role_id
  AND permission.permission_name = addition.permission_name
  AND addition.source_migration = 84;
ALTER TABLE role_permissions ENABLE TRIGGER role_permissions_system_role_guard;

DROP TABLE plugin_webhook_rbac_grant_additions_084;
DROP TABLE plugin_webhook_rbac_catalog_additions_084;

DELETE FROM custom_rbac_permission_catalog
WHERE permission_name IN ('plugin_webhooks.read', 'plugin_webhooks.manage');
DELETE FROM permissions
WHERE name IN ('plugin_webhooks.read', 'plugin_webhooks.manage');

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
                  'package_subscriptions.read', 'package_subscriptions.manage'
              ) OR
              (role.system_role AND role.name = 'tenant_owner') OR
              (role.system_role AND role.name = 'tenant_viewer' AND
               role_permission.permission_name = 'package_subscriptions.read')
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

DO $$
BEGIN
    EXECUTE format(
        'REVOKE USAGE ON SCHEMA %I FROM cdnca_control_app, cdnca_plugin_webhook_runtime',
        current_schema()
    );
END;
$$;
