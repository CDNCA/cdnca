-- Only the three CHECK entry points need a function-local path; nested helpers inherit it.
DO $migration_273_up$
DECLARE
    schema_name text := pg_catalog.current_schema();
    schema_oid oid := pg_catalog.to_regnamespace(schema_name);
    baseline_valid boolean;
    function_valid boolean;
    expected record;
BEGIN
    IF schema_oid IS NULL OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_namespace WHERE oid=schema_oid AND nspowner=current_user::regrole
    ) OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_namespace n,
            LATERAL pg_catalog.aclexplode(COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a
        WHERE n.oid=schema_oid AND a.privilege_type='CREATE' AND a.grantee<>n.nspowner
    ) THEN
        RAISE EXCEPTION 'migration 273 requires the owner-controlled application schema' USING ERRCODE='P2731';
    END IF;
    EXECUTE pg_catalog.format('LOCK TABLE %I.schema_migrations IN ACCESS EXCLUSIVE MODE',schema_name);
    EXECUTE pg_catalog.format($sql$
        SELECT count(*)=272 AND min(version)=1 AND max(version)=272 AND
            bool_and(integrity_state IS NOT DISTINCT FROM 'verified' AND migration_id IS NOT NULL AND
                checksum_sha256 IS NOT NULL AND down_checksum_sha256 IS NOT NULL AND
                checksum_sha256 ~ '^[0-9a-f]{64}$' AND down_checksum_sha256 ~ '^[0-9a-f]{64}$' AND
                metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL) AND
            count(*) FILTER (WHERE version=272 AND migration_id='272_site_group_administration' AND
                checksum_sha256='aa6fdfc3d0d59309b78c71ef0ce412648135a771a791fbdc76e860c911e9d7ee' AND
                down_checksum_sha256='6d85d876690b12824d6ac9d601b3292f0195e7bde0af84d15951c0843a261e46')=1
        FROM %I.schema_migrations
    $sql$,schema_name) INTO baseline_valid;
    IF baseline_valid IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'migration 273 requires the exact verified 272 release head' USING ERRCODE='P2730';
    END IF;

    -- Pin all transitive non-catalog helpers, not only the functions being altered.
    FOR expected IN SELECT * FROM (VALUES
        ('site_group_trim_name_082','value text','text','sql','s','cb073d0074023a01271711528627a08053e5d75acc985a2344ac07df2da31b68'),
        ('site_group_name_is_valid_082','value text','bool','sql','s','5bb61cac46dc2a25f1fe4fc369281363c93302f0cedfad4009c3b73138fbc861'),
        ('plugin_webhook_mod_084','value numeric, modulus numeric','numeric','sql','u','d23922a8be12b0374a851b69ce79309d70e5ae3b62fc94e8b790babb393c2f50'),
        ('plugin_webhook_le_numeric_084','value bytea','numeric','plpgsql','u','0d75f45ddf2292d0184c4967feccc6c1736b9b782f17dbc4aa9f5de3bfcd4f50'),
        ('plugin_webhook_mod_pow_084','value numeric, exponent numeric, modulus numeric','numeric','plpgsql','u','c5eb591e6ca4fa30f10bf89d0c4c5d0f0c888df3727a7401df21249c4ec12940'),
        ('plugin_webhook_ed25519_decode_084','encoded bytea','numeric[]','plpgsql','u','32c284fdc3209763d14b92e01c27017f0bdbe69fa6ba34c91ced2256cea1fa9b'),
        ('plugin_webhook_ed25519_add_084','left_point numeric[], right_point numeric[]','numeric[]','plpgsql','u','62dac18eea1369ccc7cce852625aa097439a16759ccaa72da8c763d0a3bd4f47'),
        ('plugin_webhook_ed25519_double_084','point numeric[]','numeric[]','plpgsql','u','3f80c3872af88bd39f9e4400710be9cabc59906fb594516661c17a8a7545b740'),
        ('plugin_webhook_ed25519_scalarmult_084','point numeric[], scalar numeric','numeric[]','plpgsql','u','a187fa1ee2931ca8eee25d747d041eb91b343bac3eba6573b2a0303d95bed40a'),
        ('plugin_webhook_ed25519_prime_order_point_084','point numeric[]','bool','plpgsql','u','60b1637831526be9b19156a9bf95eb2111eb67c53dc4f55f28a6066adf475c94')
    ) AS pinned(name,arguments,result,language,parallel,source_sha256) LOOP
        SELECT count(*)=1 AND bool_and(
            pg_catalog.pg_get_function_identity_arguments(p.oid)=expected.arguments AND
            p.prorettype=pg_catalog.to_regtype('pg_catalog.'||expected.result) AND
            l.lanname=expected.language AND p.prokind='f' AND p.provolatile='i' AND p.proisstrict AND
            p.proparallel::text=expected.parallel AND NOT p.prosecdef AND NOT p.proleakproof AND
            NOT p.proretset AND p.provariadic=0 AND p.pronargdefaults=0 AND p.proargmodes IS NULL AND
            p.proallargtypes IS NULL AND p.procost=100 AND p.prorows=0 AND p.prosupport=0 AND
            p.proowner=current_user::regrole AND p.proconfig IS NULL AND
            pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc,'UTF8')),'hex')=expected.source_sha256
        ) INTO function_valid
        FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
        WHERE p.pronamespace=schema_oid AND p.proname=expected.name;
        IF function_valid IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'migration 273 refuses unknown validator %',expected.name USING ERRCODE='P2731';
        END IF;
    END LOOP;

    -- No CREATE OR REPLACE, owner/ACL change, session SET, or CHECK rewrite.
    EXECUTE pg_catalog.format('ALTER FUNCTION %I.site_group_name_is_valid_082(text) SET search_path = pg_catalog, %I, pg_temp',schema_name,schema_name);
    EXECUTE pg_catalog.format('ALTER FUNCTION %I.plugin_webhook_ed25519_decode_084(bytea) SET search_path = pg_catalog, %I, pg_temp',schema_name,schema_name);
    EXECUTE pg_catalog.format('ALTER FUNCTION %I.plugin_webhook_ed25519_prime_order_point_084(numeric[]) SET search_path = pg_catalog, %I, pg_temp',schema_name,schema_name);
END;
$migration_273_up$;
