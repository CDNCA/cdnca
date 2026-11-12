LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

-- Guard: the verified 658 head (658_cname_custom_label).
DO $migration_659_up$
DECLARE
    schema_name text := pg_catalog.current_schema();
    schema_oid oid := pg_catalog.to_regnamespace(pg_catalog.current_schema());
    function_valid boolean;
    expected record;
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 658 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 658 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=658 AND
        migration_id='658_cname_custom_label' AND
        checksum_sha256='7949bcb4d3a72abead67e4fdd0878eaea72efdb1620f4624672c6fca66f1c937' AND
        down_checksum_sha256='1faf1c8f2d38eb653d0148aabd706384b0b7a3ac1bf56202afdb6dc637702c48' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 659 requires the exact verified 658 release head' USING ERRCODE='P6590';
    END IF;

    -- 659. pg_dump writes set_config('search_path','') before COPY, and a
    -- CHECK that inlines a SQL function resolves its unqualified helper calls under that empty
    -- path. A database holding an announcement could therefore not be restored from its own
    -- dump (announcement_codepoint_is_go_space(integer) does not exist). Migration 273 pinned
    -- three such entry points; these are the others reachable from a CHECK. Only entry points
    -- need a function-local path; nested helpers inherit it.
    -- Each function is matched on its exact shape and source hash first, as 273 does.
    FOR expected IN SELECT * FROM (VALUES
        ('announcement_codepoint_is_format','codepoint integer','bool','sql','s','48f3027b9eb9d3cfd2e8762c22b645473f1f740109c3789cc0e186d78cff4336'),
        ('announcement_codepoint_is_go_space','codepoint integer','bool','sql','s','5be28a1a9a1c70fa345e21c46909ec14b6672df020aaeae75f02cfc32c682c68'),
        ('announcement_valid_body','value text','bool','sql','s','d7d696633f9cfd4fb98c2b5ac758e0ed0904867c21298a46b1ef173960ca50a0'),
        ('announcement_valid_title','value text','bool','sql','s','64bb81a34b7e1c7d5b3f24c46d7834afc30cf146169fa0ae7eccca4f72b1e7b6'),
        ('plugin_webhook_event_type_valid_122','value text','bool','sql','s','0ef23168f3c8150014fbe2dc005c52f6f33ce3c0eb61ac53255224a9c551ba06'),
        ('plugin_webhook_event_types_shape_122','value text[]','bool','sql','s','e76949440e613717018651fbeef32532c2bd5d92cfc5db43a2f3a1eb154631a2'),
        ('valid_l4_origins_496','origins jsonb','bool','plpgsql','u','751e68995bb73e0c2ae51b055b92cdd9d16b7b5109e96a4a3a81177fca33d730'),
        ('validate_l4_runtime_spec_496','target_stream_id uuid, target_scope_id uuid, target_site_id uuid, runtime_spec jsonb','bool','plpgsql','u','d58114ef3df11f63f52b1e7f0009cfe2db38eb2e8058390895c97d4bc012dae8'),
        ('validate_l4_runtime_spec_506','target_stream_id uuid, target_scope_id uuid, runtime_spec jsonb','bool','plpgsql','u','75cfda27dd7017335a2da14e485e20fc91573e3cbac0e46a8ca91c768aa7a127')
    ) AS pinned(name,arguments,result,language,parallel,source_sha256) LOOP
        SELECT count(*)=1 AND bool_and(
            pg_catalog.pg_get_function_identity_arguments(p.oid)=expected.arguments AND
            p.prorettype=pg_catalog.to_regtype('pg_catalog.'||expected.result) AND
            l.lanname=expected.language AND p.prokind='f' AND p.provolatile='i' AND
            p.proparallel::text=expected.parallel AND NOT p.prosecdef AND NOT p.proleakproof AND
            NOT p.proretset AND p.procost=100 AND p.prorows=0 AND p.prosupport=0 AND
            p.proowner=current_user::regrole AND p.proconfig IS NULL AND
            pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc,'UTF8')),'hex')=expected.source_sha256
        ) INTO function_valid
        FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
        WHERE p.pronamespace=schema_oid AND p.proname=expected.name;
        IF function_valid IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'migration 659 refuses unknown function %',expected.name USING ERRCODE='P6591';
        END IF;
    END LOOP;

    -- No CREATE OR REPLACE, owner/ACL change, session SET, or CHECK rewrite.
    EXECUTE pg_catalog.format('ALTER FUNCTION %I.announcement_codepoint_is_format(integer) SET search_path = pg_catalog, %I, pg_temp',schema_name,schema_name);
    EXECUTE pg_catalog.format('ALTER FUNCTION %I.announcement_codepoint_is_go_space(integer) SET search_path = pg_catalog, %I, pg_temp',schema_name,schema_name);
    EXECUTE pg_catalog.format('ALTER FUNCTION %I.announcement_valid_body(text) SET search_path = pg_catalog, %I, pg_temp',schema_name,schema_name);
    EXECUTE pg_catalog.format('ALTER FUNCTION %I.announcement_valid_title(text) SET search_path = pg_catalog, %I, pg_temp',schema_name,schema_name);
    EXECUTE pg_catalog.format('ALTER FUNCTION %I.plugin_webhook_event_type_valid_122(text) SET search_path = pg_catalog, %I, pg_temp',schema_name,schema_name);
    EXECUTE pg_catalog.format('ALTER FUNCTION %I.plugin_webhook_event_types_shape_122(text[]) SET search_path = pg_catalog, %I, pg_temp',schema_name,schema_name);
    EXECUTE pg_catalog.format('ALTER FUNCTION %I.valid_l4_origins_496(jsonb) SET search_path = pg_catalog, %I, pg_temp',schema_name,schema_name);
    EXECUTE pg_catalog.format('ALTER FUNCTION %I.validate_l4_runtime_spec_496(uuid, uuid, uuid, jsonb) SET search_path = pg_catalog, %I, pg_temp',schema_name,schema_name);
    EXECUTE pg_catalog.format('ALTER FUNCTION %I.validate_l4_runtime_spec_506(uuid, uuid, jsonb) SET search_path = pg_catalog, %I, pg_temp',schema_name,schema_name);
END;
$migration_659_up$;
