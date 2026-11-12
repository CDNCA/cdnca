LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_659_down$
DECLARE
    schema_name text := pg_catalog.current_schema();
    name text;
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 659 OR
       (SELECT max(version) FROM schema_migrations) <> 659 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=659 AND migration_id='659_check_function_search_path' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 659 down requires the exact verified migration head' USING ERRCODE='P6662';
    END IF;
    FOREACH name IN ARRAY ARRAY[
        'announcement_codepoint_is_format(integer)',
        'announcement_codepoint_is_go_space(integer)',
        'announcement_valid_body(text)',
        'announcement_valid_title(text)',
        'plugin_webhook_event_type_valid_122(text)',
        'plugin_webhook_event_types_shape_122(text[])',
        'valid_l4_origins_496(jsonb)',
        'validate_l4_runtime_spec_496(uuid, uuid, uuid, jsonb)',
        'validate_l4_runtime_spec_506(uuid, uuid, jsonb)'
    ] LOOP
        EXECUTE pg_catalog.format('ALTER FUNCTION %I.%s RESET search_path',schema_name,name);
    END LOOP;
END;
$migration_659_down$;
