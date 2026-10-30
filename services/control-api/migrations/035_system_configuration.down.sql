LOCK TABLE system_configuration_streams,
           system_configuration_revisions,
           system_configuration_preflights,
           system_configuration_write_requests
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM system_configuration_streams) OR
       EXISTS (SELECT 1 FROM system_configuration_revisions) OR
       EXISTS (SELECT 1 FROM system_configuration_preflights) OR
       EXISTS (SELECT 1 FROM system_configuration_write_requests) THEN
        RAISE EXCEPTION 'system configuration migration 035 down refused: facts exist';
    END IF;
END;
$$;

DROP TRIGGER system_configuration_write_requests_no_truncate ON system_configuration_write_requests;
DROP TRIGGER system_configuration_preflights_no_truncate ON system_configuration_preflights;
DROP TRIGGER system_configuration_revisions_no_truncate ON system_configuration_revisions;
DROP TRIGGER system_configuration_streams_no_truncate ON system_configuration_streams;
DROP FUNCTION prevent_system_configuration_truncate();
DROP TRIGGER system_configuration_write_requests_protected ON system_configuration_write_requests;
DROP FUNCTION protect_system_configuration_write_request();
DROP TRIGGER system_configuration_revisions_projection_consistent ON system_configuration_revisions;
DROP TRIGGER system_configuration_streams_projection_consistent ON system_configuration_streams;
DROP FUNCTION validate_system_configuration_stream_projection();
DROP TRIGGER system_configuration_preflights_append_only ON system_configuration_preflights;
DROP FUNCTION prevent_system_configuration_preflight_mutation();
DROP TRIGGER system_configuration_preflights_validate_insert ON system_configuration_preflights;
DROP FUNCTION validate_system_configuration_preflight_insert();
DROP FUNCTION system_configuration_preflight_checks_are_valid(jsonb, boolean);
DROP TRIGGER system_configuration_revisions_protected ON system_configuration_revisions;
DROP FUNCTION protect_system_configuration_revision();
DROP TRIGGER system_configuration_revisions_validate_insert ON system_configuration_revisions;
DROP FUNCTION validate_system_configuration_revision_insert();
DROP TRIGGER system_configuration_streams_protected ON system_configuration_streams;
DROP FUNCTION protect_system_configuration_stream();
DROP TRIGGER system_configuration_streams_platform_scope ON system_configuration_streams;
DROP FUNCTION validate_system_configuration_platform_scope();
DROP FUNCTION system_configuration_snapshot_is_valid(bytea);
DROP FUNCTION system_configuration_render_canonical_snapshot(jsonb);
DROP FUNCTION system_configuration_actor_has_permission(uuid, uuid, text);
DROP FUNCTION system_configuration_json_integer(jsonb, numeric, numeric);
DROP FUNCTION system_configuration_json_keys_exact(jsonb, text[]);

DROP TABLE system_configuration_write_requests;
DROP TABLE system_configuration_preflights;
ALTER TABLE system_configuration_streams
    DROP CONSTRAINT system_configuration_streams_active_revision_fk;
DROP TABLE system_configuration_revisions;
DROP TABLE system_configuration_streams;

DELETE FROM role_permissions
WHERE permission_name IN ('system_configuration.read', 'system_configuration.manage');
DELETE FROM permissions
WHERE name IN ('system_configuration.read', 'system_configuration.manage');
