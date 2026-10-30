LOCK TABLE schema_migrations,http_policy_revisions,http_policy_publication_heads,edge_configuration_scopes IN ACCESS EXCLUSIVE MODE;

DO $migration_167$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>166 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>166 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=166 AND migration_id='166_identity_managed_password_reset' AND
              checksum_sha256='4d3f0986b1c0f158ef971e08278fdb6a3766d49c32addf7e173991c1c5980916' AND
              down_checksum_sha256='47cb396b783e50472360124f89a756f94b60280d150de6a9bec09e11f84ea566' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 167 requires the exact verified 166 release head'
            USING ERRCODE='P1670';
    END IF;
END;
$migration_167$;

CREATE FUNCTION advance_http_policy_edge_source_revision_167()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM advance_edge_configuration_scope_revision(NEW.tenant_scope_id);
    RETURN NULL;
END;
$$;

CREATE TRIGGER zz_http_policy_edge_source_revision_167
AFTER INSERT ON http_policy_revisions
FOR EACH ROW EXECUTE FUNCTION advance_http_policy_edge_source_revision_167();
