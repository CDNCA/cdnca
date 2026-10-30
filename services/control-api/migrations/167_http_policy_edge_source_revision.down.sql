LOCK TABLE schema_migrations,http_policy_revisions,http_policy_publication_heads,edge_configuration_scopes IN ACCESS EXCLUSIVE MODE;

DO $migration_167$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>167 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>167 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=167 AND migration_id='167_http_policy_edge_source_revision' AND
              checksum_sha256='a4409fe5ab7ced09a42212526a956979a1dabe2d6a036fbb59a8169f0fdaf1e3' AND integrity_state='verified' AND
              metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 167 rollback requires the exact verified 167 head'
            USING ERRCODE='P1670';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM edge_config_publications publication
        JOIN http_policy_revisions revision
          ON revision.tenant_scope_id=publication.configuration_scope_id
         AND revision.created_at<=publication.created_at
        JOIN schema_migrations migration
          ON migration.version=167 AND migration.migration_id='167_http_policy_edge_source_revision'
        WHERE publication.created_at>=migration.applied_at
    ) THEN
        RAISE EXCEPTION 'migration 167 rollback would detach HTTP policy revisions from published edge source revisions'
            USING ERRCODE='P1671';
    END IF;
END;
$migration_167$;

DROP TRIGGER zz_http_policy_edge_source_revision_167 ON http_policy_revisions;
DROP FUNCTION advance_http_policy_edge_source_revision_167();
