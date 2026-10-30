LOCK TABLE schema_migrations,system_configuration_edge_publications IN ACCESS EXCLUSIVE MODE;

DO $migration_178_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>178 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>178 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=178 AND migration_id='178_system_configuration_edge_publication' AND
              checksum_sha256='4745546d27de98d94bbb28c3b2cc9d9538c39fdd717bd1ea258bd0cad89780a2' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 178 rollback requires the exact verified 178 head' USING ERRCODE='P1781';
    END IF;
    IF EXISTS (SELECT 1 FROM system_configuration_edge_publications) THEN
        RAISE EXCEPTION 'migration 178 rollback would discard system configuration edge publication facts'
            USING ERRCODE='P1782';
    END IF;
END;
$migration_178_down$;

DROP TRIGGER system_configuration_edge_publications_no_truncate ON system_configuration_edge_publications;
DROP FUNCTION prevent_system_configuration_edge_publication_truncate_178();
DROP TRIGGER system_configuration_edge_publications_append_only ON system_configuration_edge_publications;
DROP FUNCTION prevent_system_configuration_edge_publication_mutation_178();
DROP TRIGGER system_configuration_edge_publications_validate ON system_configuration_edge_publications;
DROP FUNCTION validate_system_configuration_edge_publication_178();
DROP TABLE system_configuration_edge_publications;
