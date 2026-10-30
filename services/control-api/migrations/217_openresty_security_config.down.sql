LOCK TABLE schema_migrations,openresty_security_configs,openresty_security_config_revisions,
    openresty_security_write_receipts,openresty_security_publication_outbox,openresty_security_task_outbox
    IN ACCESS EXCLUSIVE MODE;

DO $migration_217_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>217 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>217 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=217 AND migration_id='217_openresty_security_config' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR EXISTS(SELECT 1 FROM openresty_security_configs) OR
       EXISTS(SELECT 1 FROM openresty_security_config_revisions) OR
       EXISTS(SELECT 1 FROM openresty_security_write_receipts) OR
       EXISTS(SELECT 1 FROM openresty_security_publication_outbox) OR
       EXISTS(SELECT 1 FROM openresty_security_task_outbox) THEN
        RAISE EXCEPTION 'migration 217 rollback would discard OpenResty security configuration facts'
            USING ERRCODE='P2172';
    END IF;
END;
$migration_217_down$;

REVOKE SELECT,INSERT ON TABLE openresty_security_config_revisions,openresty_security_write_receipts FROM cdnca_control_app;
REVOKE SELECT,INSERT,UPDATE ON TABLE openresty_security_configs,openresty_security_publication_outbox,
    openresty_security_task_outbox FROM cdnca_control_app;

DROP TRIGGER openresty_security_publication_no_truncate_217 ON openresty_security_publication_outbox;
DROP TRIGGER openresty_security_publication_guard_217 ON openresty_security_publication_outbox;
DROP FUNCTION protect_openresty_security_publication_217();
DROP TRIGGER openresty_security_receipts_no_truncate_217 ON openresty_security_write_receipts;
DROP TRIGGER openresty_security_revisions_no_truncate_217 ON openresty_security_config_revisions;
DROP TRIGGER openresty_security_receipts_append_only_217 ON openresty_security_write_receipts;
DROP TRIGGER openresty_security_revisions_append_only_217 ON openresty_security_config_revisions;
DROP FUNCTION prevent_openresty_security_fact_mutation_217();

DROP TABLE openresty_security_task_outbox;
DROP TABLE openresty_security_publication_outbox;
DROP TABLE openresty_security_write_receipts;
DROP TABLE openresty_security_config_revisions;
DROP TABLE openresty_security_configs;

DELETE FROM role_permissions WHERE permission_name IN ('openresty_security.read','openresty_security.manage');
DELETE FROM permissions WHERE name IN ('openresty_security.read','openresty_security.manage');

