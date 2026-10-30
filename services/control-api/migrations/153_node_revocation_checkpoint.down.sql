LOCK TABLE schema_migrations,control_installation_entitlement,
    node_revocation_checkpoint_history,node_revocation_checkpoint_lkg IN ACCESS EXCLUSIVE MODE;

DO $migration_153$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>153 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>153 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=153 AND migration_id='153_node_revocation_checkpoint' AND
              checksum_sha256='625a59e7f6be7ebe73877550e87ac230f7fb118aeb8e69243553fe16574d1fbf' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=152 AND migration_id='152_recharge_payment_lifecycle' AND
              checksum_sha256='5aa5c735685cb02cce34fca432592f280c8f53a4f8c8c006067e43e997d279e0' AND
              down_checksum_sha256='1bf753f13c76111d465396b6ac2b446892325b18ff3b8929ead84985963decce' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 153 rollback requires the exact verified 153 head'
            USING ERRCODE='P1530';
    END IF;
    IF EXISTS(SELECT 1 FROM node_revocation_checkpoint_history) OR
       EXISTS(SELECT 1 FROM node_revocation_checkpoint_lkg) THEN
        RAISE EXCEPTION 'migration 153 rollback would discard durable node revocation checkpoints'
            USING ERRCODE='P1534';
    END IF;
END;
$migration_153$;

DROP TRIGGER node_revocation_checkpoint_lkg_truncate_153 ON node_revocation_checkpoint_lkg;
DROP TRIGGER node_revocation_checkpoint_lkg_guard_153 ON node_revocation_checkpoint_lkg;
DROP TRIGGER node_revocation_checkpoint_history_immutable_153 ON node_revocation_checkpoint_history;
DROP TRIGGER node_revocation_checkpoint_history_sequence_153 ON node_revocation_checkpoint_history;
DROP FUNCTION prevent_node_revocation_checkpoint_lkg_truncate_153();
DROP FUNCTION guard_node_revocation_checkpoint_lkg_153();
DROP FUNCTION prevent_node_revocation_checkpoint_history_mutation_153();
DROP FUNCTION guard_node_revocation_checkpoint_history_insert_153();
DROP TABLE node_revocation_checkpoint_lkg;
DROP TABLE node_revocation_checkpoint_history;
