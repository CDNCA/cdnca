LOCK TABLE schema_migrations, nodes, node_metric_samples IN ACCESS EXCLUSIVE MODE;

DO $migration_150$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 150 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 150 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 150 AND migration_id = '150_node_metrics' AND
              checksum_sha256 = 'bfa06ab9348dd9791060bd7624747234507d8dca015934070e0bdf6f04b89a65' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 149 AND migration_id = '149_api_key_pepper_rotation' AND
              checksum_sha256 = '32099eee305e8bd90c0b4e86392b3b7859267f9d9dd4aa5c379c8b6d1d028336' AND
              down_checksum_sha256 = '465b9544a68a59997217e1e24b9154637fcf463afc838cb14211c0e2dc3dac90' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 150 rollback requires the exact verified 150 head'
            USING ERRCODE = 'P1500';
    END IF;
    IF EXISTS (SELECT 1 FROM node_metric_samples) THEN
        RAISE EXCEPTION 'migration 150 rollback would discard durable node metric samples'
            USING ERRCODE = 'P1503';
    END IF;
END;
$migration_150$;

DROP VIEW node_metric_latest;
DROP TRIGGER node_metric_samples_immutable_150 ON node_metric_samples;
DROP TRIGGER node_metric_sequence_guard_150 ON node_metric_samples;
DROP FUNCTION protect_node_metric_sample_150();
DROP FUNCTION guard_node_metric_sequence_150();
DROP TABLE node_metric_samples;
