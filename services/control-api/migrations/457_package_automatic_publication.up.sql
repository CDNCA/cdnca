LOCK TABLE schema_migrations, edge_automatic_publication_policy_facts IN ACCESS EXCLUSIVE MODE;

DO $migration_457_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 456 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 456 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=456 AND
        migration_id='456_control_site_content' AND
        checksum_sha256='c42f022d826ff72206472a690103364ddb7716a474c9e86d4cdf8f793f202d06' AND
        down_checksum_sha256='c856accbac81be891b3e97778930f48b8fd8795c4670290f0b98fec4905c4b62' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid='edge_automatic_publication_policy_facts'::regclass
          AND conname='edge_automatic_publication_policy_facts_check' AND contype='c'
       ) THEN
        RAISE EXCEPTION 'migration 457 requires the exact verified 456 release head' USING ERRCODE='P4570';
    END IF;
END;
$migration_457_up$;

-- 457 (r136 autopub). Opening a
-- package turns on automatic publication for the tenant (user decision
-- 10-22). Such a policy names no nodes: every publication targets the nodes
-- of the line groups the scope's live sites use (their own or their
-- package's primary/backup group), resolved when it is published
-- (edgeautopublish publicationNodeIDs). 086 required an automatic policy to
-- name 1..10000 nodes or a target snapshot; it may now name none.
ALTER TABLE edge_automatic_publication_policy_facts
    DROP CONSTRAINT edge_automatic_publication_policy_facts_check;
ALTER TABLE edge_automatic_publication_policy_facts
    ADD CONSTRAINT edge_automatic_publication_policy_facts_check CHECK (
        (mode = 'manual' AND cardinality(node_ids) = 0 AND target_snapshot_id IS NULL AND
         target_snapshot_revision IS NULL AND target_snapshot_sha256 IS NULL) OR
        (mode = 'automatic' AND (
            (cardinality(node_ids) BETWEEN 0 AND 10000 AND target_snapshot_id IS NULL AND
             target_snapshot_revision IS NULL AND target_snapshot_sha256 IS NULL) OR
            (cardinality(node_ids) = 0 AND target_snapshot_id IS NOT NULL AND
             target_snapshot_revision > 0 AND octet_length(target_snapshot_sha256) = 32)
        ))
    );
