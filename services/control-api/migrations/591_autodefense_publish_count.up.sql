LOCK TABLE schema_migrations, autodefense_node_snapshots IN ACCESS EXCLUSIVE MODE;

DO $migration_591_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 590 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 590 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=590 AND
        migration_id='590_node_installation_serving' AND
        checksum_sha256='e9b5df4be7f7bad641b9ca3140fab6e778b462d9e2229fbd68047db49a5a2ad0' AND
        down_checksum_sha256='1065990a1acf86afedccf6f4e13f5986f98ebff4de0c0909dd994f12994f839a' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='autodefense_node_snapshots' AND column_name='publish_count'
       ) THEN
        RAISE EXCEPTION 'migration 591 requires the exact verified 590 release head' USING ERRCODE='P5910';
    END IF;
END;
$migration_591_up$;

-- 591 (r136 fix-nrecovery2, placeholder: renumber at the merge). How many
-- times the newest revision of a node's automatic defense snapshot was handed
-- to the gateway (0 before the first; a new revision starts again at 0). The
-- release dialog shows the automatic resends of a release a node has not
-- confirmed yet.
ALTER TABLE autodefense_node_snapshots
    ADD COLUMN publish_count integer NOT NULL DEFAULT 0
        CONSTRAINT autodefense_node_snapshots_publish_count_591_check CHECK (publish_count >= 0);
