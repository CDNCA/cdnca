LOCK TABLE schema_migrations, edge_capability_publication_holds IN ACCESS EXCLUSIVE MODE;

DO $migration_352_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 351 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 351 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=351 AND
        migration_id='351_drop_release_compat_objects' AND
        checksum_sha256='812ab13b15b806bc1f54355046f599ab3936c92b0251c0e02c0542e5b644cfb3' AND
        down_checksum_sha256='5dfbdc3c31dd83c2f9df51c0fb8bed2fedc7ca5cb55caabb16cc2eb3d8f36e5e' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='edge_capability_publication_holds' AND column_name='published'
       ) THEN
        RAISE EXCEPTION 'migration 352 requires the exact verified 351 release head' USING ERRCODE='P3520';
    END IF;
END;
$migration_352_up$;

-- r136 challenge-promote: a capability hold is written either for a refused
-- publication (nothing of that revision went out; published = false) or in
-- the transaction of a publication that left some nodes out (a JS challenge
-- promotion deferring offline, isolated or disabled nodes, an automatic
-- publication excluding incapable nodes; published = true). Only the latter
-- keeps its refused nodes targets of the scope's system republication at the
-- publication's own revision: a refused publication followed by another one
-- of the same revision to fewer nodes is the tenant's later choice.
ALTER TABLE edge_capability_publication_holds ADD COLUMN published boolean NOT NULL DEFAULT false;
