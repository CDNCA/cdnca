LOCK TABLE schema_migrations, sites IN ACCESS EXCLUSIVE MODE;

DO $migration_651_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 650 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 650 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=650 AND
        migration_id='650_certificate_publication_redelivery_recovery' AND
        checksum_sha256='040422c0fcc1978e51a07ed4102076d3c84ccb1ea8e0bc23e22bf11295db2d6a' AND
        down_checksum_sha256='427f8b8777889e6fbb06f341b1ffc465332d764b70caa1c333d047134194cc38' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='sites' AND column_name='server_timing'
       ) THEN
        RAISE EXCEPTION 'migration 651 requires the exact verified 650 release head' USING ERRCODE='P6510';
    END IF;
END;
$migration_651_up$;

-- Server-Timing 响应头. A site with the switch on has
-- the node append the Server-Timing entries cdn-cache, cdn-hit-layer,
-- cdn-connect and cdn-ttfb to its responses. Off by default. A site at attack
-- escalation level B or above is published with it off, like
-- cache_status_header (472). Any change of the column advances the scope's
-- source revision (335 compares whole rows). A constant default adds the
-- column without rewriting the table.
ALTER TABLE sites
    ADD COLUMN server_timing boolean NOT NULL DEFAULT false;
