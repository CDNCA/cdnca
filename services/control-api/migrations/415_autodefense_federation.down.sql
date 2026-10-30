LOCK TABLE schema_migrations, autodefense_signatures, security_ban_entries IN ACCESS EXCLUSIVE MODE;

DO $migration_415_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 415 OR
       (SELECT max(version) FROM schema_migrations) <> 415 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=415 AND
        migration_id='415_autodefense_federation' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 415 down requires the exact verified migration head' USING ERRCODE='P4151';
    END IF;
    -- A solidified signature is the tenant's rule now; dropping the link
    -- would hand it back to automatic management behind the user's back.
    IF EXISTS (SELECT 1 FROM autodefense_signatures WHERE solidified_pack_id IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 415 down refused: signatures were solidified into user rule packs' USING ERRCODE='P4152';
    END IF;
END;
$migration_415_down$;

-- Autodefense ban list entries are derived from autodefense_mitigations;
-- without the source value they cannot stay.
DELETE FROM security_ban_entries WHERE source='autodefense';
ALTER TABLE security_ban_entries DROP CONSTRAINT security_ban_entries_source_415;
ALTER TABLE security_ban_entries ADD CONSTRAINT security_ban_entries_source_check CHECK (source IN ('waf', 'cc', 'manual'));

DROP TABLE autodefense_platform_intel;
DROP TABLE autodefense_site_federation;
DROP TABLE autodefense_signature_sightings;
DROP INDEX autodefense_signatures_evaluation_415;
ALTER TABLE autodefense_signatures
    DROP CONSTRAINT autodefense_signatures_solidified_415,
    DROP COLUMN solidified_version,
    DROP COLUMN solidified_pack_id,
    DROP COLUMN last_seen_at,
    DROP COLUMN evaluated_at,
    DROP COLUMN evaluation_reason,
    DROP COLUMN misfire_ppm,
    DROP COLUMN site_count,
    DROP COLUMN node_count,
    DROP COLUMN confidence_permille,
    DROP COLUMN evaluation;
