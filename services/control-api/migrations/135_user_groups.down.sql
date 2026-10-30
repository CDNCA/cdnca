-- migration 135 rollback requires the verified 135 head
LOCK TABLE schema_migrations, identity_user_groups, identity_user_group_memberships,
           identity_user_group_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_135$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 135 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 135 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 135 AND migration_id = '135_user_groups' AND
              checksum_sha256 = 'cac03de016d85a2e4fbaf225b987e72cd72ecec406d3520adbc168b32097c121' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 134 AND migration_id = '134_global_firewall' AND
              checksum_sha256 = 'cedf471ecef9136cf9480b298d2dfb9dcdfb98c6bd34011c5d3a56d649bd1624' AND
              down_checksum_sha256 = 'c36ab4bf4bf18253d1a7e357a45d60df38c0aaded3e26f4f31118b375feae22e' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR EXISTS (SELECT 1 FROM identity_user_group_memberships) OR
       EXISTS (SELECT 1 FROM identity_user_groups) OR
       EXISTS (SELECT 1 FROM identity_user_group_write_requests) THEN
        RAISE EXCEPTION 'migration 135 rollback would discard user group facts'
            USING ERRCODE = 'P1356';
    END IF;
END;
$migration_135$;

DROP TRIGGER identity_user_group_write_requests_truncate_guard_135
    ON identity_user_group_write_requests;
DROP TRIGGER identity_user_group_write_requests_guard_135
    ON identity_user_group_write_requests;
DROP FUNCTION guard_identity_user_group_write_requests_135();
DROP TABLE identity_user_group_write_requests;

DROP TRIGGER identity_user_group_memberships_validate_135
    ON identity_user_group_memberships;
DROP FUNCTION validate_identity_user_group_membership_135();
DROP TABLE identity_user_group_memberships;

DROP TRIGGER identity_user_groups_validate_135 ON identity_user_groups;
DROP FUNCTION validate_identity_user_group_135();
DROP TABLE identity_user_groups;
