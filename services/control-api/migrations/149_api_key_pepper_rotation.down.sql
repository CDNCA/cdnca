LOCK TABLE schema_migrations, api_keys, api_key_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_149$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 149 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 149 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 149 AND migration_id = '149_api_key_pepper_rotation' AND
              checksum_sha256 = '32099eee305e8bd90c0b4e86392b3b7859267f9d9dd4aa5c379c8b6d1d028336' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 148 AND migration_id = '148_site_domains' AND
              checksum_sha256 = '18e34a28e5f078b55e4143a497376643bad4b8414a13bdd05d97c4be04d62ec4' AND
              down_checksum_sha256 = '70a95c5d2365a40eb1c9d54a71e2ae2c9785182c5e17087bb3af70a08cc5a2c6' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 149 rollback requires the exact verified 149 head'
            USING ERRCODE = 'P1490';
    END IF;
    IF EXISTS (
        SELECT 1 FROM api_keys
        WHERE pepper_version IS NOT NULL AND pepper_version <> 'legacy-v1'
    ) OR EXISTS (
        SELECT 1 FROM api_key_write_requests
        WHERE pepper_version <> 'legacy-v1'
    ) THEN
        RAISE EXCEPTION 'migration 149 rollback would discard API key pepper version facts'
            USING ERRCODE = 'P1495';
    END IF;
END;
$migration_149$;

DROP TRIGGER api_key_write_requests_pepper_version_guard_149 ON api_key_write_requests;
DROP TRIGGER api_keys_pepper_version_guard_149 ON api_keys;

ALTER TABLE api_key_write_requests
    DROP CONSTRAINT api_key_write_requests_pepper_version_valid,
    DROP COLUMN pepper_version;

ALTER TABLE api_keys
    DROP CONSTRAINT api_keys_pepper_version_bound,
    DROP COLUMN pepper_version;

DROP FUNCTION protect_api_key_pepper_version_149();
DROP FUNCTION api_key_pepper_version_is_valid(text);
