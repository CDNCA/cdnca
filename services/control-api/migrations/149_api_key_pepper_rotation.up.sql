LOCK TABLE schema_migrations, api_keys, api_key_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_149$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 148 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 148 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 148 AND migration_id = '148_site_domains' AND
              checksum_sha256 = '18e34a28e5f078b55e4143a497376643bad4b8414a13bdd05d97c4be04d62ec4' AND
              down_checksum_sha256 = '70a95c5d2365a40eb1c9d54a71e2ae2c9785182c5e17087bb3af70a08cc5a2c6' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name IN ('api_keys','api_key_write_requests')
          AND column_name='pepper_version'
    ) OR to_regprocedure('api_key_pepper_version_is_valid(text)') IS NOT NULL OR
         to_regprocedure('protect_api_key_pepper_version_149()') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 149 requires the exact verified 148 release head'
            USING ERRCODE = 'P1490';
    END IF;
END;
$migration_149$;

CREATE FUNCTION api_key_pepper_version_is_valid(value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT value ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$';
$$;

ALTER TABLE api_keys ADD COLUMN pepper_version text;
ALTER TABLE api_key_write_requests ADD COLUMN pepper_version text;

DROP TRIGGER api_keys_lifecycle_protected ON api_keys;
DROP TRIGGER api_key_write_requests_protected ON api_key_write_requests;

UPDATE api_keys
SET pepper_version='legacy-v1'
WHERE secret_digest IS NOT NULL;

UPDATE api_key_write_requests
SET pepper_version='legacy-v1';

CREATE TRIGGER api_keys_lifecycle_protected
BEFORE INSERT OR UPDATE OR DELETE ON api_keys
FOR EACH ROW EXECUTE FUNCTION protect_api_key_lifecycle();

CREATE TRIGGER api_key_write_requests_protected
BEFORE INSERT OR UPDATE OR DELETE ON api_key_write_requests
FOR EACH ROW EXECUTE FUNCTION protect_api_key_write_request();

ALTER TABLE api_keys
    ADD CONSTRAINT api_keys_pepper_version_bound CHECK (
        (secret_digest IS NULL AND pepper_version IS NULL) OR
        (secret_digest IS NOT NULL AND api_key_pepper_version_is_valid(pepper_version))
    );

ALTER TABLE api_key_write_requests
    ALTER COLUMN pepper_version SET NOT NULL,
    ADD CONSTRAINT api_key_write_requests_pepper_version_valid
        CHECK (api_key_pepper_version_is_valid(pepper_version));

CREATE FUNCTION protect_api_key_pepper_version_149()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_TABLE_NAME = 'api_keys' THEN
        IF (NEW.secret_digest IS NULL) IS DISTINCT FROM (NEW.pepper_version IS NULL) OR
           (NEW.pepper_version IS NOT NULL AND
            NOT api_key_pepper_version_is_valid(NEW.pepper_version)) THEN
            RAISE EXCEPTION 'API key digest and pepper version must be bound together'
                USING ERRCODE = 'P1491';
        END IF;
        IF TG_OP = 'UPDATE' AND
           NEW.secret_digest IS NOT DISTINCT FROM OLD.secret_digest AND
           NEW.pepper_version IS DISTINCT FROM OLD.pepper_version THEN
            RAISE EXCEPTION 'API key pepper version cannot change without its digest'
                USING ERRCODE = 'P1492';
        END IF;
        RETURN NEW;
    END IF;

    IF NOT api_key_pepper_version_is_valid(NEW.pepper_version) THEN
        RAISE EXCEPTION 'API key write request pepper version is invalid'
            USING ERRCODE = 'P1493';
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.pepper_version IS DISTINCT FROM OLD.pepper_version THEN
        RAISE EXCEPTION 'API key write request pepper version is immutable'
            USING ERRCODE = 'P1494';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER api_keys_pepper_version_guard_149
BEFORE INSERT OR UPDATE ON api_keys
FOR EACH ROW EXECUTE FUNCTION protect_api_key_pepper_version_149();

CREATE TRIGGER api_key_write_requests_pepper_version_guard_149
BEFORE INSERT OR UPDATE ON api_key_write_requests
FOR EACH ROW EXECUTE FUNCTION protect_api_key_pepper_version_149();

REVOKE ALL ON FUNCTION api_key_pepper_version_is_valid(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_api_key_pepper_version_149() FROM PUBLIC;
