LOCK TABLE schema_migrations, system_configuration_revisions IN ACCESS EXCLUSIVE MODE;

DO $migration_226$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 225 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 225 OR
       EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 225 AND migration_id = '225_system_configuration_resource_overrides' AND
              checksum_sha256 = '6ca959a26bb17feffb477cb9435e09c5b74f3183523f1c428ba4b425264b32f6' AND
              down_checksum_sha256 = '06c67ec2c633361a7710dec75d4dea238ddc5095c1f21943ebfbddca871e0754' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regprocedure(
            current_schema() || '.system_configuration_v2_tls_protocols(jsonb)'
       ) IS NULL OR
       system_configuration_v2_tls_protocols('["SSLv2"]'::jsonb) OR
       system_configuration_v2_tls_protocols('["SSLv3"]'::jsonb) OR
       NOT system_configuration_v2_tls_protocols('["TLSv1","TLSv1.1","TLSv1.2","TLSv1.3"]'::jsonb) THEN
        RAISE EXCEPTION 'migration 226 requires the exact verified 225 release head and the canonical TLS protocol validator'
            USING ERRCODE = 'P2260';
    END IF;
END;
$migration_226$;

CREATE OR REPLACE FUNCTION system_configuration_v2_tls_protocols(candidate jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT system_configuration_v2_string_set(
        candidate, ARRAY['SSLv2','SSLv3','TLSv1','TLSv1.1','TLSv1.2','TLSv1.3'], 1, 6
    );
$$;
