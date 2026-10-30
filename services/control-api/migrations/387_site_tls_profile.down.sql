LOCK TABLE schema_migrations, sites IN ACCESS EXCLUSIVE MODE;

DO $migration_387_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 387 OR
       (SELECT max(version) FROM schema_migrations) <> 387 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=387 AND
        migration_id='387_site_tls_profile' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 387 down requires the exact verified migration head' USING ERRCODE='P3871';
    END IF;
    -- 160 only knows the TLSv1.2+TLSv1.3 baseline: a site with another
    -- profile would lose it silently.
    IF EXISTS (
        SELECT 1 FROM sites WHERE tls_protocols <> ARRAY['TLSv1.2','TLSv1.3']::text[] OR
            tls_cipher_preset <> 'modern' OR tls_ocsp_stapling OR tls_client_auth <> 'off'
    ) THEN
        RAISE EXCEPTION 'migration 387 down refuses: sites use TLS profiles 386 cannot hold' USING ERRCODE='P3872';
    END IF;
END;
$migration_387_down$;

ALTER TABLE sites
    DROP CONSTRAINT sites_tls_client_auth_387,
    DROP CONSTRAINT sites_tls_cipher_preset_387,
    DROP CONSTRAINT sites_tls_protocols_valid_387,
    DROP COLUMN tls_client_ca_pem,
    DROP COLUMN tls_client_auth,
    DROP COLUMN tls_ocsp_stapling,
    DROP COLUMN tls_cipher_preset;
ALTER TABLE sites ADD CONSTRAINT sites_tls_protocols_valid_160 CHECK (
    cardinality(tls_protocols) BETWEEN 1 AND 6 AND
    array_position(tls_protocols,NULL) IS NULL AND
    tls_protocols <@ ARRAY['SSLv2','SSLv3','TLSv1','TLSv1.1','TLSv1.2','TLSv1.3']::text[] AND
    (
        tls_protocols = ARRAY['TLSv1.2','TLSv1.3']::text[] OR
        tls_protocols && ARRAY['SSLv2','SSLv3','TLSv1','TLSv1.1']::text[]
    )
);

CREATE OR REPLACE FUNCTION system_configuration_v2_default_ssl(candidate jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT system_configuration_v2_json_keys_exact(candidate,
               ARRAY['mode','protocols','cipher_suites','prefer_server_ciphers'])
       AND candidate->>'mode' IN ('recommended','legacy_tls12','legacy_full','custom')
       AND system_configuration_v2_tls_protocols(candidate->'protocols')
       AND jsonb_typeof(candidate->'cipher_suites') = 'string'
       AND char_length(candidate->>'cipher_suites') <= 4096
       AND candidate->>'cipher_suites' !~ '[[:cntrl:]]'
       AND jsonb_typeof(candidate->'prefer_server_ciphers') = 'boolean'
       AND (
           candidate->>'mode' = 'custom'
           OR (
               candidate->>'mode' = 'recommended'
               AND candidate->'protocols' = '["TLSv1.2","TLSv1.3"]'::jsonb
               AND candidate->>'cipher_suites' = 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305'
               AND candidate->'prefer_server_ciphers' = 'false'::jsonb
           )
           OR (
               candidate->>'mode' = 'legacy_tls12'
               AND candidate->'protocols' = '["TLSv1.2","TLSv1.3"]'::jsonb
               AND candidate->>'cipher_suites' = 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA'
               AND candidate->'prefer_server_ciphers' = 'true'::jsonb
           )
           OR (
               candidate->>'mode' = 'legacy_full'
               AND candidate->'protocols' = '["TLSv1","TLSv1.1","TLSv1.2","TLSv1.3"]'::jsonb
               AND candidate->>'cipher_suites' = 'DEFAULT:@SECLEVEL=0'
               AND candidate->'prefer_server_ciphers' = 'true'::jsonb
           )
       );
$$;
