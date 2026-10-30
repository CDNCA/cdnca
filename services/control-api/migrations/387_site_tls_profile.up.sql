LOCK TABLE schema_migrations, sites IN ACCESS EXCLUSIVE MODE;

DO $migration_387_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 386 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 386 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=386 AND
        migration_id='386_plugin_ui_pages' AND
        checksum_sha256='b8adf13c8b724c1e22376a55b838c94722ab58e68a70f8d94d75304c83f34ef3' AND
        down_checksum_sha256='216acb746ead9b0bce071f74588ea0a21defa21a3d6d2c9122a1431066a3546f' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='sites' AND column_name='tls_cipher_preset'
       ) THEN
        RAISE EXCEPTION 'migration 387 requires the exact verified 386 release head' USING ERRCODE='P3870';
    END IF;
END;
$migration_387_up$;

-- r136 ge-tls: a site's TLS profile.
-- tls_protocols: an ascending contiguous range of TLSv1..TLSv1.3 (TLSv1.3
-- only, the TLSv1.2+TLSv1.3 baseline, or older clients down to TLSv1).
-- SSLv2/SSLv3 are never accepted. TLSv1/TLSv1.1 need the legacy cipher
-- preset (their SHA-1 CBC suites and signatures need security level 0).
-- tls_cipher_preset: modern (ECDHE AEAD only), compatible (adds CBC and RSA
-- key exchange for old TLS 1.2 clients), legacy (OpenSSL DEFAULT@SECLEVEL=0).
-- tls_ocsp_stapling: the node staples the issuer's OCSP response.
-- tls_client_auth / tls_client_ca_pem: client certificate verification
-- (off/optional/required) against the site's own CA bundle (PEM CA
-- certificates only, no key: certificate assets need a key and names).
ALTER TABLE sites DROP CONSTRAINT sites_tls_protocols_valid_160;
ALTER TABLE sites
    ADD COLUMN tls_cipher_preset text NOT NULL DEFAULT 'modern',
    ADD COLUMN tls_ocsp_stapling boolean NOT NULL DEFAULT false,
    ADD COLUMN tls_client_auth text NOT NULL DEFAULT 'off',
    ADD COLUMN tls_client_ca_pem text,
    ADD CONSTRAINT sites_tls_protocols_valid_387 CHECK (
        tls_protocols IN (
            ARRAY['TLSv1.3']::text[],
            ARRAY['TLSv1.2','TLSv1.3']::text[],
            ARRAY['TLSv1.2']::text[],
            ARRAY['TLSv1.1','TLSv1.2','TLSv1.3']::text[],
            ARRAY['TLSv1.1','TLSv1.2']::text[],
            ARRAY['TLSv1','TLSv1.1','TLSv1.2','TLSv1.3']::text[],
            ARRAY['TLSv1','TLSv1.1','TLSv1.2']::text[]
        )
    ),
    ADD CONSTRAINT sites_tls_cipher_preset_387 CHECK (
        tls_cipher_preset IN ('modern','compatible','legacy') AND
        (tls_cipher_preset = 'legacy' OR NOT tls_protocols && ARRAY['TLSv1','TLSv1.1']::text[])
    ),
    ADD CONSTRAINT sites_tls_client_auth_387 CHECK (
        tls_client_auth IN ('off','optional','required') AND
        ((tls_client_auth = 'off') = (tls_client_ca_pem IS NULL)) AND
        (tls_client_ca_pem IS NULL OR octet_length(tls_client_ca_pem) BETWEEN 1 AND 262144 AND
         tls_client_ca_pem LIKE '-----BEGIN CERTIFICATE-----%')
    );

-- The system SSL default is what new sites inherit (site TLS profile): only
-- the three presets map to a site profile. "custom" (a free cipher string
-- nothing could check) is gone.
CREATE OR REPLACE FUNCTION system_configuration_v2_default_ssl(candidate jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT system_configuration_v2_json_keys_exact(candidate,
               ARRAY['mode','protocols','cipher_suites','prefer_server_ciphers'])
       AND candidate->>'mode' IN ('recommended','legacy_tls12','legacy_full')
       AND system_configuration_v2_tls_protocols(candidate->'protocols')
       AND jsonb_typeof(candidate->'cipher_suites') = 'string'
       AND char_length(candidate->>'cipher_suites') <= 4096
       AND candidate->>'cipher_suites' !~ '[[:cntrl:]]'
       AND jsonb_typeof(candidate->'prefer_server_ciphers') = 'boolean'
       AND (
           (
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
