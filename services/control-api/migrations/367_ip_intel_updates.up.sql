LOCK TABLE schema_migrations, artifact_catalog_entries IN ACCESS EXCLUSIVE MODE;

DO $migration_367_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 366 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 366 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=366 AND
        migration_id='366_aggregated_edge_schedule' AND
        checksum_sha256='27ea5f67dd2fdf1b5d1e224021832c5401266c1223fcca08324f1f83392d1b1d' AND
        down_checksum_sha256='99155af5c2dcc842ca8faa42770ccf8b2cddd212ece7b1145be983f79181da74' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.ip_intel_update_settings') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 367 requires the exact verified 366 release head' USING ERRCODE='P3670';
    END IF;
END;
$migration_367_up$;

-- PA-16 IP intelligence updates (official plugin module.ipintel.dnspup, ADR
-- 0007 section 4.4, user decisions 2026-10-17). The license service pulls the
-- base library once (ipintel/base); updates come from the platform's own
-- dnspup customer API key pair entered here. The control plane pulls the
-- snapshot on the schedule set here, builds the library locally
-- (libs/entitlement/ipintel/builder) and stores it as the local artifact
-- ipintel/local next to the catalog entries, requiring the feature
-- module.ipintel.dnspup: without that feature artifactsync does not return
-- it and the node artifact set falls back to ipintel/base. Nodes run the one
-- of the two whose data is newer (data_updated_at).
--
-- 1. artifact_catalog_entries.origin: 'catalog' rows come from the license
--    catalog (delivery_id set, withdrawn when no longer delivered); the one
--    'local' row is ipintel/local (no delivery, never withdrawn by the
--    catalog sync).
-- 2. ip_intel_update_settings: one row. api_key in clear (shown on the page),
--    api_secret sealed with the control-api credential keyring
--    (secret_key_id + secret_ciphertext, plaintext bound to its purpose),
--    write-only; secret_fingerprint only says "set / replaced". interval and
--    anchor (minute of day, IANA time zone) define the pull times.
-- 3. ip_intel_update_state: one row, the pull lease and last outcome.
-- 4. ip_intel_update_write_requests: idempotent settings / test / check writes.
-- 5. Permission system.ip_intel_updates.manage (platform owner).
-- No data is migrated (BATCH-PLUGIN section 9: fresh install).

ALTER TABLE artifact_catalog_entries
    ADD COLUMN origin text NOT NULL DEFAULT 'catalog' CHECK (origin IN ('catalog', 'local')),
    ALTER COLUMN delivery_id DROP NOT NULL,
    ADD CONSTRAINT artifact_catalog_entries_origin_367_ck CHECK (
        (origin = 'catalog' AND delivery_id IS NOT NULL) OR
        (origin = 'local' AND delivery_id IS NULL AND artifact_id = 'ipintel/local' AND kind = 'ipintel' AND
         requires_feature = 'module.ipintel.dnspup' AND NOT resident AND encryption = 'none'));

CREATE TABLE ip_intel_update_settings (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    enabled boolean NOT NULL DEFAULT false,
    url text NOT NULL DEFAULT '' CHECK (char_length(url) <= 2048),
    api_key text NOT NULL DEFAULT '' CHECK (char_length(api_key) <= 512),
    secret_key_id text CHECK (secret_key_id IS NULL OR char_length(secret_key_id) BETWEEN 1 AND 128),
    secret_ciphertext bytea CHECK (secret_ciphertext IS NULL OR octet_length(secret_ciphertext) BETWEEN 29 AND 4096),
    secret_fingerprint text NOT NULL DEFAULT '' CHECK (secret_fingerprint ~ '^([0-9a-f]{16})?$'),
    interval_minutes integer NOT NULL DEFAULT 1440 CHECK (interval_minutes BETWEEN 60 AND 43200),
    anchor_minute integer NOT NULL DEFAULT 240 CHECK (anchor_minute BETWEEN 0 AND 1439),
    time_zone text NOT NULL DEFAULT 'Asia/Shanghai' CHECK (char_length(time_zone) BETWEEN 1 AND 64),
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    updated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT ip_intel_update_settings_secret_367_ck CHECK (
        (secret_key_id IS NULL) = (secret_ciphertext IS NULL)
        AND (secret_ciphertext IS NULL) = (secret_fingerprint = '')),
    CONSTRAINT ip_intel_update_settings_enabled_367_ck CHECK (
        NOT enabled OR (url <> '' AND api_key <> '' AND secret_ciphertext IS NOT NULL))
);
INSERT INTO ip_intel_update_settings(singleton, updated_at) VALUES (true, CURRENT_TIMESTAMP);

CREATE TABLE ip_intel_update_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    last_checked_at timestamptz,
    last_success_at timestamptz,
    last_outcome text NOT NULL DEFAULT '' CHECK (
        last_outcome IN ('', 'not_modified', 'published', 'unchanged', 'pending', 'failed')),
    last_release text NOT NULL DEFAULT '' CHECK (char_length(last_release) <= 128),
    last_http_status integer NOT NULL DEFAULT 0 CHECK (last_http_status BETWEEN 0 AND 599),
    last_error_code text NOT NULL DEFAULT '' CHECK (last_error_code ~ '^[a-z_]{0,64}$'),
    last_error text NOT NULL DEFAULT '' CHECK (char_length(last_error) <= 500),
    next_check_at timestamptz,
    check_requested_at timestamptz,
    running_until timestamptz,
    updated_at timestamptz NOT NULL
);
INSERT INTO ip_intel_update_state(singleton, updated_at) VALUES (true, CURRENT_TIMESTAMP);

CREATE TABLE ip_intel_update_write_requests (
    actor_session_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    operation text NOT NULL CHECK (operation IN ('settings', 'test', 'check')),
    request_digest_sha256 bytea NOT NULL CHECK (octet_length(request_digest_sha256) = 32),
    response_body jsonb NOT NULL CHECK (jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    PRIMARY KEY (actor_session_id, idempotency_key)
);

INSERT INTO permissions(name, description)
VALUES ('system.ip_intel_updates.manage', 'Configure IP intelligence updates (dnspup customer API key pair and schedule)');

INSERT INTO role_permissions(role_id, permission_name)
SELECT role.id, 'system.ip_intel_updates.manage'
FROM roles role
JOIN access_scopes scope ON scope.id = role.scope_id AND scope.kind = 'platform'
WHERE role.system_role AND role.name = 'platform_owner'
ON CONFLICT DO NOTHING;

REVOKE ALL ON ip_intel_update_settings, ip_intel_update_state, ip_intel_update_write_requests FROM PUBLIC;
GRANT SELECT, UPDATE ON ip_intel_update_settings, ip_intel_update_state TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT ON ip_intel_update_write_requests TO cdnca_control_app, cdnca_control_runtime;
