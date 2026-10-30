LOCK TABLE schema_migrations, sites, nodes IN ACCESS EXCLUSIVE MODE;

DO $migration_390_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 389 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 389 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=389 AND
        migration_id='389_acme_ca_credentials' AND
        checksum_sha256='7ed8cf7fc6ce984a50f5316ab13456c7bc23f89a6c6403351602723a36dcc044' AND
        down_checksum_sha256='0696ea87dff35b604c11a9c2325b52d057bd8f33e21ace16154421d6b1bbe226' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('site_schedule302_settings') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 390 requires the exact verified 389 release head' USING ERRCODE='P3900';
    END IF;
END;
$migration_390_up$;

-- r136 sched302 (placeholder number; renumbered on merge): HTTP 302
-- scheduling ("DNS + 302 双调度"). A site's settings
-- (libs/edgeconfig/sched302.Site) and its signing key; a site without a row
-- is not scheduled. A write advances sites.revision (GET ETag / PUT If-Match)
-- and publishes the site as every site setting does. The key never leaves
-- the control plane except in the signed scheduling table pushed to the
-- site's nodes (ConnectResponse.sched302_table).
CREATE TABLE site_schedule302_settings (
    scope_id uuid NOT NULL,
    site_id uuid PRIMARY KEY,
    target text NOT NULL CHECK (target IN ('address', 'hostname')),
    keep_path boolean NOT NULL,
    keep_query boolean NOT NULL,
    signature_ttl_seconds integer NOT NULL CHECK (signature_ttl_seconds BETWEEN 10 AND 3600),
    https_to_http boolean NOT NULL,
    extensions text[] NOT NULL CHECK (cardinality(extensions) <= 64),
    path_prefixes text[] NOT NULL CHECK (cardinality(path_prefixes) <= 32),
    min_size_bytes bigint NOT NULL CHECK (min_size_bytes BETWEEN 0 AND 1099511627776),
    sign_key bytea NOT NULL CHECK (octet_length(sign_key) = 32),
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE
);

CREATE INDEX site_schedule302_settings_scope_idx ON site_schedule302_settings (scope_id);

CREATE TABLE site_schedule302_write_requests (
    id uuid PRIMARY KEY,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    response_body jsonb NOT NULL CHECK (jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL,
    UNIQUE (actor_scope_id, actor_user_id, idempotency_key)
);

CREATE INDEX site_schedule302_write_requests_scope_created_idx
    ON site_schedule302_write_requests (target_scope_id, created_at DESC);

-- A node's direct hostname (where target=hostname sends scheduled clients;
-- it must resolve to the node, the operator's DNS) is
-- nodes.management_settings->>'schedule302_hostname': optional, a lower-case
-- hostname, unique among nodes.
ALTER TABLE nodes ADD CONSTRAINT nodes_schedule302_hostname_390_check CHECK (
    management_settings->'schedule302_hostname' IS NULL OR (
        jsonb_typeof(management_settings->'schedule302_hostname') = 'string' AND
        char_length(management_settings->>'schedule302_hostname') BETWEEN 4 AND 253 AND
        management_settings->>'schedule302_hostname' = lower(management_settings->>'schedule302_hostname') AND
        management_settings->>'schedule302_hostname' ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$'));

CREATE UNIQUE INDEX nodes_schedule302_hostname_390_idx ON nodes ((management_settings->>'schedule302_hostname'))
    WHERE management_settings ? 'schedule302_hostname';

-- Per node: the last scheduling table pushed (revision only grows; digest
-- of the table body without generated_at, so an unchanged table is only
-- refreshed, not re-sent, until its hold half-life).
CREATE TABLE node_schedule302_tables (
    node_id uuid PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision > 0),
    content_sha256 bytea NOT NULL CHECK (octet_length(content_sha256) = 32),
    pushed_at timestamptz NOT NULL
);

GRANT SELECT, INSERT, UPDATE, DELETE ON site_schedule302_settings, site_schedule302_write_requests,
    node_schedule302_tables TO cdnca_control_app, cdnca_control_runtime;
