LOCK TABLE schema_migrations, site_origin_pools, site_origins, site_origin_routes IN ACCESS EXCLUSIVE MODE;

DO $migration_379_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 378 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 378 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=378 AND
        migration_id='378_node_external_probe_setting' AND
        checksum_sha256='0a8f26000686f9e8af3b740ec8ec2c5a416d244ed51e88e2b6ffa9b8e5e2f8ae' AND
        down_checksum_sha256='8e4181c14a12722f3b5c655dcfbb47aba48876b49f7a39ad8e35d949b68dea4b' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='site_origin_pools' AND column_name='request_host_mode'
       ) OR to_regclass(current_schema() || '.site_origin_trust_bundles') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 379 requires the exact verified 378 release head' USING ERRCODE='P3790';
    END IF;
END;
$migration_379_up$;

-- GoEdge comparison G3 (origin): how the edge talks to a site's origins.
--   balance: hash (custom key) and sticky (cookie/header/argument) join the
--     existing methods; random now really is random (rendering only).
--   request Host: the visitor's (default), the origin's host name, or a
--     custom value.
--   scheme: http, https (SNI defaults to the request Host; the certificate is
--     always verified, against the node's system CAs or a custom CA bundle),
--     or follow (TLS listeners use https on https_port).
--   follow_port: the origin port is the listener's public port.
--   websocket: per site, with an optional Origin allowlist.
--   trusted_proxy_cidrs: peers whose X-Forwarded-For / X-Real-IP the edge
--     keeps; anyone else's are replaced by the peer address.
-- Origins gain backup (used only when every primary origin is down) and
-- max_conns (0: unlimited). Conditional origin routes may match the request
-- host.
ALTER TABLE site_origin_pools
    DROP CONSTRAINT site_origin_pools_balance_method_check,
    ADD CONSTRAINT site_origin_pools_balance_method_check CHECK (
        balance_method IN ('round_robin', 'ip_hash', 'url_hash', 'least_conn', 'random', 'hash', 'sticky')
    ),
    ADD COLUMN hash_key text CHECK (hash_key IS NULL OR char_length(hash_key) BETWEEN 1 AND 256),
    ADD COLUMN sticky_source text CHECK (sticky_source IS NULL OR sticky_source IN ('cookie', 'header', 'arg')),
    ADD COLUMN sticky_name text CHECK (sticky_name IS NULL OR sticky_name ~ '^[A-Za-z0-9_-]{1,64}$'),
    ADD COLUMN request_host_mode text NOT NULL DEFAULT 'visitor'
        CHECK (request_host_mode IN ('visitor', 'origin', 'custom')),
    ADD COLUMN request_host text CHECK (request_host IS NULL OR char_length(request_host) BETWEEN 1 AND 259),
    ADD COLUMN origin_scheme text NOT NULL DEFAULT 'http' CHECK (origin_scheme IN ('http', 'https', 'follow')),
    ADD COLUMN https_port integer NOT NULL DEFAULT 443 CHECK (https_port BETWEEN 1 AND 65535),
    ADD COLUMN tls_sni text CHECK (tls_sni IS NULL OR char_length(tls_sni) BETWEEN 1 AND 253),
    ADD COLUMN tls_trust text NOT NULL DEFAULT 'system' CHECK (tls_trust IN ('system', 'custom')),
    ADD COLUMN tls_ca_pem text CHECK (tls_ca_pem IS NULL OR octet_length(tls_ca_pem) BETWEEN 1 AND 65536),
    ADD COLUMN tls_ca_sha256 bytea CHECK (tls_ca_sha256 IS NULL OR octet_length(tls_ca_sha256) = 32),
    ADD COLUMN follow_port boolean NOT NULL DEFAULT false,
    ADD COLUMN websocket_enabled boolean NOT NULL DEFAULT true,
    ADD COLUMN websocket_allowed_origins text[] NOT NULL DEFAULT ARRAY[]::text[]
        CHECK (cardinality(websocket_allowed_origins) <= 64),
    ADD COLUMN trusted_proxy_cidrs cidr[] NOT NULL DEFAULT ARRAY[]::cidr[]
        CHECK (cardinality(trusted_proxy_cidrs) <= 64),
    ADD CONSTRAINT site_origin_pools_hash_key_379 CHECK ((balance_method = 'hash') = (hash_key IS NOT NULL)),
    ADD CONSTRAINT site_origin_pools_sticky_379 CHECK (
        (balance_method = 'sticky') = (sticky_source IS NOT NULL) AND (sticky_source IS NULL) = (sticky_name IS NULL)
    ),
    ADD CONSTRAINT site_origin_pools_request_host_379 CHECK ((request_host_mode = 'custom') = (request_host IS NOT NULL)),
    ADD CONSTRAINT site_origin_pools_tls_ca_379 CHECK (
        (tls_trust = 'custom') = (tls_ca_pem IS NOT NULL) AND
        (tls_ca_pem IS NULL) = (tls_ca_sha256 IS NULL) AND
        (tls_ca_sha256 IS NULL OR tls_ca_sha256 = sha256(convert_to(tls_ca_pem, 'UTF8')))
    ),
    ADD CONSTRAINT site_origin_pools_tls_379 CHECK (
        (origin_scheme <> 'http' OR (tls_sni IS NULL AND tls_trust = 'system')) AND
        (origin_scheme = 'follow' OR https_port = 443)
    );

ALTER TABLE site_origins
    ADD COLUMN backup boolean NOT NULL DEFAULT false,
    ADD COLUMN max_conns integer NOT NULL DEFAULT 0 CHECK (max_conns BETWEEN 0 AND 100000);

ALTER TABLE site_origin_routes
    ADD COLUMN hosts text[] NOT NULL DEFAULT ARRAY[]::text[] CHECK (cardinality(hosts) <= 100),
    DROP CONSTRAINT site_origin_routes_check,
    ADD CONSTRAINT site_origin_routes_condition_379 CHECK (
        path_prefix IS NOT NULL OR cardinality(node_regions) > 0 OR cardinality(client_cidrs) > 0 OR cardinality(hosts) > 0
    );

-- Custom origin CA bundles by content: a publication ships the bundles its
-- sites name (origin-trust/<sha256>.pem), and a republication of a captured
-- document still finds a bundle the site has since replaced.
CREATE TABLE site_origin_trust_bundles (
    sha256 bytea PRIMARY KEY CHECK (octet_length(sha256) = 32),
    pem text NOT NULL CHECK (octet_length(pem) BETWEEN 1 AND 65536),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (sha256 = sha256(convert_to(pem, 'UTF8')))
);

-- A pool needs a primary (non-backup) enabled origin.
CREATE OR REPLACE FUNCTION validate_site_origin_pool(target_site_id uuid) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    pool_failover smallint;
    origin_count integer;
    enabled_count integer;
    primary_count integer;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM sites WHERE id = target_site_id) THEN
        RETURN;
    END IF;

    SELECT failover_tries
    INTO pool_failover
    FROM site_origin_pools
    WHERE site_id = target_site_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'site origin pool is required for site %', target_site_id
            USING ERRCODE = '23514';
    END IF;

    SELECT count(*), count(*) FILTER (WHERE enabled), count(*) FILTER (WHERE enabled AND NOT backup)
    INTO origin_count, enabled_count, primary_count
    FROM site_origins
    WHERE site_id = target_site_id;

    IF origin_count < 1 OR origin_count > 32 OR enabled_count < 1 OR primary_count < 1 OR
       pool_failover > enabled_count THEN
        RAISE EXCEPTION 'site origin pool invariant failed for site %', target_site_id
            USING ERRCODE = '23514';
    END IF;
END;
$$;
