LOCK TABLE schema_migrations, node_line_groups, node_line_group_revisions, dns_providers,
    node_serving_holds, node_serving_events IN ACCESS EXCLUSIVE MODE;

DO $migration_376_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 375 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 375 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=375 AND
        migration_id='375_aggregated_edge_sync' AND
        checksum_sha256='d2308d69879b56ad3e8c9f7e949040be172ee0a885c7e35ae82e7a53f36eaabf' AND
        down_checksum_sha256='aa57e0f7c659acf870036af06900e12be5325abaf735b22c390aa36bdbb90071' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 376 requires the exact verified 375 release head' USING ERRCODE='P3760';
    END IF;
END;
$migration_376_up$;

-- GoEdge parity G6 (r136 ge-nodes).

-- Logic item 8: failover_mode 'interval' had no rotation semantics and ran
-- as primary_offline. New writes are limited to the two implemented modes;
-- sealed history is left as is (NOT VALID), 1.0.35 migrates no data.
ALTER TABLE node_line_groups
    DROP CONSTRAINT node_line_groups_failover_mode_234_check,
    ADD CONSTRAINT node_line_groups_failover_mode_376_check CHECK (
        failover_mode IN ('primary_offline', 'online_less_than_backup_count')
    ) NOT VALID;
ALTER TABLE node_line_group_revisions
    DROP CONSTRAINT node_line_group_revisions_failover_mode_234_check,
    ADD CONSTRAINT node_line_group_revisions_failover_mode_376_check CHECK (
        failover_mode IN ('primary_offline', 'online_less_than_backup_count')
    ) NOT VALID;

-- Item 4 / logic 4: the site CNAME owner per carrier DNS line. The default
-- line keeps every published address (cnameallocation); each non-default
-- line (telecom/unicom/mobile/overseas) holds the published endpoints whose
-- carrier/region map to it. One row per (site, line) this controller wrote;
-- no row = the line is not ours (empty, or the aggregated edge's).
CREATE TABLE cname_carrier_line_records (
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    line_scope text NOT NULL CHECK (line_scope IN ('telecom', 'unicom', 'mobile', 'overseas')),
    desired_digest text NOT NULL CHECK (desired_digest ~ '^[0-9a-f]{64}$'),
    published_digest text CHECK (published_digest IS NULL OR published_digest ~ '^[0-9a-f]{64}$'),
    published_a text[] NOT NULL DEFAULT '{}',
    published_aaaa text[] NOT NULL DEFAULT '{}',
    published_at timestamptz CHECK (published_at IS NULL OR isfinite(published_at)),
    publish_error text NOT NULL DEFAULT '' CHECK (char_length(publish_error) <= 64),
    next_attempt_at timestamptz NOT NULL CHECK (isfinite(next_attempt_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (site_id, line_scope)
);
REVOKE ALL ON cname_carrier_line_records FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON cname_carrier_line_records TO cdnca_control_app, cdnca_control_runtime;

-- Item 12: the "自定义 HTTP 接口" DNS provider (custom_http): the operator's
-- own DNS behind a signed HTTPS endpoint (docs/dns/custom-http-provider.md).
ALTER TABLE dns_providers DROP CONSTRAINT dns_providers_provider_type_check;
ALTER TABLE dns_providers ADD CONSTRAINT dns_providers_provider_type_check CHECK (
    provider_type IN ('aliyun', 'cloudflare', 'huawei', 'dnspod_cn', 'dns_com', 'dnsdun', 'dns_la', 'custom_http')
);

-- Items 3/15, logic 1/2/3: external probes (controller + peer nodes per
-- monitoring group, nodeprobe) hold a node whose every published endpoint is
-- unreachable from outside; node_line_endpoint_serving removes a node held
-- by any source and keeps its fail-open.
ALTER TABLE node_serving_holds DROP CONSTRAINT node_serving_holds_source_check,
    ADD CONSTRAINT node_serving_holds_source_check
        CHECK (source IN ('availability_monitor', 'auto_disable', 'config_sync', 'external_probe'));
ALTER TABLE node_serving_events DROP CONSTRAINT node_serving_events_source_check,
    ADD CONSTRAINT node_serving_events_source_check
        CHECK (source IN ('availability_monitor', 'auto_disable', 'config_sync', 'external_probe'));

-- Items 1/2: SSH remote installation (nodesshinstall). One row per target
-- host; a batch shares batch_id. The SSH secret is an AES-GCM envelope bound
-- to the row (dnsacme.AESGCMCredentialCipher) and is wiped when the job ends.
-- progress keeps only the installer's own "[cdnca-edge]" lines.
CREATE TABLE node_ssh_install_jobs (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE CASCADE,
    batch_id uuid NOT NULL,
    host text NOT NULL CHECK (char_length(host) BETWEEN 1 AND 253),
    port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    username text NOT NULL CHECK (username ~ '^[a-z_][a-z0-9_.-]{0,31}$'),
    auth_kind text NOT NULL CHECK (auth_kind IN ('password', 'private_key')),
    node_name text NOT NULL DEFAULT '' CHECK (char_length(node_name) <= 128),
    node_region text NOT NULL DEFAULT 'default' CHECK (node_region ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    control_plane text NOT NULL CHECK (control_plane ~ '^https://[^/?#@ ]+$'),
    host_key_sha256 text NOT NULL DEFAULT '' CHECK (host_key_sha256 = '' OR host_key_sha256 ~ '^SHA256:[A-Za-z0-9+/]{43}$'),
    host_key_confirmed boolean NOT NULL DEFAULT false,
    credential_key_id text NOT NULL DEFAULT '',
    credential_ciphertext bytea,
    state text NOT NULL CHECK (state IN ('awaiting_host_key', 'pending', 'running', 'succeeded', 'failed', 'cancelled')),
    failure_code text NOT NULL DEFAULT '' CHECK (failure_code ~ '^([a-z][a-z0-9_]{0,63})?$'),
    progress text[] NOT NULL DEFAULT '{}' CHECK (cardinality(progress) <= 200),
    node_id uuid REFERENCES nodes(id) ON DELETE SET NULL,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 10),
    lease_owner text NOT NULL DEFAULT '',
    lease_until timestamptz,
    created_by_user_id uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL,
    started_at timestamptz,
    finished_at timestamptz,
    updated_at timestamptz NOT NULL,
    -- A secret only while the job can still run.
    CHECK ((credential_ciphertext IS NOT NULL) = (state IN ('awaiting_host_key', 'pending', 'running'))),
    CHECK (state <> 'pending' OR host_key_confirmed),
    CHECK ((state IN ('succeeded', 'failed', 'cancelled')) = (finished_at IS NOT NULL))
);
CREATE INDEX node_ssh_install_jobs_due_376_idx ON node_ssh_install_jobs (state, created_at) WHERE state IN ('pending', 'running');
CREATE INDEX node_ssh_install_jobs_batch_376_idx ON node_ssh_install_jobs (scope_id, batch_id, created_at);
-- One live job per host and port.
CREATE UNIQUE INDEX node_ssh_install_jobs_live_host_376_idx ON node_ssh_install_jobs (scope_id, host, port)
    WHERE state IN ('awaiting_host_key', 'pending', 'running');
REVOKE ALL ON node_ssh_install_jobs FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON node_ssh_install_jobs TO cdnca_control_app, cdnca_control_runtime;
