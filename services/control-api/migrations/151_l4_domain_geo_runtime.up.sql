LOCK TABLE schema_migrations, sites, l4_forwards, l4_publish_intents IN ACCESS EXCLUSIVE MODE;

DO $migration_151$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 150 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 150 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 150 AND migration_id = '150_node_metrics' AND
              checksum_sha256 = 'bfa06ab9348dd9791060bd7624747234507d8dca015934070e0bdf6f04b89a65' AND
              down_checksum_sha256 = 'c9702eddf7dbe49c1404da9acdcf4a8e26ce72adf599cb898dde355fd5903d22' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name IN ('l4_forwards', 'l4_publish_intents') AND
              column_name IN ('site_id', 'upstream_host', 'remark', 'dns_policy', 'geo_policy', 'proxy_protocol_inbound')
    ) OR to_regprocedure('validate_l4_runtime_spec_151(uuid,uuid,uuid,jsonb)') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 151 requires the exact verified 150 release head'
            USING ERRCODE = 'P1510';
    END IF;
END;
$migration_151$;

ALTER TABLE l4_forwards
    ADD COLUMN site_id uuid,
    ADD COLUMN remark text NOT NULL DEFAULT '' CHECK (remark = btrim(remark) AND char_length(remark) <= 256),
    ALTER COLUMN upstream_address DROP NOT NULL,
    ADD COLUMN upstream_host text,
    ADD COLUMN dns_policy jsonb NOT NULL DEFAULT '{"positive_min_ttl_seconds":0,"positive_max_ttl_seconds":0,"negative_ttl_seconds":0,"stale_if_error_seconds":0,"allow_private_addresses":false}'::jsonb,
    ADD COLUMN geo_policy jsonb NOT NULL DEFAULT '{"enabled":false,"unknown_region_action":"allow","trusted_proxy_cidrs":[],"blocked_regions":[],"region_cidrs":[]}'::jsonb,
    ADD COLUMN proxy_protocol_inbound boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT l4_forwards_site_scope_151
        FOREIGN KEY (scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT l4_forwards_id_scope_site_151 UNIQUE (id, scope_id, site_id),
    ADD CONSTRAINT l4_forwards_endpoint_151 CHECK (
        (upstream_address IS NOT NULL AND upstream_host IS NULL) OR
        (upstream_address IS NULL AND site_id IS NOT NULL AND upstream_host IS NOT NULL AND
         upstream_host = lower(upstream_host) AND upstream_host = btrim(upstream_host) AND
         char_length(upstream_host) BETWEEN 1 AND 253)
    ),
    ADD CONSTRAINT l4_forwards_runtime_facts_151 CHECK (
        jsonb_typeof(dns_policy) = 'object' AND jsonb_typeof(geo_policy) = 'object' AND
        (
            site_id IS NOT NULL OR
            (upstream_host IS NULL AND NOT proxy_protocol_inbound AND
             dns_policy = '{"positive_min_ttl_seconds":0,"positive_max_ttl_seconds":0,"negative_ttl_seconds":0,"stale_if_error_seconds":0,"allow_private_addresses":false}'::jsonb AND
             geo_policy = '{"enabled":false,"unknown_region_action":"allow","trusted_proxy_cidrs":[],"blocked_regions":[],"region_cidrs":[]}'::jsonb)
        )
    );

CREATE FUNCTION validate_l4_runtime_spec_151(
    target_stream_id uuid, target_scope_id uuid, target_site_id uuid, runtime_spec jsonb
) RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    endpoint jsonb;
    dns jsonb;
    geo jsonb;
    listener jsonb;
    top_level_keys text[];
    endpoint_keys text[];
    dns_keys text[];
    geo_keys text[];
    listener_keys text[];
    region_entry jsonb;
BEGIN
    IF target_site_id IS NULL THEN
        RETURN validate_l4_runtime_spec_092(target_stream_id, runtime_spec);
    END IF;
    IF target_stream_id IS NULL OR target_scope_id IS NULL OR runtime_spec IS NULL OR
       jsonb_typeof(runtime_spec) <> 'object' OR runtime_spec ->> 'schema_version' <> 'cdnca.edge.l4/v2' THEN
        RETURN false;
    END IF;

    SELECT array_agg(key ORDER BY key) INTO top_level_keys FROM jsonb_object_keys(runtime_spec) keys(key);
    IF top_level_keys IS DISTINCT FROM ARRAY[
        'connect_timeout_ms','dns','drain_timeout_ms','endpoint','geo','listener',
        'max_connections_per_client','proxy_protocol_inbound','proxy_protocol_outbound',
        'response_timeout_ms','revision','schema_version','site_id','stream_id','tenant_id'
    ]::text[] THEN
        RETURN false;
    END IF;

    listener := runtime_spec -> 'listener';
    endpoint := runtime_spec -> 'endpoint';
    dns := runtime_spec -> 'dns';
    geo := runtime_spec -> 'geo';
    IF jsonb_typeof(listener) <> 'object' OR jsonb_typeof(endpoint) <> 'object' OR
       jsonb_typeof(dns) <> 'object' OR jsonb_typeof(geo) <> 'object' THEN
        RETURN false;
    END IF;
    SELECT array_agg(key ORDER BY key) INTO listener_keys FROM jsonb_object_keys(listener) keys(key);
    SELECT array_agg(key ORDER BY key) INTO endpoint_keys FROM jsonb_object_keys(endpoint) keys(key);
    SELECT array_agg(key ORDER BY key) INTO dns_keys FROM jsonb_object_keys(dns) keys(key);
    SELECT array_agg(key ORDER BY key) INTO geo_keys FROM jsonb_object_keys(geo) keys(key);
    IF listener_keys IS DISTINCT FROM ARRAY['address','port','protocol']::text[] OR
       endpoint_keys NOT IN (ARRAY['address','port']::text[], ARRAY['host','port']::text[]) OR
       dns_keys IS DISTINCT FROM ARRAY[
           'allow_private_addresses','negative_ttl_seconds','positive_max_ttl_seconds',
           'positive_min_ttl_seconds','stale_if_error_seconds'
       ]::text[] OR
       geo_keys IS DISTINCT FROM ARRAY[
           'blocked_regions','enabled','region_cidrs','revision','site_id','stream_id','tenant_id',
           'trusted_proxy_cidrs','unknown_region_action'
       ]::text[] THEN
        RETURN false;
    END IF;

    IF jsonb_typeof(geo -> 'trusted_proxy_cidrs') <> 'array' OR
       jsonb_typeof(geo -> 'blocked_regions') <> 'array' OR
       jsonb_typeof(geo -> 'region_cidrs') <> 'array' OR EXISTS (
        SELECT 1 FROM jsonb_array_elements(geo -> 'trusted_proxy_cidrs') value WHERE jsonb_typeof(value) <> 'string'
    ) OR EXISTS (
        SELECT 1 FROM jsonb_array_elements(geo -> 'blocked_regions') value WHERE jsonb_typeof(value) <> 'string'
    ) THEN
        RETURN false;
    END IF;
    FOR region_entry IN SELECT value FROM jsonb_array_elements(geo -> 'region_cidrs') value LOOP
        IF jsonb_typeof(region_entry) <> 'object' OR
           (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(region_entry) keys(key))
               IS DISTINCT FROM ARRAY['cidrs','region']::text[] OR
           jsonb_typeof(region_entry -> 'region') <> 'string' OR
           jsonb_typeof(region_entry -> 'cidrs') <> 'array' OR EXISTS (
               SELECT 1 FROM jsonb_array_elements(region_entry -> 'cidrs') value WHERE jsonb_typeof(value) <> 'string'
           ) THEN
            RETURN false;
        END IF;
    END LOOP;

    RETURN COALESCE(
        (runtime_spec ->> 'tenant_id')::uuid = target_scope_id AND
        (runtime_spec ->> 'site_id')::uuid = target_site_id AND
        (runtime_spec ->> 'stream_id')::uuid = target_stream_id AND
        (runtime_spec ->> 'revision')::bigint > 0 AND
        listener ->> 'protocol' IN ('tcp', 'udp') AND listener ->> 'address' = '*' AND
        (listener ->> 'port')::integer BETWEEN 1 AND 65535 AND
        (endpoint ->> 'port')::integer BETWEEN 1 AND 65535 AND
        (runtime_spec ->> 'connect_timeout_ms')::integer BETWEEN 50 AND 30000 AND
        (runtime_spec ->> 'response_timeout_ms')::integer BETWEEN 100 AND 600000 AND
        (runtime_spec ->> 'max_connections_per_client')::integer BETWEEN 1 AND 10000 AND
        (runtime_spec ->> 'drain_timeout_ms')::integer BETWEEN 1000 AND 600000 AND
        (geo ->> 'tenant_id')::uuid = target_scope_id AND
        (geo ->> 'site_id')::uuid = target_site_id AND
        (geo ->> 'stream_id')::uuid = target_stream_id AND
        (geo ->> 'revision')::bigint = (runtime_spec ->> 'revision')::bigint AND
        geo ->> 'unknown_region_action' IN ('allow', 'block') AND
        NOT (dns ->> 'allow_private_addresses')::boolean AND
        (
            endpoint ? 'address' AND dns = '{"positive_min_ttl_seconds":0,"positive_max_ttl_seconds":0,"negative_ttl_seconds":0,"stale_if_error_seconds":0,"allow_private_addresses":false}'::jsonb OR
            endpoint ? 'host' AND
            (dns ->> 'positive_min_ttl_seconds')::integer BETWEEN 1 AND 300 AND
            (dns ->> 'positive_max_ttl_seconds')::integer BETWEEN (dns ->> 'positive_min_ttl_seconds')::integer AND 86400 AND
            (dns ->> 'negative_ttl_seconds')::integer BETWEEN 1 AND 3600 AND
            (dns ->> 'stale_if_error_seconds')::integer BETWEEN (dns ->> 'positive_max_ttl_seconds')::integer AND 86400
        ) AND
        (listener ->> 'protocol' = 'tcp' OR
         (NOT (runtime_spec ->> 'proxy_protocol_inbound')::boolean AND
          NOT (runtime_spec ->> 'proxy_protocol_outbound')::boolean)), false);
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;

REVOKE ALL ON FUNCTION validate_l4_runtime_spec_151(uuid, uuid, uuid, jsonb) FROM PUBLIC;

ALTER TABLE l4_publish_intents
    DROP CONSTRAINT l4_publish_intents_runtime_spec_092,
    ADD COLUMN site_id uuid,
    ADD CONSTRAINT l4_publish_intents_stream_scope_site_151
        FOREIGN KEY (stream_id, scope_id, site_id)
        REFERENCES l4_forwards(id, scope_id, site_id) ON DELETE RESTRICT,
    ADD CONSTRAINT l4_publish_intents_site_schema_151 CHECK (
        (site_id IS NULL AND runtime_spec ->> 'schema_version' IS NULL) OR
        (site_id IS NOT NULL AND runtime_spec ->> 'schema_version' = 'cdnca.edge.l4/v2')
    ),
    ADD CONSTRAINT l4_publish_intents_runtime_spec_151
        CHECK (validate_l4_runtime_spec_151(stream_id, scope_id, site_id, runtime_spec));
