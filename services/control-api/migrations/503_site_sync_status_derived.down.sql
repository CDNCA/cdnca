-- 503（r136 s5b PJ-C02）回退：恢复 sites.sync_status 列（全部 synced）与 089 v1 站点权威摘要。
LOCK TABLE schema_migrations, sites, dns_reconcile_provider_mutation_claims IN ACCESS EXCLUSIVE MODE;

DO $migration_503_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 503 OR
       (SELECT max(version) FROM schema_migrations) <> 503 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=503 AND
        migration_id='503_site_sync_status_derived' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 503 down requires the exact verified migration head' USING ERRCODE='P5032';
    END IF;
    IF EXISTS (SELECT 1 FROM dns_reconcile_provider_mutation_claims WHERE state IN ('claimed','uncertain')) THEN
        RAISE EXCEPTION 'migration 503 down needs no active DNS provider mutation claim' USING ERRCODE='P5033';
    END IF;
END;
$migration_503_down$;

-- 不回填：UPDATE sites 会推进作用域源修订并经过站点触发器；旧二进制建站缺省也是 synced。
ALTER TABLE sites ADD COLUMN sync_status text NOT NULL DEFAULT 'synced'
    CHECK (sync_status IN ('synced', 'pending', 'failed'));

CREATE OR REPLACE FUNCTION dns_reconcile_site_config_digest_089(checked_site sites)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT sha256(convert_to(jsonb_build_array(
        'cdnca:dns-reconcile:site-authority:v1',
        checked_site.id, checked_site.scope_id, checked_site.owner_user_id,
        checked_site.domain, checked_site.http_ports, checked_site.https_ports,
        checked_site.origins, checked_site.origin_hosts, checked_site.cname,
        checked_site.https_enabled, checked_site.enabled, checked_site.status,
        checked_site.sync_status, checked_site.is_default,
        checked_site.package_id, checked_site.package_name,
        checked_site.group_id, checked_site.group_name, checked_site.group_active,
        checked_site.region_id, checked_site.region_name,
        checked_site.node_group_id, checked_site.node_group_name,
        checked_site.lock_reason, checked_site.locked_by_user_id,
        checked_site.locked_at IS NOT NULL, checked_site.deleted_at IS NOT NULL
    )::text, 'UTF8'))
$$;

DROP FUNCTION site_sync_status_503(uuid, uuid);
DROP INDEX edge_automatic_publication_requests_site_source_503_idx;
