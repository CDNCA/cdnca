-- 503（r136 s5b PJ-C02，主会话 10-25 12:1x 定：sync_status 只由服务端派生，删 sites.sync_status 列）。
-- 本地占位 497，merge-p6 改号 503（前驱 502）。
-- 原列只有客户端写（建站缺省 synced），JA4 就绪、仪表盘同步失败数、列表/导出筛选都读它，等于由
-- 用户自报。派生值：该作用域里以本站为源资源的最新一条自动发布请求的最新状态——succeeded→synced、
-- failed→failed、其余（排队/执行/被新修订取代）→pending；本站没有任何请求（手动发布作用域、
-- 只有批量操作）→synced（同 l4forward syncStateExpression）。
LOCK TABLE schema_migrations, sites, dns_reconcile_provider_mutation_claims IN ACCESS EXCLUSIVE MODE;

DO $migration_503_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 502 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 502 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=502 AND
        migration_id='502_notification_event_subjects' AND
        checksum_sha256='3a1885578bdcd584f45113699c3d0fae0e44c4c91b24ba97ecbbb3b5c174140c' AND
        down_checksum_sha256='c222a60b7ce3ec9203929a3df0b49c20736d9221a3f6bb8e43ca16b80c32593d' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='sites' AND column_name='sync_status'
       ) THEN
        RAISE EXCEPTION 'migration 503 requires the exact verified 502 release head' USING ERRCODE='P5030';
    END IF;
    -- 089 DNS 认领把 dns_reconcile_site_config_digest_089(site) 钉在认领上并逐次复核；删列会改变
    -- 摘要，进行中的认领会被判冲突。要求先跑完。
    IF EXISTS (SELECT 1 FROM dns_reconcile_provider_mutation_claims WHERE state IN ('claimed','uncertain')) THEN
        RAISE EXCEPTION 'migration 503 needs no active DNS provider mutation claim' USING ERRCODE='P5031';
    END IF;
END;
$migration_503_up$;

CREATE INDEX edge_automatic_publication_requests_site_source_503_idx
    ON edge_automatic_publication_requests(target_scope_id, source_resource_id, created_at DESC, id DESC)
    WHERE source_kind='site' AND source_resource_id IS NOT NULL;

-- 唯一派生规则：Go 读方（站点列表/详情/筛选/导出、仪表盘、JA4 就绪）都调用它。
CREATE FUNCTION site_sync_status_503(scope_id uuid, site_id uuid) RETURNS text
LANGUAGE sql STABLE AS $$
    SELECT COALESCE((
        SELECT CASE state.state WHEN 'succeeded' THEN 'synced' WHEN 'failed' THEN 'failed' ELSE 'pending' END
        FROM edge_automatic_publication_requests request_row
        JOIN LATERAL (SELECT state FROM edge_automatic_publication_request_state_facts
            WHERE request_id=request_row.id ORDER BY sequence DESC LIMIT 1) state ON true
        WHERE request_row.target_scope_id=$1 AND request_row.source_kind='site' AND request_row.source_resource_id=$2
        ORDER BY request_row.created_at DESC, request_row.id DESC LIMIT 1
    ), 'synced')
$$;

-- 089 站点权威摘要去掉 sync_status（它不再是站点配置）；标签升 v2，其余字段与顺序不变。
-- 调用方（dnsproviderremotesource、475 守卫）按函数名调用，不用改。
CREATE OR REPLACE FUNCTION dns_reconcile_site_config_digest_089(checked_site sites)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT sha256(convert_to(jsonb_build_array(
        'cdnca:dns-reconcile:site-authority:v2',
        checked_site.id, checked_site.scope_id, checked_site.owner_user_id,
        checked_site.domain, checked_site.http_ports, checked_site.https_ports,
        checked_site.origins, checked_site.origin_hosts, checked_site.cname,
        checked_site.https_enabled, checked_site.enabled, checked_site.status,
        checked_site.is_default,
        checked_site.package_id, checked_site.package_name,
        checked_site.group_id, checked_site.group_name, checked_site.group_active,
        checked_site.region_id, checked_site.region_name,
        checked_site.node_group_id, checked_site.node_group_name,
        checked_site.lock_reason, checked_site.locked_by_user_id,
        checked_site.locked_at IS NOT NULL, checked_site.deleted_at IS NOT NULL
    )::text, 'UTF8'))
$$;

ALTER TABLE sites DROP COLUMN sync_status;

REVOKE ALL ON FUNCTION site_sync_status_503(uuid, uuid) FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='cdnca_control_app') THEN
        GRANT EXECUTE ON FUNCTION site_sync_status_503(uuid, uuid) TO cdnca_control_app;
    END IF;
END $$;
