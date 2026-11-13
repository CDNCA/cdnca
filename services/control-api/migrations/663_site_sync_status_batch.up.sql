-- 663：dashboard 的“同步失败站点数”对每个站点调一次 site_sync_status_503 →
--   site_publication_outcome_618（多 CTE 的 SQL 函数，不能内联），1 万站点实测 52s，超过 dashboard 5s 查询
--   超时（504）。这里加 site_sync_status_batch_663：同一份判定逻辑（618 + 619），对站点集合一次计算，
--   逐站结果必须与 site_sync_status_503(scope_id, site_id) 相等（等价性测试：internal/site
--   TestSiteSyncStatusBatchMatchesPerSitePostgres）。618/503 原函数不改，其余读方照旧。
--   参数 scope_ids：NULL = 所有作用域（管理员 dashboard），数组 = 只算这些作用域（租户 dashboard）。
--   只覆盖未删除站点（调用方都是 deleted_at IS NULL）。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_663_up$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) <> 662 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT count(*) FROM schema_migrations) <> 662 OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure('site_publication_outcome_618(uuid,uuid)') IS NULL
         OR to_regprocedure('site_sync_status_batch_663(uuid[])') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 663 requires the exact verified 662 release head' USING ERRCODE='P6630';
    END IF;
END;
$migration_663_up$;

CREATE FUNCTION site_sync_status_batch_663(scope_ids uuid[])
RETURNS TABLE (out_scope_id uuid, out_site_id uuid, sync_status text)
LANGUAGE sql STABLE AS $$
    WITH target AS (
        SELECT site.scope_id AS tscope, site.id AS tsite
        FROM sites site
        WHERE site.deleted_at IS NULL AND ($1 IS NULL OR site.scope_id = ANY($1))
    ), req AS (
        -- 每个站点最新的自动发布请求及其最新状态（618 的 request）
        SELECT DISTINCT ON (request_row.target_scope_id, request_row.source_resource_id)
            request_row.target_scope_id AS rscope, request_row.source_resource_id AS rsite,
            request_row.source_revision, latest.state, latest.terminal_code
        FROM edge_automatic_publication_requests request_row
        JOIN LATERAL (SELECT fact.state, fact.terminal_code FROM edge_automatic_publication_request_state_facts fact
            WHERE fact.request_id=request_row.id ORDER BY fact.sequence DESC LIMIT 1) latest ON true
        WHERE request_row.source_kind='site' AND ($1 IS NULL OR request_row.target_scope_id = ANY($1))
        ORDER BY request_row.target_scope_id, request_row.source_resource_id,
            request_row.created_at DESC, request_row.id DESC
    ), pub AS (
        -- 每个作用域最新的发布（618 的 publication，carries 在最后按站点判断）
        SELECT DISTINCT ON (published.configuration_scope_id)
            published.configuration_scope_id AS pscope, published.rollout_id, published.config_version_id,
            published.source_revision
        FROM edge_config_publications published
        WHERE $1 IS NULL OR published.configuration_scope_id = ANY($1)
        ORDER BY published.configuration_scope_id, published.created_at DESC, published.id DESC
    ), serving AS (
        -- 承担本站的节点（618 的 serving，两路 UNION）
        SELECT site.scope_id AS sscope, site.id AS ssite, endpoint.node_id
        FROM sites site
        LEFT JOIN package_subscriptions subscription ON subscription.tenant_scope_id=site.scope_id
         AND subscription.id=site.package_subscription_id AND subscription.deleted_at IS NULL
        LEFT JOIN escalate_site_routes route ON route.tenant_scope_id=site.scope_id AND route.site_id=site.id
        JOIN node_line_groups line_group ON line_group.deleted_at IS NULL AND line_group.id IN (
             site.node_group_id,
             (subscription.product_snapshot->'spec'->>'node_group_id')::uuid,
             (subscription.product_snapshot->'spec'->>'backup_node_group_id')::uuid,
             route.line_group_id, route.next_group_id)
        JOIN node_line_endpoints endpoint ON endpoint.tenant_scope_id=line_group.tenant_scope_id
         AND endpoint.line_group_id=line_group.id AND endpoint.config_revision=line_group.current_revision
         AND endpoint.enabled AND endpoint.node_id IS NOT NULL
        WHERE site.deleted_at IS NULL AND ($1 IS NULL OR site.scope_id = ANY($1))
        UNION
        SELECT site.scope_id, site.id, member.node_id
        FROM sites site
        JOIN site_origin_pools pool ON pool.site_id=site.id AND pool.l2_mode<>'off'
        LEFT JOIN package_subscriptions subscription ON subscription.tenant_scope_id=site.scope_id
         AND subscription.id=site.package_subscription_id AND subscription.deleted_at IS NULL
        LEFT JOIN node_line_groups line_group ON pool.l2_mode='package' AND line_group.deleted_at IS NULL
         AND line_group.id=COALESCE(site.node_group_id, (subscription.product_snapshot->'spec'->>'node_group_id')::uuid)
        JOIN l2_topology_configs config ON config.deleted_at IS NULL AND (
             pool.l2_mode='custom' AND config.tenant_scope_id=site.scope_id AND config.id=pool.l2_config_id OR
             pool.l2_mode='package' AND config.tenant_scope_id=line_group.tenant_scope_id AND config.id=line_group.l2_config_id)
        JOIN l2_topology_nodes member ON member.tenant_scope_id=config.tenant_scope_id AND member.config_id=config.id
         AND member.enabled AND member.deleted_at IS NULL
        WHERE site.deleted_at IS NULL AND ($1 IS NULL OR site.scope_id = ANY($1))
    ), latest AS (
        -- 最新发布的 rollout 里每个节点的最新部署
        SELECT pub.pscope, deployment.node_id, deployment.id, deployment.attempt, deployment.state,
            deployment.config_version_id
        FROM pub
        JOIN LATERAL (SELECT DISTINCT ON (d.node_id) d.node_id, d.id, d.attempt, d.state, d.config_version_id
            FROM node_deployments d WHERE d.rollout_id=pub.rollout_id
            ORDER BY d.node_id, d.attempt DESC, d.created_at DESC) deployment ON true
    ), deployed AS (
        SELECT serving.sscope, serving.ssite,
            CASE WHEN latest.state IN ('healthy','superseded')
                      OR config_state.current_config_version_id=latest.config_version_id THEN 'healthy'
                 WHEN latest.state IN ('failed','reverted','rollback_failed','cancelled') THEN 'failed'
                 ELSE 'pending' END AS outcome
        FROM serving
        JOIN latest ON latest.pscope=serving.sscope AND latest.node_id=serving.node_id
        JOIN nodes node ON node.id=latest.node_id AND node.admin_state='active'
        LEFT JOIN node_config_state config_state ON config_state.node_id=latest.node_id
         AND config_state.configuration_scope_id=serving.sscope
    ), summary AS (
        SELECT sscope, ssite, count(*) AS total, count(*) FILTER (WHERE outcome='healthy') AS healthy,
            count(*) FILTER (WHERE outcome='failed') AS failed
        FROM deployed GROUP BY sscope, ssite
    ), serving_active AS (
        -- 619：现在承担本站的 active 节点数，不论最新发布有没有到达它们
        SELECT serving.sscope, serving.ssite, count(*) AS total
        FROM serving JOIN nodes node ON node.id=serving.node_id AND node.admin_state='active'
        GROUP BY serving.sscope, serving.ssite
    ), inflight AS (
        -- 619：作用域内有在途的自动发布请求（任何来源）
        SELECT DISTINCT request_row.target_scope_id AS iscope
        FROM edge_automatic_publication_requests request_row
        JOIN LATERAL (SELECT fact.state FROM edge_automatic_publication_request_state_facts fact
            WHERE fact.request_id=request_row.id ORDER BY fact.sequence DESC LIMIT 1) latest ON true
        WHERE ($1 IS NULL OR request_row.target_scope_id = ANY($1))
          AND latest.state IN ('pending','leased','retry_wait','reconciling')
    )
    SELECT target.tscope, target.tsite,
        CASE decided.state
            WHEN 'failed' THEN 'failed' WHEN 'request_failed' THEN 'failed' WHEN 'undelivered' THEN 'failed'
            WHEN 'pending' THEN 'pending' ELSE 'synced' END
    FROM target
    LEFT JOIN req ON req.rscope=target.tscope AND req.rsite=target.tsite
    LEFT JOIN pub ON pub.pscope=target.tscope
    LEFT JOIN summary ON summary.sscope=target.tscope AND summary.ssite=target.tsite
    LEFT JOIN serving_active ON serving_active.sscope=target.tscope AND serving_active.ssite=target.tsite
    LEFT JOIN inflight ON inflight.iscope=target.tscope
    CROSS JOIN LATERAL (SELECT CASE
        WHEN req.state IN ('pending','leased','retry_wait','reconciling') THEN 'pending'
        WHEN req.state='failed' AND NOT EXISTS (SELECT 1 FROM edge_config_publications covering
             WHERE covering.configuration_scope_id=target.tscope AND covering.source_revision>=req.source_revision) THEN 'request_failed'
        WHEN pub.rollout_id IS NULL THEN ''
        WHEN NOT EXISTS (SELECT 1 FROM config_version_telemetry_site_bindings carried
             WHERE carried.config_version_id=pub.config_version_id AND carried.site_id=target.tsite) THEN 'excluded'
        WHEN COALESCE(summary.failed, 0) > 0 THEN 'failed'
        WHEN COALESCE(summary.total, 0) > 0 AND summary.healthy=summary.total THEN 'succeeded'
        WHEN COALESCE(summary.total, 0) = 0 AND COALESCE(serving_active.total, 0) > 0
             AND inflight.iscope IS NULL THEN 'undelivered'
        ELSE 'pending' END AS state) decided
$$;

REVOKE ALL ON FUNCTION site_sync_status_batch_663(uuid[]) FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='cdnca_control_app') THEN
        GRANT EXECUTE ON FUNCTION site_sync_status_batch_663(uuid[]) TO cdnca_control_app;
    END IF;
END $$;
