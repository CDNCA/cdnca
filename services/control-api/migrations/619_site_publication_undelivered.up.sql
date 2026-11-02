-- 619（r136 fix-edgeboot，前驱 618，合入时按连号改号）：site_publication_outcome_618 把“承担本站的
--   节点都不在最近一次发布的 rollout 里”判成 pending（发布中），而 site.Republish 在 pending 时返回
--   409 ErrPublishInFlight。73 上重装的 78/85 加回线路组后，最近一次发布（rev 112）的部署只在已删除
--   的旧节点上，线路组重新发布又一直失败到截止：接入状态永远“发布中”，“重新发布”永远 409，站点
--   永远到不了新节点（OpenResty 不拉起，全部 503）。
--   规则：承担本站的 active 节点存在、最近一次发布在它们上面一条部署都没有、作用域也没有在途的自动
--   发布请求 → failed，terminal_code=serving_nodes_undelivered。
--   其余判定与 618 完全相同。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_619_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 618 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 618 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=618 AND migration_id='618_site_publication_outcome' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure('site_publication_outcome_618(uuid,uuid)') IS NULL THEN
        RAISE EXCEPTION 'migration 619 requires the verified 618 release head with site_publication_outcome_618'
            USING ERRCODE='P6190';
    END IF;
END;
$migration_619_up$;

CREATE OR REPLACE FUNCTION site_publication_outcome_618(scope_id uuid, site_id uuid,
    OUT state text, OUT terminal_code text, OUT failed_nodes jsonb)
LANGUAGE sql STABLE AS $$
    WITH request AS (
        SELECT request_row.source_revision, latest.state, latest.terminal_code
        FROM edge_automatic_publication_requests request_row
        JOIN LATERAL (SELECT fact.state, fact.terminal_code FROM edge_automatic_publication_request_state_facts fact
            WHERE fact.request_id=request_row.id ORDER BY fact.sequence DESC LIMIT 1) latest ON true
        WHERE request_row.target_scope_id=$1 AND request_row.source_kind='site' AND request_row.source_resource_id=$2
        ORDER BY request_row.created_at DESC, request_row.id DESC LIMIT 1
    ), publication AS (
        SELECT published.rollout_id, published.config_version_id, published.source_revision,
            EXISTS (SELECT 1 FROM config_version_telemetry_site_bindings carried
                WHERE carried.config_version_id=published.config_version_id AND carried.site_id=$2) AS carries
        FROM edge_config_publications published
        WHERE published.configuration_scope_id=$1
        ORDER BY published.created_at DESC, published.id DESC LIMIT 1
    ), serving AS (
        SELECT endpoint.node_id
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
        WHERE site.id=$2 AND site.scope_id=$1
        UNION
        SELECT member.node_id
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
        WHERE site.id=$2 AND site.scope_id=$1
    ), deployed AS (
        SELECT latest.node_id, node.name AS node_name, latest.state, latest.id, latest.attempt,
            CASE WHEN latest.state IN ('healthy','superseded') OR config_state.current_config_version_id=latest.config_version_id
                     THEN 'healthy'
                 WHEN latest.state IN ('failed','reverted','rollback_failed','cancelled') THEN 'failed'
                 ELSE 'pending' END AS outcome
        FROM publication
        JOIN LATERAL (SELECT DISTINCT ON (deployment.node_id) deployment.node_id, deployment.id, deployment.attempt,
                deployment.state, deployment.config_version_id
            FROM node_deployments deployment WHERE deployment.rollout_id=publication.rollout_id
            ORDER BY deployment.node_id, deployment.attempt DESC, deployment.created_at DESC) latest ON true
        JOIN nodes node ON node.id=latest.node_id AND node.admin_state='active'
        JOIN serving ON serving.node_id=latest.node_id
        LEFT JOIN node_config_state config_state ON config_state.node_id=latest.node_id AND config_state.configuration_scope_id=$1
    ), summary AS (
        SELECT count(*) AS total, count(*) FILTER (WHERE outcome='healthy') AS healthy,
            count(*) FILTER (WHERE outcome='failed') AS failed,
            COALESCE(jsonb_agg(jsonb_build_object('node_id', deployed.node_id, 'node_name', deployed.node_name,
                'state', deployed.state, 'error_code', (SELECT event.error_code FROM deployment_status_events event
                    WHERE event.deployment_id=deployed.id AND event.attempt=deployed.attempt AND event.error_code IS NOT NULL
                    ORDER BY event.transition_sequence DESC LIMIT 1))
                ORDER BY deployed.node_name, deployed.node_id) FILTER (WHERE outcome='failed'), '[]'::jsonb) AS nodes
        FROM deployed
    ), serving_active AS (
        -- 619: the active nodes now serving the site, whether or not the latest
        -- publication reached them.
        SELECT count(*) AS total FROM serving JOIN nodes node ON node.id=serving.node_id AND node.admin_state='active'
    ), scope_request AS (
        -- 619: a scope republication in flight (a line group's node set, node
        -- networks, a sync retry...) delivers the site too: still publishing.
        SELECT EXISTS (SELECT 1 FROM edge_automatic_publication_requests request_row
            JOIN LATERAL (SELECT fact.state FROM edge_automatic_publication_request_state_facts fact
                WHERE fact.request_id=request_row.id ORDER BY fact.sequence DESC LIMIT 1) latest ON true
            WHERE request_row.target_scope_id=$1
              AND latest.state IN ('pending','leased','retry_wait','reconciling')) AS in_flight
    ), decided AS (
        SELECT CASE
            WHEN request.state IN ('pending','leased','retry_wait','reconciling') THEN 'pending'
            WHEN request.state='failed' AND NOT EXISTS (SELECT 1 FROM edge_config_publications covering
                 WHERE covering.configuration_scope_id=$1 AND covering.source_revision>=request.source_revision) THEN 'request_failed'
            WHEN publication.rollout_id IS NULL THEN ''
            WHEN NOT publication.carries THEN 'excluded'
            WHEN summary.failed > 0 THEN 'failed'
            WHEN summary.total > 0 AND summary.healthy=summary.total THEN 'succeeded'
            -- 619: nodes serve the site but the latest publication has no
            -- deployment on any of them (they joined or were reinstalled after
            -- it) and nothing is publishing: never delivered, not in flight.
            -- 重新发布 (refused while pending) is the way out.
            WHEN summary.total = 0 AND serving_active.total > 0 AND NOT scope_request.in_flight THEN 'undelivered'
            ELSE 'pending' END AS state,
            request.terminal_code, summary.nodes
        FROM (SELECT 1) one
        LEFT JOIN request ON true
        LEFT JOIN publication ON true
        LEFT JOIN summary ON true
        CROSS JOIN serving_active
        CROSS JOIN scope_request
    )
    SELECT CASE WHEN decided.state IN ('request_failed','undelivered') THEN 'failed' ELSE decided.state END,
        CASE decided.state WHEN 'request_failed' THEN decided.terminal_code
            WHEN 'undelivered' THEN 'serving_nodes_undelivered' END,
        CASE WHEN decided.state='failed' THEN decided.nodes ELSE '[]'::jsonb END
    FROM decided
$$;
