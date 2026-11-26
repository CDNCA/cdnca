-- 705 回退：函数恢复为 701（618 / 663）与 692（692）的定义。补上的 community_default 策略是不可变事实
-- （自动发布请求按修订引用它们），保留；回退后的主控对这些作用域仍按自动发布处理。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_705_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 705 OR
       (SELECT max(version) FROM schema_migrations) <> 705 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=705 AND
        migration_id='705_community_default_publication' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 705 rollback requires the exact verified 705 release head' USING ERRCODE='P7051';
    END IF;
END;
$migration_705_down$;

CREATE OR REPLACE FUNCTION site_publication_expected_692(scope_id uuid, site_id uuid) RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT EXISTS (SELECT 1 FROM sites site
        JOIN package_subscriptions subscription ON subscription.tenant_scope_id=site.scope_id
         AND subscription.id=site.package_subscription_id
        WHERE site.id=$2 AND site.scope_id=$1 AND site.deleted_at IS NULL AND site.enabled
          AND site.status<>'traffic_exceeded'
          AND subscription.admin_enabled AND subscription.deleted_at IS NULL AND subscription.suspended_at IS NULL
          AND NOT EXISTS (SELECT 1 FROM package_traffic_site_suspensions open
              WHERE open.site_id=site.id AND open.recovered_at IS NULL)
          AND NOT EXISTS (SELECT 1 FROM domain_claim_suspensions claim
              WHERE claim.site_id=site.id AND claim.released_at IS NULL))
$$;

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
        LEFT JOIN LATERAL (SELECT package_subscription_current_product_snapshot(subscription.id,now()) AS product_snapshot) subscription_current ON true
        LEFT JOIN escalate_site_routes route ON route.tenant_scope_id=site.scope_id AND route.site_id=site.id
        JOIN node_line_groups line_group ON line_group.deleted_at IS NULL AND line_group.id IN (
             site.node_group_id,
             (subscription_current.product_snapshot->'spec'->>'node_group_id')::uuid,
             (subscription_current.product_snapshot->'spec'->>'backup_node_group_id')::uuid,
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
        LEFT JOIN LATERAL (SELECT package_subscription_current_product_snapshot(subscription.id,now()) AS product_snapshot) subscription_current ON true
        LEFT JOIN node_line_groups line_group ON pool.l2_mode='package' AND line_group.deleted_at IS NULL
         AND line_group.id=COALESCE(site.node_group_id, (subscription_current.product_snapshot->'spec'->>'node_group_id')::uuid)
        JOIN l2_topology_configs config ON config.deleted_at IS NULL AND (
             pool.l2_mode='custom' AND config.tenant_scope_id=site.scope_id AND config.id=pool.l2_config_id OR
             pool.l2_mode='package' AND config.tenant_scope_id=line_group.tenant_scope_id AND config.id=line_group.l2_config_id)
        JOIN l2_topology_nodes member ON member.tenant_scope_id=config.tenant_scope_id AND member.config_id=config.id
         AND member.enabled AND member.deleted_at IS NULL
        WHERE site.id=$2 AND site.scope_id=$1
          AND COALESCE(subscription_current.product_snapshot#>>'{spec,limits,l2_origin}','')<>'false'
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
    ), restoring AS (
        -- 692: the site belongs in the publication and a scope publication that
        -- will carry it is in flight: an automatic request of any source (an
        -- unsuspend's is scope-level, source_resource_id NULL), or on a manual
        -- scope the system channel with a stop/restore trigger.
        SELECT site_publication_expected_692($1, $2) AS expected,
            scope_request.in_flight OR EXISTS (SELECT 1 FROM edge_system_republication_heads head
                WHERE head.scope_id=$1 AND head.state IN ('pending','leased')
                  AND head.triggers && ARRAY['package_suspension','package_expiry','traffic_enforcement',
                      'domain_ownership','secondary_verification','account_suspension']::text[]) AS in_flight
        FROM scope_request
    ), decided AS (
        SELECT CASE
            WHEN request.state IN ('pending','leased','retry_wait','reconciling') THEN 'pending'
            WHEN request.state='failed' AND NOT EXISTS (SELECT 1 FROM edge_config_publications covering
                 WHERE covering.configuration_scope_id=$1 AND covering.source_revision>=request.source_revision
                   AND covering.publication_kind='content') THEN 'request_failed'
            -- 692: not (yet) carried, but on its way.
            WHEN (publication.rollout_id IS NULL OR NOT publication.carries) AND restoring.expected AND restoring.in_flight
                 THEN 'pending'
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
        CROSS JOIN restoring
    )
    SELECT CASE WHEN decided.state IN ('request_failed','undelivered') THEN 'failed' ELSE decided.state END,
        CASE decided.state WHEN 'request_failed' THEN decided.terminal_code
            WHEN 'undelivered' THEN 'serving_nodes_undelivered' END,
        CASE WHEN decided.state='failed' THEN decided.nodes ELSE '[]'::jsonb END
    FROM decided
$$;

CREATE OR REPLACE FUNCTION site_sync_status_batch_663(scope_ids uuid[])
RETURNS TABLE (out_scope_id uuid, out_site_id uuid, sync_status text)
LANGUAGE sql STABLE AS $$
    WITH target AS (
        SELECT site.scope_id AS tscope, site.id AS tsite
        FROM sites site
        WHERE site.deleted_at IS NULL AND ($1 IS NULL OR site.scope_id = ANY($1))
    ), expected AS (
        -- 692：本站此刻应当在发布里（site_publication_expected_692 的同一组条件）
        SELECT site.scope_id AS escope, site.id AS esite
        FROM sites site
        JOIN package_subscriptions subscription ON subscription.tenant_scope_id=site.scope_id
         AND subscription.id=site.package_subscription_id
        WHERE site.deleted_at IS NULL AND ($1 IS NULL OR site.scope_id = ANY($1)) AND site.enabled
          AND site.status<>'traffic_exceeded'
          AND subscription.admin_enabled AND subscription.deleted_at IS NULL AND subscription.suspended_at IS NULL
          AND NOT EXISTS (SELECT 1 FROM package_traffic_site_suspensions open
              WHERE open.site_id=site.id AND open.recovered_at IS NULL)
          AND NOT EXISTS (SELECT 1 FROM domain_claim_suspensions claim
              WHERE claim.site_id=site.id AND claim.released_at IS NULL)
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
        LEFT JOIN LATERAL (SELECT package_subscription_current_product_snapshot(subscription.id,now()) AS product_snapshot) subscription_current ON true
        LEFT JOIN escalate_site_routes route ON route.tenant_scope_id=site.scope_id AND route.site_id=site.id
        JOIN node_line_groups line_group ON line_group.deleted_at IS NULL AND line_group.id IN (
             site.node_group_id,
             (subscription_current.product_snapshot->'spec'->>'node_group_id')::uuid,
             (subscription_current.product_snapshot->'spec'->>'backup_node_group_id')::uuid,
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
        LEFT JOIN LATERAL (SELECT package_subscription_current_product_snapshot(subscription.id,now()) AS product_snapshot) subscription_current ON true
        LEFT JOIN node_line_groups line_group ON pool.l2_mode='package' AND line_group.deleted_at IS NULL
         AND line_group.id=COALESCE(site.node_group_id, (subscription_current.product_snapshot->'spec'->>'node_group_id')::uuid)
        JOIN l2_topology_configs config ON config.deleted_at IS NULL AND (
             pool.l2_mode='custom' AND config.tenant_scope_id=site.scope_id AND config.id=pool.l2_config_id OR
             pool.l2_mode='package' AND config.tenant_scope_id=line_group.tenant_scope_id AND config.id=line_group.l2_config_id)
        JOIN l2_topology_nodes member ON member.tenant_scope_id=config.tenant_scope_id AND member.config_id=config.id
         AND member.enabled AND member.deleted_at IS NULL
        WHERE site.deleted_at IS NULL AND ($1 IS NULL OR site.scope_id = ANY($1))
          AND COALESCE(subscription_current.product_snapshot#>>'{spec,limits,l2_origin}','')<>'false'
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
    ), system_inflight AS (
        -- 692：手动作用域在途的系统重新发布（停站/恢复类触发器，含 package_suspension）
        SELECT head.scope_id AS hscope
        FROM edge_system_republication_heads head
        WHERE ($1 IS NULL OR head.scope_id = ANY($1)) AND head.state IN ('pending','leased')
          AND head.triggers && ARRAY['package_suspension','package_expiry','traffic_enforcement',
              'domain_ownership','secondary_verification','account_suspension']::text[]
    )
    SELECT target.tscope, target.tsite,
        CASE decided.state
            WHEN 'failed' THEN 'failed' WHEN 'request_failed' THEN 'failed' WHEN 'undelivered' THEN 'failed'
            WHEN 'pending' THEN 'pending' WHEN 'succeeded' THEN 'synced'
            ELSE CASE WHEN expected.esite IS NOT NULL THEN 'pending' ELSE 'synced' END END
    FROM target
    LEFT JOIN expected ON expected.escope=target.tscope AND expected.esite=target.tsite
    LEFT JOIN req ON req.rscope=target.tscope AND req.rsite=target.tsite
    LEFT JOIN pub ON pub.pscope=target.tscope
    LEFT JOIN summary ON summary.sscope=target.tscope AND summary.ssite=target.tsite
    LEFT JOIN serving_active ON serving_active.sscope=target.tscope AND serving_active.ssite=target.tsite
    LEFT JOIN inflight ON inflight.iscope=target.tscope
    LEFT JOIN system_inflight ON system_inflight.hscope=target.tscope
    CROSS JOIN LATERAL (SELECT EXISTS (SELECT 1 FROM config_version_telemetry_site_bindings carried
             WHERE carried.config_version_id=pub.config_version_id AND carried.site_id=target.tsite) AS carries) carried
    CROSS JOIN LATERAL (SELECT CASE
        WHEN req.state IN ('pending','leased','retry_wait','reconciling') THEN 'pending'
        WHEN req.state='failed' AND NOT EXISTS (SELECT 1 FROM edge_config_publications covering
             WHERE covering.configuration_scope_id=target.tscope AND covering.source_revision>=req.source_revision
               AND covering.publication_kind='content') THEN 'request_failed'
        WHEN (pub.rollout_id IS NULL OR NOT carried.carries) AND expected.esite IS NOT NULL
             AND (inflight.iscope IS NOT NULL OR system_inflight.hscope IS NOT NULL) THEN 'pending'
        WHEN pub.rollout_id IS NULL THEN ''
        WHEN NOT carried.carries THEN 'excluded'
        WHEN COALESCE(summary.failed, 0) > 0 THEN 'failed'
        WHEN COALESCE(summary.total, 0) > 0 AND summary.healthy=summary.total THEN 'succeeded'
        WHEN COALESCE(summary.total, 0) = 0 AND COALESCE(serving_active.total, 0) > 0
             AND inflight.iscope IS NULL THEN 'undelivered'
        ELSE 'pending' END AS state) decided
$$;
