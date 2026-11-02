-- 618（r136 fix-readiness，前驱 617_node_ssh_install_allow_cidrs，合入时按连号改号）：
--   站点“已发布到节点”与“同步状态”统一由 site_publication_outcome_618 判定，只看当前生效配置在
--   当前仍承担本站的节点上的结果。修两个不会自动恢复的缺陷：
--   ① 本站最近一次自动发布请求 failed 后，之后作用域的发布（线路组/节点改 IP/同步重试等系统重新发布，
--      source_kind 不是 site）即使全部成功，状态也一直是“发布失败/同步失败”，直到用户再保存一次网站；
--   ② 最近一次发布 rollout 里已退役、已删除或已移出线路组的节点的失败部署仍计入失败。
--   规则：本站最新请求在途→pending；failed 且没有 source_revision ≥ 它的作用域发布→failed（请求终态码）；
--   否则看作用域最新发布：不含本站→excluded；含本站→只取 rollout 中“当前承担本站”的节点（本站/套餐
--   主备/升级路由线路组当前版本的启用端点、L2 成员，节点 admin_state=active），每个节点取最新一次
--   attempt：healthy/superseded，或 node_config_state 当前版本就是本次发布版本→成功；
--   failed/reverted/rollback_failed/cancelled→失败（失败节点名与最近状态事件的 error_code 一并返回）；
--   其余→进行中。全部成功→succeeded；有失败→failed；没有承担本站的节点或仍在进行→pending。
--   site_sync_status_503 改为调用它：failed→failed，pending→pending，其余→synced。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_618_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 617 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 617 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=617 AND
        migration_id='617_node_ssh_install_allow_cidrs' AND
        checksum_sha256='0b9f2ed8a9607f426be2b68d3b1b0fff53e5b62bf43a5a9e51c84c4fc4bdf697' AND
        down_checksum_sha256='ce8baf327543f174aac8864dc76a93c2654af7bf66251a712f1f8532b9417bc9' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure('site_publication_outcome_618(uuid,uuid)') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 618 requires the exact verified 617 release head' USING ERRCODE='P6180';
    END IF;
END;
$migration_618_up$;

CREATE FUNCTION site_publication_outcome_618(scope_id uuid, site_id uuid,
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
    ), decided AS (
        SELECT CASE
            WHEN request.state IN ('pending','leased','retry_wait','reconciling') THEN 'pending'
            WHEN request.state='failed' AND NOT EXISTS (SELECT 1 FROM edge_config_publications covering
                 WHERE covering.configuration_scope_id=$1 AND covering.source_revision>=request.source_revision) THEN 'request_failed'
            WHEN publication.rollout_id IS NULL THEN ''
            WHEN NOT publication.carries THEN 'excluded'
            WHEN summary.failed > 0 THEN 'failed'
            WHEN summary.total > 0 AND summary.healthy=summary.total THEN 'succeeded'
            ELSE 'pending' END AS state,
            request.terminal_code, summary.nodes
        FROM (SELECT 1) one
        LEFT JOIN request ON true
        LEFT JOIN publication ON true
        LEFT JOIN summary ON true
    )
    SELECT CASE WHEN decided.state='request_failed' THEN 'failed' ELSE decided.state END,
        CASE WHEN decided.state='request_failed' THEN decided.terminal_code END,
        CASE WHEN decided.state='failed' THEN decided.nodes ELSE '[]'::jsonb END
    FROM decided
$$;

-- 唯一派生规则（503 起 Go 读方都调用它）改为读 618 的判定。
CREATE OR REPLACE FUNCTION site_sync_status_503(scope_id uuid, site_id uuid) RETURNS text
LANGUAGE sql STABLE AS $$
    SELECT CASE outcome.state WHEN 'failed' THEN 'failed' WHEN 'pending' THEN 'pending' ELSE 'synced' END
    FROM site_publication_outcome_618($1, $2) outcome
$$;

REVOKE ALL ON FUNCTION site_publication_outcome_618(uuid, uuid) FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='cdnca_control_app') THEN
        GRANT EXECUTE ON FUNCTION site_publication_outcome_618(uuid, uuid) TO cdnca_control_app;
    END IF;
END $$;
