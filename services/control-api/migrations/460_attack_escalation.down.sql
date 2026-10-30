LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_460_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 460 OR
       (SELECT max(version) FROM schema_migrations) <> 460 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=460 AND
        migration_id='460_attack_escalation' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 460 down requires the exact verified migration head' USING ERRCODE='P4601';
    END IF;
END;
$migration_460_down$;

-- 承载函数回到 287/342 原文（CREATE OR REPLACE 会清掉 SET，287 的 search_path 重新固定）。
CREATE OR REPLACE FUNCTION tenant_carries_node_287(checked_tenant_scope_id uuid, checked_node_id uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1 FROM nodes node
        WHERE node.id = checked_node_id AND node.admin_state <> 'retired' AND (
            node.scope_id = checked_tenant_scope_id OR (
                EXISTS (SELECT 1 FROM access_scopes scope WHERE scope.id = node.scope_id AND scope.kind = 'platform')
                AND (
                    EXISTS (SELECT 1 FROM node_config_state state
                        WHERE state.node_id = node.id AND state.configuration_scope_id = checked_tenant_scope_id)
                    OR EXISTS (
                        SELECT 1 FROM sites site
                        LEFT JOIN package_subscriptions subscription
                          ON subscription.tenant_scope_id = site.scope_id AND subscription.id = site.package_subscription_id
                         AND subscription.deleted_at IS NULL
                        JOIN node_line_groups line_group ON line_group.deleted_at IS NULL
                         AND line_group.tenant_scope_id IN (node.scope_id, site.scope_id)
                         AND line_group.id IN (
                             site.node_group_id,
                             (subscription.product_snapshot->'spec'->>'node_group_id')::uuid,
                             (subscription.product_snapshot->'spec'->>'backup_node_group_id')::uuid)
                        JOIN node_line_endpoint_serving endpoint
                          ON endpoint.tenant_scope_id = line_group.tenant_scope_id
                         AND endpoint.line_group_id = line_group.id
                         AND endpoint.config_revision = line_group.current_revision
                         AND endpoint.node_id = node.id
                        WHERE site.scope_id = checked_tenant_scope_id AND site.deleted_at IS NULL
                    )
                )
            )
        )
    )
$$;

CREATE OR REPLACE FUNCTION acme_http01_site_candidate_nodes(target_scope_id uuid, target_site_id uuid)
RETURNS SETOF uuid LANGUAGE sql STABLE AS $$
    SELECT DISTINCT endpoint.node_id FROM sites site
    LEFT JOIN package_subscriptions subscription ON subscription.tenant_scope_id=site.scope_id
     AND subscription.id=site.package_subscription_id AND subscription.deleted_at IS NULL
    JOIN node_line_groups line_group ON line_group.deleted_at IS NULL AND line_group.id IN (
         site.node_group_id,
         (subscription.product_snapshot->'spec'->>'node_group_id')::uuid,
         (subscription.product_snapshot->'spec'->>'backup_node_group_id')::uuid)
    JOIN node_line_endpoints endpoint ON endpoint.tenant_scope_id=line_group.tenant_scope_id
     AND endpoint.line_group_id=line_group.id AND endpoint.config_revision=line_group.current_revision
     AND endpoint.enabled AND endpoint.node_id IS NOT NULL
    JOIN nodes node ON node.id=endpoint.node_id AND node.admin_state='active'
    JOIN access_scopes node_scope ON node_scope.id=node.scope_id
    WHERE site.scope_id=target_scope_id AND site.id=target_site_id
      AND line_group.tenant_scope_id IN (site.scope_id, node.scope_id)
      AND (node.scope_id=site.scope_id OR node_scope.kind='platform')
      AND NOT EXISTS (SELECT 1 FROM node_serving_holds hold WHERE hold.node_id=node.id AND hold.held)
$$;

DO $migration_460_down_path$
BEGIN
    EXECUTE format('ALTER FUNCTION %I.tenant_carries_node_287(uuid, uuid) SET search_path = pg_catalog, %I, pg_temp',
        current_schema(), current_schema());
END;
$migration_460_down_path$;

ALTER TABLE aggregated_edge_switch_events DROP CONSTRAINT aggregated_edge_switch_events_reason_460_check;
ALTER TABLE aggregated_edge_switch_events ADD CONSTRAINT aggregated_edge_switch_events_reason_420_check
    CHECK (reason IN ('failover', 'failback', 'quality', 'manual', 'unbind', 'bind', 'freeze', 'unfreeze',
        'all_unhealthy', 'current_unhealthy', 'origin_unhealthy', 'edge_all_unhealthy', 'recovered'));

-- 系统重新发布 trigger 枚举回到 451（attack_escalation 的行在回退前必须已处理完）。
DO $migration_460_down_trigger$
BEGIN
    IF EXISTS (SELECT 1 FROM edge_system_republication_heads WHERE 'attack_escalation' = ANY(triggers)) OR
       EXISTS (SELECT 1 FROM edge_system_republication_attempts WHERE 'attack_escalation' = ANY(triggers)) OR
       EXISTS (SELECT 1 FROM edge_system_revision_segments WHERE source = 'attack_escalation') THEN
        RAISE EXCEPTION 'migration 460 down: attack escalation republications exist' USING ERRCODE='P4601';
    END IF;
END;
$migration_460_down_trigger$;
ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 17 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery', 'module_entitlement',
            'theme_activation', 'account_suspension', 'node_networks', 'error_page_published',
            'origin_auth_published', 'origin_failover', 'market_limits', 'ip_list']::text[]);
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 17);
ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification', 'rule_catalog', 'challenge_delivery',
        'module_entitlement', 'account_suspension', 'node_networks', 'error_page_published', 'origin_auth_published',
        'origin_failover', 'market_limits', 'ip_list'));

-- 回退前：TTL 60 或平台线路组的 retarget 不能回到 280 的约束，拒绝回退。
DO $migration_460_down_retarget$
BEGIN
    IF EXISTS (SELECT 1 FROM dns_cname_retargets WHERE ttl <> 300 OR node_group_scope_id <> tenant_scope_id) THEN
        RAISE EXCEPTION 'migration 460 down: escalation retargets exist' USING ERRCODE='P4601';
    END IF;
END;
$migration_460_down_retarget$;
ALTER TABLE dns_cname_retargets
    DROP CONSTRAINT dns_cname_retargets_ttl_460_check,
    ADD CONSTRAINT dns_cname_retargets_ttl_check CHECK (ttl = 300),
    DROP CONSTRAINT dns_cname_retargets_node_group_460_fkey,
    ADD CONSTRAINT dns_cname_retargets_node_group_280_fkey
        FOREIGN KEY (tenant_scope_id, node_group_id, node_group_revision)
        REFERENCES node_line_group_revisions(tenant_scope_id, line_group_id, revision) ON DELETE RESTRICT,
    DROP COLUMN node_group_scope_id;

DO $migration_460_down_notice$
BEGIN
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id = 'security.escalate.blackhole.zh-cn') THEN
        RAISE EXCEPTION 'migration 460 down would orphan blackhole notifications' USING ERRCODE='P4601';
    END IF;
END;
$migration_460_down_notice$;
ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id = 'security.escalate.blackhole.zh-cn' AND version = 1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type = 'security.escalate.blackhole';
DELETE FROM notification_event_policies WHERE event_type = 'security.escalate.blackhole';

DROP TABLE escalate_site_drop_node_states;
DROP TABLE escalate_site_routes;
DROP TABLE escalate_events;
DROP TABLE escalate_site_states;
DROP TABLE escalate_sites;
DROP TABLE escalate_package_policies;
DROP FUNCTION guard_escalate_package_policy_460();
DROP TABLE node_line_group_grants;
DROP FUNCTION guard_node_line_group_grant_460();
DROP FUNCTION scope_may_use_line_group_460(uuid, uuid, uuid);
DROP TABLE node_line_group_tiers;
