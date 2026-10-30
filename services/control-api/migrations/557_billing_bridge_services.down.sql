-- 557 回滚（占位，合入时由主会话改号）：去掉门面服务映射、客户映射、写请求幂等、免密登录票据与插件设置。
-- 已有服务映射或客户映射时，财务系统那边的服务正依赖它们；回滚会让幂等与免密登录悄悄失效，此时拒绝回滚。
LOCK TABLE schema_migrations, billing_bridge_clients, billing_bridge_services, billing_bridge_requests,
    billing_bridge_sso_tickets, billing_bridge_settings IN ACCESS EXCLUSIVE MODE;

DO $migration_557_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 557 OR
       (SELECT max(version) FROM schema_migrations) <> 557 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=557 AND
        migration_id='557_billing_bridge_services' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 557 down requires the exact verified migration head' USING ERRCODE='P5574';
    END IF;
    IF EXISTS (SELECT 1 FROM billing_bridge_services) OR EXISTS (SELECT 1 FROM billing_bridge_clients) THEN
        RAISE EXCEPTION 'migration 557 rollback would discard billing bridge service mappings' USING ERRCODE='P5575';
    END IF;
END;
$migration_557_down$;

DROP TABLE billing_bridge_settings;
DROP TABLE billing_bridge_sso_tickets;
DROP TABLE billing_bridge_requests;
DROP TABLE billing_bridge_services;
DROP TABLE billing_bridge_clients;
DROP FUNCTION guard_billing_bridge_sso_ticket_557();
DROP FUNCTION guard_billing_bridge_service_557();
