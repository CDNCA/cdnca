-- 500（r136 fp-net2）回退：同一 IP+端口挂在多个运营商线路上的配置在 499 无法表达时拒绝回退。
LOCK TABLE schema_migrations, node_line_endpoints IN ACCESS EXCLUSIVE MODE;

DO $migration_500_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 500 OR
       (SELECT max(version) FROM schema_migrations) <> 500 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=500 AND
        migration_id='500_node_line_endpoint_carrier_unique' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 500 down requires the exact verified migration head' USING ERRCODE='P5002';
    END IF;
    IF EXISTS (SELECT 1 FROM node_line_endpoints
               GROUP BY tenant_scope_id, line_group_id, config_revision, address, port HAVING count(*) > 1) THEN
        RAISE EXCEPTION 'retain line group endpoints sharing an address across carrier lines during binary rollback'
            USING ERRCODE='P5003';
    END IF;
END;
$migration_500_down$;

ALTER TABLE node_line_endpoints DROP CONSTRAINT node_line_endpoints_carrier_address_port_500,
    ADD UNIQUE (tenant_scope_id, line_group_id, config_revision, address, port);
