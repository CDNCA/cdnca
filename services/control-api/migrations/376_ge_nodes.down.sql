LOCK TABLE schema_migrations, node_line_groups, node_line_group_revisions, dns_providers,
    node_serving_holds, node_serving_events IN ACCESS EXCLUSIVE MODE;

DO $migration_376_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 376 OR
       (SELECT max(version) FROM schema_migrations) <> 376 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=376 AND
        migration_id='376_ge_nodes' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (SELECT 1 FROM node_serving_holds WHERE source='external_probe')
         OR EXISTS (SELECT 1 FROM node_serving_events WHERE source='external_probe')
         OR EXISTS (SELECT 1 FROM dns_providers WHERE provider_type='custom_http') THEN
        RAISE EXCEPTION 'migration 376 down requires the exact verified migration head and no external_probe holds or custom_http providers' USING ERRCODE='P3761';
    END IF;
END;
$migration_376_down$;

DROP TABLE node_ssh_install_jobs;
DROP TABLE cname_carrier_line_records;

ALTER TABLE node_serving_holds DROP CONSTRAINT node_serving_holds_source_check,
    ADD CONSTRAINT node_serving_holds_source_check
        CHECK (source IN ('availability_monitor', 'auto_disable', 'config_sync'));
ALTER TABLE node_serving_events DROP CONSTRAINT node_serving_events_source_check,
    ADD CONSTRAINT node_serving_events_source_check
        CHECK (source IN ('availability_monitor', 'auto_disable', 'config_sync'));

ALTER TABLE dns_providers DROP CONSTRAINT dns_providers_provider_type_check;
ALTER TABLE dns_providers ADD CONSTRAINT dns_providers_provider_type_check CHECK (
    provider_type IN ('aliyun', 'cloudflare', 'huawei', 'dnspod_cn', 'dns_com', 'dnsdun', 'dns_la')
);

ALTER TABLE node_line_group_revisions
    DROP CONSTRAINT node_line_group_revisions_failover_mode_376_check,
    ADD CONSTRAINT node_line_group_revisions_failover_mode_234_check CHECK (
        failover_mode IN ('primary_offline', 'online_less_than_backup_count', 'interval')
    );
ALTER TABLE node_line_groups
    DROP CONSTRAINT node_line_groups_failover_mode_376_check,
    ADD CONSTRAINT node_line_groups_failover_mode_234_check CHECK (
        failover_mode IN ('primary_offline', 'online_less_than_backup_count', 'interval')
    );
