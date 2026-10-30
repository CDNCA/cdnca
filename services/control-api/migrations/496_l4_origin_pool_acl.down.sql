-- 496（r136 stream-be）回退：源站列表、IPv6、ACL、设置状态与批量收据在 495 无法表达时拒绝回退。
LOCK TABLE schema_migrations, l4_forwards, l4_publish_intents, l4_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_496_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 496 OR
       (SELECT max(version) FROM schema_migrations) <> 496 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=496 AND
        migration_id='496_l4_origin_pool_acl' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 496 down requires the exact verified migration head' USING ERRCODE='P4961';
    END IF;
    IF EXISTS (SELECT 1 FROM l4_forwards WHERE origins IS NOT NULL OR listen_ipv6 OR acl_default_action <> 'allow' OR
               acl_rules IS NOT NULL OR admin_status <> 'normal') OR
       EXISTS (SELECT 1 FROM l4_publish_intents WHERE runtime_spec ? 'listen_ipv6' OR
               COALESCE(runtime_spec->'endpoint' ?| ARRAY['origins', 'balance'], false)) OR
       EXISTS (SELECT 1 FROM l4_write_requests WHERE operation IN ('stream.batch_create', 'stream.batch_action')) THEN
        RAISE EXCEPTION 'retain L4 origin pools, ACLs and batch history during binary rollback' USING ERRCODE='P4962';
    END IF;
END;
$migration_496_down$;

ALTER TABLE l4_write_requests DROP CONSTRAINT l4_write_requests_operation_496,
    ADD CONSTRAINT l4_write_requests_operation_check
    CHECK (operation IN ('stream.create', 'stream.update', 'stream.delete'));
ALTER TABLE l4_publish_intents DROP CONSTRAINT l4_publish_intents_runtime_spec_496,
    ADD CONSTRAINT l4_publish_intents_runtime_spec_341
    CHECK(validate_l4_runtime_spec_341(stream_id,scope_id,site_id,runtime_spec));
DROP FUNCTION validate_l4_runtime_spec_496(uuid,uuid,uuid,jsonb);
ALTER TABLE l4_forwards
    DROP CONSTRAINT l4_forwards_admin_status_496,
    DROP CONSTRAINT l4_forwards_acl_496,
    DROP CONSTRAINT l4_forwards_origins_496,
    DROP COLUMN admin_status,
    DROP COLUMN acl_rules,
    DROP COLUMN acl_default_action,
    DROP COLUMN listen_ipv6,
    DROP COLUMN origins;
DROP FUNCTION valid_l4_acl_rules_496(jsonb);
DROP FUNCTION valid_l4_origins_496(jsonb);
