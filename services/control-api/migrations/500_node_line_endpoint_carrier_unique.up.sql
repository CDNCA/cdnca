-- 500（r136 fp-net2，NET-02 后半，主会话 10-25 13:4x 定：按竞品 DNS 线路语义，同一 IP 可分别挂到
-- 电信/联通/移动等不同运营商线路）。merge-p5 由 497 改号 500，前驱 499。
-- 线路组端点去重键从 (address, port) 改为 (carrier, address, port)：同一线路组版本、同一运营商下
-- 同一 IP+端口仍不能重复。
LOCK TABLE schema_migrations, node_line_endpoints IN ACCESS EXCLUSIVE MODE;

DO $migration_500_up$
DECLARE old_constraint name;
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 499 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 499 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=499 AND
        migration_id='499_l4_forward_line_cname' AND
        checksum_sha256='8e2a262111f086a12ed9477dffe2b342c047a521c5fd219be3ffd845e0b5cc15' AND
        down_checksum_sha256='f670e99b6f6387dde2cd07fb3190da658f2f553a5178313f82c44596a887c133' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM pg_constraint WHERE conrelid='node_line_endpoints'::regclass AND
        conname='node_line_endpoints_carrier_address_port_500'
       ) THEN
        RAISE EXCEPTION 'migration 500 requires the exact verified 499 release head' USING ERRCODE='P5000';
    END IF;
    -- 033 的唯一约束由 PG 自动命名（超长被截断），按列定义查找。
    SELECT constraint_row.conname INTO old_constraint
    FROM pg_constraint constraint_row
    WHERE constraint_row.conrelid='node_line_endpoints'::regclass AND constraint_row.contype='u' AND
          ARRAY(SELECT attribute.attname::text FROM unnest(constraint_row.conkey) WITH ORDINALITY key(attnum, position)
                JOIN pg_attribute attribute ON attribute.attrelid=constraint_row.conrelid AND attribute.attnum=key.attnum
                ORDER BY key.position) =
          ARRAY['tenant_scope_id', 'line_group_id', 'config_revision', 'address', 'port'];
    IF old_constraint IS NULL THEN
        RAISE EXCEPTION 'migration 500 cannot find the 033 endpoint address uniqueness' USING ERRCODE='P5001';
    END IF;
    EXECUTE format('ALTER TABLE node_line_endpoints DROP CONSTRAINT %I', old_constraint);
END;
$migration_500_up$;

ALTER TABLE node_line_endpoints ADD CONSTRAINT node_line_endpoints_carrier_address_port_500
    UNIQUE (tenant_scope_id, line_group_id, config_revision, carrier, address, port);
