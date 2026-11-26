-- 686（前驱 685_registration_proof_consumed_digest_index）。
-- 清除CDN无关解析的计划项原先只存展示用的 item_id（"删除记录 <名称> <类型> <值> #<域名>/<记录ID>"，值过长会被截断），
-- 执行时只核对记录 ID 和类型，就按服务商回读的当前值删除：服务商在同一个 ID 上改了值，旧任务会把新值删掉。
-- dns_cleanup_plan_records 与计划项在同一事务里写入，存计划时读到的规范化名称（小写、带末尾点）、类型、
-- 完整值和服务商记录 ID；执行前回读核对这四项，任一不符就保留远端记录（dns_record_changed）。
-- 升级前创建、这里没有对应行的清除任务一律不删（dns_cleanup_plan_stale，提示重新执行清除），不回填。
-- 错误码：头检查 P6860；down 头检查 P6861。
LOCK TABLE schema_migrations, background_job_items IN ACCESS EXCLUSIVE MODE;

DO $migration_686_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 685 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 685 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=685 AND
        migration_id='685_registration_proof_consumed_digest_index' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.dns_cleanup_plan_records') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 686 requires the exact verified 685 release head' USING ERRCODE='P6860';
    END IF;
END;
$migration_686_up$;

CREATE TABLE dns_cleanup_plan_records (
    tenant_id uuid NOT NULL,
    job_id uuid NOT NULL,
    item_id text NOT NULL,
    zone_id uuid NOT NULL,
    provider_record_id text NOT NULL CHECK (char_length(provider_record_id) BETWEEN 1 AND 256),
    owner_name text NOT NULL CHECK (
        char_length(owner_name) BETWEEN 2 AND 254 AND owner_name = lower(owner_name) AND right(owner_name, 1) = '.'
    ),
    record_type text NOT NULL CHECK (record_type IN ('A', 'AAAA', 'CNAME')),
    record_value text NOT NULL CHECK (char_length(record_value) BETWEEN 1 AND 4096),
    PRIMARY KEY (tenant_id, job_id, item_id),
    FOREIGN KEY (tenant_id, job_id, item_id)
        REFERENCES background_job_items(tenant_id, job_id, item_id) ON DELETE CASCADE
);
GRANT SELECT, INSERT ON dns_cleanup_plan_records TO cdnca_control_app, cdnca_control_runtime;
