-- 665：前驱钉 664_status_page_sources。状态页按分钟的异常明细。
-- 采样器判定某组件这一分钟为降级或中断时写一行：组件 id、分钟、状态、原因摘要（HTTP 码/超时/连接被拒/可用比例等）。
-- 只供排查和发事件用，公开页和管理页都不展示；保留 30 天，由采样器每小时清理。
-- 组件被删时明细随之删除。同一分钟多个副本各写一次，主键去重。新表，无回填。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_665_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 664 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 664 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=664 AND
        migration_id='664_status_page_sources' AND
        checksum_sha256='30e1ad2edca8446d79f1b566f7a67bb9c0d1f02a9d07c1f6ae2b863a5626cb07' AND
        down_checksum_sha256='bfd55ae0f6f6d6611bb8f096940d8695f95897e0b69b2f443d4c22cae4d0d113' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.status_page_samples') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 665 requires the exact verified 664 release head' USING ERRCODE='P6650';
    END IF;
END;
$migration_665_up$;

CREATE TABLE status_page_samples (
    component_id uuid NOT NULL REFERENCES status_page_components(id) ON DELETE CASCADE,
    minute timestamptz NOT NULL,
    status text NOT NULL CHECK (status IN ('degraded', 'outage')),
    reason text NOT NULL DEFAULT '' CHECK (char_length(reason) <= 120 AND reason !~ '[[:cntrl:]]'),
    PRIMARY KEY (component_id, minute)
);
CREATE INDEX status_page_samples_minute_665_idx ON status_page_samples (minute);
GRANT SELECT, INSERT, DELETE ON status_page_samples TO cdnca_control_app, cdnca_control_runtime;
