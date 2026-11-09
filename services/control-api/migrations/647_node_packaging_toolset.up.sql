-- 647（节点打包脚本上报；前驱 646_challenge_pow_difficulty）：node_presence 新增 toolset_* 八列与形状约束，存量行全部为 NULL。
LOCK TABLE schema_migrations, node_presence IN ACCESS EXCLUSIVE MODE;

DO $migration_647_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 646 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 646 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=646 AND
        migration_id='646_challenge_pow_difficulty' AND
        checksum_sha256='fbceec4e1780af8f5eb4123542667e6fe020c574fca67283e17f0a1f8ebc93f3' AND
        down_checksum_sha256='f6b712f21df0b4f6138bfbed0122f5f5a34e78506358aadca1c70ea7c7992c34' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='node_presence' AND column_name='toolset_refresh_status'
       ) THEN
        RAISE EXCEPTION 'migration 647 requires the exact verified 646 release head' USING ERRCODE='P6470';
    END IF;
END;
$migration_647_up$;

-- The packaging toolset of the latest heartbeat
-- (EdgeRuntimeStatus.packaging_toolset, capability PACKAGING_TOOLSET_REPORT
-- 83): the last toolset refresh (status, version, reason, time, helper result)
-- and the installed scripts / packaging helper digests. All NULL: the node's
-- Agent does not report it (the console shows "not reported").
ALTER TABLE node_presence
    ADD COLUMN toolset_refresh_status text
        CONSTRAINT node_presence_toolset_refresh_status_647_check
        CHECK (toolset_refresh_status IN ('none', 'unknown', 'ok', 'failed', 'skipped')),
    ADD COLUMN toolset_refresh_version text
        CONSTRAINT node_presence_toolset_refresh_version_647_check
        CHECK (toolset_refresh_version ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    ADD COLUMN toolset_refresh_reason text
        CONSTRAINT node_presence_toolset_refresh_reason_647_check
        CHECK (toolset_refresh_reason ~ '^[ -~]{1,200}$'),
    ADD COLUMN toolset_refreshed_at timestamptz
        CONSTRAINT node_presence_toolset_refreshed_at_647_check CHECK (isfinite(toolset_refreshed_at)),
    ADD COLUMN toolset_helper_status text
        CONSTRAINT node_presence_toolset_helper_status_647_check
        CHECK (toolset_helper_status IN ('ok', 'unchanged', 'failed', 'skipped')),
    ADD COLUMN toolset_helper_reason text
        CONSTRAINT node_presence_toolset_helper_reason_647_check
        CHECK (toolset_helper_reason ~ '^[ -~]{1,200}$'),
    ADD COLUMN toolset_scripts_sha256 text
        CONSTRAINT node_presence_toolset_scripts_sha256_647_check CHECK (toolset_scripts_sha256 ~ '^[0-9a-f]{64}$'),
    ADD COLUMN toolset_helper_sha256 text
        CONSTRAINT node_presence_toolset_helper_sha256_647_check CHECK (toolset_helper_sha256 ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT node_presence_toolset_647_shape_check CHECK (
        (toolset_refresh_status IS NOT NULL OR (toolset_scripts_sha256 IS NULL AND toolset_helper_sha256 IS NULL)) AND
        (toolset_refresh_status IN ('ok', 'failed', 'skipped')) = (toolset_refresh_version IS NOT NULL) AND
        (toolset_refresh_status IN ('ok', 'failed', 'skipped')) = (toolset_refreshed_at IS NOT NULL) AND
        (toolset_refresh_version IS NOT NULL OR (toolset_refresh_reason IS NULL AND toolset_helper_status IS NULL)) AND
        (toolset_helper_status IS NOT NULL OR toolset_helper_reason IS NULL)
    );
