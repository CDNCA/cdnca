LOCK TABLE schema_migrations, node_presence IN ACCESS EXCLUSIVE MODE;

DO $migration_468_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 467 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 467 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=467 AND
        migration_id='467_site_theme_scopes' AND
        checksum_sha256='8358bf5a3e5e1f2e87e42895411bb0f5a0a70f9af243f7d41fd7d91f6cdddb54' AND
        down_checksum_sha256='0d0b96fb19d7ba8eb812e6ee200edb84373e718676b43d5e4b20fbaabe086084' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='node_presence' AND column_name='native_runtime_state'
       ) THEN
        RAISE EXCEPTION 'migration 468 requires the exact verified 467 release head' USING ERRCODE='P4680';
    END IF;
END;
$migration_468_up$;

-- 468 (r136 node-runtime-upgrade; renumber at the merge if 468 is taken).
-- The native runtime switch outcome of the latest heartbeat
-- (EdgeRuntimeStatus.native_runtime = 7): switched (the runtime of the Agent
-- release became active), unchanged (it already was) or rolled_back (the
-- switch failed and the previous runtime stays active, error_code says why).
-- release / previous_release are runtime manifest sha256 values. All NULL:
-- the node is not native or did not report it.
ALTER TABLE node_presence
    ADD COLUMN native_runtime_state text
        CONSTRAINT node_presence_native_runtime_state_468_check
        CHECK (native_runtime_state IN ('switched', 'unchanged', 'rolled_back')),
    ADD COLUMN native_runtime_release text
        CONSTRAINT node_presence_native_runtime_release_468_check
        CHECK (native_runtime_release ~ '^[0-9a-f]{64}$'),
    ADD COLUMN native_runtime_previous_release text
        CONSTRAINT node_presence_native_runtime_previous_release_468_check
        CHECK (native_runtime_previous_release ~ '^[0-9a-f]{64}$'),
    ADD COLUMN native_runtime_error_code text
        CONSTRAINT node_presence_native_runtime_error_code_468_check
        CHECK (native_runtime_error_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
    ADD CONSTRAINT node_presence_native_runtime_468_shape_check CHECK (
        (native_runtime_state IS NOT NULL OR (native_runtime_release IS NULL AND
            native_runtime_previous_release IS NULL AND native_runtime_error_code IS NULL)) AND
        (native_runtime_error_code IS NULL OR native_runtime_state = 'rolled_back')
    );
