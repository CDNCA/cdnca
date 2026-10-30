-- 499（r136 stream-be2）回退：转发自有 CNAME/线路覆盖在 498 无法表达时拒绝回退。
LOCK TABLE schema_migrations, l4_forwards IN ACCESS EXCLUSIVE MODE;

DO $migration_499_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 499 OR
       (SELECT max(version) FROM schema_migrations) <> 499 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=499 AND
        migration_id='499_l4_forward_line_cname' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 499 down requires the exact verified migration head' USING ERRCODE='P4991';
    END IF;
    IF EXISTS (SELECT 1 FROM l4_forwards WHERE cname_domain IS NOT NULL OR cname_mode IS NOT NULL OR region_id IS NOT NULL OR
               node_group_id IS NOT NULL OR backup_node_group_id IS NOT NULL) THEN
        RAISE EXCEPTION 'retain L4 forward CNAME and line overrides during binary rollback' USING ERRCODE='P4992';
    END IF;
END;
$migration_499_down$;

DROP INDEX l4_forwards_backup_node_group_499_idx;
DROP INDEX l4_forwards_node_group_499_idx;
ALTER TABLE l4_forwards DROP CONSTRAINT l4_forwards_line_cname_499,
    DROP COLUMN backup_node_group_id, DROP COLUMN node_group_id, DROP COLUMN region_id,
    DROP COLUMN cname_mode, DROP COLUMN cname_domain;
