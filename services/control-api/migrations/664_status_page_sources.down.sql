-- 664 回退：删除分组表与新增列，组件来源只保留 manual / line_group（其他来源的组件一并删除，含其采样历史）。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_664_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 664 OR
       (SELECT max(version) FROM schema_migrations) <> 664 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=664 AND
        migration_id='664_status_page_sources' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 664 down requires the exact verified migration head' USING ERRCODE='P6641';
    END IF;
END;
$migration_664_down$;

ALTER TABLE status_page_settings DROP COLUMN defaults_seeded_at;
DELETE FROM status_page_components WHERE source NOT IN ('manual', 'line_group');
ALTER TABLE status_page_components
    DROP CONSTRAINT status_page_components_source_664_ck,
    DROP CONSTRAINT status_page_components_line_group_664_ck,
    DROP CONSTRAINT status_page_components_node_664_ck;
DROP INDEX status_page_components_group_664_idx;
ALTER TABLE status_page_components DROP COLUMN node_id, DROP COLUMN group_id, DROP COLUMN name_en;
ALTER TABLE status_page_components
    ADD CHECK (source IN ('manual', 'line_group')),
    ADD CHECK ((source = 'line_group') = (line_group_id IS NOT NULL AND line_group_scope_id IS NOT NULL)),
    ADD CHECK (source = 'line_group' OR (line_group_id IS NULL AND line_group_scope_id IS NULL));
DROP TABLE status_page_groups;
