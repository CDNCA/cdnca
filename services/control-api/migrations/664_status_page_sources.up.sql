-- 664：前驱钉 663_site_sync_status_batch。
-- 主控公开状态页组件来源扩充与分组。
--   status_page_groups：管理员自建的分组（公开页可折叠），sort_order 排序，hidden 整组隐藏。
--   status_page_components.source 增加 node / node_overall / gateway / control_api / web_console / dns_sync / cert_issue；
--     node_id 指向单个节点（不加外键：节点被删时组件保留，显示「未监测」），group_id 指向所属分组，name_en 为英文名。
--   status_page_settings.defaults_seeded_at：推荐默认组件只种一次。
-- 权限沿用 system_configuration.read / manage，不新增权限码。老数据不回填。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_664_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 663 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 663 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=663 AND
        migration_id='663_site_sync_status_batch' AND
        checksum_sha256='927072c4fc90999d21da7787e5a28651c2836d72813baa3d01d3204922f3147b' AND
        down_checksum_sha256='efca72d23c6fd1fc64eae2993abd13e36106fe275706bf645444b3f47c3016ae' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.status_page_groups') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 664 requires the exact verified 663 release head' USING ERRCODE='P6640';
    END IF;
END;
$migration_664_up$;

CREATE TABLE status_page_groups (
    id uuid PRIMARY KEY,
    name text NOT NULL CHECK (name = btrim(name) AND char_length(name) BETWEEN 1 AND 64 AND name !~ '[[:cntrl:]]'),
    name_en text NOT NULL DEFAULT '' CHECK (name_en = btrim(name_en) AND char_length(name_en) <= 64 AND name_en !~ '[[:cntrl:]]'),
    sort_order integer NOT NULL CHECK (sort_order BETWEEN 0 AND 1000),
    hidden boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX status_page_groups_name_664_uq ON status_page_groups (lower(name));
GRANT SELECT, INSERT, UPDATE, DELETE ON status_page_groups TO cdnca_control_app, cdnca_control_runtime;

-- 660 的来源检查是未命名的表级约束：按定义找出旧的两条（来源枚举、线路组配对）后换成新的。
DO $migration_664_constraints$
DECLARE
    old_check record;
BEGIN
    FOR old_check IN
        SELECT conname FROM pg_constraint
        WHERE conrelid = 'status_page_components'::regclass AND contype = 'c'
          AND (pg_get_constraintdef(oid) LIKE '%line_group%')
    LOOP
        EXECUTE format('ALTER TABLE status_page_components DROP CONSTRAINT %I', old_check.conname);
    END LOOP;
END;
$migration_664_constraints$;

ALTER TABLE status_page_components
    ADD COLUMN node_id uuid,
    ADD COLUMN group_id uuid REFERENCES status_page_groups(id) ON DELETE SET NULL,
    ADD COLUMN name_en text NOT NULL DEFAULT '' CHECK (name_en = btrim(name_en) AND char_length(name_en) <= 64 AND name_en !~ '[[:cntrl:]]');
ALTER TABLE status_page_components
    ADD CONSTRAINT status_page_components_source_664_ck CHECK (source IN (
        'manual', 'line_group', 'node', 'node_overall', 'gateway', 'control_api', 'web_console', 'dns_sync', 'cert_issue')),
    ADD CONSTRAINT status_page_components_line_group_664_ck CHECK (
        (source = 'line_group') = (line_group_id IS NOT NULL AND line_group_scope_id IS NOT NULL)),
    ADD CONSTRAINT status_page_components_node_664_ck CHECK ((source = 'node') = (node_id IS NOT NULL));
CREATE INDEX status_page_components_group_664_idx ON status_page_components (group_id);

ALTER TABLE status_page_settings ADD COLUMN defaults_seeded_at timestamptz;
