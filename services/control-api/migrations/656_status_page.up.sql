-- 656 公开服务状态页。
--   status_page_settings：单行设置（是否公开、标题、说明、是否显示 logo），revision 乐观锁。
--   status_page_components：客户命名的组件，source=manual 只看手动状态，source=line_group 另按线路组
--     可用端点比例算自动状态；不引用 node_line_groups 外键（线路组被删时组件保留，自动状态缺省正常）。
--   status_page_incidents / status_page_incident_updates：事件（调查中→已定位→监控中→已恢复）与维护窗口。
--   status_page_daily：每组件每 UTC 日的分钟累计，采样器每分钟一次，last_minute 去重；保留 120 天。
-- 权限沿用 system_configuration.read / manage，不新增权限码。新表，无回填。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_656_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 655 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 655 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=655 AND
        migration_id='655_site_content_rewrite' AND
        checksum_sha256='01ac1f868003831c8c59bdaffe896170670c8a826a4fc955de920fcb223348bd' AND
        down_checksum_sha256='03ca64cf7a862642a3f460b475144fd3a700c0271d3f8711630b5938b0938425' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.status_page_settings') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 656 requires the exact verified 655 release head' USING ERRCODE='P6560';
    END IF;
END;
$migration_656_up$;

CREATE TABLE status_page_settings (
    id smallint PRIMARY KEY CHECK (id = 1),
    enabled boolean NOT NULL DEFAULT false,
    title text NOT NULL DEFAULT '' CHECK (title = btrim(title) AND char_length(title) <= 64 AND title !~ '[[:cntrl:]]'),
    description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 500),
    show_logo boolean NOT NULL DEFAULT true,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL
);
INSERT INTO status_page_settings(id) VALUES (1);

CREATE TABLE status_page_components (
    id uuid PRIMARY KEY,
    name text NOT NULL CHECK (name = btrim(name) AND char_length(name) BETWEEN 1 AND 64 AND name !~ '[[:cntrl:]]'),
    description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 200 AND description !~ '[[:cntrl:]]'),
    source text NOT NULL CHECK (source IN ('manual', 'line_group')),
    line_group_scope_id uuid,
    line_group_id uuid,
    manual_status text NOT NULL DEFAULT 'operational'
        CHECK (manual_status IN ('operational', 'degraded', 'outage', 'maintenance')),
    sort_order integer NOT NULL CHECK (sort_order BETWEEN 0 AND 1000),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK ((source = 'line_group') = (line_group_id IS NOT NULL AND line_group_scope_id IS NOT NULL)),
    CHECK (source = 'line_group' OR (line_group_id IS NULL AND line_group_scope_id IS NULL))
);
CREATE UNIQUE INDEX status_page_components_name_656_uq ON status_page_components (lower(name));

CREATE TABLE status_page_incidents (
    id uuid PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN ('incident', 'maintenance')),
    title text NOT NULL CHECK (title = btrim(title) AND char_length(title) BETWEEN 1 AND 120 AND title !~ '[[:cntrl:]]'),
    impact text NOT NULL CHECK (impact IN ('degraded', 'outage', 'maintenance')),
    status text NOT NULL CHECK (status IN (
        'investigating', 'identified', 'monitoring', 'resolved', 'scheduled', 'in_progress', 'completed')),
    component_ids uuid[] NOT NULL DEFAULT '{}' CHECK (cardinality(component_ids) <= 50),
    scheduled_start timestamptz,
    scheduled_end timestamptz,
    started_at timestamptz NOT NULL,
    resolved_at timestamptz,
    created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (kind = 'incident' AND impact IN ('degraded', 'outage')
           AND status IN ('investigating', 'identified', 'monitoring', 'resolved')
           AND scheduled_start IS NULL AND scheduled_end IS NULL
        OR kind = 'maintenance' AND impact = 'maintenance'
           AND status IN ('scheduled', 'in_progress', 'completed')
           AND scheduled_start IS NOT NULL AND scheduled_end > scheduled_start),
    CHECK ((resolved_at IS NOT NULL) = (status IN ('resolved', 'completed')))
);
CREATE INDEX status_page_incidents_open_656_idx ON status_page_incidents (started_at DESC)
    WHERE resolved_at IS NULL;
CREATE INDEX status_page_incidents_resolved_656_idx ON status_page_incidents (resolved_at DESC)
    WHERE resolved_at IS NOT NULL;

CREATE TABLE status_page_incident_updates (
    id uuid PRIMARY KEY,
    incident_id uuid NOT NULL REFERENCES status_page_incidents(id) ON DELETE CASCADE,
    status text NOT NULL CHECK (status IN (
        'investigating', 'identified', 'monitoring', 'resolved', 'scheduled', 'in_progress', 'completed')),
    message text NOT NULL CHECK (char_length(message) BETWEEN 1 AND 2000),
    created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL
);
CREATE INDEX status_page_incident_updates_incident_656_idx ON status_page_incident_updates (incident_id, created_at);

CREATE TABLE status_page_daily (
    component_id uuid NOT NULL REFERENCES status_page_components(id) ON DELETE CASCADE,
    day date NOT NULL,
    sampled_minutes integer NOT NULL DEFAULT 0 CHECK (sampled_minutes BETWEEN 0 AND 1440),
    degraded_minutes integer NOT NULL DEFAULT 0 CHECK (degraded_minutes BETWEEN 0 AND 1440),
    outage_minutes integer NOT NULL DEFAULT 0 CHECK (outage_minutes BETWEEN 0 AND 1440),
    maintenance_minutes integer NOT NULL DEFAULT 0 CHECK (maintenance_minutes BETWEEN 0 AND 1440),
    last_minute timestamptz NOT NULL,
    PRIMARY KEY (component_id, day),
    CHECK (degraded_minutes + outage_minutes + maintenance_minutes <= sampled_minutes)
);
CREATE INDEX status_page_daily_day_656_idx ON status_page_daily (day);
