LOCK TABLE schema_migrations, permissions, access_scopes, roles, role_permissions,
    users, memberships, l4_forwards, l4_forward_display_id_sequences, l4_write_requests
IN ACCESS EXCLUSIVE MODE;

DO $migration_236$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 235 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 235 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 235 AND migration_id = '235_region_catalog_management' AND
              checksum_sha256 = '165c59e45df388ca3105f7627e617aab7b5bdd59fcc2557d63148ee5003b0f8d' AND
              down_checksum_sha256 = '0491b8691f7c8271073d758137d77acc9f8d8cac3cfa38a7b49c1028fec92e2d' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass(current_schema() || '.l4_stream_groups') IS NOT NULL OR
            to_regclass(current_schema() || '.l4_stream_group_members') IS NOT NULL OR
            to_regclass(current_schema() || '.l4_stream_user_defaults') IS NOT NULL OR
            to_regclass(current_schema() || '.l4_stream_group_default_write_requests') IS NOT NULL OR
            to_regprocedure(current_schema() || '.allocate_l4_stream_group_display_id_236()') IS NOT NULL OR
            to_regprocedure(current_schema() || '.protect_l4_stream_group_236()') IS NOT NULL OR
            EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = current_schema() AND table_name = 'l4_forwards' AND
                      column_name = 'balance_way'
            ) THEN
        RAISE EXCEPTION 'migration 236 requires the exact verified 235 release head and an untouched stream group schema'
            USING ERRCODE = 'P2360';
    END IF;
END;
$migration_236$;

-- 竞品的「负载方式」是转发上的真实字段（rr=轮循 / ip_hash=定源），默认设置可为其配置默认值。
-- 转发表单本身不含该控件，批量修改与默认值带入才是它的入口，故此处只落库不落表单元件。
ALTER TABLE l4_forwards
    ADD COLUMN balance_way text NOT NULL DEFAULT 'rr',
    ADD CONSTRAINT l4_forwards_balance_way_236_check CHECK (balance_way IN ('rr', 'ip_hash'));

CREATE TABLE l4_stream_groups (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    display_id bigint NOT NULL CHECK (display_id > 0),
    owner_user_id uuid NOT NULL,
    name text NOT NULL CHECK (
        name = btrim(name) AND octet_length(name) BETWEEN 1 AND 128 AND name !~ '[[:cntrl:]]'
    ),
    remark text NOT NULL DEFAULT '' CHECK (remark = btrim(remark) AND char_length(remark) <= 256),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by_user_id uuid NOT NULL,
    updated_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz,
    FOREIGN KEY (scope_id, owner_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id, updated_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT l4_stream_groups_scope_display_id_236_unique UNIQUE (scope_id, display_id),
    CONSTRAINT l4_stream_groups_finite_time_236 CHECK (
        isfinite(created_at) AND isfinite(updated_at) AND updated_at >= created_at AND
        (deleted_at IS NULL OR isfinite(deleted_at) AND deleted_at >= created_at)
    )
);

CREATE UNIQUE INDEX l4_stream_groups_scope_name_lower_active_236_idx
    ON l4_stream_groups (scope_id, lower(name)) WHERE deleted_at IS NULL;
CREATE INDEX l4_stream_groups_scope_created_active_236_idx
    ON l4_stream_groups (scope_id, created_at DESC, id DESC) WHERE deleted_at IS NULL;
CREATE INDEX l4_stream_groups_owner_created_active_236_idx
    ON l4_stream_groups (owner_user_id, created_at DESC, id DESC) WHERE deleted_at IS NULL;

-- 竞品「所属分组」是多选（ivu-select-multiple，占位符「转发分组, 可不选」），故一个转发可属多组。
-- 分组删除时先摘除成员关系，转发本身保留，与竞品「未分组」的呈现一致。
CREATE TABLE l4_stream_group_members (
    group_id uuid NOT NULL REFERENCES l4_stream_groups(id) ON DELETE RESTRICT,
    stream_id uuid NOT NULL REFERENCES l4_forwards(id) ON DELETE RESTRICT,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now() CHECK (isfinite(created_at)),
    PRIMARY KEY (group_id, stream_id)
);

CREATE INDEX l4_stream_group_members_stream_236_idx ON l4_stream_group_members (stream_id);
CREATE INDEX l4_stream_group_members_scope_236_idx ON l4_stream_group_members (scope_id);

CREATE TABLE l4_stream_user_defaults (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    display_id bigint NOT NULL CHECK (display_id > 0),
    owner_user_id uuid NOT NULL,
    setting_name text NOT NULL CHECK (
        setting_name IN ('proxy_protocol', 'listen_protocol', 'balance_way')
    ),
    setting_value text NOT NULL CHECK (setting_value = btrim(setting_value) AND setting_value <> ''),
    scope_name text NOT NULL DEFAULT 'global' CHECK (scope_name IN ('global', 'group')),
    group_id uuid REFERENCES l4_stream_groups(id) ON DELETE RESTRICT,
    created_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (scope_id, owner_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT l4_stream_user_defaults_scope_236_check CHECK (
        (scope_name = 'global' AND group_id IS NULL) OR
        (scope_name = 'group' AND group_id IS NOT NULL)
    ),
    CONSTRAINT l4_stream_user_defaults_value_236_check CHECK (
        (setting_name = 'listen_protocol' AND setting_value IN ('tcp', 'udp')) OR
        (setting_name = 'balance_way' AND setting_value IN ('rr', 'ip_hash')) OR
        (setting_name = 'proxy_protocol' AND setting_value IN ('1', '0'))
    ),
    CONSTRAINT l4_stream_user_defaults_scope_display_id_236_unique UNIQUE (scope_id, display_id)
);

-- 同一用户同一设置项：全局至多一条；分组级每组至多一条。两条部分唯一索引覆盖两种生效范围，
-- 避免依赖 NULLS NOT DISTINCT（PostgreSQL 15+ 才有的特性）。
CREATE UNIQUE INDEX l4_stream_user_defaults_global_236_idx
    ON l4_stream_user_defaults (owner_user_id, setting_name) WHERE group_id IS NULL;
CREATE UNIQUE INDEX l4_stream_user_defaults_group_236_idx
    ON l4_stream_user_defaults (owner_user_id, setting_name, group_id) WHERE group_id IS NOT NULL;
CREATE INDEX l4_stream_user_defaults_scope_created_236_idx
    ON l4_stream_user_defaults (scope_id, created_at DESC, id DESC);

-- 默认设置同样按租户分配展示序号：创建响应与列表读取必须给出同一个 ID 列。
CREATE TABLE l4_stream_user_default_display_id_sequences (
    scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    next_value bigint NOT NULL CHECK (next_value > 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO l4_stream_user_default_display_id_sequences (scope_id, next_value)
SELECT scope.id, COALESCE(max(stream_default.display_id), 0) + 1
FROM access_scopes scope
LEFT JOIN l4_stream_user_defaults stream_default ON stream_default.scope_id = scope.id
WHERE scope.kind = 'tenant'
GROUP BY scope.id;

-- display_id 是分配器拥有的列，插入时不允许调用方指定。
CREATE FUNCTION allocate_l4_stream_user_default_display_id_236()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.display_id IS NULL THEN
        INSERT INTO l4_stream_user_default_display_id_sequences (scope_id, next_value, updated_at)
        VALUES (NEW.scope_id, 2, now())
        ON CONFLICT (scope_id) DO UPDATE
        SET next_value = l4_stream_user_default_display_id_sequences.next_value + 1, updated_at = now()
        RETURNING next_value - 1 INTO NEW.display_id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TABLE l4_stream_group_default_write_requests (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN (
        'stream_group.create', 'stream_group.update', 'stream_group.delete',
        'stream_default.create', 'stream_default.delete'
    )),
    idempotency_key text NOT NULL CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128 AND
        idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    resource_id uuid,
    response_status integer CHECK (response_status BETWEEN 200 AND 299),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now() CHECK (isfinite(created_at)),
    completed_at timestamptz CHECK (completed_at IS NULL OR isfinite(completed_at) AND completed_at >= created_at),
    CONSTRAINT l4_stream_group_default_write_requests_identity_236_unique
        UNIQUE (actor_user_id, operation, idempotency_key),
    CONSTRAINT l4_stream_group_default_write_requests_completion_236_check CHECK (
        (response_status IS NULL AND response_body IS NULL AND completed_at IS NULL) OR
        (response_status IS NOT NULL AND response_body IS NOT NULL AND completed_at IS NOT NULL)
    )
);

CREATE INDEX l4_stream_group_default_write_requests_scope_236_idx
    ON l4_stream_group_default_write_requests (target_scope_id, created_at DESC);

-- 分组沿用 214 的按租户分配 display_id 模式，保持「ID」列在各列表间的一致性。
CREATE TABLE l4_stream_group_display_id_sequences (
    scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    next_value bigint NOT NULL CHECK (next_value > 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO l4_stream_group_display_id_sequences (scope_id, next_value)
SELECT scope.id, COALESCE(max(stream_group.display_id), 0) + 1
FROM access_scopes scope
LEFT JOIN l4_stream_groups stream_group ON stream_group.scope_id = scope.id
WHERE scope.kind = 'tenant'
GROUP BY scope.id;

CREATE FUNCTION allocate_l4_stream_group_display_id_236()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.display_id IS NULL THEN
        INSERT INTO l4_stream_group_display_id_sequences (scope_id, next_value, updated_at)
        VALUES (NEW.scope_id, 2, now())
        ON CONFLICT (scope_id) DO UPDATE
        SET next_value = l4_stream_group_display_id_sequences.next_value + 1, updated_at = now()
        RETURNING next_value - 1 INTO NEW.display_id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION protect_l4_stream_group_236()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'stream groups cannot be truncated' USING ERRCODE = 'P2362';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR
       NEW.scope_id IS DISTINCT FROM OLD.scope_id OR
       NEW.display_id IS DISTINCT FROM OLD.display_id OR
       NEW.created_at IS DISTINCT FROM OLD.created_at OR
       NEW.revision <> OLD.revision + 1 OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'stream group revision must advance by one' USING ERRCODE = 'P2361';
    END IF;
    IF TG_OP = 'DELETE' AND EXISTS (
        SELECT 1 FROM l4_stream_user_defaults stream_default WHERE stream_default.group_id = OLD.id
    ) THEN
        RAISE EXCEPTION 'referenced stream group cannot be deleted' USING ERRCODE = 'P2362';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION protect_l4_stream_group_write_request_236()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- resource_id 属于「完成时」才填写的列，不是不可变列：完成写入正是设置它的那一次变更。
    IF TG_OP = 'UPDATE' AND OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL AND
       OLD.resource_id IS NULL AND NEW.resource_id IS NOT NULL AND
       OLD.response_status IS NULL AND NEW.response_status IS NOT NULL AND
       NEW.id IS NOT DISTINCT FROM OLD.id AND
       NEW.actor_user_id IS NOT DISTINCT FROM OLD.actor_user_id AND
       NEW.target_scope_id IS NOT DISTINCT FROM OLD.target_scope_id AND
       NEW.operation IS NOT DISTINCT FROM OLD.operation AND
       NEW.idempotency_key IS NOT DISTINCT FROM OLD.idempotency_key AND
       NEW.request_digest IS NOT DISTINCT FROM OLD.request_digest AND
       NEW.created_at IS NOT DISTINCT FROM OLD.created_at THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'stream group write requests are immutable after completion';
END;
$$;

CREATE TRIGGER l4_stream_groups_display_id_236 BEFORE INSERT ON l4_stream_groups
FOR EACH ROW EXECUTE FUNCTION allocate_l4_stream_group_display_id_236();

CREATE TRIGGER l4_stream_user_defaults_display_id_236 BEFORE INSERT ON l4_stream_user_defaults
FOR EACH ROW EXECUTE FUNCTION allocate_l4_stream_user_default_display_id_236();

CREATE TRIGGER l4_stream_groups_update_236 BEFORE UPDATE ON l4_stream_groups
FOR EACH ROW EXECUTE FUNCTION protect_l4_stream_group_236();

CREATE TRIGGER l4_stream_groups_delete_236 BEFORE DELETE ON l4_stream_groups
FOR EACH ROW EXECUTE FUNCTION protect_l4_stream_group_236();

CREATE TRIGGER l4_stream_groups_truncate_236 BEFORE TRUNCATE ON l4_stream_groups
FOR EACH STATEMENT EXECUTE FUNCTION protect_l4_stream_group_236();

CREATE TRIGGER l4_stream_group_default_write_requests_immutable_236
BEFORE UPDATE OR DELETE ON l4_stream_group_default_write_requests
FOR EACH ROW EXECUTE FUNCTION protect_l4_stream_group_write_request_236();

CREATE TRIGGER l4_stream_group_default_write_requests_truncate_236
BEFORE TRUNCATE ON l4_stream_group_default_write_requests
FOR EACH STATEMENT EXECUTE FUNCTION protect_l4_stream_group_write_request_236();

DO $l4_stream_group_runtime_grants$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cdnca_control_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON l4_stream_groups TO cdnca_control_app;
        GRANT SELECT, INSERT, DELETE ON l4_stream_group_members TO cdnca_control_app;
        GRANT SELECT, INSERT, DELETE ON l4_stream_user_defaults TO cdnca_control_app;
        GRANT SELECT, INSERT, UPDATE ON l4_stream_group_default_write_requests TO cdnca_control_app;
        GRANT SELECT, INSERT, UPDATE ON l4_stream_group_display_id_sequences TO cdnca_control_app;
        GRANT SELECT, INSERT, UPDATE ON l4_stream_user_default_display_id_sequences TO cdnca_control_app;
    END IF;
END;
$l4_stream_group_runtime_grants$;

REVOKE ALL ON FUNCTION allocate_l4_stream_group_display_id_236(),
    allocate_l4_stream_user_default_display_id_236(),
    protect_l4_stream_group_236(),
    protect_l4_stream_group_write_request_236() FROM PUBLIC;
