-- 522（r136 approval-center，分支占位 530；merge-p9 改为 522，守卫钉前驱 521 的 migration_id / checksum_sha256 /
-- down_checksum_sha256，常量集中在 approval_center_522_contract_test.go）。
-- 平台审批中心（用户 10-25 19:3x 定 Q1–Q8）：
--   approval_center_settings：单行开关 + 已勾选的受管操作（目录写死在代码 internal/approvalcenter/catalog.go）；
--     无行 = 关闭（默认关闭，关闭时现有直接操作完全不变）。
--   approval_requests：平台管理端会话发起受管操作时原样存下的请求（方法/路径/查询/请求体/幂等键/If-Match），
--     待审 24 小时过期（读时派生），审批人批准即用审批人会话执行，记录执行返回码。
--   权限 approvals.read / approvals.approve / approvals.manage 授给平台系统角色。自定义角色只在租户作用域可用
--   （rbacmanager lockActiveActorPrincipal 拒绝平台作用域），平台码进 custom_rbac_permission_catalog 无意义，不进目录。
LOCK TABLE schema_migrations, permissions, access_scopes, roles, role_permissions IN ACCESS EXCLUSIVE MODE;

DO $migration_522_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 521 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 521 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=521 AND
        migration_id='521_site_protocol_batch_drop' AND
        checksum_sha256='209c85d996838d9659529214b46ad4c66cdc77e9471aa25e3b9131d628ee6a61' AND
        down_checksum_sha256='99ccc20dce56fa2e9944e0721bfa41a2653a8f83b91e049686601ca362f942d7' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.approval_requests') IS NOT NULL
         OR EXISTS (SELECT 1 FROM permissions WHERE name LIKE 'approvals.%') THEN
        RAISE EXCEPTION 'migration 522 requires the exact verified 521 release head' USING ERRCODE='P5220';
    END IF;
END;
$migration_522_up$;

INSERT INTO permissions(name, description) VALUES
    ('approvals.read', 'View platform approval requests'),
    ('approvals.approve', 'Approve or reject platform approval requests (an approved request runs with the approver''s session)'),
    ('approvals.manage', 'Turn the platform approval center on or off and choose the managed operations');

INSERT INTO role_permissions(role_id, permission_name)
SELECT role.id, permission.name
FROM roles role
JOIN access_scopes scope ON scope.id = role.scope_id AND scope.kind = 'platform'
CROSS JOIN (VALUES ('approvals.read'), ('approvals.approve'), ('approvals.manage')) AS permission(name)
WHERE role.system_role AND role.name IN ('platform_owner', 'platform_admin')
ON CONFLICT DO NOTHING;

CREATE TABLE approval_center_settings (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    revision bigint NOT NULL CHECK (revision > 0),
    enabled boolean NOT NULL,
    rules text[] NOT NULL CHECK (
        cardinality(rules) <= 32 AND array_position(rules, NULL) IS NULL
    ),
    updated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at))
);

CREATE TABLE approval_requests (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    rule text NOT NULL CHECK (rule ~ '^[a-z][a-z0-9_.]{0,63}$'),
    -- 原样存下的请求步骤 [{method,path,query,headers,body_base64}]，按顺序重放。批量删四层转发前端逐条
    -- DELETE，同一发起人同一组（X-Approval-Group）2 分钟内的待审步骤并进同一张单，最多 100 步。
    items jsonb NOT NULL CHECK (jsonb_typeof(items) = 'array' AND jsonb_array_length(items) BETWEEN 1 AND 100),
    group_key text CHECK (group_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    reason text NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 500 AND reason = btrim(reason)),
    requested_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    requested_by_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    requested_at timestamptz NOT NULL CHECK (isfinite(requested_at)),
    expires_at timestamptz NOT NULL CHECK (isfinite(expires_at) AND expires_at > requested_at),
    -- executing：已批准、正在用审批人会话执行。unknown：executing 超过 10 分钟（进程中断），由恢复器标记，
    -- 不自动重放（避免执行两次），界面提示审批人到原页面核实；之后若原进程仍写回结果，以结果为准。
    -- expired 不落库，读时由 state='pending' AND expires_at<=now() 派生。
    state text NOT NULL CHECK (state IN ('pending', 'rejected', 'executing', 'unknown', 'executed', 'failed')),
    decided_by_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    decided_at timestamptz CHECK (decided_at IS NULL OR isfinite(decided_at)),
    decision_note text NOT NULL DEFAULT '' CHECK (char_length(decision_note) <= 500),
    -- mfa：审批人通过了平台作用域二次验证；none：审批人未绑定二次验证（审计标注"未二次验证"）。
    step_up text CHECK (step_up IN ('mfa', 'none')),
    self_approved boolean NOT NULL DEFAULT false,
    -- 每步执行结果 [{status,body}]（body 截断到 4 KiB）。
    results jsonb CHECK (results IS NULL OR jsonb_typeof(results) = 'array'),
    executed_at timestamptz CHECK (executed_at IS NULL OR isfinite(executed_at)),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    CHECK ((state = 'pending') = (decided_by_user_id IS NULL AND decided_at IS NULL)),
    CHECK ((state IN ('executing', 'unknown', 'executed', 'failed')) = (step_up IS NOT NULL)),
    CHECK ((state IN ('executed', 'failed')) = (results IS NOT NULL AND executed_at IS NOT NULL)),
    CHECK (NOT self_approved OR decided_by_user_id = requested_by_user_id)
);

CREATE INDEX approval_requests_list_522 ON approval_requests (requested_at DESC, id DESC);
CREATE INDEX approval_requests_pending_522 ON approval_requests (expires_at) WHERE state = 'pending';

REVOKE ALL ON approval_center_settings, approval_requests FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON approval_center_settings, approval_requests TO cdnca_control_app;
