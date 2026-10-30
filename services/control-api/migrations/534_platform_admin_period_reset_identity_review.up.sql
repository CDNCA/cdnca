-- 534（r136 fix-dec1027，主会话 10-27 分配）：用户 10-27 第 2、3 项，平台管理员代租户操作，记管理员本人身份。
-- 平台管理员 = control_platform_admin_435（与 tenantaccess.ActorOnTenantSQL 同一规则）。前驱 533，守卫钉 533 校验和。
-- 第 2 项 套餐周期重置授权绑定（165）："他不计哪个租户就是用他管理员的身份，日志记录都是管理员"。
--   加 actor_scope_id：NULL = 租户成员本人建（原规则不变）；非 NULL = 平台 scope，
--   actor_user_id 须是该平台 scope 的 platform.admin，目标租户须 active。不冒充租户成员。
--   (tenant_scope_id,actor_user_id)→memberships 外键去掉（actor_user_id→users 保留），成员规则只由触发器保证。
-- 第 3 项 实名审核（037）："平台管理员也能代审……租户审核可做的管理都可一个人做"。
--   identity_verification_actor_has_permission 对 read/review 两码加平台管理员分支（self.manage 仍只认本人成员）；
--   分配触发器内联的成员检查改调该函数；审核员/操作人五个 →memberships 外键改 →users(id)（同 531）。
--   申请人相关外键不动。
LOCK TABLE schema_migrations, package_period_reset_workload_authority_bindings_165,
    identity_verification_cases, identity_verification_state_events, identity_verification_review_assignments,
    identity_verification_reviews, identity_verification_write_requests
    IN ACCESS EXCLUSIVE MODE;

DO $migration_534_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 533 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 533 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=533 AND
        migration_id='533_cname_without_package' AND
        checksum_sha256='a7eb4f050b1ca20f34eac14c7f3aaaea42bb0e30a0c129ac88fe6094070af526' AND
        down_checksum_sha256='0cef91130d0e2740112d3b12ef8cc076cba8f1680e4faec437ea9caaf6749a4c' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema()
          AND table_name='package_period_reset_workload_authority_bindings_165' AND column_name='actor_scope_id'
       ) THEN
        RAISE EXCEPTION 'migration 534 requires the exact verified 533 release head' USING ERRCODE='P5340';
    END IF;
END;
$migration_534_up$;

-- ===== 第 2 项：周期重置授权绑定 =====
ALTER TABLE package_period_reset_workload_authority_bindings_165
    ADD COLUMN actor_scope_id uuid REFERENCES access_scopes(id) ON DELETE RESTRICT,
    DROP CONSTRAINT package_period_reset_workload_tenant_scope_id_actor_user_i_fkey;

CREATE OR REPLACE FUNCTION protect_package_period_reset_workload_authority_binding_165()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    scope_kind text;
    account_status text;
    membership_status text;
    permission_allowed boolean;
BEGIN
    IF TG_OP='TRUNCATE' THEN
        RAISE EXCEPTION 'package period reset workload authority bindings cannot be truncated' USING ERRCODE='P1651';
    ELSIF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'package period reset workload authority bindings cannot be deleted' USING ERRCODE='P1651';
    ELSIF TG_OP='INSERT' THEN
        IF NEW.status<>'active' OR NEW.revision<>1 OR NEW.revoked_at IS NOT NULL OR NEW.updated_at<>NEW.created_at THEN
            RAISE EXCEPTION 'package period reset workload authority binding must start active at revision 1'
                USING ERRCODE='P1651';
        END IF;
        IF NEW.actor_scope_id IS NOT NULL THEN
            -- 534：平台管理员代建，身份是管理员本人（平台 scope），目标须是 active 租户。
            IF NOT control_platform_admin_435(NEW.actor_user_id, NEW.actor_scope_id) OR NOT EXISTS (
                SELECT 1 FROM access_scopes scope JOIN tenants tenant ON tenant.id=scope.tenant_id
                WHERE scope.id=NEW.tenant_scope_id AND scope.kind='tenant' AND tenant.status='active') THEN
                RAISE EXCEPTION 'package period reset workload authority binding requires a platform administrator for an active tenant'
                    USING ERRCODE='P1651';
            END IF;
            RETURN NEW;
        END IF;
        SELECT scope.kind,account.status,membership.status,EXISTS(
            SELECT 1 FROM custom_rbac_effective_permissions(NEW.tenant_scope_id,NEW.actor_user_id)
            WHERE permission_name='sites.manage'
        ) INTO scope_kind,account_status,membership_status,permission_allowed
        FROM access_scopes scope
        JOIN memberships membership ON membership.scope_id=scope.id AND membership.user_id=NEW.actor_user_id
        JOIN users account ON account.id=membership.user_id
        WHERE scope.id=NEW.tenant_scope_id;
        IF scope_kind IS DISTINCT FROM 'tenant' OR account_status IS DISTINCT FROM 'active' OR
           membership_status IS DISTINCT FROM 'active' OR permission_allowed IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'package period reset workload authority binding requires an active tenant actor with sites.manage'
                USING ERRCODE='P1651';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.status<>'active' OR NEW.status<>'revoked' OR NEW.revision<>OLD.revision+1 OR
       NEW.revoked_at IS NULL OR NEW.updated_at<>NEW.revoked_at OR NEW.revoked_at<OLD.created_at OR
       NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id OR
       NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id OR NEW.actor_scope_id IS DISTINCT FROM OLD.actor_scope_id OR
       NEW.audience IS DISTINCT FROM OLD.audience OR
       NEW.permission_name IS DISTINCT FROM OLD.permission_name OR NEW.not_before IS DISTINCT FROM OLD.not_before OR
       NEW.expires_at IS DISTINCT FROM OLD.expires_at OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'package period reset workload authority binding only permits one-way revocation'
            USING ERRCODE='P1651';
    END IF;
    RETURN NEW;
END;
$$;

-- ===== 第 3 项：实名审核 =====
CREATE OR REPLACE FUNCTION identity_verification_actor_has_permission(
    scope_id uuid,
    user_id uuid,
    required_permission text
)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM memberships membership
        JOIN users actor_user
          ON actor_user.id = membership.user_id AND actor_user.status = 'active'
        JOIN role_assignments assignment
          ON assignment.scope_id = membership.scope_id
         AND assignment.user_id = membership.user_id
        JOIN role_permissions role_permission ON role_permission.role_id = assignment.role_id
        WHERE membership.scope_id = $1
          AND membership.user_id = $2
          AND membership.status = 'active'
          AND role_permission.permission_name = $3
    ) OR (
        -- 534：平台管理员可代审（读/审核），不能以申请人身份操作（self.manage）。
        $3 IN ('identity_verification.read', 'identity_verification.review')
        AND control_platform_admin_435($2, NULL)
        AND EXISTS (
            SELECT 1 FROM access_scopes target JOIN tenants tenant ON tenant.id = target.tenant_id
            WHERE target.id = $1 AND target.kind = 'tenant' AND tenant.status = 'active'
        )
    );
$$;

CREATE OR REPLACE FUNCTION validate_identity_verification_assignment_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM identity_verification_cases verification_case
        WHERE verification_case.tenant_scope_id = NEW.tenant_scope_id
          AND verification_case.id = NEW.case_id AND verification_case.status = 'submitted'
          AND verification_case.revision + 1 = NEW.case_revision
          AND verification_case.applicant_user_id <> NEW.reviewer_user_id
          AND NEW.assigned_at >= verification_case.state_changed_at
          -- 534：与其余实名触发器同一规则（含平台管理员代审）。
          AND identity_verification_actor_has_permission(
              NEW.tenant_scope_id, NEW.reviewer_user_id, 'identity_verification.review'
          )
    ) THEN
        RAISE EXCEPTION 'identity verification assignment does not match current submission';
    END IF;
    RETURN NEW;
END;
$$;

ALTER TABLE identity_verification_cases
    DROP CONSTRAINT identity_verification_cases_tenant_scope_id_reviewer_user__fkey,
    ADD CONSTRAINT identity_verification_cases_reviewer_user_fk_534
        FOREIGN KEY (reviewer_user_id) REFERENCES users(id) ON DELETE RESTRICT;
ALTER TABLE identity_verification_state_events
    DROP CONSTRAINT identity_verification_state_e_tenant_scope_id_actor_user_i_fkey,
    ADD CONSTRAINT identity_verification_state_events_actor_user_fk_534
        FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE RESTRICT;
ALTER TABLE identity_verification_review_assignments
    DROP CONSTRAINT identity_verification_review__tenant_scope_id_reviewer_use_fkey,
    ADD CONSTRAINT identity_verification_review_assignments_reviewer_user_fk_534
        FOREIGN KEY (reviewer_user_id) REFERENCES users(id) ON DELETE RESTRICT;
ALTER TABLE identity_verification_reviews
    DROP CONSTRAINT identity_verification_reviews_tenant_scope_id_reviewer_use_fkey,
    ADD CONSTRAINT identity_verification_reviews_reviewer_user_fk_534
        FOREIGN KEY (reviewer_user_id) REFERENCES users(id) ON DELETE RESTRICT;
ALTER TABLE identity_verification_write_requests
    DROP CONSTRAINT identity_verification_write_r_tenant_scope_id_actor_user_i_fkey,
    ADD CONSTRAINT identity_verification_write_requests_actor_user_fk_534
        FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE RESTRICT;
