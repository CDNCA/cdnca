LOCK TABLE schema_migrations, package_period_reset_workload_authority_bindings_165,
    identity_verification_cases, identity_verification_state_events, identity_verification_review_assignments,
    identity_verification_reviews, identity_verification_write_requests
    IN ACCESS EXCLUSIVE MODE;

DO $migration_534_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 534 OR
       (SELECT max(version) FROM schema_migrations) <> 534 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=534 AND
        migration_id='534_platform_admin_period_reset_identity_review' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 534 down requires the exact verified migration head' USING ERRCODE='P5341';
    END IF;
    -- 平台管理员代建的绑定、代审留下的事实都是只追加记录，回滚后旧外键容不下：拒绝回滚。
    IF EXISTS (SELECT 1 FROM package_period_reset_workload_authority_bindings_165 WHERE actor_scope_id IS NOT NULL) OR
       EXISTS (SELECT 1 FROM identity_verification_cases fact WHERE fact.reviewer_user_id IS NOT NULL AND NOT EXISTS (
           SELECT 1 FROM memberships m WHERE m.scope_id=fact.tenant_scope_id AND m.user_id=fact.reviewer_user_id)) OR
       EXISTS (SELECT 1 FROM identity_verification_state_events fact WHERE NOT EXISTS (
           SELECT 1 FROM memberships m WHERE m.scope_id=fact.tenant_scope_id AND m.user_id=fact.actor_user_id)) OR
       EXISTS (SELECT 1 FROM identity_verification_review_assignments fact WHERE NOT EXISTS (
           SELECT 1 FROM memberships m WHERE m.scope_id=fact.tenant_scope_id AND m.user_id=fact.reviewer_user_id)) OR
       EXISTS (SELECT 1 FROM identity_verification_reviews fact WHERE NOT EXISTS (
           SELECT 1 FROM memberships m WHERE m.scope_id=fact.tenant_scope_id AND m.user_id=fact.reviewer_user_id)) OR
       EXISTS (SELECT 1 FROM identity_verification_write_requests fact WHERE NOT EXISTS (
           SELECT 1 FROM memberships m WHERE m.scope_id=fact.tenant_scope_id AND m.user_id=fact.actor_user_id)) THEN
        RAISE EXCEPTION 'migration 534 rollback would drop platform administrator period reset or identity review facts'
            USING ERRCODE='P5342';
    END IF;
END;
$migration_534_down$;

ALTER TABLE identity_verification_write_requests
    DROP CONSTRAINT identity_verification_write_requests_actor_user_fk_534,
    ADD CONSTRAINT identity_verification_write_r_tenant_scope_id_actor_user_i_fkey
        FOREIGN KEY (tenant_scope_id, actor_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;
ALTER TABLE identity_verification_reviews
    DROP CONSTRAINT identity_verification_reviews_reviewer_user_fk_534,
    ADD CONSTRAINT identity_verification_reviews_tenant_scope_id_reviewer_use_fkey
        FOREIGN KEY (tenant_scope_id, reviewer_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;
ALTER TABLE identity_verification_review_assignments
    DROP CONSTRAINT identity_verification_review_assignments_reviewer_user_fk_534,
    ADD CONSTRAINT identity_verification_review__tenant_scope_id_reviewer_use_fkey
        FOREIGN KEY (tenant_scope_id, reviewer_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;
ALTER TABLE identity_verification_state_events
    DROP CONSTRAINT identity_verification_state_events_actor_user_fk_534,
    ADD CONSTRAINT identity_verification_state_e_tenant_scope_id_actor_user_i_fkey
        FOREIGN KEY (tenant_scope_id, actor_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;
ALTER TABLE identity_verification_cases
    DROP CONSTRAINT identity_verification_cases_reviewer_user_fk_534,
    ADD CONSTRAINT identity_verification_cases_tenant_scope_id_reviewer_user__fkey
        FOREIGN KEY (tenant_scope_id, reviewer_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;

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
          AND EXISTS (
              SELECT 1 FROM memberships reviewer_membership
              JOIN users reviewer_user
                ON reviewer_user.id = reviewer_membership.user_id AND reviewer_user.status = 'active'
              JOIN role_assignments assignment
                ON assignment.scope_id = reviewer_membership.scope_id
               AND assignment.user_id = reviewer_membership.user_id
              JOIN role_permissions role_permission ON role_permission.role_id = assignment.role_id
              WHERE reviewer_membership.scope_id = NEW.tenant_scope_id
                AND reviewer_membership.user_id = NEW.reviewer_user_id
                AND reviewer_membership.status = 'active'
                AND role_permission.permission_name = 'identity_verification.review'
          )
    ) THEN
        RAISE EXCEPTION 'identity verification assignment does not match current submission';
    END IF;
    RETURN NEW;
END;
$$;

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
    );
$$;

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
       NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id OR NEW.audience IS DISTINCT FROM OLD.audience OR
       NEW.permission_name IS DISTINCT FROM OLD.permission_name OR NEW.not_before IS DISTINCT FROM OLD.not_before OR
       NEW.expires_at IS DISTINCT FROM OLD.expires_at OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'package period reset workload authority binding only permits one-way revocation'
            USING ERRCODE='P1651';
    END IF;
    RETURN NEW;
END;
$$;

ALTER TABLE package_period_reset_workload_authority_bindings_165
    DROP COLUMN actor_scope_id,
    ADD CONSTRAINT package_period_reset_workload_tenant_scope_id_actor_user_i_fkey
        FOREIGN KEY (tenant_scope_id, actor_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;
