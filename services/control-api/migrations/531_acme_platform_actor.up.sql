-- 531（r136 fix-acme，主会话 10-26 分配）：平台成员代租户申请/续期证书。
-- acme_runtime_actor_is_active_048 原先只认目标租户的活跃成员，平台管理员在
-- 主控「证书管理」点"重新申请"一律被 certificate_orders 触发器拒绝（P0001）。
-- 现在也接受：活跃的平台 scope 成员，且在平台 scope 持 platform.admin 或
-- certificates.manage；目标租户仍须 active。函数签名不变，048/103 的调用点随之生效。
-- 048 的 6 个 (scope_id,user_id)→memberships 外键要求操作人是目标租户成员，平台成员代下单
-- 会被拒（23503）；改为 user_id→users(id)，"操作人须为目标租户 active 成员或上述平台成员"
-- 只由触发器（本函数）保证（主会话 10-26 定案 A'）。
-- 047 的 validate_acme_issuance_operation_snapshot_047 也直接查目标租户成员关系（worker
-- 认领平台代下单会被拒），改为调用上面的函数（同样要求租户/用户 active）。
-- 同时修正 048 的跨租户放行：SQL 函数里列名优先于同名参数，原 WHERE scope.id = scope_id
-- 实际比较的是 membership.scope_id，任意活跃租户的成员都能通过。函数体改用 $1/$2。
LOCK TABLE schema_migrations, acme_tenant_key_facts, acme_account_registration_facts,
    acme_issuance_operations, certificate_orders, acme_renewal_claim_facts
IN ACCESS EXCLUSIVE MODE;

DO $migration_531_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 530 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 530 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=530 AND
        migration_id='530_installation_ban_rejected_notice' AND
        checksum_sha256='018fa04ca61d86e61d93af9d31a1bd59eeff5ec99c49e561e2660d7074373e5b' AND
        down_checksum_sha256='f480e877472a5f6dbe432723530b50827d79c1be502bbb8be6e0478babf7658b' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 531 requires the exact verified 530 release head' USING ERRCODE='P5310';
    END IF;
END;
$migration_531_up$;

CREATE OR REPLACE FUNCTION acme_runtime_actor_is_active_048(scope_id uuid, actor_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM access_scopes scope
        JOIN tenants tenant ON tenant.id = scope.tenant_id AND tenant.status = 'active'
        JOIN memberships membership
          ON membership.scope_id = scope.id
         AND membership.user_id = $2
         AND membership.status = 'active'
        JOIN users account ON account.id = membership.user_id AND account.status = 'active'
        WHERE scope.id = $1 AND scope.kind = 'tenant'
    ) OR EXISTS (
        SELECT 1
        FROM access_scopes scope
        JOIN tenants tenant ON tenant.id = scope.tenant_id AND tenant.status = 'active'
        JOIN memberships membership ON membership.user_id = $2 AND membership.status = 'active'
        JOIN access_scopes platform_scope
          ON platform_scope.id = membership.scope_id AND platform_scope.kind = 'platform'
        JOIN users account ON account.id = membership.user_id AND account.status = 'active'
        WHERE scope.id = $1 AND scope.kind = 'tenant'
          AND EXISTS (
              SELECT 1 FROM role_assignments assignment
              JOIN role_permissions permission ON permission.role_id = assignment.role_id
              WHERE assignment.scope_id = platform_scope.id AND assignment.user_id = $2
                AND permission.permission_name IN ('platform.admin', 'certificates.manage')
          )
    )
$$;

ALTER TABLE acme_tenant_key_facts
    DROP CONSTRAINT acme_tenant_key_facts_actor_fk_048,
    ADD CONSTRAINT acme_tenant_key_facts_actor_fk_531
        FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT;
ALTER TABLE acme_account_registration_facts
    DROP CONSTRAINT acme_account_registration_actor_fk_048,
    ADD CONSTRAINT acme_account_registration_actor_fk_531
        FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT;
ALTER TABLE acme_issuance_operations
    DROP CONSTRAINT acme_issuance_operations_actor_fk_048,
    ADD CONSTRAINT acme_issuance_operations_actor_fk_531
        FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE RESTRICT;
ALTER TABLE certificate_orders
    DROP CONSTRAINT certificate_orders_created_actor_fk_048,
    DROP CONSTRAINT certificate_orders_updated_actor_fk_048,
    ADD CONSTRAINT certificate_orders_created_actor_fk_531
        FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT,
    ADD CONSTRAINT certificate_orders_updated_actor_fk_531
        FOREIGN KEY (updated_by_user_id) REFERENCES users(id) ON DELETE RESTRICT;
ALTER TABLE acme_renewal_claim_facts
    DROP CONSTRAINT acme_renewal_claim_actor_fk_048,
    ADD CONSTRAINT acme_renewal_claim_actor_fk_531
        FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE RESTRICT;

CREATE OR REPLACE FUNCTION validate_acme_issuance_operation_snapshot_047()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    snapshot_tenant_id uuid;
    snapshot_scope_id uuid;
    snapshot_actor_id uuid;
    scope_tenant_id uuid;
BEGIN
    BEGIN
        snapshot_tenant_id := (NEW.request_snapshot ->> 'TenantID')::uuid;
        snapshot_scope_id := (NEW.request_snapshot ->> 'ScopeID')::uuid;
        snapshot_actor_id := (NEW.request_snapshot ->> 'ActorUserID')::uuid;
    EXCEPTION WHEN invalid_text_representation THEN
        RAISE EXCEPTION 'ACME issuance request snapshot identity is invalid' USING ERRCODE = 'P0001';
    END;

    SELECT scope.tenant_id INTO scope_tenant_id
    FROM access_scopes scope
    WHERE scope.id = NEW.tenant_scope_id AND scope.kind = 'tenant';
    IF NOT FOUND
       OR snapshot_tenant_id IS NULL
       OR snapshot_scope_id IS NULL
       OR snapshot_actor_id IS NULL
       OR snapshot_scope_id IS DISTINCT FROM NEW.tenant_scope_id
       OR snapshot_tenant_id IS DISTINCT FROM scope_tenant_id
       OR NOT acme_runtime_actor_is_active_048(NEW.tenant_scope_id, snapshot_actor_id) THEN
        RAISE EXCEPTION 'ACME issuance request snapshot is not bound to an active tenant actor'
            USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;
