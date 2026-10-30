-- 532（r136 fix-adminall，主会话 10-26 分配）：平台管理员是最高权限（用户 10-26："管理员是第一权限，没有不能操作的"）。
-- 平台 scope 下持 platform.admin 的活跃成员，对任何租户资源都可写；只认精确权限码或只认租户成员的
-- 触发器/函数一律补上这条。普通非成员仍拒。判定表见 decisions/r136-tasks/fix/fix-adminall.md。
-- 047 ACME 签发快照：改用订单同一规则 acme_runtime_actor_is_active_048（fix-acme 的 531 已放宽到平台成员）。
-- 035 系统配置 / 054 错误页 / 056 HTTP 策略 / 084 插件 Webhook / 090(481) 套餐上架：平台分支补 platform.admin。
-- 函数签名不变，CREATE OR REPLACE 后原触发器与调用点随之生效。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_532_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 531 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 531 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=531 AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 532 requires the exact verified 531 release head' USING ERRCODE='P5320';
    END IF;
END;
$migration_532_up$;

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
       -- 532: the same actor rule as the order (048, widened by 531 to platform members).
       OR NOT acme_runtime_actor_is_active_048(NEW.tenant_scope_id, snapshot_actor_id) THEN
        RAISE EXCEPTION 'ACME issuance request snapshot is not bound to an active tenant actor'
            USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION system_configuration_actor_has_permission(
    requested_scope_id uuid, requested_user_id uuid, requested_permission text
)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM access_scopes scope
        JOIN memberships membership
          ON membership.scope_id = scope.id AND membership.user_id = requested_user_id
         AND membership.status = 'active'
        JOIN users account ON account.id = membership.user_id AND account.status = 'active'
        JOIN role_assignments assignment
          ON assignment.scope_id = scope.id AND assignment.user_id = membership.user_id
        JOIN roles role ON role.id = assignment.role_id AND role.scope_id = scope.id
        JOIN role_permissions permission ON permission.role_id = role.id
        WHERE scope.id = requested_scope_id AND scope.kind = 'platform' AND scope.tenant_id IS NULL
          AND permission.permission_name IN (requested_permission, 'platform.admin')
    );
$$;

CREATE OR REPLACE FUNCTION error_page_actor_has_permission(actor_scope uuid, actor_user uuid, requested_permission text)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM memberships membership
        JOIN role_assignments assignment
          ON assignment.scope_id = membership.scope_id AND assignment.user_id = membership.user_id
        JOIN role_permissions grant_row ON grant_row.role_id = assignment.role_id
        WHERE membership.scope_id = actor_scope
          AND membership.user_id = actor_user
          AND membership.status = 'active'
          AND grant_row.permission_name = requested_permission
    ) OR control_platform_admin_435(actor_user, actor_scope)
$$;

CREATE OR REPLACE FUNCTION http_policy_actor_can_056(actor_scope uuid, actor_user uuid, target_scope uuid, permission text)
RETURNS boolean
LANGUAGE plpgsql
STABLE
AS $$
DECLARE actor_kind text;
BEGIN
    SELECT scope.kind INTO actor_kind
    FROM access_scopes scope
    JOIN memberships membership
      ON membership.scope_id = scope.id AND membership.user_id = actor_user
     AND membership.status = 'active'
    JOIN users account ON account.id = membership.user_id AND account.status = 'active'
    WHERE scope.id = actor_scope;
    IF actor_kind = 'tenant' THEN
        RETURN actor_scope = target_scope AND EXISTS (
            SELECT 1 FROM custom_rbac_effective_permissions(actor_scope, actor_user)
            WHERE permission_name = permission
        );
    END IF;
    IF actor_kind = 'platform' THEN
        RETURN EXISTS (
            SELECT 1
            FROM role_assignments assignment
            JOIN role_permissions role_permission ON role_permission.role_id = assignment.role_id
            WHERE assignment.scope_id = actor_scope AND assignment.user_id = actor_user
              AND role_permission.permission_name IN (permission, 'platform.admin')
        );
    END IF;
    RETURN false;
END;
$$;

CREATE OR REPLACE FUNCTION validate_plugin_webhook_actor_target_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_kind text;
    target_status text;
    actor_kind text;
    actor_membership text;
    actor_status text;
    actor_can_manage boolean;
    requires_live_manage boolean;
    requires_active_target boolean := true;
BEGIN
    requires_live_manage := TG_OP = 'INSERT' AND TG_TABLE_NAME IN (
        'plugin_webhook_subscriptions', 'plugin_webhook_secret_versions',
        'plugin_webhook_write_requests', 'plugin_webhook_events',
        'plugin_webhook_deliveries', 'plugin_webhook_outbox', 'plugin_webhook_rate_events'
    );
    IF TG_OP = 'UPDATE' AND
       ROW(NEW.actor_scope_id, NEW.actor_user_id) IS DISTINCT FROM
       ROW(OLD.actor_scope_id, OLD.actor_user_id) THEN
        requires_live_manage := true;
    END IF;
    IF TG_OP = 'UPDATE' AND TG_TABLE_NAME = 'plugin_webhook_write_requests' THEN
        IF OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL THEN
            requires_live_manage := true;
        END IF;
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF TG_TABLE_NAME = 'plugin_webhook_secret_versions' THEN
            IF OLD.status IN ('pending', 'retired') AND NEW.status = 'expired' THEN
                requires_active_target := false;
            END IF;
        ELSIF TG_TABLE_NAME = 'plugin_webhook_write_requests' THEN
            IF OLD.completed_at IS NOT NULL AND OLD.receipt_ciphertext IS NOT NULL AND
               NEW.receipt_ciphertext IS NULL AND NEW.receipt_cleared_at IS NOT NULL THEN
                requires_active_target := false;
            END IF;
        ELSIF TG_TABLE_NAME = 'plugin_webhook_delivery_attempts' THEN
            IF (OLD.status = 'started' AND NEW.status IN (
                   'succeeded', 'temporary_failure', 'permanent_failure'
               )) OR (OLD.status = 'claimed' AND NEW.status = 'revoked') THEN
                requires_active_target := false;
            END IF;
        ELSIF TG_TABLE_NAME = 'plugin_webhook_deliveries' THEN
            IF OLD.status = 'claimed' AND NEW.status IN (
                   'retry_scheduled', 'delivered', 'dead_letter_pending', 'revoked'
               ) OR OLD.status = 'dead_letter_pending' AND NEW.status = 'dead_lettered' THEN
                requires_active_target := false;
            END IF;
        ELSIF TG_TABLE_NAME = 'plugin_webhook_dead_letters' THEN
            requires_active_target := false;
        END IF;
    ELSIF TG_TABLE_NAME = 'plugin_webhook_dead_letters' THEN
        requires_active_target := false;
    END IF;
    IF requires_live_manage THEN
        SELECT scope.kind, tenant.status INTO target_kind, target_status
        FROM access_scopes scope JOIN tenants tenant ON tenant.id = scope.tenant_id
        WHERE scope.id = NEW.tenant_scope_id
        FOR SHARE OF scope, tenant;
        SELECT scope.kind, membership.status, account.status
          INTO actor_kind, actor_membership, actor_status
        FROM access_scopes scope
        JOIN memberships membership ON membership.scope_id = scope.id
        JOIN users account ON account.id = membership.user_id
        WHERE scope.id = NEW.actor_scope_id AND membership.user_id = NEW.actor_user_id
        FOR SHARE OF scope, membership, account;
    ELSE
        SELECT scope.kind, tenant.status INTO target_kind, target_status
        FROM access_scopes scope JOIN tenants tenant ON tenant.id = scope.tenant_id
        WHERE scope.id = NEW.tenant_scope_id;
        SELECT scope.kind, membership.status, account.status
          INTO actor_kind, actor_membership, actor_status
        FROM access_scopes scope
        JOIN memberships membership ON membership.scope_id = scope.id
        JOIN users account ON account.id = membership.user_id
        WHERE scope.id = NEW.actor_scope_id AND membership.user_id = NEW.actor_user_id;
    END IF;
    IF target_kind IS DISTINCT FROM 'tenant' OR
       (requires_active_target AND target_status IS DISTINCT FROM 'active') OR
       actor_kind NOT IN ('platform', 'tenant') OR
       (actor_kind = 'tenant' AND NEW.actor_scope_id <> NEW.tenant_scope_id) THEN
        RAISE EXCEPTION 'plugin webhook actor target boundary is invalid'
            USING ERRCODE = 'P8402';
    END IF;
    IF NOT requires_live_manage THEN
        RETURN NEW;
    END IF;
    PERFORM 1
    FROM role_assignments assignment
    JOIN roles role ON role.id = assignment.role_id AND role.scope_id = assignment.scope_id
    WHERE assignment.scope_id = NEW.actor_scope_id AND assignment.user_id = NEW.actor_user_id
    FOR SHARE OF assignment, role;
    IF actor_kind = 'tenant' THEN
        PERFORM 1
        FROM custom_role_grants grant_row
        JOIN custom_roles role
          ON role.id = grant_row.role_id AND role.tenant_scope_id = grant_row.tenant_scope_id
        WHERE grant_row.tenant_scope_id = NEW.actor_scope_id
          AND grant_row.subject_user_id = NEW.actor_user_id
        FOR SHARE OF grant_row, role;
        SELECT EXISTS (
            SELECT 1 FROM custom_rbac_effective_permissions(
                NEW.actor_scope_id, NEW.actor_user_id
            ) permission
            WHERE permission.permission_name = 'plugin_webhooks.manage'
        ) INTO actor_can_manage;
    ELSIF actor_kind = 'platform' THEN
        SELECT EXISTS (
            SELECT 1
            FROM role_assignments assignment
            JOIN roles role
              ON role.id = assignment.role_id AND role.scope_id = assignment.scope_id
             AND role.system_role
            JOIN role_permissions permission ON permission.role_id = role.id
            WHERE assignment.scope_id = NEW.actor_scope_id
              AND assignment.user_id = NEW.actor_user_id
              AND permission.permission_name IN ('plugin_webhooks.manage', 'platform.admin')
        ) INTO actor_can_manage;
    ELSE
        actor_can_manage := false;
    END IF;
    IF actor_membership IS DISTINCT FROM 'active' OR
       actor_status IS DISTINCT FROM 'active' OR
       actor_can_manage IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'plugin webhook actor target boundary is invalid'
            USING ERRCODE = 'P8402';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION validate_package_offer_publication_event_090()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_head package_offer_publication_heads%ROWTYPE;
	head_found boolean;
    product_spec jsonb;
    product_deleted boolean;
    product_enabled boolean;
    version_enabled boolean;
    product_matches_version boolean;
    product_current_revision bigint;
    claimed_operation text;
    claimed_scope uuid;
    claimed_actor uuid;
    claimed_complete timestamptz;
	actor_scope_kind text;
	actor_scope_tenant uuid;
	actor_membership_status text;
	actor_user_status text;
	actor_can_manage boolean;
BEGIN
	IF NEW.catalog_sequence IS NOT NULL THEN
		RAISE EXCEPTION 'package offer catalog sequence is server assigned'
			USING ERRCODE = 'P9002';
	END IF;
	PERFORM iam_global_lock_shared_v1();
	PERFORM iam_scope_locks_v1(ARRAY[NEW.actor_scope_id]);
	SELECT scope.kind,scope.tenant_id,membership.status,account.status
	INTO actor_scope_kind,actor_scope_tenant,actor_membership_status,actor_user_status
	FROM access_scopes scope
	JOIN memberships membership
	  ON membership.scope_id=scope.id AND membership.user_id=NEW.actor_user_id
	JOIN users account ON account.id=membership.user_id
	WHERE scope.id=NEW.actor_scope_id
	FOR SHARE OF scope,membership,account;
	PERFORM 1
	FROM role_assignments assignment
	JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
	WHERE assignment.scope_id=NEW.actor_scope_id AND assignment.user_id=NEW.actor_user_id
	ORDER BY assignment.role_id
	FOR SHARE OF assignment,role;
	PERFORM 1 FROM permissions permission
	WHERE permission.name IN ('packages.manage','reseller.packages.manage')
	FOR SHARE OF permission;
	PERFORM 1
	FROM role_assignments assignment
	JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
	JOIN role_permissions grant_row ON grant_row.role_id=role.id
	WHERE assignment.scope_id=NEW.actor_scope_id AND assignment.user_id=NEW.actor_user_id
	ORDER BY grant_row.role_id,grant_row.permission_name
	FOR SHARE OF assignment,role,grant_row;
	SELECT EXISTS (
		SELECT 1 FROM role_assignments assignment
		JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
		JOIN role_permissions grant_row ON grant_row.role_id=role.id
		WHERE assignment.scope_id=NEW.actor_scope_id
		  AND assignment.user_id=NEW.actor_user_id
		  AND (grant_row.permission_name=CASE WHEN actor_scope_kind='platform'
		      THEN 'packages.manage' ELSE 'reseller.packages.manage' END OR
		       actor_scope_kind='platform' AND grant_row.permission_name='platform.admin')
	) INTO actor_can_manage;
	-- 481：代理商只能上架/下架自己名下的套餐，且须是有效代理商、持 reseller.packages.manage。
	IF NOT ((actor_scope_kind = 'platform' AND actor_scope_tenant IS NULL) OR
	        (actor_scope_kind = 'tenant' AND reseller_scope_active_480(NEW.actor_scope_id) AND EXISTS (
	            SELECT 1 FROM package_products owned WHERE owned.id = NEW.product_id
	              AND owned.owner_scope_id = NEW.actor_scope_id))) OR
	   actor_membership_status IS DISTINCT FROM 'active' OR
	   actor_user_status IS DISTINCT FROM 'active' OR actor_can_manage IS DISTINCT FROM true THEN
		RAISE EXCEPTION 'package offer publication actor is unauthorized'
			USING ERRCODE = 'P9002';
	END IF;

    PERFORM 1 FROM package_offer_lifecycle_lock WHERE singleton FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'package offer lifecycle lock is unavailable'
            USING ERRCODE = 'P9002';
    END IF;

    SELECT operation,actor_scope_id,actor_user_id,completed_at
    INTO claimed_operation,claimed_scope,claimed_actor,claimed_complete
    FROM package_catalog_write_requests
    WHERE id=NEW.write_request_id
    FOR UPDATE;
    IF NOT FOUND OR claimed_complete IS NOT NULL OR claimed_scope<>NEW.actor_scope_id OR
       claimed_actor<>NEW.actor_user_id OR
       claimed_operation<>(CASE NEW.event_type
           WHEN 'withdraw' THEN 'package.product.withdraw'
           ELSE 'package.product.publish'
       END) THEN
        RAISE EXCEPTION 'invalid package offer publication write claim'
            USING ERRCODE = 'P9002';
    END IF;

	SELECT * INTO current_head
	FROM package_offer_publication_heads
	WHERE product_id=NEW.product_id
	FOR UPDATE;
	head_found := FOUND;

	IF NEW.event_type='withdraw' THEN
		IF NOT head_found OR current_head.state<>'published' OR
		   NEW.lifecycle_revision<>current_head.lifecycle_revision+1 OR
		   NEW.previous_product_revision<>current_head.product_revision OR
		   NEW.product_revision<>current_head.product_revision THEN
			RAISE EXCEPTION 'invalid package offer withdrawal'
				USING ERRCODE = 'P9002';
		END IF;
		NEW.catalog_sequence := next_package_catalog_sequence_090();
		RETURN NEW;
	END IF;

    SELECT version.spec,product.deleted_at IS NOT NULL,product.enabled,version.enabled,
           product.spec=version.spec AND product.name=version.name AND
		   product.sort_order=version.sort_order AND
		   version.spec#>>'{name}'=version.name AND
		   version.spec#>>'{sort_order}'=version.sort_order::text AND
		   version.spec#>'{enabled}'=to_jsonb(version.enabled),product.revision
    INTO product_spec,product_deleted,product_enabled,version_enabled,
         product_matches_version,product_current_revision
    FROM package_product_versions version
    JOIN package_products product ON product.id=version.product_id
    WHERE version.product_id=NEW.product_id AND version.revision=NEW.product_revision
      AND NOT version.deleted
    FOR SHARE OF product;
    IF NOT FOUND OR product_deleted OR NOT product_enabled OR NOT version_enabled OR
	   product_matches_version IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'package offer revision is unavailable'
            USING ERRCODE = 'P9002';
    END IF;

    IF NEW.event_type='publish' THEN
		IF head_found OR NEW.lifecycle_revision<>1 OR NEW.previous_product_revision IS NOT NULL OR
           product_current_revision<>NEW.product_revision THEN
            RAISE EXCEPTION 'invalid initial package offer publication'
                USING ERRCODE = 'P9002';
        END IF;
    ELSIF NEW.event_type='replace' THEN
		IF NOT head_found OR current_head.state<>'published' OR
           NEW.lifecycle_revision<>current_head.lifecycle_revision+1 OR
           NEW.previous_product_revision<>current_head.product_revision OR
           NEW.product_revision<=current_head.product_revision OR
           product_current_revision<>NEW.product_revision THEN
            RAISE EXCEPTION 'invalid package offer replacement'
                USING ERRCODE = 'P9002';
        END IF;
    ELSE
        RAISE EXCEPTION 'invalid package offer publication event'
            USING ERRCODE = 'P9002';
    END IF;

    IF NOT package_offer_spec_publishable_090(product_spec, clock_timestamp()) THEN
        RAISE EXCEPTION 'package offer publication policy is unsupported or expired'
            USING ERRCODE = 'P9002';
    END IF;
    -- 481：代理商上架时主/备线路组须仍是平台授权给它的（授权撤销后不能再上架）。
    IF actor_scope_kind = 'tenant' AND NOT package_line_groups_usable_481(NEW.actor_scope_id, product_spec) THEN
        RAISE EXCEPTION 'package offer line group is not granted to the reseller'
            USING ERRCODE = 'P9002';
    END IF;
	NEW.catalog_sequence := next_package_catalog_sequence_090();
    RETURN NEW;
END;
$$;
