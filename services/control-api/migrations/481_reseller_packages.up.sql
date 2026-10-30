LOCK TABLE schema_migrations, package_groups, package_products, package_product_versions,
    package_catalog_write_requests, package_offer_publication_events, audit_events, access_scopes,
    node_line_group_grants, escalate_package_policies IN ACCESS EXCLUSIVE MODE;

DO $migration_481_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 480 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 480 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=480 AND
        migration_id='480_reseller_core' AND
        checksum_sha256='feaf0c58cb8f33bd5fc0ec9a0c475adc00a0d62b23dc9a97c4880931e6603852' AND
        down_checksum_sha256='8a78b5ca212b82ab5f1ca38696e40b3f6b4d6e1aa4c5274374af2a97a7b00410' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure('reseller_products_using_line_group_480(uuid,uuid,uuid)') IS NULL OR
       to_regprocedure('scope_may_use_line_group_460(uuid,uuid,uuid)') IS NULL OR
       EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name IN ('package_products','package_groups') AND column_name='owner_scope_id') THEN
        RAISE EXCEPTION 'migration 481 requires the exact verified 480 release head' USING ERRCODE='P4812';
    END IF;
END;
$migration_481_up$;

-- 481（r136 rs-02-catalog，ADR 0018 RS-02；合入时按集成头改号、重钉前驱 480）。
-- 套餐目录加所有者：平台套餐/分组的 owner 是平台 scope；代理商（有效代理商、持 reseller.packages.manage）
-- 可以建、改、删、上架自己名下的套餐与分组。A4 不迁移旧数据：已有行一律记到平台 scope，新安装即带。
-- 主/备线路组只能是代理商可用的平台线路组（scope_may_use_line_group_460，平台授权给它的）。
-- 撤销授权联动下架（Q5）：reseller_products_using_line_group_480 补上代理商名下主/备线路是该组的套餐。
--
-- 错误码（480 已用到 P4811，本迁移从 P4812 起）：P4812 前驱不符；P4813 套餐/分组所有者须为平台或有效代理商；
-- P4814 所有者不可变更；P4815 代理商套餐的分组须是同一所有者的分组；P4816 代理商套餐的主/备线路组须是平台授权给它的；
-- P4817/P4818 down 前驱不符/有代理商套餐拒绝回退。

ALTER TABLE package_groups ADD COLUMN owner_scope_id uuid REFERENCES access_scopes(id) ON DELETE RESTRICT;
ALTER TABLE package_products ADD COLUMN owner_scope_id uuid REFERENCES access_scopes(id) ON DELETE RESTRICT;
-- 090/130 守卫只认 UPDATE 的状态推进，补列不能走 UPDATE；新加的列无默认值，旧行在补值前为 NULL。
ALTER TABLE package_groups DISABLE TRIGGER USER;
ALTER TABLE package_products DISABLE TRIGGER USER;
UPDATE package_groups SET owner_scope_id = (SELECT id FROM access_scopes WHERE kind = 'platform');
UPDATE package_products SET owner_scope_id = (SELECT id FROM access_scopes WHERE kind = 'platform');
ALTER TABLE package_groups ENABLE TRIGGER USER;
ALTER TABLE package_products ENABLE TRIGGER USER;

DO $migration_481_backfill$
BEGIN
    IF EXISTS (SELECT 1 FROM package_groups WHERE owner_scope_id IS NULL) OR
       EXISTS (SELECT 1 FROM package_products WHERE owner_scope_id IS NULL) THEN
        RAISE EXCEPTION 'migration 481 found package catalog rows without a platform scope' USING ERRCODE='P4813';
    END IF;
END;
$migration_481_backfill$;

-- 未写 owner_scope_id 的写入方（平台目录、节点市场隐藏套餐）默认记到平台 scope。
CREATE FUNCTION package_catalog_platform_scope_481() RETURNS uuid LANGUAGE sql STABLE AS $$
    SELECT id FROM access_scopes WHERE kind = 'platform'
$$;
ALTER TABLE package_groups ALTER COLUMN owner_scope_id SET DEFAULT package_catalog_platform_scope_481();
ALTER TABLE package_products ALTER COLUMN owner_scope_id SET DEFAULT package_catalog_platform_scope_481();
ALTER TABLE package_groups ALTER COLUMN owner_scope_id SET NOT NULL;
ALTER TABLE package_products ALTER COLUMN owner_scope_id SET NOT NULL;

-- 名称在同一所有者内唯一：两个代理商可以有同名套餐/分组。
DROP INDEX package_groups_name_active_unique;
DROP INDEX package_products_name_active_unique;
CREATE UNIQUE INDEX package_groups_owner_name_active_unique_481
    ON package_groups (owner_scope_id, lower(name)) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX package_products_owner_name_active_unique_481
    ON package_products (owner_scope_id, lower(name)) WHERE deleted_at IS NULL;
CREATE INDEX package_products_owner_active_481_idx ON package_products (owner_scope_id) WHERE deleted_at IS NULL;

-- 批发价（ADR 0018 §5，Q1 预付批发价）：平台按 (价表, 平台线路组, 周期) 定价，单位分。代理商用
-- reseller_profiles.wholesale_price_list 指定的价表；套餐售价不得低于主线路组（+ 价表里有价的备用线路组）的
-- 批发价之和。按单扣代理商预付余额由 RS-03 做；没有定价的线路组/周期本迁移不拦，由 RS-03 下单时决定。
CREATE TABLE reseller_wholesale_prices (
    price_list text NOT NULL CHECK (price_list ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
    platform_scope_id uuid NOT NULL,
    line_group_id uuid NOT NULL,
    period text NOT NULL CHECK (period IN ('month', 'quarter', 'year')),
    price_minor bigint NOT NULL CHECK (price_minor BETWEEN 0 AND 1000000000000000),
    currency text NOT NULL DEFAULT 'CNY' CHECK (currency = 'CNY'),
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (price_list, platform_scope_id, line_group_id, period),
    FOREIGN KEY (platform_scope_id, line_group_id) REFERENCES node_line_groups(tenant_scope_id, id) ON DELETE RESTRICT
);
GRANT SELECT, INSERT, UPDATE, DELETE ON reseller_wholesale_prices TO cdnca_control_app, cdnca_control_runtime;

-- 代理商套餐的主/备线路组都须是它可用的平台线路组。
CREATE FUNCTION package_line_groups_usable_481(owner uuid, product_spec jsonb)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (SELECT 1 FROM access_scopes platform JOIN node_line_groups line_group
            ON line_group.tenant_scope_id = platform.id
        WHERE platform.kind = 'platform' AND line_group.id::text = product_spec->>'node_group_id'
          AND scope_may_use_line_group_460(owner, platform.id, line_group.id))
    AND (product_spec->'backup_node_group_id' IS NULL OR product_spec->'backup_node_group_id' = 'null'::jsonb OR
        EXISTS (SELECT 1 FROM access_scopes platform JOIN node_line_groups line_group
            ON line_group.tenant_scope_id = platform.id
        WHERE platform.kind = 'platform' AND line_group.id::text = product_spec->>'backup_node_group_id'
          AND scope_may_use_line_group_460(owner, platform.id, line_group.id)))
$$;

CREATE FUNCTION guard_package_catalog_owner_481() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    owner_kind text;
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.owner_scope_id IS DISTINCT FROM OLD.owner_scope_id THEN
        RAISE EXCEPTION 'package catalog owner is immutable' USING ERRCODE='P4814';
    END IF;
    SELECT kind INTO owner_kind FROM access_scopes WHERE id = NEW.owner_scope_id;
    IF owner_kind IS DISTINCT FROM 'platform' AND NOT (owner_kind = 'tenant' AND (
        (TG_OP = 'UPDATE' AND NEW.deleted_at IS NOT NULL) OR reseller_scope_active_480(NEW.owner_scope_id))) THEN
        RAISE EXCEPTION 'package catalog owner is the platform or an active reseller' USING ERRCODE='P4813';
    END IF;
    IF TG_TABLE_NAME = 'package_products' AND owner_kind = 'tenant' AND NEW.deleted_at IS NULL THEN
        IF EXISTS (SELECT 1 FROM jsonb_array_elements_text(COALESCE(NEW.spec->'group_ids', '[]'::jsonb)) group_id(value)
            WHERE NOT EXISTS (SELECT 1 FROM package_groups owned_group
                WHERE owned_group.id::text = group_id.value AND owned_group.owner_scope_id = NEW.owner_scope_id)) THEN
            RAISE EXCEPTION 'reseller package groups belong to the same reseller' USING ERRCODE='P4815';
        END IF;
        -- 下架/停用不受授权撤销影响（撤销联动要能改写它）；保存启用中的套餐须线路组仍可用。
        IF NEW.enabled AND (TG_OP = 'INSERT' OR NEW.spec IS DISTINCT FROM OLD.spec) AND
           NOT package_line_groups_usable_481(NEW.owner_scope_id, NEW.spec) THEN
            RAISE EXCEPTION 'reseller package line groups are granted line groups' USING ERRCODE='P4816';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER package_groups_owner_guard_481
BEFORE INSERT OR UPDATE ON package_groups
FOR EACH ROW EXECUTE FUNCTION guard_package_catalog_owner_481();
CREATE TRIGGER package_products_owner_guard_481
BEFORE INSERT OR UPDATE ON package_products
FOR EACH ROW EXECUTE FUNCTION guard_package_catalog_owner_481();

-- 090 目录审计：审计 scope 可以是平台，或是该分组/套餐的所有者代理商。
CREATE OR REPLACE FUNCTION bind_package_catalog_audit_090()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    parsed_resource uuid;
    parsed_revision bigint;
    sequence_value bigint;
    kind_value text;
    scope_kind text;
    scope_tenant uuid;
BEGIN
    IF NEW.result<>'success' OR NEW.action NOT IN (
        'package.group.create','package.group.update','package.group.delete',
        'package.product.create','package.product.update','package.product.delete',
        'package.product.publish','package.product.withdraw'
    ) THEN
        RETURN NEW;
    END IF;
    IF NEW.actor_user_id IS NULL OR
       NEW.resource_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
        RAISE EXCEPTION 'invalid package catalog audit identity'
            USING ERRCODE = 'P9002';
    END IF;
    parsed_resource := NEW.resource_id::uuid;
    SELECT kind,tenant_id INTO scope_kind,scope_tenant
    FROM access_scopes WHERE id=NEW.scope_id FOR SHARE;
    -- 481：代理商（租户 scope）只能为自己名下的分组/套餐写目录审计。
    IF NOT ((scope_kind = 'platform' AND scope_tenant IS NULL) OR (scope_kind = 'tenant' AND (
        (NEW.action LIKE 'package.group.%' AND EXISTS (SELECT 1 FROM package_groups owned
            WHERE owned.id = parsed_resource AND owned.owner_scope_id = NEW.scope_id)) OR
        (NEW.action LIKE 'package.product.%' AND EXISTS (SELECT 1 FROM package_products owned
            WHERE owned.id = parsed_resource AND owned.owner_scope_id = NEW.scope_id))))) THEN
        RAISE EXCEPTION 'package catalog audit scope is not platform'
            USING ERRCODE = 'P9002';
    END IF;

    IF NEW.action LIKE 'package.group.%' THEN
        IF NEW.resource_type<>'package_group' OR
           NEW.payload->>'revision' !~ '^[1-9][0-9]{0,18}$' THEN
            RAISE EXCEPTION 'invalid package group audit payload'
                USING ERRCODE = 'P9002';
        END IF;
        parsed_revision := (NEW.payload->>'revision')::bigint;
        SELECT fact.catalog_sequence INTO sequence_value
        FROM package_group_state_facts_090 fact
        WHERE fact.group_id=parsed_resource AND fact.revision=parsed_revision
          AND fact.actor_user_id=NEW.actor_user_id AND fact.action=NEW.action
          AND ((NEW.action='package.group.delete' AND
                NEW.payload=jsonb_build_object('revision',parsed_revision)) OR
               (NEW.action<>'package.group.delete' AND
                NEW.payload=jsonb_build_object('revision',parsed_revision,'visible',fact.visible)));
        kind_value := 'group';
    ELSIF NEW.action IN ('package.product.create','package.product.update','package.product.delete') THEN
        IF NEW.resource_type<>'package_product' OR
           NEW.payload->>'revision' !~ '^[1-9][0-9]{0,18}$' THEN
            RAISE EXCEPTION 'invalid package product audit payload'
                USING ERRCODE = 'P9002';
        END IF;
        parsed_revision := (NEW.payload->>'revision')::bigint;
        SELECT fact.catalog_sequence INTO sequence_value
        FROM package_product_state_facts_090 fact
        WHERE fact.product_id=parsed_resource AND fact.revision=parsed_revision
          AND fact.actor_user_id=NEW.actor_user_id AND fact.action=NEW.action
          AND ((NEW.action='package.product.delete' AND
                NEW.payload=jsonb_build_object('revision',parsed_revision)) OR
               (NEW.action<>'package.product.delete' AND
                NEW.payload=jsonb_build_object('revision',parsed_revision,'enabled',fact.enabled)));
        kind_value := 'product';
    ELSE
        IF NEW.resource_type<>'package_product' OR
           NEW.payload->>'product_revision' !~ '^[1-9][0-9]{0,18}$' OR
           NEW.payload->>'lifecycle_revision' !~ '^[1-9][0-9]{0,18}$' THEN
            RAISE EXCEPTION 'invalid package publication audit payload'
                USING ERRCODE = 'P9002';
        END IF;
        parsed_revision := (NEW.payload->>'lifecycle_revision')::bigint;
        SELECT event.catalog_sequence INTO sequence_value
        FROM package_offer_publication_events event
        WHERE event.product_id=parsed_resource
          AND event.product_revision=(NEW.payload->>'product_revision')::bigint
          AND event.lifecycle_revision=parsed_revision
          AND event.actor_scope_id=NEW.scope_id AND event.actor_user_id=NEW.actor_user_id
          AND event.occurred_at=NEW.occurred_at
          AND NEW.action=CASE WHEN event.event_type='withdraw'
              THEN 'package.product.withdraw' ELSE 'package.product.publish' END
          AND ((event.event_type='withdraw' AND NEW.payload=jsonb_build_object(
                'product_revision',event.product_revision,'lifecycle_revision',event.lifecycle_revision)) OR
               (event.event_type<>'withdraw' AND NEW.payload=jsonb_build_object(
                'product_revision',event.product_revision,'lifecycle_revision',event.lifecycle_revision,
                'event_type',event.event_type)));
        kind_value := 'publication';
    END IF;
    IF sequence_value IS NULL OR sequence_value=0 OR EXISTS (
        SELECT 1 FROM package_catalog_audit_links_090
        WHERE catalog_sequence=sequence_value OR audit_event_id=NEW.id
    ) THEN
        RAISE EXCEPTION 'package catalog audit has no unique source fact'
            USING ERRCODE = 'P9002';
    END IF;
    INSERT INTO package_catalog_audit_links_090(
        catalog_sequence,audit_event_id,fact_kind,scope_id,actor_user_id,
        action,resource_id,resource_revision
    ) VALUES(sequence_value,NEW.id,kind_value,NEW.scope_id,NEW.actor_user_id,
             NEW.action,parsed_resource,parsed_revision);
    RETURN NEW;
END;
$$;

-- 130 版 090 事实守卫：同上，审计 scope 可以是来源行的所有者代理商。
CREATE OR REPLACE FUNCTION protect_package_catalog_state_090()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
	IF TG_TABLE_NAME='package_catalog_commit_watermark_090' THEN
		IF TG_OP='UPDATE' AND
		   NEW.singleton=OLD.singleton AND NEW.high_water=OLD.high_water+1 THEN
			RETURN NEW;
		END IF;
		RAISE EXCEPTION 'package catalog watermark is immutable and server assigned'
			USING ERRCODE = 'P9002';
	END IF;
	IF TG_TABLE_NAME='package_group_state_facts_090' THEN
		IF TG_OP='INSERT' AND NEW.catalog_sequence>0 AND
		   NEW.catalog_sequence=(SELECT high_water FROM package_catalog_commit_watermark_090 WHERE singleton) AND
		   EXISTS (
			SELECT 1 FROM package_groups source
			WHERE source.id=NEW.group_id AND source.revision=NEW.revision
			  AND source.name=NEW.name AND source.visible=NEW.visible
			  AND source.sort_order=NEW.sort_order
			  AND (source.deleted_at IS NOT NULL)=NEW.deleted
			  AND source.updated_by_user_id=NEW.actor_user_id
			  AND package_catalog_current_backend_owns_xid_130(source.xmin)
			  AND NEW.action=CASE
				WHEN source.revision=1 AND source.deleted_at IS NULL THEN 'package.group.create'
				WHEN source.deleted_at IS NOT NULL THEN 'package.group.delete'
				ELSE 'package.group.update'
			  END
		   ) THEN
			RETURN NEW;
		END IF;
		RAISE EXCEPTION 'package catalog fact is immutable and server assigned'
			USING ERRCODE = 'P9002';
	END IF;
	IF TG_TABLE_NAME='package_product_state_facts_090' THEN
		IF TG_OP='INSERT' AND NEW.catalog_sequence>0 AND
		   NEW.catalog_sequence=(SELECT high_water FROM package_catalog_commit_watermark_090 WHERE singleton) AND
		   EXISTS (
			SELECT 1 FROM package_products source
			WHERE source.id=NEW.product_id AND source.revision=NEW.revision
			  AND source.name=NEW.name AND source.enabled=NEW.enabled
			  AND source.sort_order=NEW.sort_order AND source.spec=NEW.spec
			  AND (source.deleted_at IS NOT NULL)=NEW.deleted
			  AND source.updated_by_user_id=NEW.actor_user_id
			  AND package_catalog_current_backend_owns_xid_130(source.xmin)
			  AND NEW.action=CASE
				WHEN source.revision=1 AND source.deleted_at IS NULL THEN 'package.product.create'
				WHEN source.deleted_at IS NOT NULL THEN 'package.product.delete'
				ELSE 'package.product.update'
			  END
		   ) THEN
			RETURN NEW;
		END IF;
		RAISE EXCEPTION 'package catalog fact is immutable and server assigned'
			USING ERRCODE = 'P9002';
	END IF;
	IF TG_TABLE_NAME='package_catalog_audit_links_090' THEN
		IF TG_OP='INSERT' AND NEW.catalog_sequence>0 AND NEW.fact_kind='group' AND EXISTS (
			SELECT 1 FROM package_group_state_facts_090 fact
			JOIN package_groups source ON source.id=fact.group_id AND source.revision=fact.revision
			JOIN audit_events audit ON audit.id=NEW.audit_event_id
			JOIN access_scopes scope ON scope.id=audit.scope_id
			WHERE fact.catalog_sequence=NEW.catalog_sequence
			  AND fact.group_id=NEW.resource_id AND fact.revision=NEW.resource_revision
			  AND fact.actor_user_id=NEW.actor_user_id AND fact.action=NEW.action
			  AND package_catalog_current_backend_owns_xid_130(fact.xmin)
			  AND package_catalog_current_backend_owns_xid_130(source.xmin)
			  AND source.name=fact.name AND source.visible=fact.visible
			  AND source.sort_order=fact.sort_order
			  AND (source.deleted_at IS NOT NULL)=fact.deleted
			  AND package_catalog_current_backend_owns_xid_130(audit.xmin)
			  AND audit.scope_id=NEW.scope_id AND audit.actor_user_id=NEW.actor_user_id
			  AND audit.action=NEW.action AND audit.resource_type='package_group'
			  AND audit.resource_id=NEW.resource_id::text AND audit.result='success'
			  AND ((NEW.action='package.group.delete' AND
			        audit.payload=jsonb_build_object('revision',NEW.resource_revision)) OR
			       (NEW.action<>'package.group.delete' AND
			        audit.payload=jsonb_build_object('revision',NEW.resource_revision,'visible',fact.visible)))
			  AND ((scope.kind='platform' AND scope.tenant_id IS NULL) OR (scope.kind='tenant' AND source.owner_scope_id=scope.id))
		) THEN
			RETURN NEW;
		END IF;
		IF TG_OP='INSERT' AND NEW.catalog_sequence>0 AND NEW.fact_kind='product' AND EXISTS (
			SELECT 1 FROM package_product_state_facts_090 fact
			JOIN package_products source ON source.id=fact.product_id AND source.revision=fact.revision
			JOIN package_product_versions version
			  ON version.product_id=fact.product_id AND version.revision=fact.revision
			JOIN audit_events audit ON audit.id=NEW.audit_event_id
			JOIN access_scopes scope ON scope.id=audit.scope_id
			WHERE fact.catalog_sequence=NEW.catalog_sequence
			  AND fact.product_id=NEW.resource_id AND fact.revision=NEW.resource_revision
			  AND fact.actor_user_id=NEW.actor_user_id AND fact.action=NEW.action
			  AND package_catalog_current_backend_owns_xid_130(fact.xmin)
			  AND package_catalog_current_backend_owns_xid_130(source.xmin)
			  AND source.name=fact.name AND source.enabled=fact.enabled
			  AND source.sort_order=fact.sort_order AND source.spec=fact.spec
			  AND (source.deleted_at IS NOT NULL)=fact.deleted
			  AND version.name=fact.name AND version.enabled=fact.enabled
			  AND version.sort_order=fact.sort_order AND version.spec=fact.spec
			  AND version.deleted=fact.deleted
			  AND package_catalog_current_backend_owns_xid_130(version.xmin)
			  AND package_catalog_current_backend_owns_xid_130(audit.xmin)
			  AND audit.scope_id=NEW.scope_id AND audit.actor_user_id=NEW.actor_user_id
			  AND audit.action=NEW.action AND audit.resource_type='package_product'
			  AND audit.resource_id=NEW.resource_id::text AND audit.result='success'
			  AND ((NEW.action='package.product.delete' AND
			        audit.payload=jsonb_build_object('revision',NEW.resource_revision)) OR
			       (NEW.action<>'package.product.delete' AND
			        audit.payload=jsonb_build_object('revision',NEW.resource_revision,'enabled',fact.enabled)))
			  AND ((scope.kind='platform' AND scope.tenant_id IS NULL) OR (scope.kind='tenant' AND source.owner_scope_id=scope.id))
		) THEN
			RETURN NEW;
		END IF;
		IF TG_OP='INSERT' AND NEW.catalog_sequence>0 AND NEW.fact_kind='publication' AND EXISTS (
			SELECT 1 FROM package_offer_publication_events event
			JOIN audit_events audit ON audit.id=NEW.audit_event_id
			JOIN access_scopes scope ON scope.id=audit.scope_id
			WHERE event.catalog_sequence=NEW.catalog_sequence
			  AND event.product_id=NEW.resource_id
			  AND event.lifecycle_revision=NEW.resource_revision
			  AND event.actor_scope_id=NEW.scope_id AND event.actor_user_id=NEW.actor_user_id
			  AND package_catalog_current_backend_owns_xid_130(event.xmin)
			  AND package_catalog_current_backend_owns_xid_130(audit.xmin)
			  AND audit.scope_id=NEW.scope_id AND audit.actor_user_id=NEW.actor_user_id
			  AND audit.action=NEW.action AND audit.resource_type='package_product'
			  AND audit.resource_id=NEW.resource_id::text AND audit.result='success'
			  AND audit.occurred_at=event.occurred_at
			  AND NEW.action=CASE WHEN event.event_type='withdraw'
			      THEN 'package.product.withdraw' ELSE 'package.product.publish' END
			  AND ((event.event_type='withdraw' AND audit.payload=jsonb_build_object(
			        'product_revision',event.product_revision,'lifecycle_revision',event.lifecycle_revision)) OR
			       (event.event_type<>'withdraw' AND audit.payload=jsonb_build_object(
			        'product_revision',event.product_revision,'lifecycle_revision',event.lifecycle_revision,
			        'event_type',event.event_type)))
			  AND ((scope.kind='platform' AND scope.tenant_id IS NULL) OR (scope.kind='tenant' AND EXISTS (
			      SELECT 1 FROM package_products owned WHERE owned.id=event.product_id AND owned.owner_scope_id=scope.id)))
		) THEN
			RETURN NEW;
		END IF;
		RAISE EXCEPTION 'package catalog audit link is immutable and source bound'
			USING ERRCODE = 'P9002';
	END IF;
	RAISE EXCEPTION 'package catalog state is immutable and server assigned'
		USING ERRCODE = 'P9002';
END;
$$;

-- 090 上架守卫（P9002）放宽：平台持 packages.manage；或有效代理商持 reseller.packages.manage 且套餐是它自己的，
-- 上架时主/备线路组须仍可用。平台 actor 照旧可以下架任何套餐（撤销联动由平台下架）。
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
		  AND grant_row.permission_name=CASE WHEN actor_scope_kind='platform'
		      THEN 'packages.manage' ELSE 'reseller.packages.manage' END
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

-- 撤销联动（RS-01 约定，Q5）：补上代理商名下主/备线路是该组的套餐。
CREATE OR REPLACE FUNCTION reseller_products_using_line_group_480(reseller uuid, group_owner uuid, group_id uuid)
RETURNS SETOF uuid LANGUAGE sql STABLE AS $$
    SELECT policy.product_id FROM escalate_package_policies policy
    WHERE policy.owner_scope_id = reseller AND (
        (policy.b_owner_scope_id = group_owner AND policy.b_line_group_id = group_id) OR
        (policy.c_owner_scope_id = group_owner AND policy.c_line_group_id = group_id))
    UNION
    -- 481：代理商自己名下、主线路或备用线路是该组的套餐（主/备线路组的所有者固定是平台）。
    SELECT product.id FROM package_products product
    WHERE product.owner_scope_id = reseller AND product.deleted_at IS NULL
      AND EXISTS (SELECT 1 FROM access_scopes platform WHERE platform.id = group_owner AND platform.kind = 'platform')
      AND (product.spec->>'node_group_id' = group_id::text OR product.spec->>'backup_node_group_id' = group_id::text)
$$;

REVOKE ALL ON FUNCTION guard_package_catalog_owner_481() FROM PUBLIC;
