LOCK TABLE schema_migrations, package_groups, package_products, package_product_versions,
    package_catalog_write_requests, package_offer_publication_events, audit_events, access_scopes,
    node_line_group_grants, escalate_package_policies IN ACCESS EXCLUSIVE MODE;

DO $migration_481_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 481 OR
       (SELECT max(version) FROM schema_migrations) <> 481 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=481 AND
        migration_id='481_reseller_packages' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 481 down requires the exact verified migration head' USING ERRCODE='P4817';
    END IF;
    -- 480 的目录只有平台套餐：有代理商名下的分组/套餐时拒绝，而不是把它们并入平台目录。
    IF EXISTS (SELECT 1 FROM package_groups WHERE owner_scope_id <> package_catalog_platform_scope_481()) OR
       EXISTS (SELECT 1 FROM package_products WHERE owner_scope_id <> package_catalog_platform_scope_481()) THEN
        RAISE EXCEPTION 'migration 481 down refuses to drop reseller packages' USING ERRCODE='P4818';
    END IF;
END;
$migration_481_down$;

CREATE OR REPLACE FUNCTION reseller_products_using_line_group_480(reseller uuid, group_owner uuid, group_id uuid)
RETURNS SETOF uuid LANGUAGE sql STABLE AS $$
    SELECT policy.product_id FROM escalate_package_policies policy
    WHERE policy.owner_scope_id = reseller AND (
        (policy.b_owner_scope_id = group_owner AND policy.b_line_group_id = group_id) OR
        (policy.c_owner_scope_id = group_owner AND policy.c_line_group_id = group_id))
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
	WHERE permission.name='packages.manage'
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
		  AND grant_row.permission_name='packages.manage'
	) INTO actor_can_manage;
	IF actor_scope_kind IS DISTINCT FROM 'platform' OR actor_scope_tenant IS NOT NULL OR
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
	NEW.catalog_sequence := next_package_catalog_sequence_090();
    RETURN NEW;
END;
$$;

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
			  AND scope.kind='platform' AND scope.tenant_id IS NULL
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
			  AND scope.kind='platform' AND scope.tenant_id IS NULL
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
			  AND scope.kind='platform' AND scope.tenant_id IS NULL
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
    IF scope_kind IS DISTINCT FROM 'platform' OR scope_tenant IS NOT NULL THEN
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

DROP TABLE reseller_wholesale_prices;
DROP TRIGGER package_products_owner_guard_481 ON package_products;
DROP TRIGGER package_groups_owner_guard_481 ON package_groups;
DROP FUNCTION guard_package_catalog_owner_481();
DROP FUNCTION package_line_groups_usable_481(uuid, jsonb);
DROP INDEX package_products_owner_active_481_idx;
DROP INDEX package_products_owner_name_active_unique_481;
DROP INDEX package_groups_owner_name_active_unique_481;
CREATE UNIQUE INDEX package_groups_name_active_unique
    ON package_groups (lower(name)) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX package_products_name_active_unique
    ON package_products (lower(name)) WHERE deleted_at IS NULL;
ALTER TABLE package_products DROP COLUMN owner_scope_id;
ALTER TABLE package_groups DROP COLUMN owner_scope_id;
DROP FUNCTION package_catalog_platform_scope_481();
