LOCK TABLE schema_migrations,
    package_catalog_commit_watermark_090,
    package_group_state_facts_090,
    package_product_state_facts_090,
    package_catalog_audit_links_090,
    package_groups,
    package_products,
    package_product_versions,
    package_offer_publication_events,
    audit_events,
    package_catalog_subtransaction_xid_guard_130
IN ACCESS EXCLUSIVE MODE;

DO $migration_130$
DECLARE
    activated_watermark bigint;
    current_watermark bigint;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=130 AND migration_id='130_package_catalog_subtransaction_xid_guard'
          AND checksum_sha256='32ba9ecf6db54415a10985cd1331d65338a27e1948fce53a1b9a5d7aebc628b3'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) OR to_regprocedure('package_catalog_current_backend_owns_xid_130(xid)') IS NULL OR
       to_regclass('package_catalog_subtransaction_xid_guard_130') IS NULL THEN
        RAISE EXCEPTION 'migration 130 rollback requires the verified 130 head'
            USING ERRCODE='P1300';
    END IF;
    SELECT activated_high_water INTO activated_watermark
    FROM package_catalog_subtransaction_xid_guard_130 WHERE singleton;
    SELECT high_water INTO current_watermark
    FROM package_catalog_commit_watermark_090 WHERE singleton;
    IF activated_watermark IS NULL OR current_watermark IS NULL OR
       current_watermark<>activated_watermark THEN
        RAISE EXCEPTION 'migration 130 rollback would discard subtransaction-safe catalog facts'
            USING ERRCODE='P1301';
    END IF;
END;
$migration_130$;

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
			  AND source.xmin=current_package_catalog_xid_090()
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
			  AND source.xmin=current_package_catalog_xid_090()
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
			  AND fact.xmin=current_package_catalog_xid_090()
			  AND source.xmin=current_package_catalog_xid_090()
			  AND source.name=fact.name AND source.visible=fact.visible
			  AND source.sort_order=fact.sort_order
			  AND (source.deleted_at IS NOT NULL)=fact.deleted
			  AND audit.xmin=current_package_catalog_xid_090()
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
			  AND fact.xmin=current_package_catalog_xid_090()
			  AND source.xmin=current_package_catalog_xid_090()
			  AND source.name=fact.name AND source.enabled=fact.enabled
			  AND source.sort_order=fact.sort_order AND source.spec=fact.spec
			  AND (source.deleted_at IS NOT NULL)=fact.deleted
			  AND version.name=fact.name AND version.enabled=fact.enabled
			  AND version.sort_order=fact.sort_order AND version.spec=fact.spec
			  AND version.deleted=fact.deleted
			  AND version.xmin=current_package_catalog_xid_090()
			  AND audit.xmin=current_package_catalog_xid_090()
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
			  AND event.xmin=current_package_catalog_xid_090()
			  AND audit.xmin=current_package_catalog_xid_090()
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

DROP FUNCTION package_catalog_current_backend_owns_xid_130(xid);
DROP TABLE package_catalog_subtransaction_xid_guard_130;
