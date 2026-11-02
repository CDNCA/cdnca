-- 620 回退：validate_http_policy_revision_056 / assert_http_policy_revision_audited_056 恢复 056 的定义，
--   删除留痕表 http_policy_orphan_cleanup_620。
--   不恢复被清理的孤儿策略：它们指向已删除站点，恢复只会让作用域重新发布失败；本迁移写的 delete 修订
--   保留在 http_policy_revisions（request_id=migration-620-orphan-cleanup，可追溯），修订表只增不改。
--   回退后已写修订不会再被审计约束检查（约束只在插入时触发）。
LOCK TABLE schema_migrations, http_policy_revisions IN ACCESS EXCLUSIVE MODE;

DO $migration_620_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 620 OR
       (SELECT max(version) FROM schema_migrations) <> 620 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=620 AND
        migration_id='620_http_policy_orphan_cleanup' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 620 down requires the exact verified migration head' USING ERRCODE='P6202';
    END IF;
END;
$migration_620_down$;

CREATE OR REPLACE FUNCTION validate_http_policy_revision_056()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE head http_policies%ROWTYPE;
DECLARE site_scope uuid;
DECLARE site_owner uuid;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('http-policy-publication:' || NEW.tenant_scope_id::text, 0));
    PERFORM pg_advisory_xact_lock(hashtextextended('http-policy:' || NEW.policy_id::text, 0));
    IF NOT http_policy_document_valid_056(NEW.document) THEN
        RAISE EXCEPTION 'invalid HTTP policy document' USING ERRCODE = 'P0001';
    END IF;
    IF NOT http_policy_actor_can_056(
        NEW.created_by_scope_id, NEW.created_by_user_id, NEW.tenant_scope_id, 'http_policies.manage'
    ) THEN
        RAISE EXCEPTION 'HTTP policy actor is not authorized' USING ERRCODE = 'P0001';
    END IF;
    SELECT scope_id, owner_user_id INTO site_scope, site_owner
    FROM sites WHERE id = NEW.site_id AND deleted_at IS NULL;
    IF site_scope IS DISTINCT FROM NEW.tenant_scope_id OR site_owner IS DISTINCT FROM NEW.site_owner_user_id THEN
        RAISE EXCEPTION 'HTTP policy site ownership mismatch' USING ERRCODE = 'P0001';
    END IF;
    IF EXISTS (SELECT 1 FROM access_scopes WHERE id = NEW.created_by_scope_id AND kind = 'tenant') AND
       NEW.created_by_user_id <> NEW.site_owner_user_id THEN
        RAISE EXCEPTION 'tenant actor does not own HTTP policy site' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.document ->> 'policy_id' <> NEW.policy_id::text OR
       NEW.document ->> 'tenant_scope_id' <> NEW.tenant_scope_id::text OR
       NEW.document ->> 'site_id' <> NEW.site_id::text OR
       NEW.document ->> 'site_owner_user_id' <> NEW.site_owner_user_id::text OR
       (NEW.document ->> 'revision')::bigint <> NEW.revision OR
       (NEW.document ->> 'enabled')::boolean IS DISTINCT FROM NEW.enabled OR
       (NEW.document ->> 'deleted')::boolean IS DISTINCT FROM NEW.deleted THEN
        RAISE EXCEPTION 'HTTP policy document does not match revision facts' USING ERRCODE = 'P0001';
    END IF;

    SELECT * INTO head FROM http_policies WHERE id = NEW.policy_id FOR UPDATE;
    IF NOT FOUND THEN
        IF NEW.revision <> 1 OR NEW.action <> 'create' OR NEW.deleted THEN
            RAISE EXCEPTION 'HTTP policy must start with create revision one' USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;
    IF head.current_deleted OR NEW.action = 'create' OR NEW.revision <> head.current_revision + 1 OR
       NEW.tenant_scope_id <> head.tenant_scope_id OR NEW.tenant_id <> head.tenant_id OR
       NEW.site_id <> head.site_id OR NEW.site_owner_user_id <> head.site_owner_user_id THEN
        RAISE EXCEPTION 'HTTP policy revision is not monotonic or changes identity' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.action = 'update' AND (NEW.enabled <> head.current_enabled OR NEW.deleted) THEN
        RAISE EXCEPTION 'HTTP policy update cannot change state' USING ERRCODE = 'P0001';
    ELSIF NEW.action = 'enable' AND (head.current_enabled OR NOT NEW.enabled OR NEW.deleted) THEN
        RAISE EXCEPTION 'invalid HTTP policy enable transition' USING ERRCODE = 'P0001';
    ELSIF NEW.action = 'disable' AND (NOT head.current_enabled OR NEW.enabled OR NEW.deleted) THEN
        RAISE EXCEPTION 'invalid HTTP policy disable transition' USING ERRCODE = 'P0001';
    ELSIF NEW.action = 'delete' AND (NEW.enabled OR NOT NEW.deleted) THEN
        RAISE EXCEPTION 'invalid HTTP policy delete transition' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION assert_http_policy_revision_audited_056()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM audit_events event
        WHERE event.scope_id = NEW.tenant_scope_id
          AND event.actor_user_id = NEW.created_by_user_id
          AND event.action = 'http_policy.' || NEW.action
          AND event.resource_type = 'http_policy'
          AND event.resource_id = NEW.policy_id::text
          AND event.request_id = NEW.request_id
          AND event.result = 'success'
          AND event.payload ->> 'trace_id' = NEW.trace_id
          AND event.payload ->> 'revision' = NEW.revision::text
    ) THEN
        RAISE EXCEPTION 'HTTP policy revision requires matching success audit' USING ERRCODE = 'P0001';
    END IF;
    RETURN NULL;
END;
$$;

DROP TABLE http_policy_orphan_cleanup_620;
DROP FUNCTION protect_http_policy_orphan_cleanup_620();
