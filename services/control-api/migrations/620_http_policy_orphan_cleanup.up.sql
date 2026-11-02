-- 620（r136 fix-orphanpolicy，前驱 619）：站点删除（单个 site.delete / 批量 site.batch.delete / 迁移）只把
--   sites.deleted_at 置值，站点上活着的 HTTP 策略留成孤儿；发布按作用域读全部 enabled 策略，孤儿指向
--   的站点不在源修订里，整个作用域从此发布失败（73 上 01a192ca 作用域全部 503）。
--   1. validate_http_policy_revision_056：站点已删除时只接受 delete 修订，且不再要求操作者持有
--      http_policies.manage、也不要求租户操作者是站点所有者（删站的人未必有策略权限；删孤儿不扩大权限）。
--      操作者作用域必须是站点所属租户作用域或平台作用域。站点未删除时规则与 056 完全相同。
--   2. http_policy_orphan_cleanup_620：本迁移清理的留痕表（只增不改）。迁移不能写 audit_events
--      （哈希链在应用层计算），assert_http_policy_revision_audited_056 对本迁移写的修订改认这张表。
--   3. 为已删除站点上仍未删除的 HTTP 策略追加 delete 修订（走触发器投影 http_policies、推进发布头和
--      作用域源修订），操作者记为站点所属租户作用域与站点所有者，request_id 固定为
--      migration-620-orphan-cleanup。
LOCK TABLE schema_migrations, http_policy_revisions IN ACCESS EXCLUSIVE MODE;

DO $migration_620_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 619 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 619 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=619 AND migration_id='619_site_publication_undelivered' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure('validate_http_policy_revision_056()') IS NULL OR
       to_regprocedure('assert_http_policy_revision_audited_056()') IS NULL THEN
        RAISE EXCEPTION 'migration 620 requires the verified 619 release head with the 056 HTTP policy triggers'
            USING ERRCODE='P6200';
    END IF;
END;
$migration_620_up$;

CREATE TABLE http_policy_orphan_cleanup_620 (
    policy_id uuid NOT NULL,
    revision bigint NOT NULL,
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    site_deleted_at timestamptz NOT NULL,
    previous_enabled boolean NOT NULL,
    request_id text NOT NULL CHECK (request_id = 'migration-620-orphan-cleanup'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (policy_id, revision),
    FOREIGN KEY (policy_id, revision) REFERENCES http_policy_revisions(policy_id, revision) ON DELETE RESTRICT
);

CREATE FUNCTION protect_http_policy_orphan_cleanup_620()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'http_policy_orphan_cleanup_620 is append-only' USING ERRCODE = 'P6201';
END;
$$;

CREATE TRIGGER http_policy_orphan_cleanup_620_append_only
BEFORE UPDATE OR DELETE ON http_policy_orphan_cleanup_620
FOR EACH ROW EXECUTE FUNCTION protect_http_policy_orphan_cleanup_620();
CREATE TRIGGER http_policy_orphan_cleanup_620_no_truncate
BEFORE TRUNCATE ON http_policy_orphan_cleanup_620
FOR EACH STATEMENT EXECUTE FUNCTION protect_http_policy_orphan_cleanup_620();
CREATE OR REPLACE FUNCTION validate_http_policy_revision_056()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE head http_policies%ROWTYPE;
DECLARE site_scope uuid;
DECLARE site_owner uuid;
DECLARE site_deleted boolean;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('http-policy-publication:' || NEW.tenant_scope_id::text, 0));
    PERFORM pg_advisory_xact_lock(hashtextextended('http-policy:' || NEW.policy_id::text, 0));
    IF NOT http_policy_document_valid_056(NEW.document) THEN
        RAISE EXCEPTION 'invalid HTTP policy document' USING ERRCODE = 'P0001';
    END IF;
    SELECT scope_id, owner_user_id, deleted_at IS NOT NULL INTO site_scope, site_owner, site_deleted
    FROM sites WHERE id = NEW.site_id;
    IF site_deleted THEN
        -- 620: a deleted site's policy can only be deleted, by the site delete
        -- (its actor) or the 620 cleanup; no other change is accepted.
        IF NEW.action <> 'delete' OR site_scope IS DISTINCT FROM NEW.tenant_scope_id OR
           site_owner IS DISTINCT FROM NEW.site_owner_user_id OR NOT EXISTS (
            SELECT 1 FROM access_scopes actor_scope WHERE actor_scope.id = NEW.created_by_scope_id AND
                (actor_scope.id = NEW.tenant_scope_id OR actor_scope.kind = 'platform')
           ) THEN
            RAISE EXCEPTION 'HTTP policy site ownership mismatch' USING ERRCODE = 'P0001';
        END IF;
    ELSE
        IF NOT http_policy_actor_can_056(
            NEW.created_by_scope_id, NEW.created_by_user_id, NEW.tenant_scope_id, 'http_policies.manage'
        ) THEN
            RAISE EXCEPTION 'HTTP policy actor is not authorized' USING ERRCODE = 'P0001';
        END IF;
        IF site_scope IS DISTINCT FROM NEW.tenant_scope_id OR site_owner IS DISTINCT FROM NEW.site_owner_user_id THEN
            RAISE EXCEPTION 'HTTP policy site ownership mismatch' USING ERRCODE = 'P0001';
        END IF;
        IF EXISTS (SELECT 1 FROM access_scopes WHERE id = NEW.created_by_scope_id AND kind = 'tenant') AND
           NEW.created_by_user_id <> NEW.site_owner_user_id THEN
            RAISE EXCEPTION 'tenant actor does not own HTTP policy site' USING ERRCODE = 'P0001';
        END IF;
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

-- The 620 cleanup's revisions are audited by their cleanup row (written in
-- the same transaction, before the deferred check runs).
CREATE OR REPLACE FUNCTION assert_http_policy_revision_audited_056()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.request_id = 'migration-620-orphan-cleanup' AND EXISTS (
        SELECT 1 FROM http_policy_orphan_cleanup_620 cleanup
        WHERE cleanup.policy_id = NEW.policy_id AND cleanup.revision = NEW.revision
    ) THEN
        RETURN NULL;
    END IF;
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
DO $migration_620_cleanup$
DECLARE orphan record;
DECLARE next_revision bigint;
DECLARE cleaned_at timestamptz := clock_timestamp();
BEGIN
    FOR orphan IN
        SELECT policy.id, policy.tenant_scope_id, policy.tenant_id, policy.site_id, policy.site_owner_user_id,
               policy.current_revision, policy.current_enabled, policy.current_document, site.deleted_at
        FROM http_policies policy
        JOIN sites site ON site.id = policy.site_id
        WHERE site.deleted_at IS NOT NULL AND NOT policy.current_deleted
        ORDER BY policy.tenant_scope_id, policy.id
        FOR UPDATE OF policy
    LOOP
        next_revision := orphan.current_revision + 1;
        INSERT INTO http_policy_revisions (
            policy_id, tenant_scope_id, tenant_id, site_id, site_owner_user_id,
            revision, action, enabled, deleted, document, created_by_scope_id,
            created_by_user_id, request_id, trace_id, created_at
        ) VALUES (
            orphan.id, orphan.tenant_scope_id, orphan.tenant_id, orphan.site_id, orphan.site_owner_user_id,
            next_revision, 'delete', false, true,
            orphan.current_document || jsonb_build_object('revision', next_revision, 'enabled', false, 'deleted', true),
            orphan.tenant_scope_id, orphan.site_owner_user_id,
            'migration-620-orphan-cleanup', 'migration-620-orphan-cleanup', cleaned_at
        );
        INSERT INTO http_policy_orphan_cleanup_620 (
            policy_id, revision, tenant_scope_id, site_id, site_deleted_at, previous_enabled, request_id, created_at
        ) VALUES (
            orphan.id, next_revision, orphan.tenant_scope_id, orphan.site_id, orphan.deleted_at,
            orphan.current_enabled, 'migration-620-orphan-cleanup', cleaned_at
        );
    END LOOP;
END;
$migration_620_cleanup$;
