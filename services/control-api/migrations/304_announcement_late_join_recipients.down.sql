LOCK TABLE schema_migrations, memberships, announcement_recipient_snapshots, announcement_inbox_events,
    platform_announcement_recipients_141 IN ACCESS EXCLUSIVE MODE;

DO $migration_304_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 304 OR
       (SELECT max(version) FROM schema_migrations) <> 304 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=304 AND
        migration_id='304_announcement_late_join_recipients' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 304 down requires the exact verified migration head' USING ERRCODE='P3041';
    END IF;
END;
$migration_304_down$;

-- Late recipients already written stay; they are ordinary immutable inbox
-- rows. Only the late-join path is removed and the 043/141 guards restored.
DROP TRIGGER memberships_announcement_late_join_304 ON memberships;
DROP FUNCTION announcement_late_join_304();

CREATE OR REPLACE FUNCTION protect_announcement_recipient_snapshot()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    version_status text;
    version_sealed timestamptz;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'announcement recipient snapshots are immutable';
    END IF;
    SELECT status,sealed_at INTO version_status,version_sealed FROM announcement_versions
     WHERE tenant_scope_id=NEW.tenant_scope_id AND announcement_id=NEW.announcement_id
       AND version=NEW.announcement_version;
    IF version_status NOT IN ('draft','scheduled')
       OR (version_status = 'scheduled' AND version_sealed IS NULL) THEN
        RAISE EXCEPTION 'recipient snapshots may only be created during publication';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION protect_announcement_inbox_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    version_status text;
    version_title text;
    version_body text;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'announcement inbox events are immutable';
    END IF;
    SELECT status,title,body INTO version_status,version_title,version_body FROM announcement_versions
     WHERE tenant_scope_id=NEW.tenant_scope_id AND announcement_id=NEW.announcement_id
       AND version=NEW.announcement_version;
    IF version_status NOT IN ('draft','scheduled') OR NEW.title IS DISTINCT FROM version_title
       OR NEW.body IS DISTINCT FROM version_body THEN
        RAISE EXCEPTION 'announcement inbox event does not match the sealed publication';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION protect_platform_announcement_recipient_141()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    root_status text;
    scope_kind text;
    tenant_status text;
    account_status text;
    membership_status text;
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'platform global announcement recipients cannot be deleted'
            USING ERRCODE = 'P1419';
    END IF;
    IF TG_OP = 'INSERT' THEN
        SELECT root.status INTO root_status
        FROM platform_announcements_141 root
        WHERE root.id = NEW.announcement_id FOR SHARE;
        SELECT scope.kind, tenant.status, account.status, membership.status
          INTO scope_kind, tenant_status, account_status, membership_status
          FROM memberships membership
          JOIN access_scopes scope ON scope.id = membership.scope_id
          JOIN tenants tenant ON tenant.id = scope.tenant_id
          JOIN users account ON account.id = membership.user_id
         WHERE membership.scope_id = NEW.tenant_scope_id AND membership.user_id = NEW.user_id
         FOR SHARE OF membership, scope, tenant, account;
        IF root_status IS DISTINCT FROM 'draft' OR scope_kind IS DISTINCT FROM 'tenant' OR
           tenant_status IS DISTINCT FROM 'active' OR account_status IS DISTINCT FROM 'active' OR
           membership_status IS DISTINCT FROM 'active' OR NEW.revision <> 1 OR
           NEW.delivered_at IS NOT NULL OR NEW.read_at IS NOT NULL OR
           NEW.updated_at IS DISTINCT FROM NEW.published_at THEN
            RAISE EXCEPTION 'platform global announcement recipient must be an active frozen tenant recipient'
                USING ERRCODE = 'P14A0';
        END IF;
        RETURN NEW;
    END IF;
    IF ROW(NEW.announcement_id, NEW.tenant_scope_id, NEW.user_id, NEW.event_id, NEW.published_at)
       IS DISTINCT FROM
       ROW(OLD.announcement_id, OLD.tenant_scope_id, OLD.user_id, OLD.event_id, OLD.published_at) OR
       NEW.revision <> OLD.revision + 1 OR NEW.updated_at < OLD.updated_at OR
       NEW.delivered_at IS NULL OR NEW.delivered_at < NEW.published_at OR
       (OLD.delivered_at IS NOT NULL AND NEW.delivered_at IS DISTINCT FROM OLD.delivered_at) OR
       (OLD.read_at IS NOT NULL AND NEW.read_at IS DISTINCT FROM OLD.read_at) OR
       (NEW.read_at IS NOT NULL AND NEW.read_at < NEW.delivered_at) THEN
        RAISE EXCEPTION 'platform global announcement recipient state must advance monotonically'
            USING ERRCODE = 'P14A1';
    END IF;
    RETURN NEW;
END;
$$;
