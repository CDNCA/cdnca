LOCK TABLE schema_migrations, memberships, announcement_recipient_snapshots, announcement_inbox_events,
    announcement_inbox_states, platform_announcement_recipients_141, announcement_state_facts,
    announcement_state_watermarks IN ACCESS EXCLUSIVE MODE;

DO $migration_304_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 303 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 303 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=303 AND
        migration_id='303_domain_trust' AND
        checksum_sha256='ab0677edaf2c2db45e8b7f7d764a6ff5d766911f9de519209777363ccb876153' AND
        down_checksum_sha256='7c851de89b64a91c45efe4acd9e4e89387774a69ac1daf67bd6a87bf1a522b9a' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure('announcement_late_join_304()') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 304 requires the exact verified 303 release head' USING ERRCODE='P3040';
    END IF;
END;
$migration_304_up$;

-- FX16: audience "all" announcements (tenant audience_mode='all', platform
-- all_tenants or an explicit tenant scope list) froze their recipients at
-- publication, so a user who registered or joined later never saw them on
-- the home page or the message page. A membership that becomes active now
-- receives the currently published announcements of those audiences. The
-- late recipient rows go through the same inbox tables and state facts as
-- publication; withdrawal and withdrawal_visibility keep applying at read
-- time. Late joins only fill the inbox: no publication notice is sent.
-- "Selected" audiences (users, groups, role or user targets) stay frozen.

-- Only the late-join trigger (pg_trigger_depth() >= 2 with the transaction
-- local flag) may add a recipient to an already published version, and only
-- for the current published version of an audience "all" announcement and an
-- active membership.
CREATE OR REPLACE FUNCTION protect_announcement_recipient_snapshot()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    version_status text;
    version_sealed timestamptz;
    version_audience text;
    current_version bigint;
    member_status text;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'announcement recipient snapshots are immutable';
    END IF;
    SELECT status,sealed_at,audience_mode INTO version_status,version_sealed,version_audience
      FROM announcement_versions
     WHERE tenant_scope_id=NEW.tenant_scope_id AND announcement_id=NEW.announcement_id
       AND version=NEW.announcement_version;
    IF version_status = 'published' AND pg_trigger_depth() >= 2
       AND current_setting('cdnca.announcement_late_join', true) = 'on' THEN
        SELECT current_published_version INTO current_version FROM announcements
         WHERE tenant_scope_id=NEW.tenant_scope_id AND id=NEW.announcement_id;
        SELECT status INTO member_status FROM memberships
         WHERE scope_id=NEW.tenant_scope_id AND user_id=NEW.user_id;
        IF version_audience = 'all' AND current_version = NEW.announcement_version
           AND member_status = 'active' THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'late announcement recipient must join the current audience-all publication';
    END IF;
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
    version_published timestamptz;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'announcement inbox events are immutable';
    END IF;
    SELECT status,title,body,published_at INTO version_status,version_title,version_body,version_published
      FROM announcement_versions
     WHERE tenant_scope_id=NEW.tenant_scope_id AND announcement_id=NEW.announcement_id
       AND version=NEW.announcement_version;
    IF version_status = 'published' AND pg_trigger_depth() >= 2
       AND current_setting('cdnca.announcement_late_join', true) = 'on'
       AND NEW.title IS NOT DISTINCT FROM version_title
       AND NEW.body IS NOT DISTINCT FROM version_body
       AND NEW.published_at IS NOT DISTINCT FROM version_published THEN
        RETURN NEW;
    END IF;
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
    root_published timestamptz;
    root_audience jsonb;
    scope_kind text;
    tenant_status text;
    account_status text;
    membership_status text;
    late_join boolean;
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'platform global announcement recipients cannot be deleted'
            USING ERRCODE = 'P1419';
    END IF;
    IF TG_OP = 'INSERT' THEN
        SELECT root.status, root.published_at, root.audience INTO root_status, root_published, root_audience
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
        -- A late join may only add a member of an audience that is defined by
        -- tenant membership, and keeps the original publication time.
        late_join := root_status = 'published' AND pg_trigger_depth() >= 2 AND
            current_setting('cdnca.announcement_late_join', true) = 'on' AND
            NEW.published_at IS NOT DISTINCT FROM root_published AND (
                (root_audience->>'all_tenants')::boolean OR
                (root_audience->'tenant_scope_ids') ? NEW.tenant_scope_id::text
            );
        IF (root_status IS DISTINCT FROM 'draft' AND NOT late_join) OR scope_kind IS DISTINCT FROM 'tenant' OR
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

CREATE FUNCTION announcement_late_join_304()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    item record;
    late_event_id uuid;
    next_value bigint;
    joined_at timestamptz := now();
    scope_kind text;
    tenant_status text;
    account_status text;
BEGIN
    IF NEW.status IS DISTINCT FROM 'active' OR
       (TG_OP = 'UPDATE' AND OLD.status IS NOT DISTINCT FROM 'active') THEN
        RETURN NEW;
    END IF;
    SELECT scope.kind, tenant.status, account.status INTO scope_kind, tenant_status, account_status
      FROM access_scopes scope
      JOIN tenants tenant ON tenant.id = scope.tenant_id
      JOIN users account ON account.id = NEW.user_id
     WHERE scope.id = NEW.scope_id;
    IF scope_kind IS DISTINCT FROM 'tenant' THEN
        RETURN NEW;
    END IF;
    PERFORM set_config('cdnca.announcement_late_join', 'on', true);

    -- Tenant announcements: the current published version of every audience
    -- "all" announcement of this tenant the member does not hold yet.
    FOR item IN
        SELECT version.announcement_id, version.version, version.title, version.body, version.published_at
          FROM announcements root
          JOIN announcement_versions version ON version.tenant_scope_id = root.tenant_scope_id
           AND version.announcement_id = root.id AND version.version = root.current_published_version
         WHERE root.tenant_scope_id = NEW.scope_id AND version.status = 'published'
           AND version.audience_mode = 'all'
           AND NOT EXISTS (
               SELECT 1 FROM announcement_recipient_snapshots snapshot
                WHERE snapshot.tenant_scope_id = NEW.scope_id AND snapshot.announcement_id = version.announcement_id
                  AND snapshot.announcement_version = version.version AND snapshot.user_id = NEW.user_id)
         ORDER BY version.published_at, version.announcement_id
    LOOP
        INSERT INTO announcement_recipient_snapshots(
            tenant_scope_id, announcement_id, announcement_version, user_id, resolved_at
        ) VALUES (NEW.scope_id, item.announcement_id, item.version, NEW.user_id, joined_at);
        late_event_id := gen_random_uuid();
        INSERT INTO announcement_inbox_events(
            id, tenant_scope_id, announcement_id, announcement_version, recipient_user_id,
            title, body, published_at, created_at
        ) VALUES (late_event_id, NEW.scope_id, item.announcement_id, item.version, NEW.user_id,
            item.title, item.body, item.published_at, item.published_at);
        INSERT INTO announcement_inbox_states(tenant_scope_id, event_id, user_id, revision, updated_at)
        VALUES (NEW.scope_id, late_event_id, NEW.user_id, 1, item.published_at);
    END LOOP;

    -- Platform announcements: published ones addressed to all tenants or to
    -- this tenant scope. Role and user targets stay frozen at publication.
    IF tenant_status = 'active' AND account_status = 'active' THEN
        FOR item IN
            SELECT root.* FROM platform_announcements_141 root
             WHERE root.status = 'published' AND (
                   (root.audience->>'all_tenants')::boolean OR
                   (root.audience->'tenant_scope_ids') ? NEW.scope_id::text)
               AND NOT EXISTS (
                   SELECT 1 FROM platform_announcement_recipients_141 recipient
                    WHERE recipient.announcement_id = root.id AND recipient.tenant_scope_id = NEW.scope_id
                      AND recipient.user_id = NEW.user_id)
             ORDER BY root.published_at, root.id
        LOOP
            -- The inbox joins on a per-scope version fact; publication only
            -- wrote one for the scopes it reached.
            IF NOT EXISTS (
                SELECT 1 FROM announcement_state_facts fact
                 WHERE fact.tenant_scope_id = NEW.scope_id AND fact.fact_type = 'version'
                   AND fact.announcement_id = item.id AND fact.announcement_version = item.version) THEN
                next_value := next_announcement_state_watermark(NEW.scope_id);
                INSERT INTO announcement_state_facts(
                    tenant_scope_id, watermark, fact_type, announcement_id, announcement_version,
                    payload, occurred_at
                ) VALUES (
                    NEW.scope_id, next_value, 'version', item.id, item.version,
                    jsonb_build_object(
                        'id', item.id, 'scope_id', NEW.scope_id, 'version', item.version,
                        'revision', item.revision, 'status', item.status,
                        'title', item.title, 'body', item.body,
                        'audience_mode', 'selected',
                        'withdrawal_visibility', item.withdrawal_visibility,
                        'scheduled_at', NULL, 'sealed_at', item.published_at,
                        'published_at', item.published_at, 'withdrawn_at', item.withdrawn_at,
                        'created_at', item.created_at, 'root_created_at', item.created_at,
                        'state_changed_at', item.updated_at,
                        'audience_user_ids', jsonb_build_array(NEW.user_id),
                        'audience_group_ids', '[]'::jsonb,
                        'source', 'platform_global',
                        'content_format', item.content_format, 'link_url', item.link_url,
                        'sort_order', item.sort_order, 'is_visible', item.is_visible,
                        'is_popup', item.is_popup, 'style_red', item.style_red, 'style_bold', item.style_bold
                    ), item.updated_at
                );
            END IF;
            INSERT INTO platform_announcement_recipients_141(
                announcement_id, tenant_scope_id, user_id, event_id, revision, published_at, updated_at
            ) VALUES (item.id, NEW.scope_id, NEW.user_id, gen_random_uuid(), 1, item.published_at, item.published_at);
        END LOOP;
    END IF;
    PERFORM set_config('cdnca.announcement_late_join', 'off', true);
    RETURN NEW;
END;
$$;

CREATE TRIGGER memberships_announcement_late_join_304
AFTER INSERT OR UPDATE OF status ON memberships
FOR EACH ROW EXECUTE FUNCTION announcement_late_join_304();
