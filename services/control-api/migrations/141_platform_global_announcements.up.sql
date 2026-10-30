LOCK TABLE schema_migrations, announcement_write_requests, announcement_state_facts,
    announcement_state_watermarks, access_scopes, tenants, users, memberships
    IN ACCESS EXCLUSIVE MODE;

DO $migration_141$
DECLARE
    operation_constraint text;
    operation_attnum smallint;
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 140 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 140 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 140 AND migration_id = '140_package_subscription_manual_open' AND
              checksum_sha256 = 'a89707a1033c0b192569081af1119ca1e075016a06cdd40df71fb8d7d28d5489' AND
              down_checksum_sha256 = '58a58b9c789b244eff9eb88b35eab2c924f4721c00f1fc9a6cbb44d2b2bfd542' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('platform_announcements_141') IS NOT NULL OR
         to_regclass('platform_announcement_recipients_141') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 141 requires the exact verified 140 release head'
            USING ERRCODE = 'P1410';
    END IF;

    SELECT attnum INTO operation_attnum
    FROM pg_attribute
    WHERE attrelid = 'announcement_write_requests'::regclass AND attname = 'operation';
    SELECT conname INTO operation_constraint
    FROM pg_constraint
    WHERE conrelid = 'announcement_write_requests'::regclass AND contype = 'c' AND
          conkey = ARRAY[operation_attnum]::smallint[];
    IF operation_constraint IS NULL THEN
        RAISE EXCEPTION 'migration 141 requires the announcement write operation constraint'
            USING ERRCODE = 'P1411';
    END IF;
    EXECUTE format('ALTER TABLE announcement_write_requests DROP CONSTRAINT %I', operation_constraint);
END;
$migration_141$;

ALTER TABLE announcement_write_requests
    ADD CONSTRAINT announcement_write_requests_operation_141_check CHECK (operation IN (
        'announcement.create', 'announcement.update', 'announcement.schedule',
        'announcement.publish', 'announcement.scheduled_publish', 'announcement.revise',
        'announcement.withdraw', 'announcement.deliver', 'announcement.read',
        'announcement.global.create', 'announcement.global.update',
        'announcement.global.publish', 'announcement.global.withdraw'
    ));

CREATE TABLE platform_announcements_141 (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    platform_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    version bigint NOT NULL DEFAULT 1 CHECK (version = 1),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    status text NOT NULL CHECK (status IN ('draft', 'published', 'withdrawn')),
    title text NOT NULL CHECK (announcement_valid_title(title)),
    body text NOT NULL CHECK (announcement_valid_body(body)),
    audience jsonb NOT NULL CHECK (
        jsonb_typeof(audience) = 'object' AND
        audience ?& ARRAY['all_tenants', 'tenant_scope_ids', 'role_targets', 'user_targets'] AND
        jsonb_typeof(audience->'all_tenants') = 'boolean' AND
        jsonb_typeof(audience->'tenant_scope_ids') = 'array' AND
        jsonb_typeof(audience->'role_targets') = 'array' AND
        jsonb_typeof(audience->'user_targets') = 'array' AND
        jsonb_array_length(audience->'tenant_scope_ids') <= 10000 AND
        jsonb_array_length(audience->'role_targets') <= 10000 AND
        jsonb_array_length(audience->'user_targets') <= 10000 AND
        (
            ((audience->>'all_tenants')::boolean AND
             jsonb_array_length(audience->'tenant_scope_ids') = 0 AND
             jsonb_array_length(audience->'role_targets') = 0 AND
             jsonb_array_length(audience->'user_targets') = 0) OR
            (NOT (audience->>'all_tenants')::boolean AND
             jsonb_array_length(audience->'tenant_scope_ids') +
             jsonb_array_length(audience->'role_targets') +
             jsonb_array_length(audience->'user_targets') BETWEEN 1 AND 10000)
        )
    ),
    withdrawal_visibility text NOT NULL CHECK (withdrawal_visibility IN ('retain', 'hide')),
    created_by_user_id uuid NOT NULL,
    published_at timestamptz,
    withdrawn_at timestamptz,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    FOREIGN KEY (platform_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (
        (status = 'draft' AND published_at IS NULL AND withdrawn_at IS NULL) OR
        (status = 'published' AND published_at IS NOT NULL AND isfinite(published_at) AND withdrawn_at IS NULL) OR
        (status = 'withdrawn' AND published_at IS NOT NULL AND isfinite(published_at) AND
         withdrawn_at IS NOT NULL AND isfinite(withdrawn_at) AND withdrawn_at >= published_at)
    )
);

CREATE INDEX platform_announcements_141_scope_page_idx
    ON platform_announcements_141 (platform_scope_id, created_at DESC, id DESC);
CREATE INDEX platform_announcements_141_scope_status_page_idx
    ON platform_announcements_141 (platform_scope_id, status, created_at DESC, id DESC);

CREATE TABLE platform_announcement_recipients_141 (
    announcement_id uuid NOT NULL REFERENCES platform_announcements_141(id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    user_id uuid NOT NULL,
    event_id uuid NOT NULL UNIQUE CHECK (event_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    delivered_at timestamptz,
    read_at timestamptz,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    published_at timestamptz NOT NULL CHECK (isfinite(published_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= published_at),
    PRIMARY KEY (announcement_id, tenant_scope_id, user_id),
    FOREIGN KEY (tenant_scope_id, user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (
        delivered_at IS NULL OR
        (isfinite(delivered_at) AND delivered_at >= published_at)
    ),
    CHECK (
        read_at IS NULL OR
        (delivered_at IS NOT NULL AND isfinite(read_at) AND read_at >= delivered_at)
    )
);

CREATE INDEX platform_announcement_recipients_141_inbox_idx
    ON platform_announcement_recipients_141
       (tenant_scope_id, user_id, published_at DESC, event_id DESC);

CREATE FUNCTION protect_platform_announcement_141()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    scope_kind text;
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'platform global announcements cannot be deleted'
            USING ERRCODE = 'P1412';
    END IF;
    SELECT kind INTO scope_kind FROM access_scopes
    WHERE id = NEW.platform_scope_id FOR SHARE;
    IF scope_kind IS DISTINCT FROM 'platform' THEN
        RAISE EXCEPTION 'platform global announcement requires a platform scope'
            USING ERRCODE = 'P1413';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.version <> 1 OR NEW.revision <> 1 OR NEW.status <> 'draft' OR
           NEW.published_at IS NOT NULL OR NEW.withdrawn_at IS NOT NULL OR
           NEW.updated_at IS DISTINCT FROM NEW.created_at THEN
            RAISE EXCEPTION 'platform global announcement must start as revision one draft'
                USING ERRCODE = 'P1414';
        END IF;
        RETURN NEW;
    END IF;
    IF ROW(NEW.id, NEW.platform_scope_id, NEW.version, NEW.created_by_user_id, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.platform_scope_id, OLD.version, OLD.created_by_user_id, OLD.created_at) OR
       NEW.revision <> OLD.revision + 1 OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'platform global announcement identity or revision is immutable'
            USING ERRCODE = 'P1415';
    END IF;
    IF OLD.status = 'draft' AND NEW.status = 'draft' THEN
        RETURN NEW;
    END IF;
    IF OLD.status = 'draft' AND NEW.status = 'published' THEN
        IF ROW(NEW.title, NEW.body, NEW.audience, NEW.withdrawal_visibility)
           IS DISTINCT FROM
           ROW(OLD.title, OLD.body, OLD.audience, OLD.withdrawal_visibility) OR
           NEW.published_at IS DISTINCT FROM NEW.updated_at OR
           NOT EXISTS (
               SELECT 1 FROM platform_announcement_recipients_141 recipient
               WHERE recipient.announcement_id = OLD.id
           ) THEN
            RAISE EXCEPTION 'platform global announcement publication must seal a non-empty audience'
                USING ERRCODE = 'P1416';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.status = 'published' AND NEW.status = 'withdrawn' THEN
        IF ROW(NEW.title, NEW.body, NEW.audience, NEW.withdrawal_visibility, NEW.published_at)
           IS DISTINCT FROM
           ROW(OLD.title, OLD.body, OLD.audience, OLD.withdrawal_visibility, OLD.published_at) OR
           NEW.withdrawn_at IS DISTINCT FROM NEW.updated_at THEN
            RAISE EXCEPTION 'withdrawal may only advance sealed platform global announcement state'
                USING ERRCODE = 'P1417';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid platform global announcement transition'
        USING ERRCODE = 'P1418';
END;
$$;

CREATE TRIGGER platform_announcements_141_guard
BEFORE INSERT OR UPDATE OR DELETE ON platform_announcements_141
FOR EACH ROW EXECUTE FUNCTION protect_platform_announcement_141();
CREATE TRIGGER platform_announcements_141_truncate_guard
BEFORE TRUNCATE ON platform_announcements_141
FOR EACH STATEMENT EXECUTE FUNCTION protect_platform_announcement_141();
ALTER TABLE platform_announcements_141 ENABLE ALWAYS TRIGGER platform_announcements_141_guard;
ALTER TABLE platform_announcements_141 ENABLE ALWAYS TRIGGER platform_announcements_141_truncate_guard;

CREATE FUNCTION protect_platform_announcement_recipient_141()
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

CREATE TRIGGER platform_announcement_recipients_141_guard
BEFORE INSERT OR UPDATE OR DELETE ON platform_announcement_recipients_141
FOR EACH ROW EXECUTE FUNCTION protect_platform_announcement_recipient_141();
CREATE TRIGGER platform_announcement_recipients_141_truncate_guard
BEFORE TRUNCATE ON platform_announcement_recipients_141
FOR EACH STATEMENT EXECUTE FUNCTION protect_platform_announcement_recipient_141();
ALTER TABLE platform_announcement_recipients_141 ENABLE ALWAYS TRIGGER platform_announcement_recipients_141_guard;
ALTER TABLE platform_announcement_recipients_141 ENABLE ALWAYS TRIGGER platform_announcement_recipients_141_truncate_guard;

CREATE FUNCTION record_platform_announcement_recipient_facts_141()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    root_row platform_announcements_141%ROWTYPE;
    next_value bigint;
BEGIN
    SELECT * INTO root_row FROM platform_announcements_141
    WHERE id = NEW.announcement_id;
    next_value := next_announcement_state_watermark(NEW.tenant_scope_id);
    INSERT INTO announcement_state_facts(
        tenant_scope_id, watermark, fact_type, announcement_id, announcement_version,
        event_id, recipient_user_id, payload, occurred_at
    ) VALUES (
        NEW.tenant_scope_id, next_value, 'inbox_event', NEW.announcement_id, root_row.version,
        NEW.event_id, NEW.user_id, jsonb_build_object(
            'id', NEW.event_id,
            'announcement_id', NEW.announcement_id,
            'announcement_version', root_row.version,
            'recipient_user_id', NEW.user_id,
            'title', root_row.title,
            'body', root_row.body,
            'published_at', NEW.published_at,
            'created_at', NEW.published_at,
            'source', 'platform_global'
        ), NEW.published_at
    );
    next_value := next_announcement_state_watermark(NEW.tenant_scope_id);
    INSERT INTO announcement_state_facts(
        tenant_scope_id, watermark, fact_type, event_id, recipient_user_id, payload, occurred_at
    ) VALUES (
        NEW.tenant_scope_id, next_value, 'inbox_state', NEW.event_id, NEW.user_id,
        jsonb_build_object(
            'event_id', NEW.event_id,
            'user_id', NEW.user_id,
            'delivered_at', NEW.delivered_at,
            'read_at', NEW.read_at,
            'revision', NEW.revision,
            'updated_at', NEW.updated_at,
            'source', 'platform_global'
        ), NEW.updated_at
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER platform_announcement_recipients_141_insert_facts
AFTER INSERT ON platform_announcement_recipients_141
FOR EACH ROW EXECUTE FUNCTION record_platform_announcement_recipient_facts_141();

CREATE FUNCTION record_platform_announcement_recipient_state_fact_141()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    next_value bigint;
BEGIN
    next_value := next_announcement_state_watermark(NEW.tenant_scope_id);
    INSERT INTO announcement_state_facts(
        tenant_scope_id, watermark, fact_type, event_id, recipient_user_id, payload, occurred_at
    ) VALUES (
        NEW.tenant_scope_id, next_value, 'inbox_state', NEW.event_id, NEW.user_id,
        jsonb_build_object(
            'event_id', NEW.event_id,
            'user_id', NEW.user_id,
            'delivered_at', NEW.delivered_at,
            'read_at', NEW.read_at,
            'revision', NEW.revision,
            'updated_at', NEW.updated_at,
            'source', 'platform_global'
        ), NEW.updated_at
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER platform_announcement_recipients_141_update_fact
AFTER UPDATE ON platform_announcement_recipients_141
FOR EACH ROW EXECUTE FUNCTION record_platform_announcement_recipient_state_fact_141();

CREATE FUNCTION record_platform_announcement_version_facts_141()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    requested_scope_id uuid;
    next_value bigint;
BEGIN
    IF NEW.status IS NOT DISTINCT FROM OLD.status THEN
        RETURN NEW;
    END IF;
    FOR requested_scope_id IN
        SELECT DISTINCT recipient.tenant_scope_id
        FROM platform_announcement_recipients_141 recipient
        WHERE recipient.announcement_id = NEW.id
        ORDER BY recipient.tenant_scope_id
    LOOP
        next_value := next_announcement_state_watermark(requested_scope_id);
        INSERT INTO announcement_state_facts(
            tenant_scope_id, watermark, fact_type, announcement_id, announcement_version,
            payload, occurred_at
        ) VALUES (
            requested_scope_id, next_value, 'version', NEW.id, NEW.version,
            jsonb_build_object(
                'id', NEW.id,
                'scope_id', requested_scope_id,
                'version', NEW.version,
                'revision', NEW.revision,
                'status', NEW.status,
                'title', NEW.title,
                'body', NEW.body,
                'audience_mode', 'selected',
                'withdrawal_visibility', NEW.withdrawal_visibility,
                'scheduled_at', NULL,
                'sealed_at', NEW.published_at,
                'published_at', NEW.published_at,
                'withdrawn_at', NEW.withdrawn_at,
                'created_at', NEW.created_at,
                'root_created_at', NEW.created_at,
                'state_changed_at', NEW.updated_at,
                'audience_user_ids', COALESCE((
                    SELECT jsonb_agg(recipient.user_id ORDER BY recipient.user_id)
                    FROM platform_announcement_recipients_141 recipient
                    WHERE recipient.announcement_id = NEW.id AND
                          recipient.tenant_scope_id = requested_scope_id
                ), '[]'::jsonb),
                'audience_group_ids', '[]'::jsonb,
                'source', 'platform_global'
            ), NEW.updated_at
        );
    END LOOP;
    RETURN NEW;
END;
$$;

CREATE TRIGGER platform_announcements_141_version_facts
AFTER UPDATE OF status ON platform_announcements_141
FOR EACH ROW EXECUTE FUNCTION record_platform_announcement_version_facts_141();
