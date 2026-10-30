INSERT INTO permissions (name, description) VALUES
    ('announcements.read', 'Read tenant announcements and the current user inbox'),
    ('announcements.manage', 'Create, schedule, publish, revise, and withdraw tenant announcements');

INSERT INTO custom_rbac_permission_catalog (permission_name, step_up_required) VALUES
    ('announcements.read', false),
    ('announcements.manage', false);

CREATE TABLE announcement_state_watermarks (
    tenant_scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    current_watermark bigint NOT NULL DEFAULT 0 CHECK (current_watermark >= 0)
);

INSERT INTO announcement_state_watermarks (tenant_scope_id)
SELECT id FROM access_scopes WHERE kind = 'tenant';

CREATE TABLE announcement_state_facts (
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    watermark bigint NOT NULL CHECK (watermark > 0),
    fact_type text NOT NULL CHECK (fact_type IN ('version', 'inbox_event', 'inbox_state')),
    announcement_id uuid,
    announcement_version bigint,
    event_id uuid,
    recipient_user_id uuid,
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    occurred_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, watermark)
);

CREATE INDEX announcement_state_facts_version_idx
    ON announcement_state_facts (tenant_scope_id, fact_type, announcement_id, announcement_version, watermark DESC);

CREATE INDEX announcement_state_facts_event_idx
    ON announcement_state_facts (tenant_scope_id, fact_type, event_id, watermark DESC);

CREATE TABLE announcements (
    id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    head_version bigint NOT NULL DEFAULT 1 CHECK (head_version > 0),
    current_published_version bigint,
    created_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (tenant_scope_id, id),
    FOREIGN KEY (tenant_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (current_published_version IS NULL OR
           (current_published_version > 0 AND current_published_version <= head_version)),
    CHECK (updated_at >= created_at)
);

CREATE INDEX announcements_tenant_created_idx
    ON announcements (tenant_scope_id, created_at DESC, id DESC);

CREATE FUNCTION announcement_codepoint_is_go_space(codepoint integer)
RETURNS boolean
LANGUAGE sql
IMMUTABLE STRICT PARALLEL SAFE
AS $$
    SELECT codepoint BETWEEN 9 AND 13
        OR codepoint IN (32, 133, 160, 5760, 8232, 8233, 8239, 8287, 12288)
        OR codepoint BETWEEN 8192 AND 8202;
$$;

CREATE FUNCTION announcement_codepoint_is_format(codepoint integer)
RETURNS boolean
LANGUAGE sql
IMMUTABLE STRICT PARALLEL SAFE
AS $$
    SELECT codepoint IN (173, 1564, 1757, 1807, 2192, 2193, 2274, 6158, 65279, 69821, 69837, 917505)
        OR codepoint BETWEEN 1536 AND 1541
        OR codepoint BETWEEN 8203 AND 8207
        OR codepoint BETWEEN 8234 AND 8238
        OR codepoint BETWEEN 8288 AND 8292
        OR codepoint BETWEEN 8294 AND 8303
        OR codepoint BETWEEN 65529 AND 65531
        OR codepoint BETWEEN 78896 AND 78911
        OR codepoint BETWEEN 113824 AND 113827
        OR codepoint BETWEEN 119155 AND 119162
        OR codepoint BETWEEN 917536 AND 917631;
$$;

CREATE FUNCTION announcement_valid_title(value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE STRICT PARALLEL SAFE
AS $$
    SELECT char_length(value) BETWEEN 1 AND 160
       AND NOT announcement_codepoint_is_go_space(ascii(substr(value, 1, 1)))
       AND NOT announcement_codepoint_is_go_space(ascii(substr(value, char_length(value), 1)))
       AND NOT EXISTS (
           SELECT 1
             FROM generate_series(1, char_length(value)) AS position
            WHERE ascii(substr(value, position, 1)) BETWEEN 0 AND 31
               OR ascii(substr(value, position, 1)) BETWEEN 127 AND 159
               OR announcement_codepoint_is_format(ascii(substr(value, position, 1)))
       );
$$;

CREATE FUNCTION announcement_valid_body(value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE STRICT PARALLEL SAFE
AS $$
    SELECT octet_length(value) BETWEEN 1 AND 65536
       AND NOT announcement_codepoint_is_go_space(ascii(substr(value, 1, 1)))
       AND NOT announcement_codepoint_is_go_space(ascii(substr(value, char_length(value), 1)))
       AND NOT EXISTS (
           SELECT 1
             FROM generate_series(1, char_length(value)) AS position
            WHERE (ascii(substr(value, position, 1)) BETWEEN 0 AND 31
                   AND ascii(substr(value, position, 1)) NOT IN (9, 10))
               OR ascii(substr(value, position, 1)) BETWEEN 127 AND 159
               OR announcement_codepoint_is_format(ascii(substr(value, position, 1)))
       )
       AND value !~ '[<>]'
	       AND lower(value) !~ '(javascript:|vbscript:|data:|file:|mailto:|https?:|ftps?:|wss?:|://)'
	       AND position('www.' in lower(value)) = 0
       AND position('![' in value) = 0
       AND position('](' in value) = 0
       AND position('] (' in value) = 0
       AND position('][' in value) = 0
       AND position('//' in value) = 0;
$$;

CREATE TABLE announcement_versions (
    tenant_scope_id uuid NOT NULL,
    announcement_id uuid NOT NULL,
    version bigint NOT NULL CHECK (version > 0),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    status text NOT NULL CHECK (status IN ('draft', 'scheduled', 'published', 'withdrawn')),
    title text NOT NULL CHECK (announcement_valid_title(title)),
    body text NOT NULL CHECK (announcement_valid_body(body)),
    audience_mode text NOT NULL CHECK (audience_mode IN ('all', 'selected')),
    withdrawal_visibility text NOT NULL CHECK (withdrawal_visibility IN ('retain', 'hide')),
    scheduled_at timestamptz,
    sealed_at timestamptz,
    published_at timestamptz,
    withdrawn_at timestamptz,
    created_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    state_changed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, announcement_id, version),
    FOREIGN KEY (tenant_scope_id, announcement_id)
        REFERENCES announcements(tenant_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (state_changed_at >= created_at),
    CHECK (
        (status = 'draft' AND scheduled_at IS NULL AND sealed_at IS NULL AND
         published_at IS NULL AND withdrawn_at IS NULL) OR
        (status = 'scheduled' AND scheduled_at IS NOT NULL AND sealed_at IS NOT NULL AND
         published_at IS NULL AND withdrawn_at IS NULL AND scheduled_at >= sealed_at) OR
        (status = 'published' AND sealed_at IS NOT NULL AND published_at IS NOT NULL AND
         withdrawn_at IS NULL AND published_at >= sealed_at AND
         (scheduled_at IS NULL OR published_at >= scheduled_at)) OR
        (status = 'withdrawn' AND sealed_at IS NOT NULL AND withdrawn_at IS NOT NULL AND (
            (published_at IS NOT NULL AND published_at >= sealed_at AND withdrawn_at >= published_at) OR
            (published_at IS NULL AND scheduled_at IS NOT NULL AND withdrawn_at >= sealed_at)
        ))
    )
);

CREATE INDEX announcement_versions_due_idx
    ON announcement_versions (scheduled_at, tenant_scope_id, announcement_id, version)
    WHERE status = 'scheduled';

CREATE INDEX announcement_versions_tenant_status_idx
    ON announcement_versions (tenant_scope_id, status, state_changed_at DESC, announcement_id, version DESC);

ALTER TABLE announcements
    ADD CONSTRAINT announcements_current_published_fk
    FOREIGN KEY (tenant_scope_id, id, current_published_version)
    REFERENCES announcement_versions(tenant_scope_id, announcement_id, version)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE announcements
    ADD CONSTRAINT announcements_head_version_fk
    FOREIGN KEY (tenant_scope_id, id, head_version)
    REFERENCES announcement_versions(tenant_scope_id, announcement_id, version)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION ensure_current_published_version_truth()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    requested_scope_id uuid;
    requested_announcement_id uuid;
    current_version bigint;
    latest_published_version bigint;
BEGIN
    IF TG_TABLE_NAME = 'announcements' THEN
        requested_scope_id := NEW.tenant_scope_id;
        requested_announcement_id := NEW.id;
    ELSE
        requested_scope_id := NEW.tenant_scope_id;
        requested_announcement_id := NEW.announcement_id;
    END IF;
    SELECT current_published_version INTO current_version
      FROM announcements
     WHERE tenant_scope_id=requested_scope_id AND id=requested_announcement_id;
    SELECT max(version) INTO latest_published_version
      FROM announcement_versions
     WHERE tenant_scope_id=requested_scope_id AND announcement_id=requested_announcement_id
       AND status='published' AND published_at IS NOT NULL;
    IF current_version IS DISTINCT FROM latest_published_version THEN
        RAISE EXCEPTION 'current published version must equal the latest published version';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER announcements_current_published_truth
AFTER INSERT OR UPDATE OF current_published_version ON announcements
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION ensure_current_published_version_truth();

CREATE CONSTRAINT TRIGGER announcement_versions_current_published_truth
AFTER INSERT OR UPDATE OF status ON announcement_versions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION ensure_current_published_version_truth();

CREATE TABLE announcement_audience_users (
    tenant_scope_id uuid NOT NULL,
    announcement_id uuid NOT NULL,
    announcement_version bigint NOT NULL,
    user_id uuid NOT NULL,
    PRIMARY KEY (tenant_scope_id, announcement_id, announcement_version, user_id),
    FOREIGN KEY (tenant_scope_id, announcement_id, announcement_version)
        REFERENCES announcement_versions(tenant_scope_id, announcement_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

CREATE TABLE announcement_audience_groups (
    tenant_scope_id uuid NOT NULL,
    announcement_id uuid NOT NULL,
    announcement_version bigint NOT NULL,
    group_role_id uuid NOT NULL,
    PRIMARY KEY (tenant_scope_id, announcement_id, announcement_version, group_role_id),
    FOREIGN KEY (tenant_scope_id, announcement_id, announcement_version)
        REFERENCES announcement_versions(tenant_scope_id, announcement_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, group_role_id)
        REFERENCES roles(scope_id, id) ON DELETE RESTRICT
);

CREATE TABLE announcement_recipient_snapshots (
    tenant_scope_id uuid NOT NULL,
    announcement_id uuid NOT NULL,
    announcement_version bigint NOT NULL,
    user_id uuid NOT NULL,
    resolved_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, announcement_id, announcement_version, user_id),
    FOREIGN KEY (tenant_scope_id, announcement_id, announcement_version)
        REFERENCES announcement_versions(tenant_scope_id, announcement_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

CREATE TABLE announcement_inbox_events (
    id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    announcement_id uuid NOT NULL,
    announcement_version bigint NOT NULL,
    recipient_user_id uuid NOT NULL,
    title text NOT NULL,
    body text NOT NULL,
    published_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (tenant_scope_id, id, recipient_user_id),
    UNIQUE (tenant_scope_id, announcement_id, announcement_version, recipient_user_id),
    FOREIGN KEY (tenant_scope_id, announcement_id, announcement_version, recipient_user_id)
        REFERENCES announcement_recipient_snapshots(
            tenant_scope_id, announcement_id, announcement_version, user_id
        ) ON DELETE RESTRICT,
    CHECK (created_at = published_at)
);

CREATE INDEX announcement_inbox_events_user_page_idx
    ON announcement_inbox_events (tenant_scope_id, recipient_user_id, published_at DESC, id DESC);

CREATE TABLE announcement_inbox_states (
    tenant_scope_id uuid NOT NULL,
    event_id uuid NOT NULL,
    user_id uuid NOT NULL,
    delivered_at timestamptz,
    read_at timestamptz,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, event_id, user_id),
    FOREIGN KEY (tenant_scope_id, event_id, user_id)
        REFERENCES announcement_inbox_events(tenant_scope_id, id, recipient_user_id) ON DELETE RESTRICT,
    CHECK (read_at IS NULL OR (delivered_at IS NOT NULL AND read_at >= delivered_at))
);

CREATE TABLE announcement_write_requests (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation IN (
        'announcement.create', 'announcement.update', 'announcement.schedule',
        'announcement.publish', 'announcement.scheduled_publish', 'announcement.revise',
        'announcement.withdraw', 'announcement.deliver', 'announcement.read'
    )),
    idempotency_key text NOT NULL CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128 AND
        idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    FOREIGN KEY (tenant_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (tenant_scope_id, actor_user_id, operation, idempotency_key),
    CHECK (
        (completed_at IS NULL AND response_body IS NULL) OR
        (completed_at IS NOT NULL AND response_body IS NOT NULL AND completed_at >= created_at)
    )
);

CREATE FUNCTION protect_announcement_root()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    previous_status text;
    latest_published_version bigint;
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'announcements cannot be physically deleted';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.head_version <> 1 OR NEW.current_published_version IS NOT NULL THEN
            RAISE EXCEPTION 'announcement must start at draft version one';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
       OR NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'announcement identity is immutable';
    END IF;
    IF NEW.head_version = OLD.head_version + 1
       AND NEW.current_published_version IS NOT DISTINCT FROM OLD.current_published_version THEN
        RETURN NEW;
    END IF;
    IF NEW.head_version = OLD.head_version
       AND NEW.current_published_version IS NOT NULL
       AND (OLD.current_published_version IS NULL OR NEW.current_published_version > OLD.current_published_version) THEN
        RETURN NEW;
    END IF;
    IF NEW.head_version = OLD.head_version
       AND OLD.current_published_version IS NOT NULL
       AND NEW.current_published_version IS DISTINCT FROM OLD.current_published_version THEN
        SELECT status INTO previous_status
          FROM announcement_versions
         WHERE tenant_scope_id=OLD.tenant_scope_id AND announcement_id=OLD.id
           AND version=OLD.current_published_version;
        SELECT max(version) INTO latest_published_version
          FROM announcement_versions
         WHERE tenant_scope_id=OLD.tenant_scope_id AND announcement_id=OLD.id
           AND status='published';
        IF previous_status = 'withdrawn'
           AND NEW.current_published_version IS NOT DISTINCT FROM latest_published_version THEN
            RETURN NEW;
        END IF;
    END IF;
    RAISE EXCEPTION 'announcement pointers must advance monotonically';
END;
$$;

CREATE TRIGGER announcements_state_guard
BEFORE INSERT OR UPDATE OR DELETE ON announcements
FOR EACH ROW EXECUTE FUNCTION protect_announcement_root();

CREATE TRIGGER announcements_truncate_guard
BEFORE TRUNCATE ON announcements
FOR EACH STATEMENT EXECUTE FUNCTION protect_announcement_root();

CREATE FUNCTION protect_announcement_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    recipient_count bigint;
    event_count bigint;
    state_count bigint;
    selector_count bigint;
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'announcement versions cannot be deleted';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'draft' OR NEW.revision <> 1 OR NEW.scheduled_at IS NOT NULL
           OR NEW.sealed_at IS NOT NULL OR NEW.published_at IS NOT NULL OR NEW.withdrawn_at IS NOT NULL THEN
            RAISE EXCEPTION 'announcement version must start as draft';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
       OR NEW.announcement_id IS DISTINCT FROM OLD.announcement_id
       OR NEW.version IS DISTINCT FROM OLD.version
       OR NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.revision <> OLD.revision + 1
       OR NEW.state_changed_at < OLD.state_changed_at THEN
        RAISE EXCEPTION 'announcement version facts or revision are invalid';
    END IF;
    IF OLD.status = 'draft' AND NEW.status = 'draft'
       AND NEW.scheduled_at IS NULL AND NEW.sealed_at IS NULL
       AND NEW.published_at IS NULL AND NEW.withdrawn_at IS NULL THEN
        RETURN NEW;
    END IF;
    IF OLD.status = 'draft' AND NEW.status = 'scheduled'
       AND NEW.title IS NOT DISTINCT FROM OLD.title
       AND NEW.body IS NOT DISTINCT FROM OLD.body
       AND NEW.audience_mode IS NOT DISTINCT FROM OLD.audience_mode
       AND NEW.withdrawal_visibility IS NOT DISTINCT FROM OLD.withdrawal_visibility
       AND NEW.scheduled_at IS NOT NULL AND NEW.sealed_at IS NOT NULL
       AND NEW.published_at IS NULL AND NEW.withdrawn_at IS NULL THEN
        SELECT count(*) INTO selector_count FROM (
            SELECT user_id FROM announcement_audience_users
             WHERE tenant_scope_id=NEW.tenant_scope_id AND announcement_id=NEW.announcement_id
               AND announcement_version=NEW.version
            UNION ALL
            SELECT group_role_id FROM announcement_audience_groups
             WHERE tenant_scope_id=NEW.tenant_scope_id AND announcement_id=NEW.announcement_id
               AND announcement_version=NEW.version
        ) selectors;
        IF (NEW.audience_mode = 'all' AND selector_count <> 0)
           OR (NEW.audience_mode = 'selected' AND selector_count = 0) THEN
            RAISE EXCEPTION 'announcement audience selectors do not match mode';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.status IN ('draft', 'scheduled') AND NEW.status = 'published'
       AND NEW.title IS NOT DISTINCT FROM OLD.title
       AND NEW.body IS NOT DISTINCT FROM OLD.body
       AND NEW.audience_mode IS NOT DISTINCT FROM OLD.audience_mode
       AND NEW.withdrawal_visibility IS NOT DISTINCT FROM OLD.withdrawal_visibility
       AND NEW.scheduled_at IS NOT DISTINCT FROM OLD.scheduled_at
       AND NEW.sealed_at IS NOT NULL AND NEW.published_at IS NOT NULL
       AND NEW.withdrawn_at IS NULL THEN
        SELECT count(*) INTO recipient_count FROM announcement_recipient_snapshots
         WHERE tenant_scope_id=NEW.tenant_scope_id AND announcement_id=NEW.announcement_id
           AND announcement_version=NEW.version;
        SELECT count(*) INTO event_count FROM announcement_inbox_events
         WHERE tenant_scope_id=NEW.tenant_scope_id AND announcement_id=NEW.announcement_id
           AND announcement_version=NEW.version;
        SELECT count(*) INTO state_count FROM announcement_inbox_states state
          JOIN announcement_inbox_events event
            ON event.tenant_scope_id=state.tenant_scope_id AND event.id=state.event_id
           AND event.recipient_user_id=state.user_id
         WHERE event.tenant_scope_id=NEW.tenant_scope_id AND event.announcement_id=NEW.announcement_id
           AND event.announcement_version=NEW.version;
        IF recipient_count = 0 OR recipient_count <> event_count OR recipient_count <> state_count THEN
            RAISE EXCEPTION 'announcement publication requires a complete recipient and inbox snapshot';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.status = 'published' AND NEW.status = 'withdrawn'
       AND NEW.title IS NOT DISTINCT FROM OLD.title
       AND NEW.body IS NOT DISTINCT FROM OLD.body
       AND NEW.audience_mode IS NOT DISTINCT FROM OLD.audience_mode
       AND NEW.withdrawal_visibility IS NOT DISTINCT FROM OLD.withdrawal_visibility
       AND NEW.scheduled_at IS NOT DISTINCT FROM OLD.scheduled_at
       AND NEW.sealed_at IS NOT DISTINCT FROM OLD.sealed_at
       AND NEW.published_at IS NOT DISTINCT FROM OLD.published_at
       AND NEW.withdrawn_at IS NOT NULL THEN
        RETURN NEW;
    END IF;
    IF OLD.status = 'scheduled' AND NEW.status = 'withdrawn'
       AND NEW.title IS NOT DISTINCT FROM OLD.title
       AND NEW.body IS NOT DISTINCT FROM OLD.body
       AND NEW.audience_mode IS NOT DISTINCT FROM OLD.audience_mode
       AND NEW.withdrawal_visibility IS NOT DISTINCT FROM OLD.withdrawal_visibility
       AND NEW.scheduled_at IS NOT DISTINCT FROM OLD.scheduled_at
       AND NEW.sealed_at IS NOT DISTINCT FROM OLD.sealed_at
       AND NEW.published_at IS NULL AND NEW.withdrawn_at IS NOT NULL THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'announcement version transition is invalid';
END;
$$;

CREATE TRIGGER announcement_versions_state_guard
BEFORE INSERT OR UPDATE OR DELETE ON announcement_versions
FOR EACH ROW EXECUTE FUNCTION protect_announcement_version();

CREATE TRIGGER announcement_versions_truncate_guard
BEFORE TRUNCATE ON announcement_versions
FOR EACH STATEMENT EXECUTE FUNCTION protect_announcement_version();

CREATE FUNCTION protect_announcement_selector()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    scope_id uuid;
    root_id uuid;
    version_id bigint;
    version_status text;
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'announcement audience selectors cannot be truncated';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'announcement audience selectors are replaced, not updated';
    END IF;
    IF TG_OP = 'DELETE' THEN
        scope_id := OLD.tenant_scope_id;
        root_id := OLD.announcement_id;
        version_id := OLD.announcement_version;
    ELSE
        scope_id := NEW.tenant_scope_id;
        root_id := NEW.announcement_id;
        version_id := NEW.announcement_version;
    END IF;
    SELECT status INTO version_status FROM announcement_versions
     WHERE tenant_scope_id=scope_id AND announcement_id=root_id AND version=version_id;
    IF version_status IS DISTINCT FROM 'draft' THEN
        RAISE EXCEPTION 'announcement audience is immutable after draft';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE TRIGGER announcement_audience_users_guard
BEFORE INSERT OR UPDATE OR DELETE ON announcement_audience_users
FOR EACH ROW EXECUTE FUNCTION protect_announcement_selector();
CREATE TRIGGER announcement_audience_users_truncate_guard
BEFORE TRUNCATE ON announcement_audience_users
FOR EACH STATEMENT EXECUTE FUNCTION protect_announcement_selector();
CREATE TRIGGER announcement_audience_groups_guard
BEFORE INSERT OR UPDATE OR DELETE ON announcement_audience_groups
FOR EACH ROW EXECUTE FUNCTION protect_announcement_selector();
CREATE TRIGGER announcement_audience_groups_truncate_guard
BEFORE TRUNCATE ON announcement_audience_groups
FOR EACH STATEMENT EXECUTE FUNCTION protect_announcement_selector();

CREATE FUNCTION protect_announcement_recipient_snapshot()
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

CREATE TRIGGER announcement_recipient_snapshots_guard
BEFORE INSERT OR UPDATE OR DELETE ON announcement_recipient_snapshots
FOR EACH ROW EXECUTE FUNCTION protect_announcement_recipient_snapshot();
CREATE TRIGGER announcement_recipient_snapshots_truncate_guard
BEFORE TRUNCATE ON announcement_recipient_snapshots
FOR EACH STATEMENT EXECUTE FUNCTION protect_announcement_recipient_snapshot();

CREATE FUNCTION protect_announcement_inbox_event()
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

CREATE TRIGGER announcement_inbox_events_guard
BEFORE INSERT OR UPDATE OR DELETE ON announcement_inbox_events
FOR EACH ROW EXECUTE FUNCTION protect_announcement_inbox_event();
CREATE TRIGGER announcement_inbox_events_truncate_guard
BEFORE TRUNCATE ON announcement_inbox_events
FOR EACH STATEMENT EXECUTE FUNCTION protect_announcement_inbox_event();

CREATE FUNCTION protect_announcement_inbox_state()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    event_published_at timestamptz;
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE') THEN
        RAISE EXCEPTION 'announcement inbox states cannot be deleted';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.revision <> 1 OR NEW.delivered_at IS NOT NULL OR NEW.read_at IS NOT NULL THEN
            RAISE EXCEPTION 'announcement inbox state must start unread and undelivered';
        END IF;
        RETURN NEW;
    END IF;
    SELECT published_at INTO event_published_at FROM announcement_inbox_events
     WHERE tenant_scope_id=NEW.tenant_scope_id AND id=NEW.event_id
       AND recipient_user_id=NEW.user_id;
    IF NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
       OR NEW.event_id IS DISTINCT FROM OLD.event_id
       OR NEW.user_id IS DISTINCT FROM OLD.user_id
       OR NEW.revision <> OLD.revision + 1
       OR NEW.updated_at < OLD.updated_at
       OR (OLD.delivered_at IS NOT NULL AND NEW.delivered_at IS DISTINCT FROM OLD.delivered_at)
       OR (OLD.read_at IS NOT NULL AND NEW.read_at IS DISTINCT FROM OLD.read_at)
       OR (NEW.delivered_at IS NULL)
       OR NEW.delivered_at < event_published_at
       OR (NEW.read_at IS NOT NULL AND NEW.read_at < NEW.delivered_at) THEN
        RAISE EXCEPTION 'announcement inbox state must advance monotonically';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER announcement_inbox_states_guard
BEFORE INSERT OR UPDATE OR DELETE ON announcement_inbox_states
FOR EACH ROW EXECUTE FUNCTION protect_announcement_inbox_state();
CREATE TRIGGER announcement_inbox_states_truncate_guard
BEFORE TRUNCATE ON announcement_inbox_states
FOR EACH STATEMENT EXECUTE FUNCTION protect_announcement_inbox_state();

CREATE FUNCTION protect_announcement_write_request()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE') THEN
        RAISE EXCEPTION 'announcement write requests are immutable';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.completed_at IS NOT NULL OR NEW.response_body IS NOT NULL THEN
            RAISE EXCEPTION 'announcement write request must start incomplete';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
       OR NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id OR NEW.operation IS DISTINCT FROM OLD.operation
       OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
       OR NEW.request_digest IS DISTINCT FROM OLD.request_digest OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR OLD.completed_at IS NOT NULL OR OLD.response_body IS NOT NULL
       OR NEW.completed_at IS NULL OR NEW.response_body IS NULL THEN
        RAISE EXCEPTION 'announcement write request completion is invalid';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER announcement_write_requests_guard
BEFORE INSERT OR UPDATE OR DELETE ON announcement_write_requests
FOR EACH ROW EXECUTE FUNCTION protect_announcement_write_request();
CREATE TRIGGER announcement_write_requests_truncate_guard
BEFORE TRUNCATE ON announcement_write_requests
FOR EACH STATEMENT EXECUTE FUNCTION protect_announcement_write_request();

CREATE FUNCTION protect_announcement_state_watermark()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE') THEN
        RAISE EXCEPTION 'announcement state watermarks cannot be removed';
    END IF;
    IF pg_trigger_depth() < 2 THEN
        RAISE EXCEPTION 'announcement state watermarks are allocator controlled';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.current_watermark <> 1 THEN
            RAISE EXCEPTION 'announcement state watermark must start at one';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
       OR NEW.current_watermark <> OLD.current_watermark + 1 THEN
        RAISE EXCEPTION 'announcement state watermark must advance exactly once';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER announcement_state_watermarks_guard
BEFORE INSERT OR UPDATE OR DELETE ON announcement_state_watermarks
FOR EACH ROW EXECUTE FUNCTION protect_announcement_state_watermark();
CREATE TRIGGER announcement_state_watermarks_truncate_guard
BEFORE TRUNCATE ON announcement_state_watermarks
FOR EACH STATEMENT EXECUTE FUNCTION protect_announcement_state_watermark();

CREATE FUNCTION next_announcement_state_watermark(requested_scope_id uuid)
RETURNS bigint
LANGUAGE plpgsql
AS $$
DECLARE
    next_value bigint;
BEGIN
    INSERT INTO announcement_state_watermarks (tenant_scope_id, current_watermark)
    VALUES (requested_scope_id, 1)
    ON CONFLICT (tenant_scope_id) DO UPDATE
      SET current_watermark = announcement_state_watermarks.current_watermark + 1
    RETURNING current_watermark INTO next_value;
    RETURN next_value;
END;
$$;

REVOKE ALL ON FUNCTION next_announcement_state_watermark(uuid) FROM PUBLIC;

CREATE FUNCTION append_announcement_version_fact(
    requested_scope_id uuid,
    requested_announcement_id uuid,
    requested_version bigint,
    requested_occurred_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    version_row record;
    next_value bigint;
    version_payload jsonb;
    root_created_at timestamptz;
BEGIN
    SELECT version,revision,status,title,body,audience_mode,withdrawal_visibility,
           scheduled_at,sealed_at,published_at,withdrawn_at,created_at,state_changed_at
      INTO version_row
      FROM announcement_versions
     WHERE tenant_scope_id=requested_scope_id AND announcement_id=requested_announcement_id
       AND version=requested_version;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    SELECT created_at INTO root_created_at
      FROM announcements
     WHERE tenant_scope_id=requested_scope_id AND id=requested_announcement_id;
    version_payload := jsonb_build_object(
        'id', requested_announcement_id,
        'scope_id', requested_scope_id,
        'version', version_row.version,
        'revision', version_row.revision,
        'status', version_row.status,
        'title', version_row.title,
        'body', version_row.body,
        'audience_mode', version_row.audience_mode,
        'withdrawal_visibility', version_row.withdrawal_visibility,
        'scheduled_at', version_row.scheduled_at,
        'sealed_at', version_row.sealed_at,
        'published_at', version_row.published_at,
        'withdrawn_at', version_row.withdrawn_at,
        'created_at', version_row.created_at,
        'root_created_at', root_created_at,
        'state_changed_at', version_row.state_changed_at,
        'audience_user_ids', COALESCE((
            SELECT jsonb_agg(user_id ORDER BY user_id)
              FROM announcement_audience_users
             WHERE tenant_scope_id=requested_scope_id AND announcement_id=requested_announcement_id
               AND announcement_version=requested_version
        ), '[]'::jsonb),
        'audience_group_ids', COALESCE((
            SELECT jsonb_agg(group_role_id ORDER BY group_role_id)
              FROM announcement_audience_groups
             WHERE tenant_scope_id=requested_scope_id AND announcement_id=requested_announcement_id
               AND announcement_version=requested_version
        ), '[]'::jsonb)
    );
    next_value := next_announcement_state_watermark(requested_scope_id);
    INSERT INTO announcement_state_facts(
        tenant_scope_id,watermark,fact_type,announcement_id,announcement_version,payload,occurred_at
    ) VALUES (
        requested_scope_id,next_value,'version',requested_announcement_id,requested_version,
        version_payload,requested_occurred_at
    );
END;
$$;

REVOKE ALL ON FUNCTION append_announcement_version_fact(uuid, uuid, bigint, timestamptz) FROM PUBLIC;

CREATE FUNCTION record_announcement_version_fact()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM append_announcement_version_fact(
        NEW.tenant_scope_id, NEW.announcement_id, NEW.version, NEW.state_changed_at
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER announcement_versions_state_fact
AFTER INSERT OR UPDATE ON announcement_versions
FOR EACH ROW EXECUTE FUNCTION record_announcement_version_fact();

CREATE FUNCTION record_announcement_selector_fact()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    requested_scope_id uuid;
    requested_announcement_id uuid;
    requested_version bigint;
    occurred_at timestamptz;
BEGIN
    IF TG_OP = 'DELETE' THEN
        requested_scope_id := OLD.tenant_scope_id;
        requested_announcement_id := OLD.announcement_id;
        requested_version := OLD.announcement_version;
    ELSE
        requested_scope_id := NEW.tenant_scope_id;
        requested_announcement_id := NEW.announcement_id;
        requested_version := NEW.announcement_version;
    END IF;
    SELECT state_changed_at INTO occurred_at
      FROM announcement_versions
     WHERE tenant_scope_id=requested_scope_id AND announcement_id=requested_announcement_id
       AND version=requested_version;
    PERFORM append_announcement_version_fact(
        requested_scope_id, requested_announcement_id, requested_version, COALESCE(occurred_at, now())
    );
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE TRIGGER announcement_audience_users_state_fact
AFTER INSERT OR DELETE ON announcement_audience_users
FOR EACH ROW EXECUTE FUNCTION record_announcement_selector_fact();
CREATE TRIGGER announcement_audience_groups_state_fact
AFTER INSERT OR DELETE ON announcement_audience_groups
FOR EACH ROW EXECUTE FUNCTION record_announcement_selector_fact();

CREATE FUNCTION record_announcement_inbox_event_fact()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    next_value bigint;
BEGIN
    next_value := next_announcement_state_watermark(NEW.tenant_scope_id);
    INSERT INTO announcement_state_facts(
        tenant_scope_id,watermark,fact_type,announcement_id,announcement_version,event_id,
        recipient_user_id,payload,occurred_at
    ) VALUES (
        NEW.tenant_scope_id,next_value,'inbox_event',NEW.announcement_id,NEW.announcement_version,
        NEW.id,NEW.recipient_user_id,jsonb_build_object(
            'id',NEW.id,'announcement_id',NEW.announcement_id,'announcement_version',NEW.announcement_version,
            'recipient_user_id',NEW.recipient_user_id,'title',NEW.title,'body',NEW.body,
            'published_at',NEW.published_at,'created_at',NEW.created_at
        ),NEW.created_at
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER announcement_inbox_events_state_fact
AFTER INSERT ON announcement_inbox_events
FOR EACH ROW EXECUTE FUNCTION record_announcement_inbox_event_fact();

CREATE FUNCTION record_announcement_inbox_state_fact()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    next_value bigint;
BEGIN
    next_value := next_announcement_state_watermark(NEW.tenant_scope_id);
    INSERT INTO announcement_state_facts(
        tenant_scope_id,watermark,fact_type,event_id,recipient_user_id,payload,occurred_at
    ) VALUES (
        NEW.tenant_scope_id,next_value,'inbox_state',NEW.event_id,NEW.user_id,jsonb_build_object(
            'event_id',NEW.event_id,'user_id',NEW.user_id,'delivered_at',NEW.delivered_at,
            'read_at',NEW.read_at,'revision',NEW.revision,'updated_at',NEW.updated_at
        ),NEW.updated_at
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER announcement_inbox_states_state_fact
AFTER INSERT OR UPDATE ON announcement_inbox_states
FOR EACH ROW EXECUTE FUNCTION record_announcement_inbox_state_fact();

CREATE FUNCTION protect_announcement_state_fact()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' AND pg_trigger_depth() < 2 THEN
        RAISE EXCEPTION 'announcement state facts may only be appended by state triggers';
    END IF;
    IF TG_OP IN ('UPDATE','DELETE','TRUNCATE') THEN
        RAISE EXCEPTION 'announcement state facts are append-only';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE TRIGGER announcement_state_facts_append_only
BEFORE INSERT OR UPDATE OR DELETE ON announcement_state_facts
FOR EACH ROW EXECUTE FUNCTION protect_announcement_state_fact();
CREATE TRIGGER announcement_state_facts_truncate_guard
BEFORE TRUNCATE ON announcement_state_facts
FOR EACH STATEMENT EXECUTE FUNCTION protect_announcement_state_fact();
