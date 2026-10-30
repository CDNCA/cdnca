LOCK TABLE schema_migrations, permissions, access_scopes, roles, role_permissions,
    notification_templates, notification_event_policies IN ACCESS EXCLUSIVE MODE;

DO $migration_302_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 301 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 301 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=301 AND
        migration_id='301_line_group_publication_sync_hold' AND
        checksum_sha256='18f6165f855411e1de1799454ec7e8c22245cdf292ddcc40b13d921ff11092f8' AND
        down_checksum_sha256='17463b2c338ce34c72c1e096c0ef5ac92eda769d7d4020ca343f1d76f8443248' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.tickets') IS NOT NULL OR
            EXISTS (SELECT 1 FROM permissions WHERE name IN ('tickets.read', 'tickets.manage')) OR
            EXISTS (SELECT 1 FROM notification_event_policies WHERE event_type LIKE 'ticket.%') THEN
        RAISE EXCEPTION 'migration 302 requires the exact verified 301 release head' USING ERRCODE='P3020';
    END IF;
END;
$migration_302_up$;

-- Support tickets (1.0.35 G6 #9, internal/tickets). Customers file tickets in
-- their tenant scope and only ever see their own; platform staff with
-- tickets.read / tickets.manage see and work all of them. Customers need no
-- permission code: an active membership in a tenant scope is enough.
INSERT INTO permissions(name, description) VALUES
    ('tickets.read', 'Read all support tickets, messages, internal notes and attachments'),
    ('tickets.manage', 'Claim, reply to, annotate and change the status and priority of support tickets');

INSERT INTO role_permissions(role_id, permission_name)
SELECT role.id, permission.name
FROM roles role
JOIN access_scopes scope ON scope.id = role.scope_id AND scope.kind = 'platform'
CROSS JOIN (VALUES ('tickets.read'), ('tickets.manage')) AS permission(name)
WHERE role.system_role AND role.name IN ('platform_owner', 'platform_admin')
ON CONFLICT DO NOTHING;

CREATE TABLE tickets (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    -- Human-facing number shown in lists and notifications; never used for access.
    ticket_no bigint GENERATED ALWAYS AS IDENTITY (START WITH 10001) UNIQUE,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    category text NOT NULL CHECK (category IN ('technical', 'billing', 'account', 'abuse', 'other')),
    subject text NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 200 AND subject !~ '[[:cntrl:]]'),
    priority text NOT NULL DEFAULT 'normal' CHECK (priority IN ('low', 'normal', 'high', 'urgent')),
    -- 待处理 / 处理中 / 待用户回复 / 已解决 / 已关闭
    status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'processing', 'pending_customer', 'resolved', 'closed')),
    assignee_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    site_id uuid REFERENCES sites(id) ON DELETE SET NULL,
    order_id uuid REFERENCES package_orders(id) ON DELETE SET NULL,
    customer_unread boolean NOT NULL DEFAULT false,
    staff_unread boolean NOT NULL DEFAULT true,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    last_message_at timestamptz NOT NULL CHECK (isfinite(last_message_at)),
    -- First customer-visible staff reply (SLA: tickets still waiting for it).
    first_response_at timestamptz CHECK (first_response_at IS NULL OR isfinite(first_response_at)),
    resolved_at timestamptz CHECK (resolved_at IS NULL OR isfinite(resolved_at)),
    closed_at timestamptz CHECK (closed_at IS NULL OR isfinite(closed_at)),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    FOREIGN KEY (tenant_scope_id, user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK ((status = 'resolved') = (resolved_at IS NOT NULL)),
    CHECK ((status = 'closed') = (closed_at IS NOT NULL))
);
CREATE INDEX tickets_owner_302_idx ON tickets (tenant_scope_id, user_id, last_message_at DESC, id);
CREATE INDEX tickets_queue_302_idx ON tickets (status, last_message_at DESC, id);
CREATE INDEX tickets_assignee_302_idx ON tickets (assignee_user_id, status) WHERE assignee_user_id IS NOT NULL;

CREATE TABLE ticket_messages (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    ticket_id uuid NOT NULL REFERENCES tickets(id) ON DELETE RESTRICT,
    author_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    author_kind text NOT NULL CHECK (author_kind IN ('customer', 'staff')),
    -- Plain text; the console renders it as text, never as HTML.
    body text NOT NULL CHECK (char_length(body) BETWEEN 1 AND 20000),
    -- Internal notes are staff-only and never returned to the customer.
    internal boolean NOT NULL DEFAULT false CHECK (NOT internal OR author_kind = 'staff'),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at))
);
CREATE INDEX ticket_messages_ticket_302_idx ON ticket_messages (ticket_id, created_at, id);

-- Attachments are uploaded first (unbound, owned by the uploader) and bound
-- to a message when the ticket or reply is posted. The object key embeds a
-- random UUID and is never returned by the API; downloads go through the
-- ticket access check.
CREATE TABLE ticket_attachments (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    owner_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    ticket_id uuid REFERENCES tickets(id) ON DELETE RESTRICT,
    message_id uuid REFERENCES ticket_messages(id) ON DELETE RESTRICT,
    file_name text NOT NULL CHECK (char_length(file_name) BETWEEN 1 AND 128 AND file_name !~ '[[:cntrl:]/\\]'),
    mime_type text NOT NULL CHECK (mime_type IN ('image/png', 'image/jpeg', 'image/gif', 'image/webp', 'application/pdf', 'text/plain')),
    size_bytes bigint NOT NULL CHECK (size_bytes BETWEEN 1 AND 1048576),
    sha256 bytea NOT NULL CHECK (octet_length(sha256) = 32),
    object_key text NOT NULL UNIQUE CHECK (object_key ~ '^ticket-attachments/[0-9a-f-]{36}/[0-9a-f-]{36}$'),
    immutable_token text NOT NULL CHECK (char_length(immutable_token) BETWEEN 1 AND 512),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    bound_at timestamptz CHECK (bound_at IS NULL OR isfinite(bound_at)),
    CHECK ((ticket_id IS NULL) = (message_id IS NULL) AND (message_id IS NULL) = (bound_at IS NULL))
);
CREATE INDEX ticket_attachments_message_302_idx ON ticket_attachments (message_id) WHERE message_id IS NOT NULL;
CREATE INDEX ticket_attachments_pending_302_idx ON ticket_attachments (owner_user_id, created_at) WHERE message_id IS NULL;

-- Idempotent creates and replies: the first response is replayed for the same
-- (user, operation, key); a different request under the same key is refused.
CREATE TABLE ticket_write_requests (
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation ~ '^ticket\.[a-z_.]{1,64}$'),
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    response_body jsonb NOT NULL CHECK (jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    PRIMARY KEY (actor_user_id, operation, idempotency_key)
);

-- Customer notifications follow the existing event policies and channel
-- switches (notification_event_policies, notification_subscriptions).
INSERT INTO notification_event_policies(event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported, updated_at)
VALUES
    ('ticket.created', true, true, true, 1, 24, true, now()),
    ('ticket.replied', true, true, true, 1, 24, true, now()),
    ('ticket.status_changed', true, true, true, 1, 24, true, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('ticket_created', 1, 'email', '工单已提交',
     '您的工单 #{{.ticket_no}}「{{.subject}}」已提交，我们会尽快处理。', ARRAY['ticket_no','subject'], '2026-10-17 00:00:00+00'),
    ('ticket_created', 1, 'sms', '',
     '您的工单#{{.ticket_no}}已提交，我们会尽快处理。', ARRAY['ticket_no'], '2026-10-17 00:00:00+00'),
    ('ticket_replied', 1, 'email', '工单有新回复',
     '您的工单 #{{.ticket_no}}「{{.subject}}」有新的客服回复，请登录控制台查看。', ARRAY['ticket_no','subject'], '2026-10-17 00:00:00+00'),
    ('ticket_replied', 1, 'sms', '',
     '您的工单#{{.ticket_no}}有新回复，请登录控制台查看。', ARRAY['ticket_no'], '2026-10-17 00:00:00+00'),
    ('ticket_status_changed', 1, 'email', '工单状态已更新',
     '您的工单 #{{.ticket_no}}「{{.subject}}」状态已更新为：{{.status_label}}。', ARRAY['ticket_no','subject','status_label'], '2026-10-17 00:00:00+00'),
    ('ticket_status_changed', 1, 'sms', '',
     '您的工单#{{.ticket_no}}状态已更新为：{{.status_label}}。', ARRAY['ticket_no','status_label'], '2026-10-17 00:00:00+00');

REVOKE ALL ON tickets, ticket_messages, ticket_attachments, ticket_write_requests FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON tickets, ticket_attachments TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT ON ticket_messages, ticket_write_requests TO cdnca_control_app, cdnca_control_runtime;
