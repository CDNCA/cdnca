LOCK TABLE schema_migrations, notification_events, notification_templates, certificate_assets IN ACCESS EXCLUSIVE MODE;

DO $migration_527_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 527 OR
       (SELECT max(version) FROM schema_migrations) <> 527 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=527 AND
        migration_id='527_tenant_member_invitations_drop' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 527 down requires the exact verified migration head' USING ERRCODE='P5272';
    END IF;
END;
$migration_527_down$;

-- 回退按 398/409/487 原定义重建（空表），不恢复任何数据。
CREATE TABLE tenant_member_invitations_398 (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    email text NOT NULL CHECK (email = lower(btrim(email)) AND char_length(email) BETWEEN 3 AND 254 AND position('@' IN email) > 1),
    token_digest bytea NOT NULL UNIQUE CHECK (octet_length(token_digest) = 32),
    anonymous_dispatch_reference uuid NOT NULL UNIQUE,
    outbox_id uuid NOT NULL UNIQUE REFERENCES notification_outbox(id) ON DELETE RESTRICT,
    invited_by_user_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('pending', 'accepted', 'revoked')),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    expires_at timestamptz NOT NULL CHECK (isfinite(expires_at) AND expires_at > created_at),
    accepted_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    finished_at timestamptz CHECK (finished_at IS NULL OR isfinite(finished_at)),
    FOREIGN KEY (scope_id, invited_by_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK ((status = 'pending') = (finished_at IS NULL)),
    CHECK ((status = 'accepted') = (accepted_user_id IS NOT NULL))
);

CREATE INDEX tenant_member_invitations_scope_created_398 ON tenant_member_invitations_398 (scope_id, created_at DESC, id);
CREATE UNIQUE INDEX tenant_member_invitations_pending_email_398 ON tenant_member_invitations_398 (scope_id, email) WHERE status = 'pending';

CREATE FUNCTION guard_tenant_member_invitations_398()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'tenant member invitations are history' USING ERRCODE='P3981';
    END IF;
    IF OLD.status <> 'pending' OR
       ROW(NEW.id, NEW.scope_id, NEW.email, NEW.token_digest, NEW.anonymous_dispatch_reference, NEW.outbox_id,
           NEW.invited_by_user_id, NEW.created_at, NEW.expires_at) IS DISTINCT FROM
       ROW(OLD.id, OLD.scope_id, OLD.email, OLD.token_digest, OLD.anonymous_dispatch_reference, OLD.outbox_id,
           OLD.invited_by_user_id, OLD.created_at, OLD.expires_at) THEN
        RAISE EXCEPTION 'only a pending tenant member invitation can finish, once' USING ERRCODE='P3981';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER tenant_member_invitations_guard_398
BEFORE UPDATE OR DELETE ON tenant_member_invitations_398
FOR EACH ROW EXECUTE FUNCTION guard_tenant_member_invitations_398();

ALTER TABLE notification_events
    DROP CONSTRAINT notification_events_recipient_one_of_049,
    ADD CONSTRAINT notification_events_recipient_one_of_049 CHECK (
        (
            recipient_kind = 'member' AND
            recipient_user_id IS NOT NULL AND
            anonymous_dispatch_reference IS NULL AND
            event_type <> 'identity.account_recovery'
        ) OR (
            recipient_kind = 'anonymous' AND
            recipient_user_id IS NULL AND
            anonymous_dispatch_reference IS NOT NULL AND
            anonymous_dispatch_reference <> '00000000-0000-0000-0000-000000000000'::uuid AND
            event_type IN (
                'identity.account_recovery',
                'identity.account_registration_verification',
                'identity.account_login_verification',
                'identity.tenant_member_invitation'
            ) AND
            delivery_policy = 'system_required'
        )
    );

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('tenant_member_invitation', 1, 'email', '账号成员邀请 / Account member invitation',
     '{{.tenant}} 邀请你成为其账号的成员（默认只读）。请在 72 小时内打开下面的链接设置用户名和密码，链接只能使用一次。' || E'\n' ||
     '{{.tenant}} invited you to join its account as a member (read-only by default). Open the link below within 72 hours to choose a username and password; it works once.',
     ARRAY['tenant'], '2026-10-19 00:00:00+00');

REVOKE ALL ON tenant_member_invitations_398 FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_tenant_member_invitations_398() FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON tenant_member_invitations_398 TO cdnca_control_app, cdnca_control_runtime;

CREATE TABLE tenant_member_password_reset_results (
    idempotency_key text PRIMARY KEY CHECK (idempotency_key ~ '^[A-Za-z0-9._-]{1,128}$'),
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    actor_scope_id uuid NOT NULL,
    member_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_id text,
    envelope bytea,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    retrieved_at timestamptz,
    CHECK ((key_id IS NULL) = (envelope IS NULL)),
    CHECK (retrieved_at IS NULL OR envelope IS NULL),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '10 minutes')
);
CREATE INDEX tenant_member_password_reset_results_created_idx ON tenant_member_password_reset_results (created_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_member_password_reset_results TO cdnca_control_app, cdnca_control_runtime;

CREATE OR REPLACE FUNCTION protect_certificate_asset_owner_276() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.owner_user_id IS DISTINCT FROM OLD.owner_user_id THEN
        IF OLD.owner_user_id IS NOT NULL AND NEW.owner_user_id IS NOT NULL AND
           current_setting('cdnca.tenant_member_handover', true) =
               OLD.owner_user_id::text || ':' || NEW.owner_user_id::text THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'certificate asset owner is immutable' USING ERRCODE='P2761';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION protect_certificate_asset_owner_276() FROM PUBLIC,cdnca_control_app;
