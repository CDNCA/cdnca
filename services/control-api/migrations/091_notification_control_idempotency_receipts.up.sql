LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE access_scopes, users, memberships, audit_events IN SHARE ROW EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 90 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 90 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state <> 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 90
          AND migration_id = '090_package_offer_publication'
          AND checksum_sha256 = '1bfa2cccb6b15dab981cf73b23754c7a1751f2f60921dda5959f51fef545b284'
          AND down_checksum_sha256 = '9450025870421a3d594f3a9e210bd463ba3021b3ac19b815dee5a127ddaf5c9b'
          AND integrity_state = 'verified'
    ) THEN
        RAISE EXCEPTION 'migration 091 requires the exact verified 090 release head'
            USING ERRCODE = 'P9100';
    END IF;
END;
$$;

CREATE UNIQUE INDEX audit_events_notification_control_denied_identity_091
ON audit_events (scope_id, actor_user_id, action, request_id)
WHERE result = 'denied'
  AND actor_user_id IS NOT NULL
  AND action IN (
    'notification.channels.update',
    'notification.template.put',
    'notification.subscription.update'
  );

CREATE TABLE notification_control_idempotency_receipts (
    id uuid PRIMARY KEY,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation IN (
        'notification.channels.update',
        'notification.template.put',
        'notification.subscription.update'
    )),
    request_key text NOT NULL CHECK (
        octet_length(request_key) BETWEEN 1 AND 128 AND
        request_key = btrim(request_key) AND
        request_key !~ '[[:cntrl:]]'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    completed_at timestamptz CHECK (completed_at IS NULL OR isfinite(completed_at)),
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (actor_scope_id, actor_user_id, operation, request_key),
    CHECK (
        (completed_at IS NULL AND response_body IS NULL) OR
        (completed_at IS NOT NULL AND response_body IS NOT NULL AND completed_at >= created_at)
    )
);

CREATE FUNCTION protect_notification_control_idempotency_receipt_091()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'notification control idempotency receipts cannot be truncated'
            USING ERRCODE = 'P9102';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.response_body IS NOT NULL OR NEW.completed_at IS NOT NULL THEN
            RAISE EXCEPTION 'notification control idempotency receipt must start incomplete'
                USING ERRCODE = 'P9102';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'notification control idempotency receipts cannot be deleted'
            USING ERRCODE = 'P9102';
    END IF;
    IF OLD.completed_at IS NOT NULL OR
       ROW(NEW.id, NEW.actor_scope_id, NEW.actor_user_id, NEW.operation,
           NEW.request_key, NEW.request_digest, NEW.created_at) IS DISTINCT FROM
       ROW(OLD.id, OLD.actor_scope_id, OLD.actor_user_id, OLD.operation,
           OLD.request_key, OLD.request_digest, OLD.created_at) OR
       NEW.response_body IS NULL OR NEW.completed_at IS NULL OR
       NEW.completed_at < OLD.created_at THEN
        RAISE EXCEPTION 'notification control idempotency receipt may complete exactly once'
            USING ERRCODE = 'P9102';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION require_notification_control_idempotency_receipt_completion_091()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_response jsonb;
    current_completed_at timestamptz;
BEGIN
    SELECT response_body, completed_at
    INTO current_response, current_completed_at
    FROM notification_control_idempotency_receipts
    WHERE id = NEW.id;
    IF NOT FOUND OR current_response IS NULL OR current_completed_at IS NULL THEN
        RAISE EXCEPTION 'notification control idempotency receipt must complete in its claiming transaction'
            USING ERRCODE = 'P9102';
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER notification_control_idempotency_receipts_protect_091
BEFORE INSERT OR UPDATE OR DELETE ON notification_control_idempotency_receipts
FOR EACH ROW EXECUTE FUNCTION protect_notification_control_idempotency_receipt_091();

CREATE TRIGGER notification_control_idempotency_receipts_no_truncate_091
BEFORE TRUNCATE ON notification_control_idempotency_receipts
FOR EACH STATEMENT EXECUTE FUNCTION protect_notification_control_idempotency_receipt_091();

CREATE CONSTRAINT TRIGGER notification_control_idempotency_receipts_complete_091
AFTER INSERT OR UPDATE ON notification_control_idempotency_receipts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION require_notification_control_idempotency_receipt_completion_091();

REVOKE ALL ON FUNCTION protect_notification_control_idempotency_receipt_091() FROM PUBLIC;
REVOKE ALL ON FUNCTION require_notification_control_idempotency_receipt_completion_091() FROM PUBLIC;
