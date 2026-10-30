ALTER TABLE error_page_write_requests
    DROP CONSTRAINT error_page_write_requests_operation_check;
ALTER TABLE error_page_write_requests
    ADD CONSTRAINT error_page_write_requests_operation_check CHECK (operation IN (
        'error_page.asset.initiate', 'error_page.asset.upload', 'error_page.asset.finalize',
        'error_page.asset.reconcile_finalize', 'error_page.asset.delete',
        'error_page.rule.create', 'error_page.rule.update', 'error_page.rule.enable',
        'error_page.rule.disable', 'error_page.rule.delete',
        'error_page.slot.bind', 'error_page.slot.unbind'
    ));

CREATE TABLE error_page_slots (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    slot_key text NOT NULL CHECK (slot_key IN (
        'blacklist', 'http_400', 'http_403', 'waf_block', 'http_502', 'http_504',
        'traffic_exceeded', 'package_expired', 'site_locked', 'domain_unconfigured',
        'node_ip_access', 'connection_limit'
    )),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_by_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    UNIQUE (scope_id, slot_key),
    FOREIGN KEY (created_by_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

CREATE TABLE error_page_slot_revisions (
    slot_id uuid NOT NULL REFERENCES error_page_slots(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    asset_id uuid REFERENCES error_page_assets(id) ON DELETE RESTRICT,
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_by_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    trace_id text NOT NULL CHECK (trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (slot_id, revision),
    FOREIGN KEY (created_by_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

CREATE INDEX error_page_slot_revisions_asset_idx
    ON error_page_slot_revisions (asset_id) WHERE asset_id IS NOT NULL;

CREATE FUNCTION validate_error_page_slot_identity_218()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_kind text;
BEGIN
    SELECT kind INTO target_kind FROM access_scopes WHERE id = NEW.scope_id FOR SHARE;
    IF NOT FOUND OR target_kind <> 'platform' OR NEW.created_by_scope_id <> NEW.scope_id OR
       NOT error_page_actor_has_permission(
           NEW.created_by_scope_id, NEW.created_by_user_id, 'error_pages.manage'
       ) THEN
        RAISE EXCEPTION 'invalid error page slot identity' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER error_page_slots_validate_insert_218
BEFORE INSERT ON error_page_slots
FOR EACH ROW EXECUTE FUNCTION validate_error_page_slot_identity_218();

CREATE FUNCTION validate_error_page_slot_revision_218()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    identity error_page_slots%ROWTYPE;
    latest_revision bigint;
    asset_scope uuid;
    asset_status text;
    asset_object_state text;
BEGIN
    SELECT * INTO identity FROM error_page_slots WHERE id = NEW.slot_id FOR UPDATE;
    SELECT COALESCE(max(revision), 0) INTO latest_revision
      FROM error_page_slot_revisions WHERE slot_id = NEW.slot_id;
    IF NOT FOUND OR NEW.revision <> latest_revision + 1 OR
       NEW.created_by_scope_id <> identity.scope_id OR
       NOT error_page_actor_has_permission(
           NEW.created_by_scope_id, NEW.created_by_user_id, 'error_pages.manage'
       ) THEN
        RAISE EXCEPTION 'invalid error page slot revision' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.asset_id IS NOT NULL THEN
        SELECT scope_id, status, object_state INTO asset_scope, asset_status, asset_object_state
          FROM error_page_assets WHERE id = NEW.asset_id FOR SHARE;
        IF NOT FOUND OR asset_scope <> identity.scope_id OR asset_status <> 'ready' OR
           asset_object_state <> 'final' THEN
            RAISE EXCEPTION 'invalid error page slot asset' USING ERRCODE = 'P0001';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER error_page_slot_revisions_validate_insert_218
BEFORE INSERT ON error_page_slot_revisions
FOR EACH ROW EXECUTE FUNCTION validate_error_page_slot_revision_218();

CREATE FUNCTION protect_error_page_slots_218()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'error page slots are append only' USING ERRCODE = 'P0001';
END;
$$;

CREATE TRIGGER error_page_slots_append_only_218
BEFORE UPDATE OR DELETE OR TRUNCATE ON error_page_slots
FOR EACH STATEMENT EXECUTE FUNCTION protect_error_page_slots_218();

CREATE TRIGGER error_page_slot_revisions_append_only_218
BEFORE UPDATE OR DELETE OR TRUNCATE ON error_page_slot_revisions
FOR EACH STATEMENT EXECUTE FUNCTION protect_error_page_slots_218();

CREATE FUNCTION protect_bound_error_page_asset_218()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status = 'ready' AND NEW.status <> 'ready' AND EXISTS (
        SELECT 1
          FROM error_page_slots slot
          JOIN LATERAL (
              SELECT revision.asset_id
                FROM error_page_slot_revisions revision
               WHERE revision.slot_id = slot.id
               ORDER BY revision.revision DESC LIMIT 1
          ) current ON true
         WHERE current.asset_id = OLD.id
    ) THEN
        RAISE EXCEPTION 'bound error page asset cannot transition' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER error_page_assets_bound_slot_guard_218
BEFORE UPDATE ON error_page_assets
FOR EACH ROW EXECUTE FUNCTION protect_bound_error_page_asset_218();

GRANT SELECT, INSERT ON TABLE error_page_slots, error_page_slot_revisions
    TO cdnca_control_app;
