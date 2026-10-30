ALTER TABLE error_page_write_requests
    DROP CONSTRAINT error_page_write_requests_operation_check;
ALTER TABLE error_page_write_requests
    ADD CONSTRAINT error_page_write_requests_operation_check CHECK (operation IN (
        'error_page.asset.initiate', 'error_page.asset.upload', 'error_page.asset.finalize',
        'error_page.asset.reconcile_finalize', 'error_page.asset.delete',
        'error_page.rule.create', 'error_page.rule.update', 'error_page.rule.enable',
        'error_page.rule.disable', 'error_page.rule.delete',
        'error_page.slot.bind', 'error_page.slot.unbind',
        'error_page.scope_override.create', 'error_page.scope_override.update',
        'error_page.scope_override.delete'
    ));

CREATE TABLE error_page_scope_overrides (
    id uuid PRIMARY KEY,
    display_id bigint GENERATED ALWAYS AS IDENTITY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    target_kind text NOT NULL CHECK (target_kind IN ('node', 'region')),
    target_node_id uuid REFERENCES nodes(id) ON DELETE RESTRICT,
    target_region text,
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_by_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    CONSTRAINT error_page_scope_overrides_target_check CHECK (
        (target_kind = 'node' AND target_node_id IS NOT NULL AND target_region IS NULL) OR
        (target_kind = 'region' AND target_node_id IS NULL AND target_region IS NOT NULL AND
         target_region = btrim(target_region) AND char_length(target_region) BETWEEN 1 AND 64)
    ),
    CONSTRAINT error_page_scope_overrides_scope_display_unique UNIQUE (scope_id, display_id),
    FOREIGN KEY (created_by_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX error_page_scope_overrides_node_unique
    ON error_page_scope_overrides (scope_id, target_node_id)
    WHERE target_kind = 'node';
CREATE UNIQUE INDEX error_page_scope_overrides_region_unique
    ON error_page_scope_overrides (scope_id, target_region)
    WHERE target_kind = 'region';

CREATE TABLE error_page_scope_override_revisions (
    override_id uuid NOT NULL REFERENCES error_page_scope_overrides(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    deleted boolean NOT NULL DEFAULT false,
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_by_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    trace_id text NOT NULL CHECK (trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (override_id, revision),
    FOREIGN KEY (created_by_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

CREATE TABLE error_page_scope_override_items (
    override_id uuid NOT NULL,
    revision bigint NOT NULL,
    slot_key text NOT NULL CHECK (slot_key IN (
        'http_400', 'http_403', 'http_502', 'http_504', 'traffic_exceeded',
        'package_expired', 'site_locked', 'domain_unconfigured', 'node_ip_access',
        'connection_limit'
    )),
    asset_id uuid NOT NULL REFERENCES error_page_assets(id) ON DELETE RESTRICT,
    PRIMARY KEY (override_id, revision, slot_key),
    FOREIGN KEY (override_id, revision)
        REFERENCES error_page_scope_override_revisions(override_id, revision) ON DELETE RESTRICT
);

CREATE INDEX error_page_scope_override_items_asset_idx
    ON error_page_scope_override_items (asset_id);

CREATE FUNCTION validate_error_page_scope_override_identity_220()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_scope_kind text;
BEGIN
    SELECT kind INTO target_scope_kind FROM access_scopes WHERE id = NEW.scope_id FOR SHARE;
    IF NOT FOUND OR target_scope_kind <> 'platform' OR NEW.created_by_scope_id <> NEW.scope_id OR
       NOT error_page_actor_has_permission(
           NEW.created_by_scope_id, NEW.created_by_user_id, 'error_pages.manage'
       ) THEN
        RAISE EXCEPTION 'invalid error page scope override identity' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.target_kind = 'node' AND NOT EXISTS (
        SELECT 1 FROM nodes
        WHERE id = NEW.target_node_id AND scope_id = NEW.scope_id AND admin_state <> 'retired'
        FOR SHARE
    ) THEN
        RAISE EXCEPTION 'invalid error page node override target' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.target_kind = 'region' AND NOT EXISTS (
        SELECT 1 FROM nodes
        WHERE scope_id = NEW.scope_id AND region = NEW.target_region AND admin_state <> 'retired'
        FOR SHARE
    ) THEN
        RAISE EXCEPTION 'invalid error page region override target' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER error_page_scope_overrides_validate_insert_220
BEFORE INSERT ON error_page_scope_overrides
FOR EACH ROW EXECUTE FUNCTION validate_error_page_scope_override_identity_220();

CREATE FUNCTION validate_error_page_scope_override_revision_220()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    identity error_page_scope_overrides%ROWTYPE;
    latest_revision bigint;
BEGIN
    SELECT * INTO identity FROM error_page_scope_overrides WHERE id = NEW.override_id FOR UPDATE;
    SELECT COALESCE(max(revision), 0) INTO latest_revision
      FROM error_page_scope_override_revisions WHERE override_id = NEW.override_id;
    IF NOT FOUND OR NEW.revision <> latest_revision + 1 OR
       NEW.created_by_scope_id <> identity.scope_id OR
       NOT error_page_actor_has_permission(
           NEW.created_by_scope_id, NEW.created_by_user_id, 'error_pages.manage'
       ) THEN
        RAISE EXCEPTION 'invalid error page scope override revision' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER error_page_scope_override_revisions_validate_insert_220
BEFORE INSERT ON error_page_scope_override_revisions
FOR EACH ROW EXECUTE FUNCTION validate_error_page_scope_override_revision_220();

CREATE FUNCTION validate_error_page_scope_override_item_220()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    identity_scope uuid;
    revision_deleted boolean;
    asset_scope uuid;
    asset_status text;
    asset_object_state text;
BEGIN
    SELECT identity.scope_id, revision.deleted
      INTO identity_scope, revision_deleted
      FROM error_page_scope_override_revisions revision
      JOIN error_page_scope_overrides identity ON identity.id = revision.override_id
     WHERE revision.override_id = NEW.override_id AND revision.revision = NEW.revision
     FOR SHARE OF identity, revision;
    IF NOT FOUND OR revision_deleted OR (
        SELECT count(*) FROM error_page_scope_override_items
        WHERE override_id = NEW.override_id AND revision = NEW.revision
    ) >= 10 THEN
        RAISE EXCEPTION 'invalid error page scope override item' USING ERRCODE = 'P0001';
    END IF;
    SELECT scope_id, status, object_state INTO asset_scope, asset_status, asset_object_state
      FROM error_page_assets WHERE id = NEW.asset_id FOR SHARE;
    IF NOT FOUND OR asset_scope <> identity_scope OR asset_status <> 'ready' OR
       asset_object_state <> 'final' THEN
        RAISE EXCEPTION 'invalid error page scope override asset' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER error_page_scope_override_items_validate_insert_220
BEFORE INSERT ON error_page_scope_override_items
FOR EACH ROW EXECUTE FUNCTION validate_error_page_scope_override_item_220();

CREATE FUNCTION validate_error_page_scope_override_cardinality_220()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    item_count integer;
BEGIN
    SELECT count(*) INTO item_count FROM error_page_scope_override_items
     WHERE override_id = NEW.override_id AND revision = NEW.revision;
    IF (NEW.deleted AND item_count <> 0) OR
       (NOT NEW.deleted AND item_count NOT BETWEEN 1 AND 10) THEN
        RAISE EXCEPTION 'invalid error page scope override item count' USING ERRCODE = 'P0001';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER error_page_scope_override_cardinality_220
AFTER INSERT ON error_page_scope_override_revisions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_error_page_scope_override_cardinality_220();

CREATE FUNCTION protect_error_page_scope_overrides_220()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'error page scope overrides are append only' USING ERRCODE = 'P0001';
END;
$$;

CREATE TRIGGER error_page_scope_overrides_append_only_220
BEFORE UPDATE OR DELETE OR TRUNCATE ON error_page_scope_overrides
FOR EACH STATEMENT EXECUTE FUNCTION protect_error_page_scope_overrides_220();
CREATE TRIGGER error_page_scope_override_revisions_append_only_220
BEFORE UPDATE OR DELETE OR TRUNCATE ON error_page_scope_override_revisions
FOR EACH STATEMENT EXECUTE FUNCTION protect_error_page_scope_overrides_220();
CREATE TRIGGER error_page_scope_override_items_append_only_220
BEFORE UPDATE OR DELETE OR TRUNCATE ON error_page_scope_override_items
FOR EACH STATEMENT EXECUTE FUNCTION protect_error_page_scope_overrides_220();

CREATE FUNCTION protect_scope_override_asset_220()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status = 'ready' AND NEW.status <> 'ready' AND EXISTS (
        SELECT 1
          FROM error_page_scope_overrides identity
          JOIN LATERAL (
              SELECT revision.revision, revision.deleted
                FROM error_page_scope_override_revisions revision
               WHERE revision.override_id = identity.id
               ORDER BY revision.revision DESC LIMIT 1
          ) current ON NOT current.deleted
          JOIN error_page_scope_override_items item
            ON item.override_id = identity.id AND item.revision = current.revision
         WHERE item.asset_id = OLD.id
    ) THEN
        RAISE EXCEPTION 'bound error page scope override asset cannot transition' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER error_page_assets_bound_scope_override_guard_220
BEFORE UPDATE ON error_page_assets
FOR EACH ROW EXECUTE FUNCTION protect_scope_override_asset_220();

GRANT SELECT, INSERT ON TABLE error_page_scope_overrides,
    error_page_scope_override_revisions, error_page_scope_override_items TO cdnca_control_app;
GRANT USAGE, SELECT ON SEQUENCE error_page_scope_overrides_display_id_seq TO cdnca_control_app;
