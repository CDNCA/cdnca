-- 521（r136 proto-batch）回退：恢复 site_protocols 权限码与授权触发器；按 136 定义（含 284 节点清除外键/删除守卫、319 作用域函数）重建空的协议批次表。
LOCK TABLE schema_migrations, permissions, custom_rbac_permission_catalog, roles, role_permissions
    IN ACCESS EXCLUSIVE MODE;

DO $migration_521_down$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) <> 521 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=521 AND
        migration_id='521_site_protocol_batch_drop' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass('site_protocol_batches') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 521 down requires the exact verified migration head' USING ERRCODE='P5211';
    END IF;
END;
$migration_521_down$;

-- 权限码、目录、系统角色授权与新角色授权触发器按 136 原样恢复。
INSERT INTO permissions(name,description) VALUES
    ('site_protocols.read','Read persisted website protocol batches and node results'),
    ('site_protocols.manage','Create, retry, and roll back website protocol batches');

INSERT INTO custom_rbac_permission_catalog(permission_name,step_up_required) VALUES
    ('site_protocols.read',false),('site_protocols.manage',false);

INSERT INTO role_permissions(role_id,permission_name)
SELECT id,'site_protocols.read' FROM roles WHERE system_role AND name IN ('platform_owner','tenant_owner','tenant_viewer')
ON CONFLICT DO NOTHING;
INSERT INTO role_permissions(role_id,permission_name)
SELECT id,'site_protocols.manage' FROM roles WHERE system_role AND name IN ('platform_owner','tenant_owner')
ON CONFLICT DO NOTHING;

CREATE FUNCTION grant_site_protocol_permissions_136()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF NOT NEW.system_role THEN RETURN NEW; END IF;
    IF NEW.name IN ('platform_owner','tenant_owner') THEN
        INSERT INTO role_permissions(role_id,permission_name) VALUES
            (NEW.id,'site_protocols.read'),(NEW.id,'site_protocols.manage') ON CONFLICT DO NOTHING;
    ELSIF NEW.name='tenant_viewer' THEN
        INSERT INTO role_permissions(role_id,permission_name) VALUES
            (NEW.id,'site_protocols.read') ON CONFLICT DO NOTHING;
    END IF;
    RETURN NEW;
END;
$function$;
CREATE TRIGGER roles_site_protocol_permissions_136 AFTER INSERT ON roles
FOR EACH ROW EXECUTE FUNCTION grant_site_protocol_permissions_136();

CREATE TABLE site_protocol_batches (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    parent_batch_id uuid,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    action text NOT NULL CHECK(action IN ('apply','rollback')),
    http3_enabled boolean NOT NULL,
    state text NOT NULL CHECK(state IN ('queued','running','succeeded','partial_failed','failed','rolled_back')),
    revision bigint NOT NULL CHECK(revision>0),
    request_sha256 bytea NOT NULL CHECK(octet_length(request_sha256)=32),
    request_id text NOT NULL CHECK(char_length(request_id) BETWEEN 1 AND 128),
    trace_id text NOT NULL CHECK(char_length(trace_id) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at),
    UNIQUE(tenant_scope_id,id),
    FOREIGN KEY(tenant_scope_id,parent_batch_id)
        REFERENCES site_protocol_batches(tenant_scope_id,id) ON DELETE RESTRICT,
    CHECK((action='apply' AND parent_batch_id IS NULL) OR (action='rollback' AND parent_batch_id IS NOT NULL))
);
CREATE INDEX site_protocol_batches_scope_created_idx
    ON site_protocol_batches(tenant_scope_id,created_at DESC,id DESC);

CREATE TABLE site_protocol_states (
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    active_http3_enabled boolean NOT NULL,
    desired_http3_enabled boolean NOT NULL,
    revision bigint NOT NULL CHECK(revision>0),
    last_batch_id uuid NOT NULL,
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at)),
    PRIMARY KEY(tenant_scope_id,site_id),
    FOREIGN KEY(tenant_scope_id,last_batch_id)
        REFERENCES site_protocol_batches(tenant_scope_id,id) ON DELETE RESTRICT
);

CREATE TABLE site_protocol_batch_items (
    batch_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    position integer NOT NULL CHECK(position>=0 AND position<128),
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    previous_http3_enabled boolean NOT NULL,
    desired_http3_enabled boolean NOT NULL,
    state text NOT NULL CHECK(state IN ('pending','applied','failed')),
    attempt integer NOT NULL CHECK(attempt BETWEEN 1 AND 64),
    error_code text CHECK(error_code IS NULL OR error_code ~ '^[A-Z0-9_]{1,128}$'),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at),
    PRIMARY KEY(batch_id,site_id),
    UNIQUE(batch_id,position),
    FOREIGN KEY(tenant_scope_id,batch_id)
        REFERENCES site_protocol_batches(tenant_scope_id,id) ON DELETE RESTRICT,
    CHECK((state='failed' AND error_code IS NOT NULL) OR (state<>'failed' AND error_code IS NULL))
);

CREATE TABLE site_protocol_jobs (
    id uuid PRIMARY KEY,
    batch_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    state text NOT NULL CHECK(state IN ('queued','running','succeeded','partial_failed','failed')),
    attempt integer NOT NULL CHECK(attempt BETWEEN 1 AND 64),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at),
    UNIQUE(tenant_scope_id,batch_id,id),
    FOREIGN KEY(tenant_scope_id,batch_id)
        REFERENCES site_protocol_batches(tenant_scope_id,id) ON DELETE RESTRICT
);

CREATE TABLE site_protocol_node_results (
    batch_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    state text NOT NULL CHECK(state IN ('pending','applied','failed')),
    attempt integer NOT NULL CHECK(attempt BETWEEN 1 AND 64),
    error_code text CHECK(error_code IS NULL OR error_code ~ '^[A-Z0-9_]{1,128}$'),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at)),
    PRIMARY KEY(batch_id,site_id,node_id),
    FOREIGN KEY(batch_id,site_id)
        REFERENCES site_protocol_batch_items(batch_id,site_id) ON DELETE RESTRICT,
    FOREIGN KEY(tenant_scope_id,batch_id)
        REFERENCES site_protocol_batches(tenant_scope_id,id) ON DELETE RESTRICT,
    CHECK((state='failed' AND error_code IS NOT NULL) OR (state<>'failed' AND error_code IS NULL))
);

CREATE TABLE site_protocol_write_requests (
    id uuid PRIMARY KEY,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK(operation IN (
        'site_protocol.batch.create','site_protocol.batch.retry','site_protocol.batch.rollback'
    )),
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    request_sha256 bytea NOT NULL CHECK(octet_length(request_sha256)=32),
    request_id text NOT NULL CHECK(char_length(request_id) BETWEEN 1 AND 128),
    trace_id text NOT NULL CHECK(char_length(trace_id) BETWEEN 1 AND 128),
    batch_id uuid REFERENCES site_protocol_batches(id) ON DELETE RESTRICT,
    response_status integer CHECK(response_status BETWEEN 200 AND 299),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    completed_at timestamptz CHECK(completed_at IS NULL OR isfinite(completed_at)),
    UNIQUE(actor_scope_id,actor_user_id,operation,idempotency_key),
    FOREIGN KEY(target_scope_id,batch_id)
        REFERENCES site_protocol_batches(tenant_scope_id,id) ON DELETE RESTRICT,
    CHECK((completed_at IS NULL AND batch_id IS NULL AND response_status IS NULL) OR
          (completed_at IS NOT NULL AND batch_id IS NOT NULL AND response_status IS NOT NULL))
);

CREATE TABLE site_protocol_outbox (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    batch_id uuid NOT NULL,
    site_id uuid NOT NULL,
    attempt integer NOT NULL CHECK(attempt BETWEEN 1 AND 64),
    http3_enabled boolean NOT NULL,
    command_sha256 bytea NOT NULL CHECK(octet_length(command_sha256)=32),
    state text NOT NULL CHECK(state IN ('pending','published','retryable','dead')),
    puback_sequence bigint CHECK(puback_sequence IS NULL OR puback_sequence>0),
    error_code text CHECK(error_code IS NULL OR error_code ~ '^[A-Z0-9_]{1,128}$'),
    available_at timestamptz NOT NULL CHECK(isfinite(available_at)),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    published_at timestamptz CHECK(published_at IS NULL OR isfinite(published_at)),
    UNIQUE(batch_id,site_id,attempt),
    FOREIGN KEY(batch_id,site_id)
        REFERENCES site_protocol_batch_items(batch_id,site_id) ON DELETE RESTRICT,
    FOREIGN KEY(tenant_scope_id,batch_id)
        REFERENCES site_protocol_batches(tenant_scope_id,id) ON DELETE RESTRICT,
    CHECK((state='published' AND puback_sequence IS NOT NULL AND published_at IS NOT NULL AND error_code IS NULL) OR
          (state='retryable' AND puback_sequence IS NULL AND published_at IS NULL AND error_code IS NOT NULL) OR
          (state='dead' AND puback_sequence IS NULL AND error_code IS NOT NULL) OR
          (state='pending' AND puback_sequence IS NULL AND published_at IS NULL AND error_code IS NULL))
);
CREATE INDEX site_protocol_outbox_ready_idx
    ON site_protocol_outbox(available_at,id) WHERE state IN ('pending','retryable');

CREATE TABLE site_protocol_audit_events (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    batch_id uuid NOT NULL,
    action text NOT NULL CHECK(action IN (
        'site_protocol.batch.create','site_protocol.batch.retry','site_protocol.batch.rollback'
    )),
    request_id text NOT NULL CHECK(char_length(request_id) BETWEEN 1 AND 128),
    request_sha256 bytea NOT NULL CHECK(octet_length(request_sha256)=32),
    occurred_at timestamptz NOT NULL CHECK(isfinite(occurred_at)),
    UNIQUE(tenant_scope_id,actor_user_id,action,request_id),
    FOREIGN KEY(tenant_scope_id,batch_id)
        REFERENCES site_protocol_batches(tenant_scope_id,id) ON DELETE RESTRICT
);

CREATE FUNCTION validate_site_protocol_scope_136()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM access_scopes WHERE id=NEW.tenant_scope_id AND kind='tenant') THEN
        RAISE EXCEPTION 'site protocol scope must be tenant' USING ERRCODE='P1361';
    END IF;
    IF TG_TABLE_NAME IN ('site_protocol_states','site_protocol_batch_items') THEN
        IF NOT EXISTS(SELECT 1 FROM sites WHERE id=NEW.site_id AND scope_id=NEW.tenant_scope_id AND deleted_at IS NULL) THEN
            RAISE EXCEPTION 'site protocol site scope mismatch' USING ERRCODE='P1362';
        END IF;
    ELSIF TG_TABLE_NAME='site_protocol_node_results' THEN
        IF NOT EXISTS(SELECT 1 FROM sites WHERE id=NEW.site_id AND scope_id=NEW.tenant_scope_id AND deleted_at IS NULL) OR
           NOT EXISTS(SELECT 1 FROM nodes WHERE id=NEW.node_id AND scope_id=NEW.tenant_scope_id AND admin_state<>'retired') THEN
            RAISE EXCEPTION 'site protocol node scope mismatch' USING ERRCODE='P1362';
        END IF;
    END IF;
    RETURN NEW;
END;
$function$;
CREATE TRIGGER site_protocol_batches_scope_136 BEFORE INSERT OR UPDATE ON site_protocol_batches
FOR EACH ROW EXECUTE FUNCTION validate_site_protocol_scope_136();
CREATE TRIGGER site_protocol_states_scope_136 BEFORE INSERT OR UPDATE ON site_protocol_states
FOR EACH ROW EXECUTE FUNCTION validate_site_protocol_scope_136();
CREATE TRIGGER site_protocol_items_scope_136 BEFORE INSERT OR UPDATE ON site_protocol_batch_items
FOR EACH ROW EXECUTE FUNCTION validate_site_protocol_scope_136();
CREATE TRIGGER site_protocol_node_results_scope_136 BEFORE INSERT OR UPDATE ON site_protocol_node_results
FOR EACH ROW EXECUTE FUNCTION validate_site_protocol_scope_136();

CREATE FUNCTION guard_site_protocol_batch_136()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF TG_OP='DELETE' OR NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id OR
       NEW.parent_batch_id IS DISTINCT FROM OLD.parent_batch_id OR NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id OR
       NEW.action IS DISTINCT FROM OLD.action OR NEW.http3_enabled IS DISTINCT FROM OLD.http3_enabled OR
       NEW.request_sha256 IS DISTINCT FROM OLD.request_sha256 OR NEW.request_id IS DISTINCT FROM OLD.request_id OR
       NEW.trace_id IS DISTINCT FROM OLD.trace_id OR NEW.created_at IS DISTINCT FROM OLD.created_at OR
       NEW.revision<>OLD.revision+1 OR NEW.updated_at<OLD.updated_at THEN
        RAISE EXCEPTION 'site protocol batch identity is immutable' USING ERRCODE='P1363';
    END IF;
    IF NOT ((OLD.state='queued' AND NEW.state IN ('running','failed')) OR
            (OLD.state='running' AND NEW.state IN ('succeeded','partial_failed','failed')) OR
            (OLD.state IN ('partial_failed','failed') AND NEW.state='queued') OR
            (OLD.state=NEW.state AND OLD.state IN ('queued','running'))) THEN
        RAISE EXCEPTION 'invalid site protocol batch transition' USING ERRCODE='P1364';
    END IF;
    RETURN NEW;
END;
$function$;
CREATE TRIGGER site_protocol_batches_guard_136 BEFORE UPDATE OR DELETE ON site_protocol_batches
FOR EACH ROW EXECUTE FUNCTION guard_site_protocol_batch_136();

CREATE FUNCTION guard_site_protocol_state_136()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF TG_OP='DELETE' OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id OR
       NEW.site_id IS DISTINCT FROM OLD.site_id OR NEW.updated_at<OLD.updated_at THEN
        RAISE EXCEPTION 'site protocol state identity is immutable' USING ERRCODE='P1363';
    END IF;
    IF NEW.desired_http3_enabled IS DISTINCT FROM OLD.desired_http3_enabled THEN
        IF NEW.revision<>OLD.revision+1 OR NEW.last_batch_id=OLD.last_batch_id OR
           NEW.active_http3_enabled IS DISTINCT FROM OLD.active_http3_enabled THEN
            RAISE EXCEPTION 'invalid site protocol desired state transition' USING ERRCODE='P1364';
        END IF;
    ELSIF NEW.active_http3_enabled IS DISTINCT FROM OLD.active_http3_enabled THEN
        IF NEW.revision<>OLD.revision OR NEW.last_batch_id<>OLD.last_batch_id OR
           NEW.active_http3_enabled<>NEW.desired_http3_enabled THEN
            RAISE EXCEPTION 'invalid site protocol active state transition' USING ERRCODE='P1364';
        END IF;
    ELSIF NEW.last_batch_id<>OLD.last_batch_id AND NEW.revision=OLD.revision+1 THEN
        NULL;
    ELSE
        RAISE EXCEPTION 'site protocol state no-op update is forbidden' USING ERRCODE='P1364';
    END IF;
    RETURN NEW;
END;
$function$;
CREATE TRIGGER site_protocol_states_guard_136 BEFORE UPDATE OR DELETE ON site_protocol_states
FOR EACH ROW EXECUTE FUNCTION guard_site_protocol_state_136();

CREATE FUNCTION guard_site_protocol_item_136()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF TG_OP='DELETE' OR NEW.batch_id IS DISTINCT FROM OLD.batch_id OR
       NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id OR NEW.position<>OLD.position OR
       NEW.site_id IS DISTINCT FROM OLD.site_id OR NEW.previous_http3_enabled<>OLD.previous_http3_enabled OR
       NEW.desired_http3_enabled<>OLD.desired_http3_enabled OR NEW.created_at<>OLD.created_at OR
       NEW.updated_at<OLD.updated_at OR NOT (
         (OLD.state='pending' AND NEW.state IN ('applied','failed') AND NEW.attempt=OLD.attempt) OR
         (OLD.state='failed' AND NEW.state='pending' AND NEW.attempt=OLD.attempt+1)
       ) THEN
        RAISE EXCEPTION 'invalid site protocol item transition' USING ERRCODE='P1364';
    END IF;
    RETURN NEW;
END;
$function$;
CREATE TRIGGER site_protocol_items_guard_136 BEFORE UPDATE OR DELETE ON site_protocol_batch_items
FOR EACH ROW EXECUTE FUNCTION guard_site_protocol_item_136();

CREATE FUNCTION guard_site_protocol_node_result_136()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF TG_OP='DELETE' OR NEW.batch_id IS DISTINCT FROM OLD.batch_id OR
       NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id OR NEW.site_id IS DISTINCT FROM OLD.site_id OR
       NEW.node_id IS DISTINCT FROM OLD.node_id OR NEW.updated_at<OLD.updated_at OR NOT (
         (OLD.state='pending' AND NEW.state IN ('applied','failed') AND NEW.attempt=OLD.attempt) OR
         (OLD.state IN ('applied','failed') AND NEW.state='pending' AND NEW.attempt=OLD.attempt+1)
       ) THEN
        RAISE EXCEPTION 'invalid site protocol node result transition' USING ERRCODE='P1364';
    END IF;
    RETURN NEW;
END;
$function$;
CREATE TRIGGER site_protocol_node_results_guard_136 BEFORE UPDATE ON site_protocol_node_results FOR EACH ROW EXECUTE FUNCTION guard_site_protocol_node_result_136();
CREATE TRIGGER site_protocol_node_results_guard_136_del BEFORE DELETE ON site_protocol_node_results FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION guard_site_protocol_node_result_136();

CREATE FUNCTION guard_site_protocol_outbox_136()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF TG_OP='DELETE' OR NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id OR
       NEW.batch_id IS DISTINCT FROM OLD.batch_id OR NEW.site_id IS DISTINCT FROM OLD.site_id OR NEW.attempt<>OLD.attempt OR
       NEW.http3_enabled<>OLD.http3_enabled OR NEW.command_sha256<>OLD.command_sha256 OR
       NEW.created_at<>OLD.created_at OR NOT (
         (OLD.state='pending' AND NEW.state IN ('published','retryable','dead')) OR
         (OLD.state='retryable' AND NEW.state IN ('published','retryable','dead'))
       ) THEN
        RAISE EXCEPTION 'invalid site protocol outbox transition' USING ERRCODE='P1364';
    END IF;
    RETURN NEW;
END;
$function$;
CREATE TRIGGER site_protocol_outbox_guard_136 BEFORE UPDATE OR DELETE ON site_protocol_outbox
FOR EACH ROW EXECUTE FUNCTION guard_site_protocol_outbox_136();

CREATE FUNCTION guard_site_protocol_receipt_136()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF TG_OP='DELETE' OR OLD.completed_at IS NOT NULL OR NEW.id IS DISTINCT FROM OLD.id OR
       NEW.actor_scope_id IS DISTINCT FROM OLD.actor_scope_id OR NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id OR
       NEW.target_scope_id IS DISTINCT FROM OLD.target_scope_id OR NEW.operation IS DISTINCT FROM OLD.operation OR
       NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key OR NEW.request_sha256 IS DISTINCT FROM OLD.request_sha256 OR
       NEW.request_id IS DISTINCT FROM OLD.request_id OR NEW.trace_id IS DISTINCT FROM OLD.trace_id OR
       NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'site protocol receipt is immutable' USING ERRCODE='P1365';
    END IF;
    RETURN NEW;
END;
$function$;
CREATE TRIGGER site_protocol_receipts_guard_136 BEFORE UPDATE OR DELETE ON site_protocol_write_requests
FOR EACH ROW EXECUTE FUNCTION guard_site_protocol_receipt_136();

CREATE FUNCTION guard_site_protocol_append_only_136()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    RAISE EXCEPTION 'site protocol facts are append-only' USING ERRCODE='P1365';
END;
$function$;
CREATE TRIGGER site_protocol_audit_guard_136 BEFORE UPDATE OR DELETE ON site_protocol_audit_events
FOR EACH ROW EXECUTE FUNCTION guard_site_protocol_append_only_136();
CREATE TRIGGER site_protocol_audit_truncate_136 BEFORE TRUNCATE ON site_protocol_audit_events
FOR EACH STATEMENT EXECUTE FUNCTION guard_site_protocol_append_only_136();

REVOKE ALL ON site_protocol_batches,site_protocol_states,site_protocol_batch_items,site_protocol_jobs,
    site_protocol_node_results,site_protocol_write_requests,site_protocol_outbox,site_protocol_audit_events FROM PUBLIC;
