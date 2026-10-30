LOCK TABLE schema_migrations,
    permissions,
    custom_rbac_permission_catalog,
    roles,
    role_permissions,
    audit_events,
    background_jobs,
    dns_reconcile_cancel_facts,
    dns_reconcile_provider_recovery_continuations
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 93 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 93 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL
           OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 93
          AND migration_id = '093_upgrade_rollout_persistence'
          AND checksum_sha256 = '3614fd6c9d624f2e75ded822c2de8fe62940267c4a5e9b76340a37e428e319af'
          AND down_checksum_sha256 = '522de2c6ff1747157b9b0cce959724f18d9395f1c20638d4bfcbdcafb29b734a'
          AND integrity_state = 'verified'
          AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 094 requires the exact verified 093 release head'
            USING ERRCODE = 'P9400';
    END IF;
END;
$$;

INSERT INTO permissions(name, description) VALUES
    ('jobs.manage', 'Cancel and retry tenant background jobs'),
    ('jobs.manage_all', 'Cancel and retry background jobs across tenants');

CREATE TABLE background_job_command_rbac_catalog_additions_094 (
    permission_name text PRIMARY KEY CHECK (permission_name = 'jobs.manage'),
    source_migration smallint NOT NULL DEFAULT 94 CHECK (source_migration = 94),
    FOREIGN KEY (permission_name)
        REFERENCES custom_rbac_permission_catalog(permission_name) ON DELETE RESTRICT
);

WITH additions AS (
    INSERT INTO custom_rbac_permission_catalog(permission_name, step_up_required)
    VALUES ('jobs.manage', false)
    RETURNING permission_name
)
INSERT INTO background_job_command_rbac_catalog_additions_094(permission_name)
SELECT permission_name FROM additions;

CREATE TABLE background_job_command_rbac_grant_additions_094 (
    role_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    permission_name text NOT NULL CHECK (permission_name IN ('jobs.manage','jobs.manage_all')),
    source_migration smallint NOT NULL DEFAULT 94 CHECK (source_migration = 94),
    PRIMARY KEY (role_id, permission_name),
    FOREIGN KEY (scope_id, role_id) REFERENCES roles(scope_id, id) ON DELETE RESTRICT,
    CONSTRAINT background_job_command_rbac_grant_role_permission_094_fk
        FOREIGN KEY (role_id, permission_name)
        REFERENCES role_permissions(role_id, permission_name) ON DELETE RESTRICT
);

CREATE OR REPLACE FUNCTION guard_system_role_permission_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_role_id uuid;
    target_system_role boolean;
    target_role_name text;
    target_permission_name text;
    scope_kind text;
    protected_permission boolean;
BEGIN
    target_role_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.role_id ELSE NEW.role_id END;
    target_permission_name := CASE
        WHEN TG_OP = 'DELETE' THEN OLD.permission_name ELSE NEW.permission_name
    END;
    SELECT role.system_role, role.name, scope.kind
      INTO target_system_role, target_role_name, scope_kind
    FROM roles role JOIN access_scopes scope ON scope.id = role.scope_id
    WHERE role.id = target_role_id;

    IF target_permission_name = 'jobs.manage_all' AND (
       TG_OP <> 'INSERT' OR target_system_role IS DISTINCT FROM true OR
       scope_kind IS DISTINCT FROM 'platform' OR target_role_name IS DISTINCT FROM 'platform_owner'
    ) THEN
        RAISE EXCEPTION 'jobs.manage_all is restricted to platform_owner'
            USING ERRCODE = 'P9403';
    END IF;
    IF TG_OP = 'INSERT' AND target_permission_name = 'jobs.manage' AND (
       scope_kind IS DISTINCT FROM 'tenant' OR
       (target_system_role AND target_role_name <> 'tenant_owner')
    ) THEN
        RAISE EXCEPTION 'jobs.manage is restricted to tenant roles'
            USING ERRCODE = 'P9403';
    END IF;

    IF NOT target_system_role THEN
        IF EXISTS (SELECT 1 FROM custom_roles WHERE id = target_role_id) AND pg_trigger_depth() < 2 THEN
            RAISE EXCEPTION 'custom role permission projection is protected';
        END IF;
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;
    SELECT EXISTS (
        SELECT 1 FROM custom_rbac_permission_catalog
        WHERE permission_name = target_permission_name
    ) INTO protected_permission;

    IF TG_OP = 'UPDATE' OR
       (TG_OP = 'DELETE' AND (protected_permission OR target_permission_name = 'jobs.manage_all')) THEN
        RAISE EXCEPTION 'system role permissions are immutable';
    END IF;
    IF TG_OP = 'INSERT' AND scope_kind = 'tenant' AND
       (NEW.permission_name IN (
            'platform.admin', 'identity.impersonation.manage', 'billing.adjustments.manage',
            'api_keys.admin.manage', 'packages.manage', 'nodes.read', 'nodes.manage',
            'control.upgrades.check', 'node_ca.manage', 'system_configuration.read',
            'system_configuration.manage', 'jobs.manage_all'
        ) OR
        (NEW.permission_name = 'package_subscriptions.read' AND
         target_role_name NOT IN ('tenant_owner', 'tenant_viewer')) OR
        (NEW.permission_name = 'package_subscriptions.manage' AND
         target_role_name <> 'tenant_owner') OR
        (NEW.permission_name = 'plugin_webhooks.read' AND
         target_role_name NOT IN ('tenant_owner', 'tenant_admin', 'tenant_member', 'tenant_viewer')) OR
        (NEW.permission_name = 'plugin_webhooks.manage' AND
         target_role_name NOT IN ('tenant_owner', 'tenant_admin')) OR
        (NEW.permission_name = 'jobs.manage' AND
         target_role_name <> 'tenant_owner') OR
        (target_role_name = 'tenant_viewer' AND
         NEW.permission_name NOT LIKE '%.read' AND
         NEW.permission_name NOT IN (
             'identity.self.update', 'identity.password.change', 'api_keys.self.manage',
             'identity_verification.self.manage', 'promotions.quote', 'promotions.redeem'
         ))) THEN
        RAISE EXCEPTION 'invalid tenant system role permission';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

WITH additions AS (
    INSERT INTO role_permissions(role_id, permission_name)
    SELECT role.id, 'jobs.manage'
    FROM roles role JOIN access_scopes scope ON scope.id = role.scope_id
    WHERE role.system_role AND scope.kind = 'tenant'
      AND role.name = 'tenant_owner'
    ON CONFLICT DO NOTHING
    RETURNING role_id, permission_name
)
INSERT INTO background_job_command_rbac_grant_additions_094(role_id, scope_id, permission_name)
SELECT addition.role_id, role.scope_id, addition.permission_name
FROM additions addition JOIN roles role ON role.id = addition.role_id;

WITH additions AS (
    INSERT INTO role_permissions(role_id, permission_name)
    SELECT role.id, 'jobs.manage_all'
    FROM roles role JOIN access_scopes scope ON scope.id = role.scope_id
    WHERE role.system_role AND scope.kind = 'platform' AND role.name = 'platform_owner'
    ON CONFLICT DO NOTHING
    RETURNING role_id, permission_name
)
INSERT INTO background_job_command_rbac_grant_additions_094(role_id, scope_id, permission_name)
SELECT addition.role_id, role.scope_id, addition.permission_name
FROM additions addition JOIN roles role ON role.id = addition.role_id;

CREATE FUNCTION project_background_job_command_permissions_094()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_scope_kind text;
BEGIN
    IF NOT NEW.system_role THEN
        RETURN NEW;
    END IF;
    SELECT kind INTO target_scope_kind FROM access_scopes WHERE id = NEW.scope_id FOR SHARE;
    WITH additions AS (
        INSERT INTO role_permissions(role_id, permission_name)
        SELECT NEW.id, permission_name
        FROM (VALUES
            ('jobs.manage', target_scope_kind = 'tenant' AND NEW.name = 'tenant_owner'),
            ('jobs.manage_all', target_scope_kind = 'platform' AND NEW.name = 'platform_owner')
        ) permission(permission_name, allowed)
        WHERE allowed
        ON CONFLICT DO NOTHING
        RETURNING role_id, permission_name
    )
    INSERT INTO background_job_command_rbac_grant_additions_094(role_id, scope_id, permission_name)
    SELECT role_id, NEW.scope_id, permission_name FROM additions;
    RETURN NEW;
END;
$$;

CREATE TRIGGER roles_project_background_job_command_permissions_094
AFTER INSERT ON roles
FOR EACH ROW EXECUTE FUNCTION project_background_job_command_permissions_094();

CREATE FUNCTION protect_background_job_command_rbac_provenance_094()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' AND pg_trigger_depth() >= 2 THEN
        RETURN NULL;
    END IF;
    RAISE EXCEPTION 'background job command RBAC provenance is immutable'
        USING ERRCODE = 'P9403';
END;
$$;

CREATE TRIGGER background_job_command_rbac_catalog_protect_094
BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON background_job_command_rbac_catalog_additions_094
FOR EACH STATEMENT EXECUTE FUNCTION protect_background_job_command_rbac_provenance_094();
CREATE TRIGGER background_job_command_rbac_grants_protect_094
BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON background_job_command_rbac_grant_additions_094
FOR EACH STATEMENT EXECUTE FUNCTION protect_background_job_command_rbac_provenance_094();
ALTER TABLE background_job_command_rbac_catalog_additions_094
    ENABLE ALWAYS TRIGGER background_job_command_rbac_catalog_protect_094;
ALTER TABLE background_job_command_rbac_grant_additions_094
    ENABLE ALWAYS TRIGGER background_job_command_rbac_grants_protect_094;

CREATE FUNCTION protect_background_job_command_catalog_094()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.permission_name = 'jobs.manage' THEN
        RAISE EXCEPTION 'background job command RBAC catalog row is immutable'
            USING ERRCODE = 'P9403';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER background_job_command_rbac_catalog_delete_guard_094
BEFORE DELETE ON custom_rbac_permission_catalog
FOR EACH ROW EXECUTE FUNCTION protect_background_job_command_catalog_094();
ALTER TABLE custom_rbac_permission_catalog
    ENABLE ALWAYS TRIGGER background_job_command_rbac_catalog_delete_guard_094;

ALTER TABLE dns_reconcile_cancel_facts
    ADD COLUMN job_transition_xact_id xid8;
ALTER TABLE dns_reconcile_provider_recovery_continuations
    ADD COLUMN job_transition_xact_id xid8;

CREATE FUNCTION mark_dns_reconcile_job_transition_source_094()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.job_transition_xact_id IS NOT NULL THEN
            RAISE EXCEPTION 'DNS reconcile job transition identity is database managed'
                USING ERRCODE = 'P9402';
        END IF;
        NEW.job_transition_xact_id := pg_current_xact_id();
        RETURN NEW;
    END IF;
    IF NEW.job_transition_xact_id IS DISTINCT FROM OLD.job_transition_xact_id THEN
        RAISE EXCEPTION 'DNS reconcile job transition identity is immutable'
            USING ERRCODE = 'P9402';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER a_dns_reconcile_cancel_facts_transition_094
BEFORE INSERT OR UPDATE ON dns_reconcile_cancel_facts
FOR EACH ROW EXECUTE FUNCTION mark_dns_reconcile_job_transition_source_094();
CREATE TRIGGER a_dns_reconcile_provider_recovery_transition_094
BEFORE INSERT OR UPDATE ON dns_reconcile_provider_recovery_continuations
FOR EACH ROW EXECUTE FUNCTION mark_dns_reconcile_job_transition_source_094();

ALTER TABLE background_jobs
    ADD COLUMN job_command_operation text,
    ADD COLUMN job_command_xact_id xid8,
    ADD CONSTRAINT background_jobs_job_command_marker_094 CHECK (
        (job_command_operation IS NULL AND job_command_xact_id IS NULL) OR
        (job_command_operation IN ('cancel','retry','dns_cancel','dns_recovery') AND
         job_command_xact_id IS NOT NULL)
    );

CREATE FUNCTION dns_reconcile_background_job_cancel_094(
    previous_job background_jobs,
    cancelled_job background_jobs
)
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL UNSAFE
AS $$
    SELECT previous_job.kind='dns_reconcile' AND
        previous_job.state IN ('queued','running') AND
        previous_job.cancel_requested_at IS NULL AND cancelled_job.state='cancelled' AND
        cancelled_job.attempt=previous_job.attempt AND
        cancelled_job.max_attempts=previous_job.max_attempts AND
        cancelled_job.total_count=previous_job.total_count AND
        cancelled_job.completed_count=previous_job.total_count AND
        cancelled_job.succeeded_count=previous_job.succeeded_count AND
        cancelled_job.failed_count=previous_job.failed_count AND
        cancelled_job.cancelled_count=previous_job.cancelled_count+
            (previous_job.total_count-previous_job.completed_count) AND
        cancelled_job.lease_id IS NULL AND cancelled_job.lease_owner IS NULL AND
        cancelled_job.lease_expires_at IS NULL AND cancelled_job.claimable_at IS NULL AND
        cancelled_job.last_error_code='cancelled' AND cancelled_job.completed_at IS NOT NULL AND
        cancelled_job.cancel_requested_at=cancelled_job.completed_at AND
        cancelled_job.updated_at=cancelled_job.completed_at AND
        ROW(cancelled_job.id,cancelled_job.tenant_id,cancelled_job.kind,cancelled_job.subject,
            cancelled_job.idempotency_key,cancelled_job.request_digest,cancelled_job.request_id,
            cancelled_job.trace_id,cancelled_job.created_at,cancelled_job.started_at)
        IS NOT DISTINCT FROM
        ROW(previous_job.id,previous_job.tenant_id,previous_job.kind,previous_job.subject,
            previous_job.idempotency_key,previous_job.request_digest,previous_job.request_id,
            previous_job.trace_id,previous_job.created_at,previous_job.started_at) AND EXISTS (
            SELECT 1
            FROM dns_reconcile_cancel_facts fact
            JOIN dns_reconcile_tasks task
              ON task.tenant_id=fact.tenant_id AND task.job_id=fact.job_id
            JOIN dns_reconcile_task_events event
              ON event.tenant_id=fact.tenant_id AND event.job_id=fact.job_id
             AND event.event_sequence=fact.event_sequence
            WHERE fact.tenant_id=previous_job.tenant_id AND fact.job_id=previous_job.id
              AND fact.job_transition_xact_id=pg_current_xact_id()
              AND fact.site_id=task.site_id
              AND fact.expected_task_revision=fact.event_sequence
              AND event.source='control' AND event.status='cancelled'
              AND event.error_class='cancelled' AND event.error_code='cancelled'
              AND event.occurred_at=fact.created_at
              AND cancelled_job.cancel_requested_at=fact.created_at
              AND NOT EXISTS (
                  SELECT 1 FROM dns_reconcile_task_events later
                  WHERE later.tenant_id=fact.tenant_id AND later.job_id=fact.job_id
                    AND later.event_sequence>fact.event_sequence
              )
        )
$$;

CREATE FUNCTION mark_background_job_command_mutation_094()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    command_operation text;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.job_command_operation IS NOT NULL OR NEW.job_command_xact_id IS NOT NULL THEN
            RAISE EXCEPTION 'background job command markers are database managed'
                USING ERRCODE = 'P9402';
        END IF;
        RETURN NEW;
    END IF;

    IF ROW(NEW.job_command_operation,NEW.job_command_xact_id) IS DISTINCT FROM
       ROW(OLD.job_command_operation,OLD.job_command_xact_id) THEN
        RAISE EXCEPTION 'background job command markers are database managed'
            USING ERRCODE = 'P9402';
    END IF;

    IF OLD.state IN ('queued','running') AND NEW.state = 'cancelled' THEN
        IF dns_reconcile_background_job_cancel_094(OLD,NEW) THEN
            command_operation := 'dns_cancel';
        ELSE
            command_operation := 'cancel';
        END IF;
    ELSIF OLD.state IN ('failed','partial_failed') AND NEW.state = 'queued' THEN
        IF dns_reconcile_background_job_recovery_retry_089(OLD,NEW) AND EXISTS (
            SELECT 1 FROM dns_reconcile_provider_recovery_continuations continuation
            WHERE continuation.tenant_id=OLD.tenant_id AND continuation.job_id=OLD.id
              AND continuation.consumed_at IS NULL
              AND continuation.job_transition_xact_id=pg_current_xact_id()
        ) THEN
            command_operation := 'dns_recovery';
        ELSE
            command_operation := 'retry';
        END IF;
    END IF;
    IF command_operation IS NOT NULL THEN
        IF OLD.job_command_xact_id = pg_current_xact_id() THEN
            RAISE EXCEPTION 'background job already has a command mutation in this transaction'
                USING ERRCODE = 'P9402';
        END IF;
        NEW.job_command_operation := command_operation;
        NEW.job_command_xact_id := pg_current_xact_id();
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER background_jobs_mark_command_mutation_094
BEFORE INSERT OR UPDATE ON background_jobs
FOR EACH ROW EXECUTE FUNCTION mark_background_job_command_mutation_094();

CREATE TABLE background_job_command_receipts (
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK (
        idempotency_key ~ '^[A-Za-z0-9._-]{1,128}$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    audience text NOT NULL CHECK (audience IN ('tenant','platform')),
    tenant_id uuid NOT NULL,
    job_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation IN ('cancel','retry')),
    job_command_xact_id xid8 NOT NULL DEFAULT pg_current_xact_id(),
    request_id text NOT NULL CHECK (
        char_length(request_id) BETWEEN 1 AND 128 AND request_id = btrim(request_id) AND
        request_id !~ '[[:cntrl:]]' AND
        position(U&'\2028' in request_id) = 0 AND position(U&'\2029' in request_id) = 0
    ),
    audit_event_id uuid NOT NULL UNIQUE,
    result_kind text NOT NULL,
    result_subject text NOT NULL,
    result_request_id text NOT NULL,
    result_trace_id text NOT NULL,
    result_state text NOT NULL CHECK (result_state IN ('queued','cancelled')),
    result_attempt integer NOT NULL CHECK (result_attempt >= 0),
    result_max_attempts integer NOT NULL CHECK (
        result_max_attempts BETWEEN 1 AND 1001 AND result_attempt <= result_max_attempts
    ),
    result_total_count integer NOT NULL CHECK (result_total_count > 0),
    result_completed_count integer NOT NULL CHECK (
        result_completed_count BETWEEN 0 AND result_total_count
    ),
    result_succeeded_count integer NOT NULL CHECK (result_succeeded_count >= 0),
    result_failed_count integer NOT NULL CHECK (result_failed_count >= 0),
    result_cancelled_count integer NOT NULL CHECK (result_cancelled_count >= 0),
    result_failure_code text,
    result_created_at timestamptz NOT NULL,
    result_started_at timestamptz,
    result_updated_at timestamptz NOT NULL,
    result_completed_at timestamptz,
    created_at timestamptz NOT NULL,
    completed_at timestamptz NOT NULL,
    UNIQUE (actor_scope_id, actor_user_id, idempotency_key),
    UNIQUE (tenant_id, job_id, job_command_xact_id),
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, job_id)
        REFERENCES background_jobs(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (audit_event_id) REFERENCES audit_events(id) ON DELETE RESTRICT,
    CHECK (
        result_completed_count = result_succeeded_count + result_failed_count + result_cancelled_count
    ),
    CHECK (
        (operation = 'cancel' AND result_state = 'cancelled' AND
         result_completed_count = result_total_count AND result_failure_code = 'cancelled' AND
         result_completed_at IS NOT NULL) OR
        (operation = 'retry' AND result_state = 'queued' AND result_attempt > 0 AND
         result_completed_count = result_succeeded_count AND result_failed_count = 0 AND
         result_cancelled_count = 0 AND result_failure_code IS NULL AND result_completed_at IS NULL)
    ),
    CHECK (
        isfinite(result_created_at) AND isfinite(result_updated_at) AND
        result_updated_at >= result_created_at AND
        (result_started_at IS NULL OR isfinite(result_started_at)) AND
        (result_completed_at IS NULL OR isfinite(result_completed_at)) AND
        isfinite(created_at) AND isfinite(completed_at) AND completed_at >= created_at
    )
);

CREATE FUNCTION validate_background_job_command_receipt_094()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    audit_row audit_events%ROWTYPE;
    job_row background_jobs%ROWTYPE;
    actor_scope_kind text;
    actor_scope_tenant uuid;
    result_payload jsonb;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'background job command receipts are append-only'
            USING ERRCODE = 'P9402';
    END IF;
    IF NEW.job_command_xact_id IS DISTINCT FROM pg_current_xact_id() THEN
        RAISE EXCEPTION 'invalid background job command receipt transaction'
            USING ERRCODE = 'P9402';
    END IF;
    IF TG_WHEN = 'BEFORE' AND EXISTS (
        SELECT 1 FROM background_job_command_receipts receipt
        WHERE receipt.tenant_id=NEW.tenant_id AND receipt.job_id=NEW.job_id
          AND receipt.job_command_xact_id=NEW.job_command_xact_id
    ) THEN
        RAISE EXCEPTION 'background job command mutation already has a receipt'
            USING ERRCODE = 'P9402';
    END IF;
    SELECT kind,tenant_id INTO actor_scope_kind,actor_scope_tenant
    FROM access_scopes WHERE id=NEW.actor_scope_id FOR SHARE;
    IF NOT FOUND OR
       (NEW.audience = 'tenant' AND
        (actor_scope_kind <> 'tenant' OR actor_scope_tenant IS DISTINCT FROM NEW.tenant_id)) OR
       (NEW.audience = 'platform' AND
        (actor_scope_kind <> 'platform' OR actor_scope_tenant IS NOT NULL)) THEN
        RAISE EXCEPTION 'invalid background job command actor scope'
            USING ERRCODE = 'P9402';
    END IF;

    SELECT * INTO audit_row FROM audit_events WHERE id=NEW.audit_event_id FOR SHARE;
    SELECT * INTO job_row FROM background_jobs
    WHERE tenant_id=NEW.tenant_id AND id=NEW.job_id FOR SHARE;
    IF NOT FOUND OR audit_row.id IS NULL OR
       audit_row.scope_id IS DISTINCT FROM NEW.actor_scope_id OR
       audit_row.actor_user_id IS DISTINCT FROM NEW.actor_user_id OR
       audit_row.action IS DISTINCT FROM 'job.'||NEW.operation OR
       audit_row.resource_type IS DISTINCT FROM 'background_job' OR
       audit_row.resource_id IS DISTINCT FROM NEW.job_id::text OR
       audit_row.request_id IS DISTINCT FROM NEW.request_id OR
       audit_row.result IS DISTINCT FROM 'success' OR
       job_row.job_command_operation IS DISTINCT FROM NEW.operation OR
       job_row.job_command_xact_id IS DISTINCT FROM NEW.job_command_xact_id OR
       ROW(job_row.kind,job_row.subject,job_row.request_id,job_row.trace_id,
           job_row.state,job_row.attempt,job_row.max_attempts,
           job_row.total_count,job_row.completed_count,job_row.succeeded_count,
           job_row.failed_count,job_row.cancelled_count,job_row.last_error_code,
           job_row.created_at,job_row.started_at,job_row.updated_at,job_row.completed_at)
       IS DISTINCT FROM
       ROW(NEW.result_kind,NEW.result_subject,NEW.result_request_id,NEW.result_trace_id,
           NEW.result_state,NEW.result_attempt,NEW.result_max_attempts,
           NEW.result_total_count,NEW.result_completed_count,NEW.result_succeeded_count,
           NEW.result_failed_count,NEW.result_cancelled_count,NEW.result_failure_code,
           NEW.result_created_at,NEW.result_started_at,NEW.result_updated_at,NEW.result_completed_at) OR
       NEW.created_at IS DISTINCT FROM NEW.result_updated_at OR
       audit_row.occurred_at < NEW.created_at THEN
        RAISE EXCEPTION 'invalid background job command receipt binding'
            USING ERRCODE = 'P9402';
    END IF;

    BEGIN
        result_payload := audit_row.payload->'result_data';
        IF audit_row.payload - ARRAY[
               'audience','operation','idempotency_key','request_digest','tenant_id','result_data'
           ] <> '{}'::jsonb OR
           NOT (audit_row.payload ?& ARRAY[
               'audience','operation','idempotency_key','request_digest','tenant_id','result_data'
           ]) OR
           audit_row.payload->>'audience' IS DISTINCT FROM NEW.audience OR
           audit_row.payload->>'operation' IS DISTINCT FROM NEW.operation OR
           audit_row.payload->>'idempotency_key' IS DISTINCT FROM NEW.idempotency_key OR
           audit_row.payload->>'request_digest' IS DISTINCT FROM encode(NEW.request_digest,'hex') OR
           audit_row.payload->>'tenant_id' IS DISTINCT FROM NEW.tenant_id::text OR
           jsonb_typeof(result_payload) IS DISTINCT FROM 'object' OR
           result_payload - ARRAY[
               'task_id','tenant_id','kind','subject','request_id','trace_id','state','attempt',
               'max_attempts','total_count','completed_count','succeeded_count','failed_count',
               'cancelled_count','failure_code','created_at','started_at','updated_at','completed_at'
           ] <> '{}'::jsonb OR
           NOT (result_payload ?& ARRAY[
               'task_id','tenant_id','kind','subject','request_id','trace_id','state','attempt',
               'max_attempts','total_count','completed_count','succeeded_count','failed_count',
               'cancelled_count','failure_code','created_at','started_at','updated_at','completed_at'
           ]) OR
           result_payload->>'task_id' IS DISTINCT FROM NEW.job_id::text OR
           result_payload->>'tenant_id' IS DISTINCT FROM NEW.tenant_id::text OR
           result_payload->>'kind' IS DISTINCT FROM NEW.result_kind OR
           result_payload->>'subject' IS DISTINCT FROM NEW.result_subject OR
           result_payload->>'request_id' IS DISTINCT FROM NEW.result_request_id OR
           result_payload->>'trace_id' IS DISTINCT FROM NEW.result_trace_id OR
           result_payload->>'state' IS DISTINCT FROM NEW.result_state OR
           (result_payload->>'attempt')::integer IS DISTINCT FROM NEW.result_attempt OR
           (result_payload->>'max_attempts')::integer IS DISTINCT FROM NEW.result_max_attempts OR
           (result_payload->>'total_count')::integer IS DISTINCT FROM NEW.result_total_count OR
           (result_payload->>'completed_count')::integer IS DISTINCT FROM NEW.result_completed_count OR
           (result_payload->>'succeeded_count')::integer IS DISTINCT FROM NEW.result_succeeded_count OR
           (result_payload->>'failed_count')::integer IS DISTINCT FROM NEW.result_failed_count OR
           (result_payload->>'cancelled_count')::integer IS DISTINCT FROM NEW.result_cancelled_count OR
           NULLIF(result_payload->>'failure_code','') IS DISTINCT FROM NEW.result_failure_code OR
           (result_payload->>'created_at')::timestamptz IS DISTINCT FROM NEW.result_created_at OR
           NULLIF(result_payload->>'started_at','')::timestamptz
               IS DISTINCT FROM NEW.result_started_at OR
           (result_payload->>'updated_at')::timestamptz IS DISTINCT FROM NEW.result_updated_at OR
           NULLIF(result_payload->>'completed_at','')::timestamptz
               IS DISTINCT FROM NEW.result_completed_at THEN
            RAISE EXCEPTION 'invalid background job command audit payload'
                USING ERRCODE = 'P9402';
        END IF;
    EXCEPTION
        WHEN SQLSTATE 'P9402' THEN RAISE;
        WHEN OTHERS THEN
            RAISE EXCEPTION 'invalid background job command audit payload'
                USING ERRCODE = 'P9402';
    END;
    RETURN NEW;
END;
$$;

CREATE TRIGGER background_job_command_receipts_validate_094
BEFORE INSERT ON background_job_command_receipts
FOR EACH ROW EXECUTE FUNCTION validate_background_job_command_receipt_094();
CREATE CONSTRAINT TRIGGER background_job_command_receipts_final_094
AFTER INSERT ON background_job_command_receipts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_background_job_command_receipt_094();
CREATE TRIGGER background_job_command_receipts_immutable_094
BEFORE UPDATE OR DELETE OR TRUNCATE ON background_job_command_receipts
FOR EACH STATEMENT EXECUTE FUNCTION validate_background_job_command_receipt_094();

CREATE FUNCTION dns_reconcile_cancel_final_094(cancelled_job background_jobs)
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL UNSAFE
AS $$
    SELECT cancelled_job.kind='dns_reconcile' AND cancelled_job.state='cancelled' AND
        cancelled_job.job_command_operation='dns_cancel' AND
        cancelled_job.job_command_xact_id=pg_current_xact_id() AND
        cancelled_job.cancel_requested_at IS NOT NULL AND
        cancelled_job.cancel_requested_at=cancelled_job.completed_at AND
        cancelled_job.cancel_requested_at=cancelled_job.updated_at AND
        cancelled_job.lease_id IS NULL AND cancelled_job.lease_owner IS NULL AND
        cancelled_job.lease_expires_at IS NULL AND cancelled_job.claimable_at IS NULL AND
        cancelled_job.last_error_code='cancelled' AND EXISTS (
            SELECT 1
            FROM dns_reconcile_cancel_facts fact
            JOIN dns_reconcile_tasks task
              ON task.tenant_id=fact.tenant_id AND task.job_id=fact.job_id
            JOIN dns_reconcile_task_events event
              ON event.tenant_id=fact.tenant_id AND event.job_id=fact.job_id
             AND event.event_sequence=fact.event_sequence
            WHERE fact.tenant_id=cancelled_job.tenant_id AND fact.job_id=cancelled_job.id
              AND fact.job_transition_xact_id=cancelled_job.job_command_xact_id
              AND fact.site_id=task.site_id
              AND fact.expected_task_revision=fact.event_sequence
              AND event.source='control' AND event.status='cancelled'
              AND event.error_class='cancelled' AND event.error_code='cancelled'
              AND event.occurred_at=fact.created_at
              AND cancelled_job.cancel_requested_at=fact.created_at
              AND NOT EXISTS (
                  SELECT 1 FROM dns_reconcile_task_events later
                  WHERE later.tenant_id=fact.tenant_id AND later.job_id=fact.job_id
                    AND later.event_sequence>fact.event_sequence
              )
        ) AND EXISTS (
            SELECT 1
            FROM (
                SELECT count(*)::integer AS total,
                    count(*) FILTER (WHERE state='succeeded')::integer AS succeeded,
                    count(*) FILTER (WHERE state='failed')::integer AS failed,
                    count(*) FILTER (WHERE state='cancelled')::integer AS cancelled,
                    count(*) FILTER (WHERE state='pending')::integer AS pending
                FROM background_job_items item
                WHERE item.tenant_id=cancelled_job.tenant_id AND item.job_id=cancelled_job.id
            ) items
            WHERE items.pending=0 AND cancelled_job.total_count=items.total
              AND cancelled_job.completed_count=items.total
              AND cancelled_job.succeeded_count=items.succeeded
              AND cancelled_job.failed_count=items.failed
              AND cancelled_job.cancelled_count=items.cancelled
        )
$$;

CREATE FUNCTION dns_reconcile_provider_recovery_final_094(recovery_job background_jobs)
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL UNSAFE
AS $$
    SELECT recovery_job.kind='dns_reconcile' AND recovery_job.state='queued' AND
        recovery_job.job_command_operation='dns_recovery' AND
        recovery_job.job_command_xact_id=pg_current_xact_id() AND
        recovery_job.lease_id IS NULL AND recovery_job.lease_owner IS NULL AND
        recovery_job.lease_expires_at IS NULL AND recovery_job.claimable_at IS NOT NULL AND
        recovery_job.completed_count=recovery_job.succeeded_count AND
        recovery_job.failed_count=0 AND recovery_job.cancelled_count=0 AND
        recovery_job.last_error_code IS NULL AND recovery_job.completed_at IS NULL AND EXISTS (
            SELECT 1
            FROM dns_reconcile_provider_recovery_continuations continuation
            JOIN background_job_items item
              ON item.tenant_id=continuation.tenant_id AND item.job_id=continuation.job_id
             AND item.item_id='reconcile'
            JOIN dns_reconcile_task_events event
              ON event.tenant_id=continuation.tenant_id AND event.job_id=continuation.job_id
             AND event.event_sequence=continuation.recovery_event_sequence
            WHERE continuation.tenant_id=recovery_job.tenant_id
              AND continuation.job_id=recovery_job.id
              AND continuation.job_transition_xact_id=recovery_job.job_command_xact_id
              AND continuation.consumed_at IS NOT NULL
              AND continuation.continuation_attempt=recovery_job.max_attempts
              AND recovery_job.attempt=continuation.continuation_attempt-1
              AND continuation.granted_at=recovery_job.claimable_at
              AND continuation.granted_at=recovery_job.updated_at
              AND item.state='pending'
              AND item.attempt=continuation.previous_item_attempt
              AND item.sequence=continuation.previous_item_sequence
              AND continuation.recovery_event_sequence=continuation.event_sequence+1
              AND event.source='control' AND event.status='applying'
              AND event.error_class='' AND event.error_code IS NULL
              AND sha256(convert_to(event.result_snapshot::text,'UTF8'))=
                  continuation.recovery_result_digest
              AND NOT EXISTS (
                  SELECT 1 FROM dns_reconcile_task_events later
                  WHERE later.tenant_id=continuation.tenant_id
                    AND later.job_id=continuation.job_id
                    AND later.event_sequence>continuation.recovery_event_sequence
              )
        )
$$;

CREATE FUNCTION dns_reconcile_background_job_recovery_final_094(
    previous_job background_jobs,
    recovery_job background_jobs
)
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL UNSAFE
AS $$
    SELECT previous_job.kind='dns_reconcile' AND
        previous_job.state IN ('failed','partial_failed') AND
        previous_job.attempt=previous_job.max_attempts AND previous_job.attempt>=1 AND
        previous_job.cancel_requested_at IS NULL AND
        recovery_job.attempt=previous_job.attempt AND
        recovery_job.max_attempts=previous_job.max_attempts+1 AND
        recovery_job.completed_count=previous_job.succeeded_count AND
        recovery_job.succeeded_count=previous_job.succeeded_count AND
        ROW(recovery_job.id,recovery_job.tenant_id,recovery_job.kind,recovery_job.subject,
            recovery_job.idempotency_key,recovery_job.request_digest,recovery_job.request_id,
            recovery_job.trace_id,recovery_job.cancel_requested_at,recovery_job.total_count,
            recovery_job.created_at,recovery_job.started_at)
        IS NOT DISTINCT FROM
        ROW(previous_job.id,previous_job.tenant_id,previous_job.kind,previous_job.subject,
            previous_job.idempotency_key,previous_job.request_digest,previous_job.request_id,
            previous_job.trace_id,previous_job.cancel_requested_at,previous_job.total_count,
            previous_job.created_at,previous_job.started_at) AND
        dns_reconcile_provider_recovery_final_094(recovery_job)
$$;

CREATE FUNCTION validate_dns_reconcile_cancel_transition_094()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    job_row background_jobs%ROWTYPE;
BEGIN
    SELECT * INTO job_row FROM background_jobs
    WHERE tenant_id=NEW.tenant_id AND id=NEW.job_id FOR SHARE;
    IF NOT FOUND OR NEW.job_transition_xact_id IS NULL OR
       NEW.job_transition_xact_id IS DISTINCT FROM pg_current_xact_id() OR
       job_row.job_command_xact_id IS DISTINCT FROM NEW.job_transition_xact_id OR
       NOT dns_reconcile_cancel_final_094(job_row) THEN
        RAISE EXCEPTION 'invalid DNS reconcile cancel job transition'
            USING ERRCODE = 'P9402';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER dns_reconcile_cancel_transition_final_094
AFTER INSERT ON dns_reconcile_cancel_facts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_dns_reconcile_cancel_transition_094();

CREATE FUNCTION validate_dns_reconcile_provider_recovery_transition_094()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    job_row background_jobs%ROWTYPE;
BEGIN
    SELECT * INTO job_row FROM background_jobs
    WHERE tenant_id=NEW.tenant_id AND id=NEW.job_id FOR SHARE;
    IF NOT FOUND OR NEW.job_transition_xact_id IS NULL OR
       NEW.job_transition_xact_id IS DISTINCT FROM pg_current_xact_id() OR
       job_row.job_command_xact_id IS DISTINCT FROM NEW.job_transition_xact_id OR
       NOT dns_reconcile_provider_recovery_final_094(job_row) THEN
        RAISE EXCEPTION 'invalid DNS reconcile provider recovery job transition'
            USING ERRCODE = 'P9402';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER dns_reconcile_provider_recovery_transition_final_094
AFTER INSERT ON dns_reconcile_provider_recovery_continuations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_dns_reconcile_provider_recovery_transition_094();

CREATE FUNCTION validate_background_job_command_mutation_094()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    job_row background_jobs%ROWTYPE;
    receipt_row background_job_command_receipts%ROWTYPE;
    audit_row audit_events%ROWTYPE;
    receipt_count integer;
BEGIN
    SELECT * INTO job_row FROM background_jobs
    WHERE id=NEW.id FOR SHARE;
    IF NOT FOUND OR job_row.tenant_id IS DISTINCT FROM NEW.tenant_id THEN
        RAISE EXCEPTION 'invalid background job command mutation identity'
            USING ERRCODE = 'P9402';
    END IF;
    IF job_row.job_command_xact_id IS DISTINCT FROM pg_current_xact_id() THEN
        RETURN NULL;
    END IF;

    IF job_row.job_command_operation='dns_cancel' THEN
        IF NOT dns_reconcile_background_job_cancel_094(OLD,job_row) OR
           NOT dns_reconcile_cancel_final_094(job_row) THEN
            RAISE EXCEPTION 'invalid DNS reconcile cancel job mutation final state'
                USING ERRCODE = 'P9402';
        END IF;
        RETURN NULL;
    ELSIF job_row.job_command_operation='dns_recovery' THEN
        IF NOT dns_reconcile_background_job_recovery_final_094(OLD,job_row) THEN
            RAISE EXCEPTION 'invalid DNS reconcile recovery job mutation final state'
                USING ERRCODE = 'P9402';
        END IF;
        RETURN NULL;
    END IF;

    SELECT count(*) INTO receipt_count
    FROM background_job_command_receipts receipt
    WHERE receipt.tenant_id=job_row.tenant_id AND receipt.job_id=job_row.id
      AND receipt.job_command_xact_id=job_row.job_command_xact_id;
    IF receipt_count <> 1 THEN
        RAISE EXCEPTION 'background job command mutation requires exactly one receipt'
            USING ERRCODE = 'P9402';
    END IF;
    SELECT * INTO receipt_row FROM background_job_command_receipts receipt
    WHERE receipt.tenant_id=job_row.tenant_id AND receipt.job_id=job_row.id
      AND receipt.job_command_xact_id=job_row.job_command_xact_id;
    SELECT * INTO audit_row FROM audit_events WHERE id=receipt_row.audit_event_id FOR SHARE;

    IF audit_row.id IS NULL OR
       receipt_row.operation IS DISTINCT FROM job_row.job_command_operation OR
       audit_row.scope_id IS DISTINCT FROM receipt_row.actor_scope_id OR
       audit_row.actor_user_id IS DISTINCT FROM receipt_row.actor_user_id OR
       audit_row.action IS DISTINCT FROM 'job.'||receipt_row.operation OR
       audit_row.resource_type IS DISTINCT FROM 'background_job' OR
       audit_row.resource_id IS DISTINCT FROM job_row.id::text OR
       audit_row.request_id IS DISTINCT FROM receipt_row.request_id OR
       audit_row.result IS DISTINCT FROM 'success' OR
       ROW(job_row.kind,job_row.subject,job_row.request_id,job_row.trace_id,
           job_row.state,job_row.attempt,job_row.max_attempts,
           job_row.total_count,job_row.completed_count,job_row.succeeded_count,
           job_row.failed_count,job_row.cancelled_count,job_row.last_error_code,
           job_row.created_at,job_row.started_at,job_row.updated_at,job_row.completed_at)
       IS DISTINCT FROM
       ROW(receipt_row.result_kind,receipt_row.result_subject,
           receipt_row.result_request_id,receipt_row.result_trace_id,
           receipt_row.result_state,receipt_row.result_attempt,receipt_row.result_max_attempts,
           receipt_row.result_total_count,receipt_row.result_completed_count,
           receipt_row.result_succeeded_count,receipt_row.result_failed_count,
           receipt_row.result_cancelled_count,receipt_row.result_failure_code,
           receipt_row.result_created_at,receipt_row.result_started_at,
           receipt_row.result_updated_at,receipt_row.result_completed_at) OR
       receipt_row.created_at IS DISTINCT FROM receipt_row.result_updated_at OR
       audit_row.occurred_at < receipt_row.created_at THEN
        RAISE EXCEPTION 'invalid background job command mutation final state'
            USING ERRCODE = 'P9402';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER background_jobs_command_receipt_final_094
AFTER UPDATE ON background_jobs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_background_job_command_mutation_094();

CREATE FUNCTION validate_background_job_command_success_audit_094()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.result = 'success' AND NEW.action IN ('job.cancel','job.retry') AND
       NOT EXISTS (
           SELECT 1 FROM background_job_command_receipts receipt
           WHERE receipt.audit_event_id=NEW.id
       ) THEN
        RAISE EXCEPTION 'successful background job command audit has no receipt'
            USING ERRCODE = 'P9402';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER audit_events_job_command_success_receipt_094
AFTER INSERT ON audit_events
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_background_job_command_success_audit_094();

CREATE UNIQUE INDEX audit_events_job_command_denied_identity_094
ON audit_events(scope_id,actor_user_id,action,request_id)
WHERE result='denied'
  AND actor_user_id IS NOT NULL
  AND action IN ('job.cancel','job.retry');

CREATE FUNCTION prevent_background_job_command_audit_truncate_094()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'job command audit events cannot be truncated'
        USING ERRCODE = 'P9402';
END;
$$;

CREATE TRIGGER audit_events_job_command_no_truncate_094
BEFORE TRUNCATE ON audit_events
FOR EACH STATEMENT EXECUTE FUNCTION prevent_background_job_command_audit_truncate_094();

REVOKE ALL ON background_job_command_receipts FROM PUBLIC;
REVOKE ALL ON background_job_command_rbac_catalog_additions_094 FROM PUBLIC;
REVOKE ALL ON background_job_command_rbac_grant_additions_094 FROM PUBLIC;
REVOKE ALL ON FUNCTION project_background_job_command_permissions_094() FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_background_job_command_rbac_provenance_094() FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_background_job_command_catalog_094() FROM PUBLIC;
REVOKE ALL ON FUNCTION mark_dns_reconcile_job_transition_source_094() FROM PUBLIC;
REVOKE ALL ON FUNCTION dns_reconcile_background_job_cancel_094(background_jobs,background_jobs) FROM PUBLIC;
REVOKE ALL ON FUNCTION mark_background_job_command_mutation_094() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_background_job_command_receipt_094() FROM PUBLIC;
REVOKE ALL ON FUNCTION dns_reconcile_cancel_final_094(background_jobs) FROM PUBLIC;
REVOKE ALL ON FUNCTION dns_reconcile_provider_recovery_final_094(background_jobs) FROM PUBLIC;
REVOKE ALL ON FUNCTION dns_reconcile_background_job_recovery_final_094(background_jobs,background_jobs) FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_dns_reconcile_cancel_transition_094() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_dns_reconcile_provider_recovery_transition_094() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_background_job_command_mutation_094() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_background_job_command_success_audit_094() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_background_job_command_audit_truncate_094() FROM PUBLIC;
