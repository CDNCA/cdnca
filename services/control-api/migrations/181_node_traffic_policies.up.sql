LOCK TABLE schema_migrations,nodes,node_config_state,config_versions,rollouts IN ACCESS EXCLUSIVE MODE;

DO $migration_181$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>180 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>180 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=180 AND migration_id='180_node_gateway_port_transitions' AND
              checksum_sha256='a3dd89eeeaa2179ececeb7556e5f242b1d1c93a088eb7a0f645fe6c15e5441a5' AND
              down_checksum_sha256='40c7f635b3d09901355484667f7738947a68f50bb141f5401f5789733819916d' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass(current_schema() || '.node_traffic_policies') IS NOT NULL OR
         to_regclass(current_schema() || '.node_traffic_policy_operations') IS NOT NULL OR
         to_regclass(current_schema() || '.node_traffic_policy_evaluations') IS NOT NULL OR
         to_regclass(current_schema() || '.node_traffic_sync_tasks') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 181 requires the exact verified 180 release head and an untouched node traffic policy schema'
            USING ERRCODE='P1810';
    END IF;
END;
$migration_181$;

CREATE TABLE node_traffic_policies (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    monthly_limit_bytes bigint NOT NULL CHECK (monthly_limit_bytes>=0),
    timezone text NOT NULL CHECK (timezone=btrim(timezone) AND char_length(timezone) BETWEEN 1 AND 128),
    windows jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (
        jsonb_typeof(windows)='array' AND jsonb_array_length(windows)<=32
    ),
    override_mode text NOT NULL CHECK (override_mode IN ('none','force_enabled','force_disabled')),
    override_revision bigint NOT NULL CHECK (override_revision>=0),
    override_expires_at timestamptz,
    revision bigint NOT NULL CHECK (revision>0),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    next_evaluation_at timestamptz NOT NULL,
    last_evaluation_error text CHECK (
        last_evaluation_error IS NULL OR last_evaluation_error ~ '^[a-z0-9_]{1,64}$'
    ),
    CHECK (updated_at>=created_at),
    CHECK (
        (override_mode='none' AND override_expires_at IS NULL) OR
        (override_mode IN ('force_enabled','force_disabled') AND override_revision>0 AND override_expires_at IS NOT NULL)
    ),
    UNIQUE (scope_id,node_id),
    UNIQUE (scope_id,node_id,revision),
    FOREIGN KEY (scope_id,node_id) REFERENCES nodes(scope_id,id) ON DELETE RESTRICT
);

CREATE INDEX node_traffic_policies_due_181_idx
    ON node_traffic_policies(next_evaluation_at,scope_id,node_id);

CREATE TABLE node_traffic_policy_operations (
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    operation text NOT NULL CHECK (operation IN ('put','evaluate')),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
    actor_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    response jsonb NOT NULL CHECK (jsonb_typeof(response)='object'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (scope_id,idempotency_key),
    CHECK ((operation='put' AND actor_user_id IS NOT NULL) OR operation='evaluate')
);

CREATE TABLE node_traffic_policy_evaluations (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL,
    node_id uuid NOT NULL,
    policy_revision bigint NOT NULL CHECK (policy_revision>0),
    period_key text NOT NULL CHECK (period_key ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL,
    usage_bytes bigint NOT NULL CHECK (usage_bytes>=0),
    monthly_limit_bytes bigint NOT NULL CHECK (monthly_limit_bytes>=0),
    suppressed boolean NOT NULL,
    sync_required boolean NOT NULL,
    reason_code text NOT NULL CHECK (reason_code IN (
        'within_policy','monthly_limit_reached','scheduled_window','manual_force_enabled',
        'manual_force_disabled','admin_state_protected','period_reset','policy_recovered'
    )),
    override_revision bigint NOT NULL CHECK (override_revision>=0),
    evaluated_at timestamptz NOT NULL,
    source_snapshot_at timestamptz NOT NULL,
    source_finalized_through timestamptz NOT NULL,
    source_digest bytea NOT NULL CHECK (octet_length(source_digest)=32),
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    CHECK (period_end>period_start),
    CHECK (source_finalized_through<=source_snapshot_at AND source_snapshot_at<=evaluated_at),
    CHECK ((reason_code IN ('manual_force_enabled','manual_force_disabled'))=(override_revision>0)),
    CHECK (
        (suppressed AND reason_code IN ('monthly_limit_reached','scheduled_window','manual_force_disabled','admin_state_protected')) OR
        (NOT suppressed AND reason_code IN ('within_policy','manual_force_enabled','period_reset','policy_recovered'))
    ),
    UNIQUE (id,scope_id,node_id),
    FOREIGN KEY (scope_id,node_id) REFERENCES node_traffic_policies(scope_id,node_id) ON DELETE RESTRICT
);

CREATE INDEX node_traffic_policy_evaluations_latest_181_idx
    ON node_traffic_policy_evaluations(scope_id,node_id,evaluated_at DESC,id DESC);

CREATE TABLE node_traffic_sync_tasks (
    id uuid PRIMARY KEY,
    evaluation_id uuid NOT NULL UNIQUE,
    scope_id uuid NOT NULL,
    node_id uuid NOT NULL,
    config_version_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('queued','running','succeeded','failed')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
    available_at timestamptz NOT NULL,
    error_code text CHECK (error_code IS NULL OR error_code ~ '^[a-z0-9_]{1,128}$'),
    rollout_id uuid,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (updated_at>=created_at),
    CHECK ((status='failed')=(error_code IS NOT NULL)),
    CHECK (status<>'succeeded' OR rollout_id IS NOT NULL),
    CHECK (status<>'queued' OR rollout_id IS NULL),
    FOREIGN KEY (evaluation_id,scope_id,node_id)
        REFERENCES node_traffic_policy_evaluations(id,scope_id,node_id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id,node_id) REFERENCES nodes(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id,config_version_id)
        REFERENCES config_versions(configuration_scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id,rollout_id)
        REFERENCES rollouts(configuration_scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (rollout_id,config_version_id)
        REFERENCES rollouts(id,config_version_id) ON DELETE RESTRICT
);

CREATE INDEX node_traffic_sync_tasks_claim_181_idx
    ON node_traffic_sync_tasks(status,available_at,id) WHERE status='queued';
CREATE INDEX node_traffic_sync_tasks_rollout_181_idx
    ON node_traffic_sync_tasks(rollout_id) WHERE rollout_id IS NOT NULL;

CREATE FUNCTION protect_node_traffic_policy_identity_181()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(NEW.id,NEW.scope_id,NEW.node_id,NEW.created_by_user_id,NEW.created_at)
       IS DISTINCT FROM ROW(OLD.id,OLD.scope_id,OLD.node_id,OLD.created_by_user_id,OLD.created_at) OR
       NEW.revision<>OLD.revision+1 OR NEW.updated_at<OLD.updated_at THEN
        RAISE EXCEPTION 'node traffic policy identity or revision is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER node_traffic_policies_identity_181
BEFORE UPDATE ON node_traffic_policies
FOR EACH ROW EXECUTE FUNCTION protect_node_traffic_policy_identity_181();

CREATE FUNCTION reject_node_traffic_evidence_mutation_181()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'node traffic policy operation and evaluation evidence is append-only';
END;
$$;

CREATE TRIGGER node_traffic_policy_operations_immutable_181
BEFORE UPDATE OR DELETE ON node_traffic_policy_operations
FOR EACH ROW EXECUTE FUNCTION reject_node_traffic_evidence_mutation_181();
CREATE TRIGGER node_traffic_policy_evaluations_immutable_181
BEFORE UPDATE OR DELETE ON node_traffic_policy_evaluations
FOR EACH ROW EXECUTE FUNCTION reject_node_traffic_evidence_mutation_181();

CREATE FUNCTION protect_node_traffic_sync_task_181()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_scope_id uuid;
    current_config_version_id uuid;
BEGIN
    IF TG_OP='INSERT' THEN
        SELECT configuration_scope_id,current_config_version_id
        INTO current_scope_id,current_config_version_id
        FROM node_config_state WHERE node_id=NEW.node_id;
        IF current_scope_id IS DISTINCT FROM NEW.scope_id OR
           current_config_version_id IS DISTINCT FROM NEW.config_version_id THEN
            RAISE EXCEPTION 'node traffic sync task must bind the current node configuration';
        END IF;
        RETURN NEW;
    END IF;
    IF ROW(NEW.id,NEW.evaluation_id,NEW.scope_id,NEW.node_id,NEW.config_version_id,NEW.created_at)
       IS DISTINCT FROM ROW(OLD.id,OLD.evaluation_id,OLD.scope_id,OLD.node_id,OLD.config_version_id,OLD.created_at) OR
       (OLD.rollout_id IS NOT NULL AND NEW.rollout_id IS DISTINCT FROM OLD.rollout_id) OR
       NEW.updated_at<OLD.updated_at OR NOT (
           (OLD.status='queued' AND NEW.status='running' AND NEW.attempts=OLD.attempts+1) OR
           (OLD.status='running' AND NEW.status='running' AND NEW.attempts=OLD.attempts) OR
           (OLD.status='running' AND NEW.status IN ('succeeded','failed') AND NEW.attempts=OLD.attempts)
       ) THEN
        RAISE EXCEPTION 'invalid node traffic sync task mutation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER node_traffic_sync_tasks_guard_181
BEFORE INSERT OR UPDATE ON node_traffic_sync_tasks
FOR EACH ROW EXECUTE FUNCTION protect_node_traffic_sync_task_181();

REVOKE ALL ON node_traffic_policies,node_traffic_policy_operations,
    node_traffic_policy_evaluations,node_traffic_sync_tasks FROM PUBLIC;
