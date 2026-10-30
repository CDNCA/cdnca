LOCK TABLE schema_migrations,nodes,node_config_state,config_versions IN ACCESS EXCLUSIVE MODE;

DO $migration_182$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>181 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>181 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=181 AND migration_id='181_node_traffic_policies' AND
              checksum_sha256='8595b4f05042263247425a1df790081fd5068ac194ac5da053946a832f414a8e' AND
              down_checksum_sha256='e359889a1250016c44a8e0dc2dc600b50a75648e60e15243f347ae707847dae4' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass(current_schema() || '.node_isolation_states') IS NOT NULL OR
         to_regclass(current_schema() || '.node_isolation_reports') IS NOT NULL OR
         to_regclass(current_schema() || '.node_isolation_alert_events') IS NOT NULL OR
         to_regprocedure(current_schema() || '.protect_node_isolation_state_182()') IS NOT NULL OR
         to_regprocedure(current_schema() || '.reject_node_isolation_evidence_mutation_182()') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 182 requires the exact verified 181 release head and an untouched node isolation schema'
            USING ERRCODE='P1820';
    END IF;
END;
$migration_182$;

CREATE TABLE node_isolation_states (
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    status text NOT NULL CHECK (status IN ('active','isolated')),
    desired_config_version_id uuid NOT NULL,
    desired_artifact_sha256 bytea NOT NULL CHECK (octet_length(desired_artifact_sha256)=32),
    desired_identity_schema integer NOT NULL CHECK (desired_identity_schema=1),
    consecutive_failures integer NOT NULL CHECK (consecutive_failures BETWEEN 0 AND 100),
    consecutive_healthy integer NOT NULL CHECK (consecutive_healthy BETWEEN 0 AND 100),
    last_session_epoch bigint NOT NULL CHECK (last_session_epoch>=0),
    last_health_sequence bigint NOT NULL CHECK (last_health_sequence>=0),
    last_report_id uuid NOT NULL,
    last_outcome text NOT NULL CHECK (last_outcome IN ('succeeded','failed','unknown')),
    last_error_code text CHECK (last_error_code IS NULL OR last_error_code ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    reason_code text NOT NULL CHECK (reason_code IN (
        'healthy','sync_failure_pending','sync_failure_threshold','sync_outcome_unknown',
        'active_config_identity_mismatch','health_evidence_stale',
        'recovery_confirmation_pending','recovered','operation_outcome_uncertain'
    )),
    revision bigint NOT NULL CHECK (revision>0),
    isolated_at timestamptz,
    recovered_at timestamptz,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (scope_id,node_id),
    UNIQUE (last_report_id),
    FOREIGN KEY (scope_id,node_id) REFERENCES nodes(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id,desired_config_version_id)
        REFERENCES config_versions(configuration_scope_id,id) ON DELETE RESTRICT,
    CHECK (recovered_at IS NULL OR isolated_at IS NOT NULL AND recovered_at>=isolated_at),
    CHECK ((status='isolated' AND isolated_at IS NOT NULL) OR status='active')
);

CREATE INDEX node_isolation_states_status_182_idx
    ON node_isolation_states(scope_id,status,updated_at DESC,node_id);

CREATE TABLE node_isolation_reports (
    report_id uuid PRIMARY KEY,
    scope_id uuid NOT NULL,
    node_id uuid NOT NULL,
    request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
    response jsonb NOT NULL CHECK (jsonb_typeof(response)='object'),
    created_at timestamptz NOT NULL,
    FOREIGN KEY (scope_id,node_id) REFERENCES node_isolation_states(scope_id,node_id) ON DELETE RESTRICT
);

CREATE INDEX node_isolation_reports_node_created_182_idx
    ON node_isolation_reports(scope_id,node_id,created_at DESC,report_id);

CREATE TABLE node_isolation_alert_events (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL,
    node_id uuid NOT NULL,
    state_revision bigint NOT NULL CHECK (state_revision>0),
    kind text NOT NULL CHECK (kind IN ('alert_opened','alert_resolved')),
    code text NOT NULL CHECK (code IN ('node_config_sync_isolated','node_config_sync_recovered')),
    dedupe_key text NOT NULL UNIQUE CHECK (
        dedupe_key=btrim(dedupe_key) AND char_length(dedupe_key) BETWEEN 1 AND 256
    ),
    created_at timestamptz NOT NULL,
    FOREIGN KEY (scope_id,node_id) REFERENCES node_isolation_states(scope_id,node_id) ON DELETE RESTRICT,
    CHECK ((kind='alert_opened')=(code='node_config_sync_isolated'))
);

CREATE INDEX node_isolation_alert_events_node_182_idx
    ON node_isolation_alert_events(scope_id,node_id,state_revision,id);

CREATE FUNCTION protect_node_isolation_state_182()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_scope_id uuid;
    current_config_version_id uuid;
    current_identity_schema integer;
    current_artifact_sha256 bytea;
BEGIN
    SELECT configuration_scope_id,current_config_version_id,current_config_identity_schema,
           current_config_artifact_sha256
    INTO current_scope_id,current_config_version_id,current_identity_schema,current_artifact_sha256
    FROM node_config_state WHERE node_id=NEW.node_id;
    IF current_scope_id IS DISTINCT FROM NEW.scope_id OR
       current_config_version_id IS DISTINCT FROM NEW.desired_config_version_id OR
       current_identity_schema IS DISTINCT FROM NEW.desired_identity_schema OR
       current_artifact_sha256 IS DISTINCT FROM NEW.desired_artifact_sha256 THEN
        RAISE EXCEPTION 'node isolation state must bind the current node configuration identity';
    END IF;
    IF TG_OP='UPDATE' AND (
       ROW(NEW.scope_id,NEW.node_id) IS DISTINCT FROM ROW(OLD.scope_id,OLD.node_id) OR
       NEW.revision<>OLD.revision+1 OR NEW.updated_at<OLD.updated_at OR
       NEW.last_session_epoch<OLD.last_session_epoch OR
       NEW.last_session_epoch=OLD.last_session_epoch AND NEW.last_health_sequence<OLD.last_health_sequence
    ) THEN
        RAISE EXCEPTION 'node isolation state identity, revision, time, and health evidence are monotonic';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER node_isolation_states_guard_182
BEFORE INSERT OR UPDATE ON node_isolation_states
FOR EACH ROW EXECUTE FUNCTION protect_node_isolation_state_182();

CREATE FUNCTION reject_node_isolation_evidence_mutation_182()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'node isolation report and alert evidence is append-only';
END;
$$;

CREATE TRIGGER node_isolation_reports_immutable_182
BEFORE UPDATE OR DELETE ON node_isolation_reports
FOR EACH ROW EXECUTE FUNCTION reject_node_isolation_evidence_mutation_182();
CREATE TRIGGER node_isolation_alert_events_immutable_182
BEFORE UPDATE OR DELETE ON node_isolation_alert_events
FOR EACH ROW EXECUTE FUNCTION reject_node_isolation_evidence_mutation_182();

REVOKE ALL ON node_isolation_states,node_isolation_reports,node_isolation_alert_events FROM PUBLIC;
