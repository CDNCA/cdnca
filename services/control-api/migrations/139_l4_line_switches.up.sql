LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_139$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 138 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 138 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 138 AND migration_id = '138_challenge_publication_facts' AND
              checksum_sha256 = '14399e504508dbe31dd78711d22ef2c2f4e5a20aad0fc299ee355553e3a3ae9e' AND
              down_checksum_sha256 = '063b1504731a6b630aed43fe46a60247ef9bc86893d4330755209a6720a04218' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('l4_line_switches') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 139 requires the exact verified 138 release head'
            USING ERRCODE = 'P1390';
    END IF;
END;
$migration_139$;

LOCK TABLE access_scopes IN SHARE ROW EXCLUSIVE MODE;

CREATE TABLE l4_line_switches (
    id uuid NOT NULL CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    configuration_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    idempotency_key text NOT NULL CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128 AND
        idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]*$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    state text NOT NULL CHECK (state IN (
        'preparing','health_gate','draining_old','compensating_old',
        'completed','rolled_back','needs_attention'
    )),
    state_revision bigint NOT NULL CHECK (state_revision > 0),
    state_document jsonb NOT NULL CHECK (
        jsonb_typeof(state_document) = 'object' AND octet_length(state_document::text) <= 8388608
    ),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    PRIMARY KEY (configuration_scope_id, id),
    UNIQUE (configuration_scope_id, idempotency_key)
);

CREATE FUNCTION state_document_identity_139(
    document jsonb,
    switch_id uuid,
    scope_id uuid,
    switch_state text,
    revision bigint,
    created timestamptz,
    updated timestamptz
) RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT document #>> '{value,id}' = switch_id::text AND
           document #>> '{value,configuration_scope_id}' = scope_id::text AND
           document #>> '{value,state}' = switch_state AND
           (document #>> '{value,state_revision}')::bigint = revision AND
           (document #>> '{value,created_at}')::timestamptz = created AND
           (document #>> '{value,updated_at}')::timestamptz = updated
$$;

CREATE FUNCTION protect_l4_line_switch_139()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'L4 line switch state is durable' USING ERRCODE = 'P1391';
    END IF;
    IF state_document_identity_139(NEW.state_document, NEW.id, NEW.configuration_scope_id,
            NEW.state, NEW.state_revision, NEW.created_at, NEW.updated_at) IS NOT TRUE THEN
        RAISE EXCEPTION 'L4 line switch state document identity mismatch' USING ERRCODE = 'P1392';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'preparing' OR NEW.state_revision <> 1 OR NEW.updated_at <> NEW.created_at THEN
            RAISE EXCEPTION 'L4 line switch must begin at preparing revision 1' USING ERRCODE = 'P1393';
        END IF;
        RETURN NEW;
    END IF;
    IF ROW(NEW.id, NEW.configuration_scope_id, NEW.idempotency_key, NEW.request_digest, NEW.created_at)
        IS DISTINCT FROM
       ROW(OLD.id, OLD.configuration_scope_id, OLD.idempotency_key, OLD.request_digest, OLD.created_at) OR
       NEW.state_revision <> OLD.state_revision + 1 OR NEW.updated_at < OLD.updated_at OR NOT (
           (OLD.state = 'preparing' AND NEW.state IN ('health_gate','rolled_back')) OR
           (OLD.state = 'health_gate' AND NEW.state IN ('draining_old','compensating_old','completed','rolled_back')) OR
           (OLD.state = 'draining_old' AND NEW.state IN ('completed','compensating_old')) OR
           (OLD.state = 'compensating_old' AND NEW.state IN ('rolled_back','needs_attention'))
       ) THEN
        RAISE EXCEPTION 'invalid L4 line switch state transition' USING ERRCODE = 'P1394';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION prevent_l4_line_switch_truncate_139()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'L4 line switch state is durable' USING ERRCODE = 'P1395';
END;
$$;

CREATE TRIGGER l4_line_switches_protected_139
BEFORE INSERT OR UPDATE OR DELETE ON l4_line_switches
FOR EACH ROW EXECUTE FUNCTION protect_l4_line_switch_139();

CREATE TRIGGER l4_line_switches_no_truncate_139
BEFORE TRUNCATE ON l4_line_switches
FOR EACH STATEMENT EXECUTE FUNCTION prevent_l4_line_switch_truncate_139();

CREATE INDEX l4_line_switches_reconcile_139
    ON l4_line_switches (state, updated_at, configuration_scope_id, id)
    WHERE state IN ('preparing','health_gate','draining_old','compensating_old');

CREATE UNIQUE INDEX l4_line_switches_one_active_139
    ON l4_line_switches (configuration_scope_id)
    WHERE state IN ('preparing','health_gate','draining_old','compensating_old');

CREATE TABLE l4_line_switch_workload_grants (
    configuration_scope_id uuid NOT NULL,
    switch_id uuid NOT NULL,
    workload_id text NOT NULL CHECK (
        workload_id = 'control-api.l4-line-switch-reconciler'
    ),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    PRIMARY KEY (configuration_scope_id, switch_id),
    FOREIGN KEY (configuration_scope_id, switch_id)
        REFERENCES l4_line_switches(configuration_scope_id, id) ON DELETE RESTRICT
);

CREATE TABLE l4_line_target_heads (
    configuration_scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    snapshot_id uuid NOT NULL CHECK (snapshot_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    snapshot_revision bigint NOT NULL CHECK (snapshot_revision > 0),
    snapshot_sha256 bytea NOT NULL CHECK (octet_length(snapshot_sha256) = 32),
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    revision bigint NOT NULL CHECK (revision > 0),
    last_switch_id uuid NOT NULL,
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    FOREIGN KEY (configuration_scope_id, last_switch_id)
        REFERENCES l4_line_switches(configuration_scope_id, id) ON DELETE RESTRICT
);

CREATE TABLE l4_line_target_events (
    configuration_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    switch_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation IN ('activate','restore')),
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    before_snapshot_id uuid NOT NULL CHECK (before_snapshot_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    before_snapshot_revision bigint NOT NULL CHECK (before_snapshot_revision > 0),
    before_snapshot_sha256 bytea NOT NULL CHECK (octet_length(before_snapshot_sha256) = 32),
    after_snapshot_id uuid NOT NULL CHECK (after_snapshot_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    after_snapshot_revision bigint NOT NULL CHECK (after_snapshot_revision > 0),
    after_snapshot_sha256 bytea NOT NULL CHECK (octet_length(after_snapshot_sha256) = 32),
    occurred_at timestamptz NOT NULL CHECK (isfinite(occurred_at)),
    PRIMARY KEY (configuration_scope_id, revision),
    UNIQUE (configuration_scope_id, switch_id, operation),
    FOREIGN KEY (configuration_scope_id, switch_id)
        REFERENCES l4_line_switches(configuration_scope_id, id) ON DELETE RESTRICT,
    CHECK (before_snapshot_id <> after_snapshot_id OR
           before_snapshot_revision <> after_snapshot_revision OR
           before_snapshot_sha256 <> after_snapshot_sha256)
);

CREATE TABLE l4_node_drain_counters (
    configuration_scope_id uuid NOT NULL,
    node_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (configuration_scope_id, node_id),
    FOREIGN KEY (configuration_scope_id, node_id)
        REFERENCES nodes(scope_id, id) ON DELETE RESTRICT
);

CREATE TABLE l4_line_switch_drain_plans (
    configuration_scope_id uuid NOT NULL,
    switch_id uuid NOT NULL,
    node_id uuid NOT NULL,
    plan_id uuid NOT NULL CHECK (plan_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    plan_revision bigint NOT NULL CHECK (plan_revision > 0),
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    config_version_id uuid NOT NULL,
    retired_version_id uuid NOT NULL CHECK (retired_version_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    canonical_plan jsonb NOT NULL CHECK (
        jsonb_typeof(canonical_plan) = 'object' AND octet_length(canonical_plan::text) <= 4194304
    ),
    plan_sha256 bytea NOT NULL CHECK (
        octet_length(plan_sha256) = 32 AND
        plan_sha256 = sha256(convert_to(canonical_plan::text, 'UTF8'))
    ),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    PRIMARY KEY (configuration_scope_id, switch_id, node_id),
    UNIQUE (configuration_scope_id, node_id, plan_revision),
    UNIQUE (configuration_scope_id, plan_id),
    FOREIGN KEY (configuration_scope_id, switch_id)
        REFERENCES l4_line_switches(configuration_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (configuration_scope_id, node_id)
        REFERENCES nodes(scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (configuration_scope_id, config_version_id)
        REFERENCES config_versions(configuration_scope_id, id) ON DELETE RESTRICT,
    CHECK (canonical_plan #>> '{schema_version}' = 'cdnca.edge.drain/v1' AND
           canonical_plan #>> '{plan_id}' = plan_id::text AND
           (canonical_plan #>> '{revision}')::bigint = plan_revision AND
           canonical_plan #>> '{old,version_id}' = config_version_id::text AND
           canonical_plan #>> '{new,version_id}' = retired_version_id::text)
);

CREATE FUNCTION protect_l4_line_target_head_139()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' OR
       NEW.configuration_scope_id IS DISTINCT FROM OLD.configuration_scope_id OR
       NEW.revision <> OLD.revision + 1 OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'L4 line target head must advance monotonically' USING ERRCODE = 'P1397';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION protect_l4_line_target_event_139()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'L4 line target events are append-only' USING ERRCODE = 'P1398';
END;
$$;

CREATE FUNCTION protect_l4_node_drain_counter_139()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' OR
       ROW(NEW.configuration_scope_id, NEW.node_id) IS DISTINCT FROM
       ROW(OLD.configuration_scope_id, OLD.node_id) OR
       NEW.revision <> OLD.revision + 1 OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'L4 node drain revision must advance monotonically' USING ERRCODE = 'P1399';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION protect_l4_line_switch_drain_plan_139()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'L4 line switch drain plans are append-only' USING ERRCODE = 'P13A0';
END;
$$;

CREATE FUNCTION protect_l4_line_switch_workload_grant_139()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'L4 line switch workload grants are append-only' USING ERRCODE = 'P13A1';
END;
$$;

CREATE TRIGGER l4_line_target_heads_protected_139
BEFORE UPDATE OR DELETE ON l4_line_target_heads
FOR EACH ROW EXECUTE FUNCTION protect_l4_line_target_head_139();

CREATE TRIGGER l4_line_target_heads_no_truncate_139
BEFORE TRUNCATE ON l4_line_target_heads
FOR EACH STATEMENT EXECUTE FUNCTION prevent_l4_line_switch_truncate_139();

CREATE TRIGGER l4_line_target_events_protected_139
BEFORE UPDATE OR DELETE ON l4_line_target_events
FOR EACH ROW EXECUTE FUNCTION protect_l4_line_target_event_139();

CREATE TRIGGER l4_line_target_events_no_truncate_139
BEFORE TRUNCATE ON l4_line_target_events
FOR EACH STATEMENT EXECUTE FUNCTION protect_l4_line_target_event_139();

CREATE TRIGGER l4_node_drain_counters_protected_139
BEFORE UPDATE OR DELETE ON l4_node_drain_counters
FOR EACH ROW EXECUTE FUNCTION protect_l4_node_drain_counter_139();

CREATE TRIGGER l4_node_drain_counters_no_truncate_139
BEFORE TRUNCATE ON l4_node_drain_counters
FOR EACH STATEMENT EXECUTE FUNCTION prevent_l4_line_switch_truncate_139();

CREATE TRIGGER l4_line_switch_drain_plans_protected_139
BEFORE UPDATE OR DELETE ON l4_line_switch_drain_plans
FOR EACH ROW EXECUTE FUNCTION protect_l4_line_switch_drain_plan_139();

CREATE TRIGGER l4_line_switch_drain_plans_no_truncate_139
BEFORE TRUNCATE ON l4_line_switch_drain_plans
FOR EACH STATEMENT EXECUTE FUNCTION protect_l4_line_switch_drain_plan_139();

CREATE TRIGGER l4_line_switch_workload_grants_protected_139
BEFORE UPDATE OR DELETE ON l4_line_switch_workload_grants
FOR EACH ROW EXECUTE FUNCTION protect_l4_line_switch_workload_grant_139();

CREATE TRIGGER l4_line_switch_workload_grants_no_truncate_139
BEFORE TRUNCATE ON l4_line_switch_workload_grants
FOR EACH STATEMENT EXECUTE FUNCTION protect_l4_line_switch_workload_grant_139();

REVOKE ALL ON FUNCTION protect_l4_line_switch_139() FROM PUBLIC;
REVOKE ALL ON FUNCTION state_document_identity_139(jsonb,uuid,uuid,text,bigint,timestamptz,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_l4_line_switch_truncate_139() FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_l4_line_target_head_139() FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_l4_line_target_event_139() FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_l4_node_drain_counter_139() FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_l4_line_switch_drain_plan_139() FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_l4_line_switch_workload_grant_139() FROM PUBLIC;
