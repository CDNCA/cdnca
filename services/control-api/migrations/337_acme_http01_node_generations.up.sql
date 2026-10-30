LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_337_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 336 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 336 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=336 AND
        migration_id='336_cc_auto_switch_notifications' AND
        checksum_sha256='6e34c6db1ba2d447b357d240e9bfc490b100f61e534062043d6a4fdcaeb7873e' AND
        down_checksum_sha256='4796a65eba5dfc3787e7c9e8231f792e6ebbe52592b806af7bf17013b8ef7067' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.acme_http01_node_challenges') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 337 requires the exact verified 336 release head' USING ERRCODE='P3370';
    END IF;
END;
$migration_337_up$;

-- FX05① / ADR-0003: production HTTP-01 through node-global overlay
-- generations. A challenge is published to every serving node of the site's
-- line groups (frozen at publish time); each node receives one full snapshot
-- (the union of every active challenge targeting it) per generation. The CA is
-- asked to validate only after every target node's latest healthy generation
-- carries the challenge. The token and key authorization stay in 047's
-- acme_issuance_challenge_attempts; nothing here holds them.
CREATE TABLE acme_http01_node_challenges (
    tenant_scope_id uuid NOT NULL,
    operation_id text NOT NULL,
    attempt_id uuid NOT NULL,
    site_id uuid NOT NULL,
    domain text NOT NULL CHECK (domain = lower(btrim(domain)) AND char_length(domain) BETWEEN 3 AND 253),
    token_sha256 bytea NOT NULL CHECK (octet_length(token_sha256) = 32),
    target_count integer NOT NULL CHECK (target_count BETWEEN 1 AND 10000),
    expires_at timestamptz NOT NULL CHECK (isfinite(expires_at)),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at) AND created_at < expires_at),
    withdrawn_at timestamptz CHECK (withdrawn_at IS NULL OR (isfinite(withdrawn_at) AND withdrawn_at >= created_at)),
    PRIMARY KEY (tenant_scope_id, operation_id, attempt_id),
    FOREIGN KEY (tenant_scope_id, operation_id, attempt_id)
        REFERENCES acme_issuance_challenge_attempts(tenant_scope_id, operation_id, attempt_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE RESTRICT
);
CREATE INDEX acme_http01_node_challenges_active_337_idx
    ON acme_http01_node_challenges(expires_at) WHERE withdrawn_at IS NULL;

CREATE TABLE acme_http01_node_challenge_targets (
    tenant_scope_id uuid NOT NULL,
    operation_id text NOT NULL,
    attempt_id uuid NOT NULL,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    PRIMARY KEY (tenant_scope_id, operation_id, attempt_id, node_id),
    FOREIGN KEY (tenant_scope_id, operation_id, attempt_id)
        REFERENCES acme_http01_node_challenges(tenant_scope_id, operation_id, attempt_id) ON DELETE RESTRICT
);
CREATE INDEX acme_http01_node_challenge_targets_node_337_idx
    ON acme_http01_node_challenge_targets(node_id);

CREATE TABLE acme_http01_node_overlay_generations (
    id uuid PRIMARY KEY,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
    previous_generation bigint NOT NULL CHECK (previous_generation >= 0 AND previous_generation < generation),
    snapshot_sha256 bytea NOT NULL CHECK (octet_length(snapshot_sha256) = 32),
    token_count integer NOT NULL CHECK (token_count BETWEEN 0 AND 4096),
    deadline_at timestamptz NOT NULL CHECK (isfinite(deadline_at)),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at) AND created_at < deadline_at),
    UNIQUE (node_id, generation),
    UNIQUE (id, node_id, generation)
);

CREATE TABLE acme_http01_node_overlay_generation_tokens (
    generation_id uuid NOT NULL REFERENCES acme_http01_node_overlay_generations(id) ON DELETE RESTRICT,
    ordinal integer NOT NULL CHECK (ordinal BETWEEN 1 AND 4096),
    tenant_scope_id uuid NOT NULL,
    operation_id text NOT NULL,
    attempt_id uuid NOT NULL,
    PRIMARY KEY (generation_id, ordinal),
    UNIQUE (generation_id, tenant_scope_id, operation_id, attempt_id),
    FOREIGN KEY (tenant_scope_id, operation_id, attempt_id)
        REFERENCES acme_http01_node_challenges(tenant_scope_id, operation_id, attempt_id) ON DELETE RESTRICT
);
CREATE INDEX acme_http01_node_overlay_generation_tokens_challenge_337_idx
    ON acme_http01_node_overlay_generation_tokens(tenant_scope_id, operation_id, attempt_id);

-- One row per node. current_generation only grows; latest_healthy_generation
-- only grows and never passes current_generation.
CREATE TABLE acme_http01_node_overlay_states (
    node_id uuid PRIMARY KEY REFERENCES nodes(id) ON DELETE RESTRICT,
    current_generation bigint NOT NULL CHECK (current_generation >= 0),
    current_generation_id uuid,
    latest_healthy_generation bigint NOT NULL CHECK (latest_healthy_generation >= 0),
    latest_healthy_generation_id uuid,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL CHECK (updated_at >= created_at),
    CHECK (latest_healthy_generation <= current_generation),
    CHECK ((current_generation = 0) = (current_generation_id IS NULL)),
    CHECK ((latest_healthy_generation = 0) = (latest_healthy_generation_id IS NULL)),
    FOREIGN KEY (current_generation_id, node_id, current_generation)
        REFERENCES acme_http01_node_overlay_generations(id, node_id, generation) ON DELETE RESTRICT,
    FOREIGN KEY (latest_healthy_generation_id, node_id, latest_healthy_generation)
        REFERENCES acme_http01_node_overlay_generations(id, node_id, generation) ON DELETE RESTRICT
);

-- Delivery of one generation to its node. deployment_id is the generation id;
-- a retry is a new attempt row once the previous attempt is terminal.
CREATE TABLE acme_http01_node_overlay_deliveries (
    generation_id uuid NOT NULL,
    node_id uuid NOT NULL,
    generation bigint NOT NULL,
    attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 1000),
    state text NOT NULL CHECK (state IN (
        'pending', 'published', 'applied', 'healthy', 'failed', 'timed_out', 'superseded')),
    lease_token uuid,
    lease_expires_at timestamptz,
    not_before timestamptz NOT NULL CHECK (isfinite(not_before)),
    publish_failures integer NOT NULL DEFAULT 0 CHECK (publish_failures BETWEEN 0 AND 1000000),
    attempt_deadline_at timestamptz CHECK (attempt_deadline_at IS NULL OR isfinite(attempt_deadline_at)),
    failure_code text CHECK (failure_code IS NULL OR failure_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL CHECK (updated_at >= created_at),
    PRIMARY KEY (generation_id, attempt),
    FOREIGN KEY (generation_id, node_id, generation)
        REFERENCES acme_http01_node_overlay_generations(id, node_id, generation) ON DELETE RESTRICT,
    CHECK ((lease_token IS NULL) = (lease_expires_at IS NULL)),
    CHECK (lease_token IS NULL OR state = 'pending'),
    CHECK ((state IN ('failed', 'timed_out', 'superseded')) = (failure_code IS NOT NULL)),
    CHECK (state NOT IN ('published', 'applied') OR attempt_deadline_at IS NOT NULL)
);
CREATE INDEX acme_http01_node_overlay_deliveries_pending_337_idx
    ON acme_http01_node_overlay_deliveries(not_before) WHERE state = 'pending';
CREATE INDEX acme_http01_node_overlay_deliveries_inflight_337_idx
    ON acme_http01_node_overlay_deliveries(attempt_deadline_at) WHERE state IN ('published', 'applied');
CREATE INDEX acme_http01_node_overlay_deliveries_node_337_idx
    ON acme_http01_node_overlay_deliveries(node_id, generation DESC, attempt DESC);
CREATE FUNCTION acme_http01_node_append_only_337()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'ACME HTTP-01 node overlay facts are append-only' USING ERRCODE='P3371';
END;
$$;

CREATE TRIGGER acme_http01_node_challenge_targets_append_only_337
    BEFORE UPDATE OR DELETE ON acme_http01_node_challenge_targets
    FOR EACH ROW EXECUTE FUNCTION acme_http01_node_append_only_337();
CREATE TRIGGER acme_http01_node_overlay_generations_append_only_337
    BEFORE UPDATE OR DELETE ON acme_http01_node_overlay_generations
    FOR EACH ROW EXECUTE FUNCTION acme_http01_node_append_only_337();
CREATE TRIGGER acme_http01_node_overlay_generation_tokens_append_only_337
    BEFORE UPDATE OR DELETE ON acme_http01_node_overlay_generation_tokens
    FOR EACH ROW EXECUTE FUNCTION acme_http01_node_append_only_337();
CREATE TRIGGER acme_http01_node_truncate_guard_337
    BEFORE TRUNCATE ON acme_http01_node_challenges
    FOR EACH STATEMENT EXECUTE FUNCTION acme_http01_node_append_only_337();
CREATE TRIGGER acme_http01_node_targets_truncate_guard_337
    BEFORE TRUNCATE ON acme_http01_node_challenge_targets
    FOR EACH STATEMENT EXECUTE FUNCTION acme_http01_node_append_only_337();
CREATE TRIGGER acme_http01_node_generations_truncate_guard_337
    BEFORE TRUNCATE ON acme_http01_node_overlay_generations
    FOR EACH STATEMENT EXECUTE FUNCTION acme_http01_node_append_only_337();
CREATE TRIGGER acme_http01_node_tokens_truncate_guard_337
    BEFORE TRUNCATE ON acme_http01_node_overlay_generation_tokens
    FOR EACH STATEMENT EXECUTE FUNCTION acme_http01_node_append_only_337();
CREATE TRIGGER acme_http01_node_states_truncate_guard_337
    BEFORE TRUNCATE ON acme_http01_node_overlay_states
    FOR EACH STATEMENT EXECUTE FUNCTION acme_http01_node_append_only_337();
CREATE TRIGGER acme_http01_node_deliveries_truncate_guard_337
    BEFORE TRUNCATE ON acme_http01_node_overlay_deliveries
    FOR EACH STATEMENT EXECUTE FUNCTION acme_http01_node_append_only_337();

-- A challenge only changes once: withdrawn_at NULL -> time.
CREATE FUNCTION guard_acme_http01_node_challenge_337()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' OR OLD.withdrawn_at IS NOT NULL OR NEW.withdrawn_at IS NULL OR
       (NEW.tenant_scope_id, NEW.operation_id, NEW.attempt_id, NEW.site_id, NEW.domain, NEW.token_sha256,
        NEW.target_count, NEW.expires_at, NEW.created_at) IS DISTINCT FROM
       (OLD.tenant_scope_id, OLD.operation_id, OLD.attempt_id, OLD.site_id, OLD.domain, OLD.token_sha256,
        OLD.target_count, OLD.expires_at, OLD.created_at) THEN
        RAISE EXCEPTION 'ACME HTTP-01 node challenge may only be withdrawn once' USING ERRCODE='P3372';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER acme_http01_node_challenges_guard_337
    BEFORE UPDATE OR DELETE ON acme_http01_node_challenges
    FOR EACH ROW EXECUTE FUNCTION guard_acme_http01_node_challenge_337();

-- At commit: the frozen target set has exactly target_count nodes.
CREATE FUNCTION validate_acme_http01_node_challenge_337()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    actual integer;
    expected integer;
BEGIN
    SELECT challenge.target_count, (SELECT count(*) FROM acme_http01_node_challenge_targets target
        WHERE target.tenant_scope_id=challenge.tenant_scope_id AND target.operation_id=challenge.operation_id
          AND target.attempt_id=challenge.attempt_id)
    INTO expected, actual
    FROM acme_http01_node_challenges challenge
    WHERE challenge.tenant_scope_id=NEW.tenant_scope_id AND challenge.operation_id=NEW.operation_id
      AND challenge.attempt_id=NEW.attempt_id;
    IF NOT FOUND OR actual IS DISTINCT FROM expected THEN
        RAISE EXCEPTION 'ACME HTTP-01 node challenge target set does not match its count' USING ERRCODE='P3373';
    END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER acme_http01_node_challenges_validate_337
    AFTER INSERT ON acme_http01_node_challenges DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_acme_http01_node_challenge_337();
CREATE CONSTRAINT TRIGGER acme_http01_node_challenge_targets_validate_337
    AFTER INSERT ON acme_http01_node_challenge_targets DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_acme_http01_node_challenge_337();

-- The canonical digest of a generation: node, generation and its challenge
-- identities in ordinal order. Go computes the same bytes.
CREATE FUNCTION acme_http01_node_generation_digest_337(target_generation_id uuid)
RETURNS bytea LANGUAGE sql STABLE AS $$
    SELECT sha256(convert_to(
        'cdnca.acme.http01-node-generation/v1' || E'\n' || generation.node_id::text || E'\n' ||
        generation.generation::text || E'\n' || COALESCE((
            SELECT string_agg(token.tenant_scope_id::text || '/' || token.operation_id || '/' ||
                token.attempt_id::text, E'\n' ORDER BY token.ordinal)
            FROM acme_http01_node_overlay_generation_tokens token
            WHERE token.generation_id=generation.id), ''), 'UTF8'))
    FROM acme_http01_node_overlay_generations generation
    WHERE generation.id=target_generation_id
$$;

-- At commit: a generation's tokens are contiguous, canonically ordered by
-- (domain, token digest), unique per host/token, each one a live challenge
-- that targets the node; the digest and count match; the generation became the
-- node's current generation (or was overtaken by a later one) and has its
-- first delivery attempt.
CREATE FUNCTION validate_acme_http01_node_generation_337()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    value acme_http01_node_overlay_generations%ROWTYPE;
    target uuid;
    token_total integer;
    max_ordinal integer;
    bad integer;
BEGIN
    IF TG_TABLE_NAME = 'acme_http01_node_overlay_generations' THEN
        target := NEW.id;
    ELSE
        target := NEW.generation_id;
    END IF;
    SELECT * INTO value FROM acme_http01_node_overlay_generations WHERE id = target;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'ACME HTTP-01 node generation is missing' USING ERRCODE='P3374';
    END IF;
    SELECT count(*), COALESCE(max(ordinal), 0) INTO token_total, max_ordinal
    FROM acme_http01_node_overlay_generation_tokens WHERE generation_id=value.id;
    IF token_total <> value.token_count OR max_ordinal <> token_total OR
       acme_http01_node_generation_digest_337(value.id) IS DISTINCT FROM value.snapshot_sha256 THEN
        RAISE EXCEPTION 'ACME HTTP-01 node generation tokens do not match its digest' USING ERRCODE='P3374';
    END IF;
    SELECT count(*) INTO bad
    FROM (
        SELECT token.ordinal, convert_to(challenge.domain, 'UTF8') AS domain, challenge.token_sha256,
               challenge.created_at, challenge.expires_at, challenge.withdrawn_at,
               lag(convert_to(challenge.domain, 'UTF8')) OVER ordered AS previous_domain,
               lag(challenge.token_sha256) OVER ordered AS previous_token,
               EXISTS (
                   SELECT 1 FROM acme_http01_node_challenge_targets target
                   WHERE target.tenant_scope_id=token.tenant_scope_id AND target.operation_id=token.operation_id
                     AND target.attempt_id=token.attempt_id AND target.node_id=value.node_id
               ) AS targeted
        FROM acme_http01_node_overlay_generation_tokens token
        JOIN acme_http01_node_challenges challenge ON challenge.tenant_scope_id=token.tenant_scope_id
         AND challenge.operation_id=token.operation_id AND challenge.attempt_id=token.attempt_id
        WHERE token.generation_id=value.id
        WINDOW ordered AS (ORDER BY token.ordinal)
    ) checked
    WHERE NOT checked.targeted OR checked.created_at > value.created_at OR checked.expires_at <= value.created_at OR
          (checked.withdrawn_at IS NOT NULL AND checked.withdrawn_at <= value.created_at) OR
          (checked.previous_domain IS NOT NULL AND
           (checked.previous_domain, checked.previous_token) >= (checked.domain, checked.token_sha256));
    IF bad <> 0 THEN
        RAISE EXCEPTION 'ACME HTTP-01 node generation carries an ineligible or unordered challenge' USING ERRCODE='P3374';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM acme_http01_node_overlay_states state
        WHERE state.node_id=value.node_id AND state.current_generation >= value.generation
    ) OR NOT EXISTS (
        SELECT 1 FROM acme_http01_node_overlay_deliveries delivery
        WHERE delivery.generation_id=value.id AND delivery.attempt=1
    ) THEN
        RAISE EXCEPTION 'ACME HTTP-01 node generation was not activated with a delivery' USING ERRCODE='P3374';
    END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER acme_http01_node_overlay_generations_validate_337
    AFTER INSERT ON acme_http01_node_overlay_generations DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_acme_http01_node_generation_337();
CREATE CONSTRAINT TRIGGER acme_http01_node_overlay_generation_tokens_validate_337
    AFTER INSERT ON acme_http01_node_overlay_generation_tokens DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION validate_acme_http01_node_generation_337();
-- Node state: inserted empty, current advances along previous_generation,
-- latest healthy only advances, never deleted.
CREATE FUNCTION guard_acme_http01_node_overlay_state_337()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    chained bigint;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'ACME HTTP-01 node overlay state cannot be deleted' USING ERRCODE='P3375';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.current_generation <> 0 OR NEW.latest_healthy_generation <> 0 THEN
            RAISE EXCEPTION 'ACME HTTP-01 node overlay state must start empty' USING ERRCODE='P3375';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.node_id <> OLD.node_id OR NEW.created_at <> OLD.created_at OR NEW.updated_at < OLD.updated_at OR
       NEW.current_generation < OLD.current_generation OR
       NEW.latest_healthy_generation < OLD.latest_healthy_generation OR
       (NEW.current_generation = OLD.current_generation AND
        NEW.current_generation_id IS DISTINCT FROM OLD.current_generation_id) OR
       (NEW.latest_healthy_generation = OLD.latest_healthy_generation AND
        NEW.latest_healthy_generation_id IS DISTINCT FROM OLD.latest_healthy_generation_id) THEN
        RAISE EXCEPTION 'ACME HTTP-01 node overlay state may only advance' USING ERRCODE='P3375';
    END IF;
    IF NEW.current_generation > OLD.current_generation THEN
        SELECT previous_generation INTO chained FROM acme_http01_node_overlay_generations
        WHERE id=NEW.current_generation_id;
        IF chained IS DISTINCT FROM OLD.current_generation THEN
            RAISE EXCEPTION 'ACME HTTP-01 node generation does not extend the current one' USING ERRCODE='P3375';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER acme_http01_node_overlay_states_guard_337
    BEFORE INSERT OR UPDATE OR DELETE ON acme_http01_node_overlay_states
    FOR EACH ROW EXECUTE FUNCTION guard_acme_http01_node_overlay_state_337();

-- Deliveries: an attempt starts pending; a retry is a new attempt after a
-- terminal failure; states only move forward and terminal rows are frozen.
CREATE FUNCTION guard_acme_http01_node_overlay_delivery_337()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'ACME HTTP-01 node overlay delivery cannot be deleted' USING ERRCODE='P3376';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'pending' OR NEW.lease_token IS NOT NULL OR NEW.publish_failures <> 0 OR
           (NEW.attempt > 1 AND NOT EXISTS (
               SELECT 1 FROM acme_http01_node_overlay_deliveries previous
               WHERE previous.generation_id=NEW.generation_id AND previous.attempt=NEW.attempt-1
                 AND previous.state IN ('failed', 'timed_out'))) OR
           EXISTS (SELECT 1 FROM acme_http01_node_overlay_deliveries later
               WHERE later.generation_id=NEW.generation_id AND later.attempt >= NEW.attempt) THEN
            RAISE EXCEPTION 'ACME HTTP-01 node overlay delivery attempt is out of order' USING ERRCODE='P3376';
        END IF;
        RETURN NEW;
    END IF;
    IF (NEW.generation_id, NEW.node_id, NEW.generation, NEW.attempt, NEW.created_at) IS DISTINCT FROM
       (OLD.generation_id, OLD.node_id, OLD.generation, OLD.attempt, OLD.created_at) OR
       NEW.updated_at < OLD.updated_at OR NEW.publish_failures < OLD.publish_failures OR
       OLD.state IN ('healthy', 'failed', 'timed_out', 'superseded') OR NOT (
           (OLD.state = 'pending' AND NEW.state IN ('pending', 'published', 'failed', 'superseded')) OR
           (OLD.state = 'published' AND NEW.state IN ('published', 'applied', 'healthy', 'failed', 'timed_out', 'superseded')) OR
           (OLD.state = 'applied' AND NEW.state IN ('applied', 'healthy', 'failed', 'timed_out', 'superseded'))) OR
       (OLD.state IN ('published', 'applied') AND NEW.attempt_deadline_at IS DISTINCT FROM OLD.attempt_deadline_at) THEN
        RAISE EXCEPTION 'ACME HTTP-01 node overlay delivery transition is invalid' USING ERRCODE='P3376';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER acme_http01_node_overlay_deliveries_guard_337
    BEFORE INSERT OR UPDATE OR DELETE ON acme_http01_node_overlay_deliveries
    FOR EACH ROW EXECUTE FUNCTION guard_acme_http01_node_overlay_delivery_337();

REVOKE ALL ON acme_http01_node_challenges, acme_http01_node_challenge_targets,
    acme_http01_node_overlay_generations, acme_http01_node_overlay_generation_tokens,
    acme_http01_node_overlay_states, acme_http01_node_overlay_deliveries FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON acme_http01_node_challenges, acme_http01_node_overlay_states,
    acme_http01_node_overlay_deliveries TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT ON acme_http01_node_challenge_targets, acme_http01_node_overlay_generations,
    acme_http01_node_overlay_generation_tokens TO cdnca_control_app, cdnca_control_runtime;
