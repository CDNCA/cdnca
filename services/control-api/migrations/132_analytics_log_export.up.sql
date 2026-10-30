LOCK TABLE schema_migrations,access_scopes,users
IN ACCESS EXCLUSIVE MODE;

DO $migration_132$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 131 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 131 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL
           OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=131 AND migration_id='131_analytics_realtime_expected_counts'
          AND checksum_sha256='a76a12a05ca5418bf4485f8e2c0895b541907984ccfb02e0a6510fdd1270ee4c'
          AND down_checksum_sha256='b6877a5be58fdf9abbfdf3babc1352751e07ddbd19f9638acd091b645e7c2d3a'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) OR to_regclass('analytics_log_exports_v1') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 132 requires the exact verified 131 release head'
            USING ERRCODE='P1320';
    END IF;
END;
$migration_132$;

CREATE TABLE analytics_log_exports_v1 (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    credential_kind text NOT NULL CHECK (credential_kind = 'session'),
    credential_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9._:-]{16,128}$'),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    filter jsonb NOT NULL CHECK (jsonb_typeof(filter) = 'object' AND octet_length(filter::text) <= 16384),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    FOREIGN KEY (scope_id,tenant_id) REFERENCES access_scopes(id,tenant_id) ON DELETE RESTRICT,
    UNIQUE (actor_scope_id,actor_user_id,credential_kind,credential_id,idempotency_key)
);

CREATE TABLE analytics_log_export_events_v1 (
    export_id uuid NOT NULL REFERENCES analytics_log_exports_v1(id) ON DELETE RESTRICT,
    sequence integer NOT NULL CHECK (sequence > 0),
    state text NOT NULL CHECK (state IN ('pending','running','completed','failed')),
    reason text NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 64),
    snapshot_at timestamptz CHECK (snapshot_at IS NULL OR isfinite(snapshot_at)),
    row_count integer CHECK (row_count IS NULL OR row_count BETWEEN 0 AND 100000),
    byte_count integer CHECK (byte_count IS NULL OR byte_count BETWEEN 0 AND 8388608),
    artifact_sha256 bytea CHECK (artifact_sha256 IS NULL OR octet_length(artifact_sha256) = 32),
    occurred_at timestamptz NOT NULL CHECK (isfinite(occurred_at)),
    CHECK (
        (state IN ('pending','running','failed') AND snapshot_at IS NULL AND row_count IS NULL
            AND byte_count IS NULL AND artifact_sha256 IS NULL) OR
        (state = 'completed' AND snapshot_at IS NOT NULL AND row_count IS NOT NULL
            AND byte_count IS NOT NULL AND artifact_sha256 IS NOT NULL)
    ),
    PRIMARY KEY (export_id,sequence)
);

CREATE TABLE analytics_log_export_leases_v1 (
    export_id uuid PRIMARY KEY REFERENCES analytics_log_exports_v1(id) ON DELETE RESTRICT,
    worker_id uuid NOT NULL,
    lease_expires_at timestamptz NOT NULL CHECK (isfinite(lease_expires_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    CHECK (lease_expires_at > updated_at AND lease_expires_at <= updated_at + INTERVAL '1 minute')
);

CREATE TABLE analytics_log_export_artifacts_v1 (
    export_id uuid PRIMARY KEY REFERENCES analytics_log_exports_v1(id) ON DELETE RESTRICT,
    content bytea NOT NULL CHECK (octet_length(content) BETWEEN 1 AND 8388608),
    content_sha256 bytea NOT NULL CHECK (octet_length(content_sha256) = 32),
    row_count integer NOT NULL CHECK (row_count BETWEEN 0 AND 100000),
    artifact_expires_at timestamptz NOT NULL CHECK (isfinite(artifact_expires_at)),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    CHECK (artifact_expires_at > created_at AND artifact_expires_at <= created_at + INTERVAL '1 hour')
);

CREATE TABLE analytics_log_export_grants_v1 (
    id uuid PRIMARY KEY,
    export_id uuid NOT NULL REFERENCES analytics_log_exports_v1(id) ON DELETE RESTRICT,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    session_id uuid NOT NULL,
    token_sha256 bytea NOT NULL CHECK (octet_length(token_sha256) = 32),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    expires_at timestamptz NOT NULL CHECK (isfinite(expires_at) AND expires_at > created_at
        AND expires_at <= created_at + INTERVAL '5 minutes'),
    consumed_at timestamptz CHECK (consumed_at IS NULL OR isfinite(consumed_at)),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at AND consumed_at < expires_at),
    UNIQUE (token_sha256)
);

CREATE INDEX analytics_log_exports_scope_created_v1_idx
    ON analytics_log_exports_v1(scope_id,tenant_id,created_at DESC,id DESC);
CREATE INDEX analytics_log_export_events_latest_v1_idx
    ON analytics_log_export_events_v1(export_id,sequence DESC);
CREATE INDEX analytics_log_export_grants_expiry_v1_idx
    ON analytics_log_export_grants_v1(expires_at) WHERE consumed_at IS NULL;
CREATE INDEX analytics_log_export_artifacts_expiry_v1_idx
    ON analytics_log_export_artifacts_v1(artifact_expires_at);

CREATE FUNCTION prevent_analytics_log_export_fact_mutation_132()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'analytics log export facts are append-only' USING ERRCODE='P1321';
END;
$$;

CREATE TRIGGER analytics_log_exports_append_only_132
BEFORE UPDATE OR DELETE ON analytics_log_exports_v1
FOR EACH ROW EXECUTE FUNCTION prevent_analytics_log_export_fact_mutation_132();
CREATE TRIGGER analytics_log_export_events_append_only_132
BEFORE UPDATE OR DELETE ON analytics_log_export_events_v1
FOR EACH ROW EXECUTE FUNCTION prevent_analytics_log_export_fact_mutation_132();
CREATE TRIGGER analytics_log_exports_no_truncate_132
BEFORE TRUNCATE ON analytics_log_exports_v1
FOR EACH STATEMENT EXECUTE FUNCTION prevent_analytics_log_export_fact_mutation_132();
CREATE TRIGGER analytics_log_export_events_no_truncate_132
BEFORE TRUNCATE ON analytics_log_export_events_v1
FOR EACH STATEMENT EXECUTE FUNCTION prevent_analytics_log_export_fact_mutation_132();

CREATE FUNCTION guard_analytics_log_export_grant_132()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'analytics log export grant truncate is forbidden' USING ERRCODE='P1322';
    ELSIF TG_OP = 'DELETE' THEN
        IF OLD.expires_at > statement_timestamp() AND OLD.consumed_at IS NULL THEN
            RAISE EXCEPTION 'live analytics log export grant deletion is forbidden' USING ERRCODE='P1322';
        END IF;
        RETURN OLD;
    ELSIF OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL OR
       NEW.id IS DISTINCT FROM OLD.id OR NEW.export_id IS DISTINCT FROM OLD.export_id OR
       NEW.scope_id IS DISTINCT FROM OLD.scope_id OR NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id OR
       NEW.session_id IS DISTINCT FROM OLD.session_id OR NEW.token_sha256 IS DISTINCT FROM OLD.token_sha256 OR
       NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'analytics log export grant mutation is forbidden' USING ERRCODE='P1322';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER analytics_log_export_grant_consume_only_132
BEFORE UPDATE ON analytics_log_export_grants_v1
FOR EACH ROW EXECUTE FUNCTION guard_analytics_log_export_grant_132();
CREATE TRIGGER analytics_log_export_grant_delete_fence_132
BEFORE DELETE ON analytics_log_export_grants_v1
FOR EACH ROW EXECUTE FUNCTION guard_analytics_log_export_grant_132();
CREATE TRIGGER analytics_log_export_grant_no_truncate_132
BEFORE TRUNCATE ON analytics_log_export_grants_v1
FOR EACH STATEMENT EXECUTE FUNCTION guard_analytics_log_export_grant_132();

CREATE FUNCTION guard_analytics_log_export_artifact_132()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' OR TG_OP = 'UPDATE' OR
       (TG_OP = 'DELETE' AND OLD.artifact_expires_at > statement_timestamp()) THEN
        RAISE EXCEPTION 'analytics log export artifact mutation is forbidden' USING ERRCODE='P1324';
    END IF;
    RETURN OLD;
END;
$$;
CREATE TRIGGER analytics_log_export_artifact_update_fence_132
BEFORE UPDATE OR DELETE ON analytics_log_export_artifacts_v1
FOR EACH ROW EXECUTE FUNCTION guard_analytics_log_export_artifact_132();
CREATE TRIGGER analytics_log_export_artifact_no_truncate_132
BEFORE TRUNCATE ON analytics_log_export_artifacts_v1
FOR EACH STATEMENT EXECUTE FUNCTION guard_analytics_log_export_artifact_132();

CREATE FUNCTION claim_analytics_log_export_132(p_worker_id uuid,p_now timestamptz,p_lease interval)
RETURNS uuid LANGUAGE plpgsql AS $$
DECLARE selected_export uuid;
BEGIN
    IF p_worker_id IS NULL OR NOT isfinite(p_now) OR p_lease <= INTERVAL '0 seconds' OR
       p_lease > INTERVAL '1 minute' THEN
        RAISE EXCEPTION 'invalid analytics log export claim lease' USING ERRCODE='P1325';
    END IF;
    SELECT request.id INTO selected_export
    FROM analytics_log_exports_v1 request
    JOIN LATERAL (
        SELECT state FROM analytics_log_export_events_v1 event
        WHERE event.export_id=request.id ORDER BY sequence DESC LIMIT 1
    ) latest ON true
    LEFT JOIN analytics_log_export_leases_v1 lease ON lease.export_id=request.id
    WHERE latest.state IN ('pending','running')
      AND (lease.export_id IS NULL OR lease.lease_expires_at <= p_now)
    ORDER BY request.created_at,request.id
    FOR UPDATE OF request SKIP LOCKED LIMIT 1;
    IF selected_export IS NULL THEN RETURN NULL; END IF;
    INSERT INTO analytics_log_export_leases_v1(export_id,worker_id,lease_expires_at,updated_at)
    VALUES(selected_export,p_worker_id,p_now+p_lease,p_now)
    ON CONFLICT(export_id) DO UPDATE SET worker_id=EXCLUDED.worker_id,
        lease_expires_at=EXCLUDED.lease_expires_at,updated_at=EXCLUDED.updated_at;
    INSERT INTO analytics_log_export_events_v1(export_id,sequence,state,reason,occurred_at)
    SELECT selected_export,COALESCE(max(sequence),0)+1,'running','worker_claimed',p_now
    FROM analytics_log_export_events_v1 WHERE export_id=selected_export;
    RETURN selected_export;
END;
$$;

COMMENT ON TABLE analytics_log_exports_v1 IS
    'Runtime appends audit_events actions analytics_log.export.create, analytics_log.export.complete, analytics_log.export.grant, analytics_log.export.download and analytics_log.export.reject transactionally.';

REVOKE ALL ON TABLE analytics_log_exports_v1,analytics_log_export_events_v1,
    analytics_log_export_leases_v1,analytics_log_export_artifacts_v1,analytics_log_export_grants_v1 FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_analytics_log_export_fact_mutation_132(),
    guard_analytics_log_export_grant_132(),guard_analytics_log_export_artifact_132(),
    claim_analytics_log_export_132(uuid,timestamptz,interval) FROM PUBLIC;
