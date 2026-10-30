LOCK TABLE schema_migrations,
    certificate_publication_intents
IN ACCESS EXCLUSIVE MODE;

-- REQUIRED_117_HEAD_FROZEN_118
DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 117 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 117 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=117 AND migration_id='117_api_key_ip_allowlist'
          AND checksum_sha256='9fa028cf6c6c65883f0289f8f12a305104e5438a10888c7970cccb08db2adccc'
          AND down_checksum_sha256='a5000b0e0561875b9533022fac293755d24a3950412aed3e2649f499c3fd4904'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 118 requires the exact verified 117 release head'
            USING ERRCODE='P1180';
    END IF;
END;
$$;

CREATE TABLE certificate_publication_intent_state_facts (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    binding_revision bigint NOT NULL CHECK (binding_revision > 0),
    sequence bigint NOT NULL CHECK (sequence > 0),
    state text NOT NULL CHECK (state IN ('pending','leased','retry_wait','succeeded','permanent_failed')),
    attempt integer NOT NULL CHECK (attempt >= 0),
    idempotency_key text NOT NULL CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 192 AND idempotency_key=btrim(idempotency_key)
        AND idempotency_key !~ '[[:cntrl:]]'
    ),
    lease_owner text CHECK (
        lease_owner IS NULL OR (
            octet_length(lease_owner) BETWEEN 1 AND 128 AND lease_owner=btrim(lease_owner)
            AND lease_owner !~ '[[:cntrl:]]' AND position(U&'\2028' in lease_owner)=0
            AND position(U&'\2029' in lease_owner)=0
        )
    ),
    lease_token uuid,
    lease_expires_at timestamptz CHECK (lease_expires_at IS NULL OR isfinite(lease_expires_at)),
    next_attempt_at timestamptz CHECK (next_attempt_at IS NULL OR isfinite(next_attempt_at)),
    failure_code text CHECK (
        failure_code IS NULL OR failure_code ~ '^[a-z][a-z0-9._-]{0,127}$'
    ),
    occurred_at timestamptz NOT NULL CHECK (isfinite(occurred_at)),
    PRIMARY KEY (tenant_scope_id,site_id,binding_revision,sequence),
    FOREIGN KEY (tenant_scope_id,site_id,binding_revision)
        REFERENCES certificate_publication_intents(tenant_scope_id,site_id,binding_revision) ON DELETE RESTRICT,
    CHECK (
        (state='pending' AND attempt=0 AND lease_owner IS NULL AND lease_token IS NULL
            AND lease_expires_at IS NULL AND next_attempt_at IS NOT NULL AND failure_code IS NULL) OR
        (state='leased' AND attempt>0 AND lease_owner IS NOT NULL AND lease_token IS NOT NULL
            AND lease_expires_at>occurred_at AND lease_expires_at<=occurred_at+interval '1 hour'
            AND next_attempt_at IS NULL AND failure_code IS NULL) OR
        (state='retry_wait' AND attempt>0 AND lease_owner IS NOT NULL AND lease_token IS NOT NULL
            AND lease_expires_at IS NOT NULL AND next_attempt_at>occurred_at
            AND next_attempt_at<=occurred_at+interval '1 hour' AND failure_code IS NOT NULL) OR
        (state='succeeded' AND attempt>0 AND lease_owner IS NOT NULL AND lease_token IS NOT NULL
            AND lease_expires_at IS NOT NULL AND next_attempt_at IS NULL AND failure_code IS NULL) OR
        (state='permanent_failed' AND attempt>0 AND lease_owner IS NOT NULL AND lease_token IS NOT NULL
            AND lease_expires_at IS NOT NULL AND next_attempt_at IS NULL AND failure_code IS NOT NULL)
    )
);

CREATE INDEX certificate_publication_intent_states_claim_118_idx
    ON certificate_publication_intent_state_facts(state,next_attempt_at,lease_expires_at,occurred_at);

CREATE FUNCTION protect_certificate_publication_intent_state_118()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'certificate publication intent state facts are append-only' USING ERRCODE='P1181';
END;
$$;

CREATE FUNCTION prevent_certificate_publication_intent_state_truncate_118()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'certificate publication intent state facts are append-only' USING ERRCODE='P1181';
END;
$$;

CREATE FUNCTION validate_certificate_publication_intent_state_118()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    intent certificate_publication_intents%ROWTYPE;
    previous certificate_publication_intent_state_facts%ROWTYPE;
    expected_key text;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'certificate-publication-state:' || NEW.tenant_scope_id::text || ':' ||
        NEW.site_id::text || ':' || NEW.binding_revision::text, 0));
    SELECT * INTO intent FROM certificate_publication_intents
    WHERE tenant_scope_id=NEW.tenant_scope_id AND site_id=NEW.site_id
      AND binding_revision=NEW.binding_revision;
    expected_key := 'certificate.publication/' || NEW.tenant_scope_id::text || '/' ||
        NEW.site_id::text || '/' || NEW.binding_revision::text;
    IF NOT FOUND OR NEW.idempotency_key IS DISTINCT FROM expected_key OR
       NEW.occurred_at IS DISTINCT FROM transaction_timestamp() THEN
        RAISE EXCEPTION 'invalid certificate publication intent state identity' USING ERRCODE='P1181';
    END IF;
    SELECT * INTO previous FROM certificate_publication_intent_state_facts
    WHERE tenant_scope_id=NEW.tenant_scope_id AND site_id=NEW.site_id
      AND binding_revision=NEW.binding_revision
    ORDER BY sequence DESC LIMIT 1;
    IF NOT FOUND THEN
        IF NEW.sequence<>1 OR NEW.state<>'pending' OR NEW.attempt<>0 OR
           NEW.next_attempt_at IS DISTINCT FROM NEW.occurred_at THEN
            RAISE EXCEPTION 'invalid initial certificate publication intent state' USING ERRCODE='P1181';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.sequence<>previous.sequence+1 OR
       NEW.idempotency_key IS DISTINCT FROM previous.idempotency_key THEN
        RAISE EXCEPTION 'invalid certificate publication intent state revision' USING ERRCODE='P1181';
    END IF;
    IF NEW.state='leased' AND EXISTS (
        SELECT 1 FROM certificate_publication_intents previous_intent
        JOIN LATERAL (
            SELECT state FROM certificate_publication_intent_state_facts previous_state
            WHERE previous_state.tenant_scope_id=previous_intent.tenant_scope_id
              AND previous_state.site_id=previous_intent.site_id
              AND previous_state.binding_revision=previous_intent.binding_revision
            ORDER BY sequence DESC LIMIT 1
        ) previous_latest ON true
        WHERE previous_intent.tenant_scope_id=NEW.tenant_scope_id
          AND previous_intent.site_id=NEW.site_id
          AND previous_intent.binding_revision<NEW.binding_revision
          AND previous_latest.state<>'succeeded'
    ) THEN
        RAISE EXCEPTION 'certificate publication intent claim is out of order' USING ERRCODE='P1181';
    END IF;
    IF previous.state IN ('pending','retry_wait') AND NEW.state='leased' THEN
        IF previous.next_attempt_at>NEW.occurred_at OR NEW.attempt<>previous.attempt+1 THEN
            RAISE EXCEPTION 'certificate publication intent was claimed before availability' USING ERRCODE='P1181';
        END IF;
    ELSIF previous.state='leased' AND NEW.state='leased' THEN
        IF previous.lease_expires_at>NEW.occurred_at OR NEW.attempt<>previous.attempt+1 OR
           NEW.lease_token IS NOT DISTINCT FROM previous.lease_token THEN
            RAISE EXCEPTION 'certificate publication intent crash reclaim is invalid' USING ERRCODE='P1181';
        END IF;
    ELSIF previous.state='leased' AND NEW.state IN ('retry_wait','succeeded','permanent_failed') THEN
        IF previous.lease_expires_at<=NEW.occurred_at OR NEW.attempt<>previous.attempt OR
           NEW.lease_owner IS DISTINCT FROM previous.lease_owner OR
           NEW.lease_token IS DISTINCT FROM previous.lease_token OR
           NEW.lease_expires_at IS DISTINCT FROM previous.lease_expires_at THEN
            RAISE EXCEPTION 'certificate publication intent settlement fence is invalid' USING ERRCODE='P1181';
        END IF;
    ELSE
        RAISE EXCEPTION 'invalid certificate publication intent state transition' USING ERRCODE='P1181';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION initialize_certificate_publication_intent_state_118()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    initial_time timestamptz := transaction_timestamp();
BEGIN
    INSERT INTO certificate_publication_intent_state_facts(
        tenant_scope_id,site_id,binding_revision,sequence,state,attempt,idempotency_key,
        next_attempt_at,occurred_at
    ) VALUES(
        NEW.tenant_scope_id,NEW.site_id,NEW.binding_revision,1,'pending',0,
        'certificate.publication/' || NEW.tenant_scope_id::text || '/' ||
            NEW.site_id::text || '/' || NEW.binding_revision::text,
        initial_time,initial_time
    );
    RETURN NULL;
END;
$$;

CREATE TRIGGER certificate_publication_intent_states_immutable_118
BEFORE UPDATE OR DELETE ON certificate_publication_intent_state_facts
FOR EACH ROW EXECUTE FUNCTION protect_certificate_publication_intent_state_118();

CREATE TRIGGER certificate_publication_intent_states_no_truncate_118
BEFORE TRUNCATE ON certificate_publication_intent_state_facts
FOR EACH STATEMENT EXECUTE FUNCTION prevent_certificate_publication_intent_state_truncate_118();

CREATE TRIGGER certificate_publication_intent_state_validate_118
BEFORE INSERT ON certificate_publication_intent_state_facts
FOR EACH ROW EXECUTE FUNCTION validate_certificate_publication_intent_state_118();

CREATE TRIGGER certificate_publication_intent_initialize_118
AFTER INSERT ON certificate_publication_intents
FOR EACH ROW EXECUTE FUNCTION initialize_certificate_publication_intent_state_118();

INSERT INTO certificate_publication_intent_state_facts(
    tenant_scope_id,site_id,binding_revision,sequence,state,attempt,idempotency_key,
    next_attempt_at,occurred_at
)
SELECT tenant_scope_id,site_id,binding_revision,1,'pending',0,
    'certificate.publication/' || tenant_scope_id::text || '/' || site_id::text || '/' || binding_revision::text,
    transaction_timestamp(),transaction_timestamp()
FROM certificate_publication_intents;
