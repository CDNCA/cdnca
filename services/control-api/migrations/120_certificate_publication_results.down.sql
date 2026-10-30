LOCK TABLE schema_migrations,
    certificate_publication_intents,
    certificate_publication_intent_state_facts,
    auth_sessions
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 120 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 120 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=120 AND migration_id='120_certificate_publication_results'
          AND checksum_sha256='8bad0019496e9f47fa92c66bf1b432d2ded681f9049717ef830cd4364923e9f0'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 120 rollback requires the exact verified 120 head'
            USING ERRCODE='P1200';
    END IF;
    IF EXISTS (
        SELECT 1 FROM certificate_publication_intents
        WHERE actor_session_id IS NOT NULL OR actor_scope_kind IS NOT NULL OR actor_user_revision IS NOT NULL
           OR target_tenant_id IS NOT NULL OR target_tenant_revision IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM certificate_publication_intent_state_facts
        WHERE publication_id IS NOT NULL OR config_version_id IS NOT NULL OR rollout_id IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 120 rollback would discard certificate publication actor or result facts'
            USING ERRCODE='P1202';
    END IF;
    IF EXISTS (
        SELECT 1 FROM certificate_publication_intent_state_facts WHERE sequence>1
    ) THEN
        RAISE EXCEPTION 'migration 120 rollback would discard certificate publication worker facts'
            USING ERRCODE='P1202';
    END IF;
END;
$$;

DROP TRIGGER certificate_publication_result_validate_120 ON certificate_publication_intent_state_facts;
DROP FUNCTION validate_certificate_publication_result_120();
ALTER TABLE certificate_publication_intent_state_facts
    DROP CONSTRAINT certificate_publication_intent_state_facts_check,
    DROP COLUMN publication_id,
    DROP COLUMN publication_revision,
    DROP COLUMN config_version_id,
    DROP COLUMN rollout_id,
    DROP COLUMN rollout_revision,
    ADD CONSTRAINT certificate_publication_intent_state_facts_check CHECK (
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
    );

CREATE OR REPLACE FUNCTION validate_certificate_publication_intent_state_118()
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

DROP TRIGGER certificate_publication_actor_validate_120 ON certificate_publication_intents;
DROP FUNCTION validate_certificate_publication_actor_120();
ALTER TABLE certificate_publication_intents
    DROP CONSTRAINT certificate_publication_deadline_120_check,
    DROP COLUMN deadline_at;
ALTER TABLE certificate_publication_intents
    DROP COLUMN actor_session_id,
    DROP COLUMN actor_scope_kind,
    DROP COLUMN actor_user_revision,
    DROP COLUMN target_tenant_id,
    DROP COLUMN target_tenant_revision;

ALTER TABLE auth_sessions
    DROP CONSTRAINT auth_sessions_certificate_actor_120_unique;
