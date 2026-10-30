LOCK TABLE schema_migrations,
    certificate_publication_intents,
    certificate_publication_intent_state_facts,
    auth_sessions,
    users,
    access_scopes,
    memberships,
    tenants,
    config_versions,
    rollouts
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 119 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 119 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=119 AND migration_id='119_cache_cancelled_report_facts'
          AND checksum_sha256='2a7e7b88433941e3e9eae3567476d261efb5382d9a1dca4900e852a2dcd6b318'
          AND down_checksum_sha256='06305ea2ffdf4260a788a475e803a037f449b5ae939449632c8967d269992b22'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 120 requires the exact verified 119 release head'
            USING ERRCODE='P1200';
    END IF;
END;
$$;

ALTER TABLE certificate_publication_intents
    ADD COLUMN actor_session_id uuid,
    ADD COLUMN actor_scope_kind text,
    ADD COLUMN actor_user_revision bigint,
    ADD COLUMN target_tenant_id uuid,
    ADD COLUMN target_tenant_revision bigint,
    ADD COLUMN deadline_at timestamptz;

-- 116 makes publication intents append-only. The deadline is a derived
-- backfill for pre-120 rows, so suspend only that guard for this update.
ALTER TABLE certificate_publication_intents
    DISABLE TRIGGER certificate_publication_intents_immutable_116;
UPDATE certificate_publication_intents
SET deadline_at=created_at+interval '1 hour'
WHERE deadline_at IS NULL;
ALTER TABLE certificate_publication_intents
    ENABLE TRIGGER certificate_publication_intents_immutable_116;

ALTER TABLE certificate_publication_intents
    ALTER COLUMN deadline_at SET NOT NULL,
    ADD CONSTRAINT certificate_publication_deadline_120_check
        CHECK (deadline_at>created_at AND isfinite(deadline_at));

ALTER TABLE auth_sessions
    ADD CONSTRAINT auth_sessions_certificate_actor_120_unique
        UNIQUE (id,scope_id,user_id);

ALTER TABLE certificate_publication_intents
    ADD CONSTRAINT certificate_publication_actor_kind_120_check
        CHECK (actor_session_id IS NULL OR actor_scope_kind IN ('tenant','platform')),
    ADD CONSTRAINT certificate_publication_actor_revision_120_check
        CHECK (actor_session_id IS NULL OR (actor_user_revision > 0 AND target_tenant_revision > 0)),
    ADD CONSTRAINT certificate_publication_actor_session_120_fk
        FOREIGN KEY (actor_session_id,actor_scope_id,actor_user_id)
        REFERENCES auth_sessions(id,scope_id,user_id) ON DELETE RESTRICT,
    ADD CONSTRAINT certificate_publication_target_tenant_120_fk
        FOREIGN KEY (target_tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

CREATE FUNCTION validate_certificate_publication_actor_120()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_scope_kind text;
    current_tenant_id uuid;
    current_user_revision bigint;
    current_tenant_revision bigint;
BEGIN
    IF NEW.actor_session_id IS NULL THEN
        IF NEW.actor_scope_kind IS NOT NULL OR NEW.actor_user_revision IS NOT NULL OR
           NEW.target_tenant_id IS NOT NULL OR NEW.target_tenant_revision IS NOT NULL THEN
            RAISE EXCEPTION 'certificate publication legacy actor reference is incomplete'
                USING ERRCODE='P1201';
        END IF;
        RETURN NEW;
    END IF;
    SELECT kind INTO current_scope_kind FROM access_scopes WHERE id=NEW.actor_scope_id FOR KEY SHARE;
    SELECT tenant_id INTO current_tenant_id FROM access_scopes WHERE id=NEW.tenant_scope_id FOR KEY SHARE;
    SELECT revision INTO current_user_revision FROM users WHERE id=NEW.actor_user_id FOR KEY SHARE;
    SELECT revision INTO current_tenant_revision FROM tenants WHERE id=current_tenant_id FOR KEY SHARE;
    IF current_scope_kind IS DISTINCT FROM NEW.actor_scope_kind OR current_tenant_id IS NULL OR
       current_tenant_id IS DISTINCT FROM NEW.target_tenant_id OR
       current_user_revision IS DISTINCT FROM NEW.actor_user_revision OR
       current_tenant_revision IS DISTINCT FROM NEW.target_tenant_revision OR NOT EXISTS (
        SELECT 1 FROM auth_sessions session_row
        JOIN users account ON account.id=session_row.user_id AND account.status='active'
        JOIN memberships membership ON membership.scope_id=session_row.scope_id
            AND membership.user_id=session_row.user_id AND membership.status='active'
        WHERE session_row.id=NEW.actor_session_id AND session_row.scope_id=NEW.actor_scope_id
          AND session_row.user_id=NEW.actor_user_id AND session_row.revoked_at IS NULL
          AND session_row.replaced_by_id IS NULL AND session_row.expires_at>transaction_timestamp()
    ) THEN
        RAISE EXCEPTION 'certificate publication actor reference is not current'
            USING ERRCODE='P1201';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER certificate_publication_actor_validate_120
BEFORE INSERT ON certificate_publication_intents
FOR EACH ROW EXECUTE FUNCTION validate_certificate_publication_actor_120();

ALTER TABLE certificate_publication_intent_state_facts
    DROP CONSTRAINT certificate_publication_intent_state_facts_check,
    ADD COLUMN publication_id uuid,
    ADD COLUMN publication_revision bigint,
    ADD COLUMN config_version_id uuid,
    ADD COLUMN rollout_id uuid,
    ADD COLUMN rollout_revision bigint,
    ADD CONSTRAINT certificate_publication_result_shape_120_check CHECK (
        (state='succeeded' AND publication_id IS NOT NULL AND publication_revision>0 AND
         config_version_id IS NOT NULL AND rollout_id IS NOT NULL AND rollout_revision>0) OR
        (state<>'succeeded' AND publication_id IS NULL AND publication_revision IS NULL AND
         config_version_id IS NULL AND rollout_id IS NULL AND rollout_revision IS NULL)
    ),
    ADD CONSTRAINT certificate_publication_result_config_120_fk
        FOREIGN KEY (tenant_scope_id,config_version_id)
        REFERENCES config_versions(configuration_scope_id,id) ON DELETE RESTRICT,
    ADD CONSTRAINT certificate_publication_result_rollout_120_fk
        FOREIGN KEY (tenant_scope_id,rollout_id)
        REFERENCES rollouts(configuration_scope_id,id) ON DELETE RESTRICT;

ALTER TABLE certificate_publication_intent_state_facts
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
        (state='permanent_failed' AND failure_code IS NOT NULL AND
            ((lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL) OR
             (failure_code='legacy_reissue_required' AND lease_owner IS NULL AND lease_token IS NULL
                AND lease_expires_at IS NULL)))
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
    IF NEW.sequence<>previous.sequence+1 OR NEW.idempotency_key IS DISTINCT FROM previous.idempotency_key THEN
        RAISE EXCEPTION 'invalid certificate publication intent state revision' USING ERRCODE='P1181';
    END IF;
    IF NEW.state='permanent_failed' AND NEW.failure_code='legacy_reissue_required' AND
       NEW.lease_owner IS NULL AND NEW.lease_token IS NULL AND NEW.lease_expires_at IS NULL THEN
        IF previous.state NOT IN ('pending','leased','retry_wait') OR NEW.attempt<1 THEN
            RAISE EXCEPTION 'invalid legacy certificate publication terminalization' USING ERRCODE='P1181';
        END IF;
        RETURN NEW;
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
          AND previous_latest.state NOT IN ('succeeded','permanent_failed')
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

INSERT INTO certificate_publication_intent_state_facts(
    tenant_scope_id,site_id,binding_revision,sequence,state,attempt,idempotency_key,
    next_attempt_at,failure_code,occurred_at
)
SELECT intent.tenant_scope_id,intent.site_id,intent.binding_revision,latest.sequence+1,
    'permanent_failed',GREATEST(latest.attempt,1),latest.idempotency_key,NULL,
    'legacy_reissue_required',transaction_timestamp()
FROM certificate_publication_intents intent
JOIN LATERAL (
    SELECT sequence,state,attempt,idempotency_key
    FROM certificate_publication_intent_state_facts state
    WHERE state.tenant_scope_id=intent.tenant_scope_id AND state.site_id=intent.site_id
      AND state.binding_revision=intent.binding_revision
    ORDER BY sequence DESC LIMIT 1
) latest ON true
WHERE latest.state NOT IN ('succeeded','permanent_failed');

CREATE FUNCTION validate_certificate_publication_result_120()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    stored_config_id uuid;
    stored_rollout_revision bigint;
BEGIN
    IF NEW.state<>'succeeded' THEN
        RETURN NEW;
    END IF;
    SELECT config_version_id,revision INTO stored_config_id,stored_rollout_revision
    FROM rollouts WHERE configuration_scope_id=NEW.tenant_scope_id AND id=NEW.rollout_id FOR KEY SHARE;
    IF stored_config_id IS DISTINCT FROM NEW.config_version_id OR
       stored_rollout_revision IS DISTINCT FROM NEW.rollout_revision OR
       NEW.publication_revision IS DISTINCT FROM NEW.rollout_revision THEN
        RAISE EXCEPTION 'certificate publication result identity is inconsistent'
            USING ERRCODE='P1201';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER certificate_publication_result_validate_120
BEFORE INSERT ON certificate_publication_intent_state_facts
FOR EACH ROW EXECUTE FUNCTION validate_certificate_publication_result_120();
