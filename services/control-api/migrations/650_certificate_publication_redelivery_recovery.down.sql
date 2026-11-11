-- 650 回退：恢复 612 的结果形状约束与 120 的状态校验，去掉 recovered_by_rollout_id。
-- 状态事实只追加：已有补发恢复的 succeeded 在旧约束下不成立，拒绝回滚。
LOCK TABLE schema_migrations, certificate_publication_intent_state_facts IN ACCESS EXCLUSIVE MODE;

DO $migration_650_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 650 OR
       (SELECT max(version) FROM schema_migrations) <> 650 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=650 AND
        migration_id='650_certificate_publication_redelivery_recovery' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 650 down requires the exact verified migration head' USING ERRCODE='P6572';
    END IF;
    IF EXISTS (SELECT 1 FROM certificate_publication_intent_state_facts WHERE recovered_by_rollout_id IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 650 rollback would drop certificate publications recovered by redelivery'
            USING ERRCODE='P6573';
    END IF;
END;
$migration_650_down$;

ALTER TABLE certificate_publication_intent_state_facts
    DROP CONSTRAINT certificate_publication_recovery_rollout_650_fk,
    DROP CONSTRAINT certificate_publication_result_shape_650_check,
    ADD CONSTRAINT certificate_publication_result_shape_612_check CHECK (
        (state='succeeded' AND noop_reason IS NULL AND publication_id IS NOT NULL AND publication_revision>0 AND
         config_version_id IS NOT NULL AND rollout_id IS NOT NULL AND rollout_revision>0) OR
        (state='succeeded' AND noop_reason IS NOT NULL AND publication_id IS NULL AND publication_revision IS NULL AND
         config_version_id IS NULL AND rollout_id IS NULL AND rollout_revision IS NULL) OR
        (state<>'succeeded' AND noop_reason IS NULL AND publication_id IS NULL AND publication_revision IS NULL AND
         config_version_id IS NULL AND rollout_id IS NULL AND rollout_revision IS NULL)
    ),
    DROP COLUMN recovered_by_rollout_id;

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
