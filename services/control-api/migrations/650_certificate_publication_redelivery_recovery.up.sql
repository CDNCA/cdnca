-- 证书补发器把站点证书送到了全部节点，控制台仍显示
--   permanent_failed（补发器不回写意图状态，redelivery.go:312-317），只能由运维同版本重新绑定一次。
--   permanent_failed 之后允许追加一条 succeeded，结果写 recovered_by_rollout_id（补发 rollout，
--   certificate-redelivery. 前缀、同范围、有 healthy 部署），发布结果各列为空，租约列为补发器自己的
--   （lease_owner=certificate-redelivery，lease_expires_at=occurred_at）；只用于 publish。
--   (certificate_publication_intent_state_facts 追加 recovered_by_rollout_id)
LOCK TABLE schema_migrations, certificate_publication_intent_state_facts IN ACCESS EXCLUSIVE MODE;

DO $migration_650_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 649 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 649 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=649 AND
        migration_id='649_edge_publication_left_out_nodes' AND
        checksum_sha256='2687543f7ffb5cfc8baddbb51bcfc2e421beca6d3f37379398e2cbc80118193e' AND
        down_checksum_sha256='6196466aa443af87197df04b53cfdfdc199b1a624f33f52464fadc6eb40bb0a4' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='certificate_publication_intent_state_facts'
          AND column_name='recovered_by_rollout_id'
       ) THEN
        RAISE EXCEPTION 'migration 650 requires the exact verified 649 release head' USING ERRCODE='P6500';
    END IF;
END;
$migration_650_up$;

ALTER TABLE certificate_publication_intent_state_facts
    ADD COLUMN recovered_by_rollout_id uuid,
    ADD CONSTRAINT certificate_publication_recovery_rollout_650_fk
        FOREIGN KEY (tenant_scope_id,recovered_by_rollout_id)
        REFERENCES rollouts(configuration_scope_id,id) ON DELETE RESTRICT,
    DROP CONSTRAINT certificate_publication_result_shape_612_check,
    ADD CONSTRAINT certificate_publication_result_shape_650_check CHECK (
        (state='succeeded' AND noop_reason IS NULL AND publication_id IS NOT NULL AND publication_revision>0 AND
         config_version_id IS NOT NULL AND rollout_id IS NOT NULL AND rollout_revision>0 AND recovered_by_rollout_id IS NULL) OR
        (state='succeeded' AND noop_reason IS NOT NULL AND publication_id IS NULL AND publication_revision IS NULL AND
         config_version_id IS NULL AND rollout_id IS NULL AND rollout_revision IS NULL AND recovered_by_rollout_id IS NULL) OR
        (state='succeeded' AND noop_reason IS NULL AND recovered_by_rollout_id IS NOT NULL AND publication_id IS NULL AND
         publication_revision IS NULL AND config_version_id IS NULL AND rollout_id IS NULL AND rollout_revision IS NULL) OR
        (state<>'succeeded' AND noop_reason IS NULL AND publication_id IS NULL AND publication_revision IS NULL AND
         config_version_id IS NULL AND rollout_id IS NULL AND rollout_revision IS NULL AND
         recovered_by_rollout_id IS NULL)
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
    ELSIF previous.state='permanent_failed' AND NEW.state='succeeded' AND NEW.recovered_by_rollout_id IS NOT NULL THEN
        -- 650：补发器把证书送到了站点的全部节点，失败的发布以 succeeded 结束（不再发布）。
        -- 失败可能是没有租约的 legacy_reissue_required：租约列固定为补发器自己的（succeeded 的形状要求非空）。
        IF NEW.attempt<>previous.attempt OR NEW.lease_owner IS DISTINCT FROM 'certificate-redelivery' OR
           NEW.lease_token IS NULL OR NEW.lease_expires_at IS DISTINCT FROM NEW.occurred_at OR
           intent.operation<>'publish' OR NOT EXISTS (
            SELECT 1 FROM rollouts rollout
            JOIN node_deployments deployment ON deployment.rollout_id=rollout.id AND deployment.state='healthy'
            WHERE rollout.id=NEW.recovered_by_rollout_id AND rollout.configuration_scope_id=NEW.tenant_scope_id
              AND starts_with(rollout.idempotency_key,'certificate-redelivery.')
           ) THEN
            RAISE EXCEPTION 'certificate publication recovery is invalid' USING ERRCODE='P6501';
        END IF;
    ELSE
        RAISE EXCEPTION 'invalid certificate publication intent state transition' USING ERRCODE='P1181';
    END IF;
    RETURN NEW;
END;
$$;
