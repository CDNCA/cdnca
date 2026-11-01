-- 612（r136 cert-publish-fix，COORD.md 11-01 登记 control 612，前驱 611_operator_user_foreign_keys）：
--   demo-fill 11-01：证书解绑时上一次发布从未落到节点（发布 permanent_failed、没有 rollout 或全部节点
--   失败且运行配置未变），certificatepublish 找不到解绑来源 → publication_unavailable 重试 10 次后
--   permanent_failed（"edge deployment not found"），后面的重新绑定一直排队。
--   没有东西可解绑时 intent 以 succeeded 结束，不建 rollout，noop_reason 记为 never_published。
--   120 的结果形状约束要求 succeeded 必须带 publication/rollout，改为：带完整结果，或是解绑的
--   no-op（结果全空 + noop_reason）。非 succeeded 行 noop_reason 必须为空。
LOCK TABLE schema_migrations, certificate_publication_intent_state_facts IN ACCESS EXCLUSIVE MODE;

DO $migration_612_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 611 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 611 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=611 AND
        migration_id='611_operator_user_foreign_keys' AND
        checksum_sha256='a92b1455fa9bc83ebe61b2a4ea88a146f71572e5a8e7e2c5c6cb71a1d04c72b7' AND
        down_checksum_sha256='a694197b3e44a487313de8444bd4047e85efca3c6835bc1188e67fc9b548e56d' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema()
          AND table_name='certificate_publication_intent_state_facts' AND column_name='noop_reason'
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname='certificate_publication_result_shape_120_check'
       ) THEN
        RAISE EXCEPTION 'migration 612 requires the exact verified 611 release head' USING ERRCODE='P6120';
    END IF;
END;
$migration_612_up$;

ALTER TABLE certificate_publication_intent_state_facts
    ADD COLUMN noop_reason text CHECK (noop_reason IS NULL OR noop_reason='never_published'),
    DROP CONSTRAINT certificate_publication_result_shape_120_check,
    ADD CONSTRAINT certificate_publication_result_shape_612_check CHECK (
        (state='succeeded' AND noop_reason IS NULL AND publication_id IS NOT NULL AND publication_revision>0 AND
         config_version_id IS NOT NULL AND rollout_id IS NOT NULL AND rollout_revision>0) OR
        (state='succeeded' AND noop_reason IS NOT NULL AND publication_id IS NULL AND publication_revision IS NULL AND
         config_version_id IS NULL AND rollout_id IS NULL AND rollout_revision IS NULL) OR
        (state<>'succeeded' AND noop_reason IS NULL AND publication_id IS NULL AND publication_revision IS NULL AND
         config_version_id IS NULL AND rollout_id IS NULL AND rollout_revision IS NULL)
    );

-- 只有解绑能以 no-op 结束：发布没有"无事可做"的情况。
CREATE FUNCTION validate_certificate_publication_noop_612()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.noop_reason IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM certificate_publication_intents intent
        WHERE intent.tenant_scope_id=NEW.tenant_scope_id AND intent.site_id=NEW.site_id
          AND intent.binding_revision=NEW.binding_revision AND intent.operation='unpublish'
    ) THEN
        RAISE EXCEPTION 'only a certificate unpublication can complete without a rollout' USING ERRCODE='P6123';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER certificate_publication_noop_validate_612
BEFORE INSERT ON certificate_publication_intent_state_facts
FOR EACH ROW EXECUTE FUNCTION validate_certificate_publication_noop_612();
