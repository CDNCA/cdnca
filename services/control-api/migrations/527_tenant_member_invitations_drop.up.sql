LOCK TABLE schema_migrations, notification_events, notification_outbox, notification_templates,
    tenant_member_invitations_398, tenant_member_password_reset_results, certificate_assets IN ACCESS EXCLUSIVE MODE;

DO $migration_527_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 526 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 526 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=526 AND
        migration_id='526_cache_cancel_deliveries' AND
        checksum_sha256='a8072a592d876d9a710dc0b9efd3c6e3ec1805897c41ce58e40e78c9840f6b0b' AND
        down_checksum_sha256='13d617fc73f2411420a930185aabd38d5059fcf7fd1f23e6ceaaaa5fcbf3a9b0' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 527 requires the exact verified 526 release head' USING ERRCODE='P5270';
    END IF;
    -- 1.0.35 是全新安装，不该有任何邀请或邀请邮件；有就说明不是全新库，停下而不是悄悄丢数据。
    IF EXISTS (SELECT 1 FROM tenant_member_invitations_398) OR
       EXISTS (SELECT 1 FROM notification_events WHERE event_type='identity.tenant_member_invitation') OR
       EXISTS (SELECT 1 FROM notification_outbox WHERE template_id='tenant_member_invitation') THEN
        RAISE EXCEPTION 'migration 527 found tenant member invitation history' USING ERRCODE='P5271';
    END IF;
END;
$migration_527_up$;

-- 527（r136 fz-x9b；分支本地 527，派单占位 529，合入时按集成头改号，P527x 随号改）。
-- 团队成员与成员邀请接口在 1.0.35 删除（用户 10-26 02:5x，fz-x9 删 9 个写接口，fz-x9b 删邀请接受）。
-- 这里删掉只服务它们的库对象：
--   398：tenant_member_invitations_398 表（连同索引、guard 触发器）、guard_tenant_member_invitations_398()、
--        邮件模板 tenant_member_invitation，匿名事件 CHECK 去掉 identity.tenant_member_invitation（回到 198 的定义）；
--   487：tenant_member_password_reset_results 表（成员重置密码结果留存）；
--   409：protect_certificate_asset_owner_276() 里"成员移交证书"放行分支（cdnca.tenant_member_handover，
--        已无代码设置），恢复 276 原定义。
-- 保留（还有别处在用）：409 的 users.password_change_required（迁移导入旧密码、登录改密门禁在用）、
-- 409 对 validate_certificate_asset_actor_target_085() 的改动（更新时不再复核已删除的创建者，与成员接口无关）。

DROP TABLE tenant_member_invitations_398;
DROP FUNCTION guard_tenant_member_invitations_398();
DROP TABLE tenant_member_password_reset_results;
ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id='tenant_member_invitation' AND version=1 AND channel='email';
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;

ALTER TABLE notification_events
    DROP CONSTRAINT notification_events_recipient_one_of_049,
    ADD CONSTRAINT notification_events_recipient_one_of_049 CHECK (
        (
            recipient_kind = 'member' AND
            recipient_user_id IS NOT NULL AND
            anonymous_dispatch_reference IS NULL AND
            event_type <> 'identity.account_recovery'
        ) OR (
            recipient_kind = 'anonymous' AND
            recipient_user_id IS NULL AND
            anonymous_dispatch_reference IS NOT NULL AND
            anonymous_dispatch_reference <> '00000000-0000-0000-0000-000000000000'::uuid AND
            event_type IN (
                'identity.account_recovery',
                'identity.account_registration_verification',
                'identity.account_login_verification'
            ) AND
            delivery_policy = 'system_required'
        )
    );

CREATE OR REPLACE FUNCTION protect_certificate_asset_owner_276() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.owner_user_id IS DISTINCT FROM OLD.owner_user_id THEN
        RAISE EXCEPTION 'certificate asset owner is immutable' USING ERRCODE='P2761';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION protect_certificate_asset_owner_276() FROM PUBLIC,cdnca_control_app;
