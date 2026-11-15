-- 670（安全激活恢复回滚单在途、退避与放弃通知）；前驱 669_security_activation_recovery_platform_nodes。
-- 原来恢复回滚失败后每个 reconcile 轮次立刻再建一条、不限次数。改为（internal/securityactivation recovery_attempts.go）：
--   1. 同一候选同一时刻最多一个在途恢复回滚；
--   2. 每次新建恢复回滚记一次尝试（security_activation_recovery_attempts_670），失败后按尝试次数退避
--      （1、2、4、8 分钟）再试，第 5 次仍失败即放弃；
--   3. 放弃时记 security_activation_recovery_failures_670（每候选一行，worker 不再处理该候选），并给持
--      platform.admin 的平台成员发 security_activation.recovery_failed（短信+邮件 zh-cn v1，进管理员站内消息）。
-- 本迁移前写入的恢复回滚不在尝试表里，不计入次数：上线后按第 1 次尝试重新开始。
LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;
LOCK TABLE security_policy_activation_recovery_rollouts IN SHARE ROW EXCLUSIVE MODE;

DO $migration_670_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 669 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 669 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=669 AND
        migration_id='669_security_activation_recovery_platform_nodes' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type='security_activation.recovery_failed'
       ) THEN
        RAISE EXCEPTION 'migration 670 requires the exact verified 669 release head' USING ERRCODE='P6700';
    END IF;
END;
$migration_670_up$;

CREATE TABLE security_activation_recovery_attempts_670 (
    candidate_id uuid NOT NULL,
    rollout_id uuid NOT NULL UNIQUE,
    attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 100),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (candidate_id, rollout_id),
    FOREIGN KEY (candidate_id, rollout_id)
        REFERENCES security_policy_activation_recovery_rollouts(candidate_id, rollout_id) ON DELETE RESTRICT
);
CREATE INDEX security_activation_recovery_attempts_670_latest
    ON security_activation_recovery_attempts_670 (candidate_id, attempt DESC);

CREATE TABLE security_activation_recovery_failures_670 (
    candidate_id uuid PRIMARY KEY REFERENCES security_policy_activation_candidates(id) ON DELETE RESTRICT,
    attempts integer NOT NULL CHECK (attempts BETWEEN 1 AND 100),
    failed_at timestamptz NOT NULL
);

REVOKE ALL ON security_activation_recovery_attempts_670, security_activation_recovery_failures_670 FROM PUBLIC;
GRANT SELECT, INSERT ON security_activation_recovery_attempts_670, security_activation_recovery_failures_670
    TO cdnca_control_app, cdnca_control_runtime;

INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES
    ('security_activation.recovery_failed', true, true, true, 1, 1, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('security_activation.recovery_failed.zh-cn', 1, 'sms', '',
     '网站{{.site_domain}}的安全策略灰度回滚连续{{.attempts}}次失败，已停止自动回滚，请尽快处理。',
     ARRAY['site_domain','candidate_id','attempts','occurred_at'], '2026-11-15 00:00:00+00'),
    ('security_activation.recovery_failed.zh-cn', 1, 'email', '安全策略灰度回滚失败：{{.site_domain}}',
     '网站 {{.site_domain}} 的安全策略灰度（候选 {{.candidate_id}}）结束后，把节点恢复到原配置的回滚连续 {{.attempts}} 次失败，系统已于 {{.occurred_at}}（UTC）停止自动重试。部分节点可能仍在运行该候选配置。请到「部署记录」查看回滚部署的失败原因，处理后重新发布该网站。',
     ARRAY['site_domain','candidate_id','attempts','occurred_at'], '2026-11-15 00:00:00+00');
