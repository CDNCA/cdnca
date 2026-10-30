LOCK TABLE schema_migrations, memberships, identity_write_requests, notification_event_policies,
    notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_305_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 304 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 304 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=304 AND
        migration_id='304_announcement_late_join_recipients' AND
        checksum_sha256='ed7e177bd4e9528f777771652491ee6f341b0aeeba6fdf41887d34946413c7b0' AND
        down_checksum_sha256='8bd6a2fbff34ea7c3c0dfd1e073c2db18bb3ee032b2c303fe71ff1dec86a92b7' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass(current_schema() || '.identity_user_secondary_verification') IS NOT NULL OR
       NOT EXISTS (SELECT 1 FROM notification_event_policies
        WHERE event_type='identity.secondary_verification' AND NOT supported) THEN
        RAISE EXCEPTION 'migration 305 requires the exact verified 304 release head' USING ERRCODE='P3050';
    END IF;
END;
$migration_305_up$;

-- Administrator-requested secondary identity verification (FX57). The user must
-- repeat personal verification with the first approved identity document
-- (identityverification personal_reverification). requested_at marks the
-- request; an approved reverification after it completes the request.
CREATE TABLE identity_user_secondary_verification (
    scope_id uuid NOT NULL,
    user_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    enabled boolean NOT NULL,
    deadline timestamptz CHECK (deadline IS NULL OR isfinite(deadline)),
    expiry_action text NOT NULL CHECK (expiry_action IN ('none','lock_sites')),
    requested_at timestamptz CHECK (requested_at IS NULL OR isfinite(requested_at)),
    enforced_at timestamptz CHECK (enforced_at IS NULL OR isfinite(enforced_at)),
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (scope_id,user_id),
    FOREIGN KEY (scope_id,user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    CHECK (NOT enabled OR requested_at IS NOT NULL),
    CHECK (enabled OR enforced_at IS NULL),
    CHECK (expiry_action = 'none' OR deadline IS NOT NULL)
);

CREATE INDEX identity_user_secondary_verification_due_305_idx
    ON identity_user_secondary_verification (deadline)
    WHERE enabled AND enforced_at IS NULL AND expiry_action = 'lock_sites';

ALTER TABLE identity_write_requests
    DROP CONSTRAINT identity_write_requests_operation_check,
    ADD CONSTRAINT identity_write_requests_operation_check CHECK (operation IN (
        'identity.user.create','identity.user.update','identity.self.update','identity.membership.suspend',
        'identity.user.password.reset','identity.user.delete','identity.user.login_security.update',
        'identity.user.secondary_verification.update'
    ));

-- 201 switched unsupported events off; now supported, restore the 200 seed defaults.
UPDATE notification_event_policies SET supported=true, enabled=true, sms_enabled=true, email_enabled=true, updated_at=now()
WHERE event_type='identity.secondary_verification';

INSERT INTO notification_templates(template_id,version,channel,subject,body,variables,created_at) VALUES
    ('identity_secondary_verification',1,'email','二次实名认证通知',
     '<p>您好，{{.username}}。平台要求您使用首次实名认证的身份证完成二次实名认证，截止时间：{{.deadline}}。逾期未完成可能导致网站被锁定。</p>',
     ARRAY['username','deadline'],now()),
    ('identity_secondary_verification',1,'sms','',
     '您好，平台要求您使用首次实名认证的身份证完成二次实名认证，截止时间：{{.deadline}}。',
     ARRAY['deadline'],now())
ON CONFLICT (template_id,version,channel) DO NOTHING;

REVOKE ALL ON identity_user_secondary_verification FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON identity_user_secondary_verification TO cdnca_control_app, cdnca_control_runtime;
