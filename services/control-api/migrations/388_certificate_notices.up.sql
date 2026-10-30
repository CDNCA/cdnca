LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_388_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 387 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 387 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=387 AND
        migration_id='387_site_tls_profile' AND
        checksum_sha256='d045cb76567eff8bba1d935f3921722678aeed08ce42a8ff291a4451d381c386' AND
        down_checksum_sha256='aa21887d5a8dc806aed7333985a5a0919171c3ccd6434ce242936435ca1c412c' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR (SELECT count(*) FROM notification_event_policies
             WHERE event_type IN ('certificate.expiring','certificate.expired') AND supported) <> 2 OR
          EXISTS (SELECT 1 FROM notification_event_policies WHERE event_type='certificate.renew_failed') THEN
        RAISE EXCEPTION 'migration 388 requires the exact verified 387 release head' USING ERRCODE='P3880';
    END IF;
END;
$migration_388_up$;

-- r136 ge-tls (GoEdge 对照缺失 6): failed automatic renewals into the
-- notification center (internal/certnotify RenewFailedTx), to the
-- certificate's owner and the tenant's members holding certificates.manage.
-- certificate.expiring / certificate.expired and their templates come from
-- 371 (PA-24); certnotify sends them on the platform notice days
-- (系统设置 > 其他设置, default 30/14/7/3/1) with the same variables.
INSERT INTO notification_event_policies(event_type, enabled, sms_enabled, email_enabled, repeat_count,
    interval_hours, supported, default_email, default_sms, updated_at) VALUES
    ('certificate.renew_failed', true, true, true, 1, 24, true, true, false, now());
INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('certificate.renew_failed.zh-cn', 1, 'sms', '',
     '证书（{{.domains}}）自动续期失败：{{.reason}}。现有证书{{.not_after}}到期，系统会继续重试。',
     ARRAY['domains','reason','not_after'], '2026-10-18 00:00:00+00'),
    ('certificate.renew_failed.zh-cn', 1, 'email', '证书自动续期失败',
     '证书（{{.domains}}）的自动续期失败，原因：{{.reason}}。现有证书将于{{.not_after}}到期，系统会按退避间隔继续重试；如原因是验证或签发机构凭据问题，请先处理后在证书页重新申请。',
     ARRAY['domains','reason','not_after'], '2026-10-18 00:00:00+00');
