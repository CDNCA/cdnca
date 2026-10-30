LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_371_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 370 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 370 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=370 AND
        migration_id='370_plugin_webhook_site_filter' AND
        checksum_sha256='3798ab70a98f87506e28f20a2bcfaaa285f4719d9f317da49c1bd61445114346' AND
        down_checksum_sha256='82f5c6601402f57afbc5bc45be513108fe306e22ea9839547a3b39123ca1ff09' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR (SELECT count(*) FROM notification_event_policies
             WHERE event_type IN ('certificate.expiring','certificate.expired') AND NOT supported) <> 2 OR EXISTS (
        SELECT 1 FROM notification_templates
        WHERE template_id IN ('certificate.expiring.zh-cn','certificate.expired.zh-cn')
       ) THEN
        RAISE EXCEPTION 'migration 371 requires the exact verified 370 release head' USING ERRCODE='P3710';
    END IF;
END;
$migration_371_up$;

-- PA-24: certificate expiry. The expiry scanner records one fact per
-- (certificate version, stage) when the active version of a tenant
-- certificate asset comes within 30/7/1 days of not_after, and once more when
-- it has expired. The primary key makes every stage happen exactly once, and
-- the insert trigger appends the public domain event in the same transaction.
LOCK TABLE certificate_asset_versions, plugin_webhook_event_contracts_122, domain_event_types_368,
    domain_event_contract_fields_368, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

-- Notification center: certificate.expiring (30/7/1 days) and
-- certificate.expired were seeded unsupported by 200; the expiry scanner now
-- produces them for the certificate owner under their own subscription.
UPDATE notification_event_policies
SET supported=true, enabled=true, sms_enabled=true, email_enabled=true, default_email=true, updated_at=now()
WHERE event_type IN ('certificate.expiring', 'certificate.expired');

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('certificate.expiring.zh-cn', 1, 'sms', '',
     '证书{{.certificate_name}}将于{{.not_after}}到期(剩余约{{.days_left}}天)，请及时续期或更换。',
     ARRAY['certificate_name','not_after','days_left','domains'], '2026-10-18 00:00:00+00'),
    ('certificate.expiring.zh-cn', 1, 'email', '证书即将到期：{{.certificate_name}}',
     '证书 {{.certificate_name}}（域名：{{.domains}}）将于 {{.not_after}} 到期，剩余约 {{.days_left}} 天。到期后使用该证书的网站将无法正常提供 HTTPS 访问，请及时续期或上传新证书。',
     ARRAY['certificate_name','not_after','days_left','domains'], '2026-10-18 00:00:00+00'),
    ('certificate.expired.zh-cn', 1, 'sms', '',
     '证书{{.certificate_name}}已于{{.not_after}}过期，使用该证书的网站HTTPS访问会受影响，请尽快更换。',
     ARRAY['certificate_name','not_after','domains'], '2026-10-18 00:00:00+00'),
    ('certificate.expired.zh-cn', 1, 'email', '证书已过期：{{.certificate_name}}',
     '证书 {{.certificate_name}}（域名：{{.domains}}）已于 {{.not_after}} 过期。使用该证书的网站 HTTPS 访问会受影响，请尽快续期或上传新证书。',
     ARRAY['certificate_name','not_after','domains'], '2026-10-18 00:00:00+00');

INSERT INTO plugin_webhook_event_contracts_122(event_type, schema_uri, status, max_data_fields) VALUES
    ('io.cdnca.certificate.v1.expiry_reached',
     'https://schemas.cdnca.example/marketplace/v1/domain-event.schema.json', 'active', 16);

INSERT INTO domain_event_types_368(event_type, subject_kind, required_permission, site_bound) VALUES
    ('io.cdnca.certificate.v1.expiry_reached', 'certificate_asset', 'events.certificate.read', false);

INSERT INTO domain_event_contract_fields_368(event_type, field_name, kind, required, allowed_values) VALUES
    ('io.cdnca.certificate.v1.expiry_reached', 'asset_id', 'uuid', true, NULL),
    ('io.cdnca.certificate.v1.expiry_reached', 'version_id', 'uuid', true, NULL),
    ('io.cdnca.certificate.v1.expiry_reached', 'stage', 'string', true,
        ARRAY['expiring_30d','expiring_7d','expiring_1d','expired']),
    ('io.cdnca.certificate.v1.expiry_reached', 'not_after', 'timestamp', true, NULL),
    ('io.cdnca.certificate.v1.expiry_reached', 'source', 'string', true, ARRAY['uploaded','acme']),
    ('io.cdnca.certificate.v1.expiry_reached', 'renewal_order_id', 'uuid', false, NULL);

CREATE TABLE certificate_expiry_facts_371 (
    tenant_scope_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    version_id uuid NOT NULL,
    stage text NOT NULL CHECK (stage IN ('expiring_30d','expiring_7d','expiring_1d','expired')),
    not_after timestamptz NOT NULL CHECK (isfinite(not_after)),
    observed_at timestamptz NOT NULL CHECK (isfinite(observed_at)),
    PRIMARY KEY (tenant_scope_id, version_id, stage),
    FOREIGN KEY (tenant_scope_id, asset_id, version_id)
        REFERENCES certificate_asset_versions(tenant_scope_id, asset_id, id) ON DELETE RESTRICT,
    -- A stage is recorded only once the threshold has actually been reached.
    CHECK (observed_at >= not_after - CASE stage
        WHEN 'expiring_30d' THEN interval '30 days' WHEN 'expiring_7d' THEN interval '7 days'
        WHEN 'expiring_1d' THEN interval '1 day' ELSE interval '0' END)
);

CREATE FUNCTION protect_certificate_expiry_fact_371()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'certificate expiry facts are append-only' USING ERRCODE='P3711';
END;
$$;

CREATE TRIGGER certificate_expiry_facts_protect_371
BEFORE UPDATE OR DELETE ON certificate_expiry_facts_371
FOR EACH ROW EXECUTE FUNCTION protect_certificate_expiry_fact_371();

CREATE FUNCTION emit_certificate_expiry_event_371()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    certificate record;
BEGIN
    SELECT asset.source, v.not_after, v.acme_order_id INTO certificate
    FROM certificate_asset_versions v
    JOIN certificate_assets asset ON asset.tenant_scope_id=v.tenant_scope_id AND asset.id=v.asset_id
    WHERE v.tenant_scope_id=NEW.tenant_scope_id AND v.asset_id=NEW.asset_id AND v.id=NEW.version_id;
    IF certificate.not_after IS DISTINCT FROM NEW.not_after THEN
        RAISE EXCEPTION 'certificate expiry fact does not match the version' USING ERRCODE='P3712';
    END IF;
    PERFORM domain_event_append_368(gen_random_uuid(), 'io.cdnca.certificate.v1.expiry_reached',
        NEW.tenant_scope_id, NULL, 'certificate_asset/' || NEW.asset_id::text,
        'certificate_expiry/' || NEW.version_id::text || '/' || NEW.stage, NEW.observed_at,
        jsonb_strip_nulls(jsonb_build_object('asset_id', NEW.asset_id::text, 'version_id', NEW.version_id::text,
            'stage', NEW.stage, 'not_after', domain_event_timestamp_369(NEW.not_after),
            'source', certificate.source, 'renewal_order_id', certificate.acme_order_id::text)));
    RETURN NULL;
END;
$$;

CREATE TRIGGER certificate_expiry_facts_emit_event_371
AFTER INSERT ON certificate_expiry_facts_371
FOR EACH ROW EXECUTE FUNCTION emit_certificate_expiry_event_371();

-- The scanner walks active versions by not_after.
CREATE INDEX certificate_asset_versions_not_after_371
    ON certificate_asset_versions (not_after, tenant_scope_id, asset_id, id);

REVOKE ALL ON certificate_expiry_facts_371 FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_certificate_expiry_fact_371(), emit_certificate_expiry_event_371() FROM PUBLIC;
GRANT SELECT, INSERT ON certificate_expiry_facts_371 TO cdnca_control_app, cdnca_control_runtime;
