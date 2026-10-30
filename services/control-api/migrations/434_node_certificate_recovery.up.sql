LOCK TABLE schema_migrations, node_certificate_events, notification_event_policies, notification_templates
    IN ACCESS EXCLUSIVE MODE;

DO $migration_434_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 433 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 433 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=433 AND
        migration_id='433_market_listing_batches' AND
        checksum_sha256='838793e1383693ab9e443b7d64cacef15dac90213b186ecdbd7de0137a20387f' AND
        down_checksum_sha256='c3d43c6a5a7740499102c0b4d510203ae6cf3a37c70780d74b52502f446e1a3a' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.node_certificate_recoveries') IS NOT NULL OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type='node.certificate.recovered'
       ) THEN
        RAISE EXCEPTION 'migration 434 requires the exact verified 433 release head' USING ERRCODE='P4340';
    END IF;
END;
$migration_434_up$;

-- 434（r136 gw-01，ADR 0013 GW-02；占位，ADR 预留 434，合入时改号）。
-- Expired node certificate self-recovery: a node whose certificate expired
-- while the control plane or every gateway was unreachable signs a recovery
-- request with its existing Ed25519 key; within the recovery window the
-- control plane re-issues a certificate for the same key.
--
-- 1. A recovery is a node_certificate_renewal_requests row proven with
--    pop_status='cryptographic_proven' (pop_method='certificate_signature',
--    reserved by 036) and an issuance_kind='renewal' certificate, so every
--    reader of the renewal chain (session facts, capabilities, upgrades) is
--    unchanged.
-- 2. node_certificate_recoveries: one row per accepted recovery. nonce is
--    unique per installation (replay), the expired and issued certificates,
--    the observed peer and how long the certificate had been expired.
-- 3. node_certificate_events gains 'recovered' (related = expired cert).
-- 4. Notification event node.certificate.recovered to the platform members
--    holding nodes.manage (email on, SMS off by default).
CREATE TABLE node_certificate_recoveries (
    request_id uuid PRIMARY KEY,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    nonce bytea NOT NULL UNIQUE CHECK (octet_length(nonce) = 32),
    expired_certificate_id uuid NOT NULL,
    issued_certificate_id uuid NOT NULL UNIQUE,
    gateway_instance_id text NOT NULL CHECK (
        gateway_instance_id = btrim(gateway_instance_id) AND char_length(gateway_instance_id) BETWEEN 1 AND 128
    ),
    peer_ip inet,
    expired_for interval NOT NULL CHECK (expired_for >= interval '0'),
    recovered_at timestamptz NOT NULL,
    FOREIGN KEY (request_id, node_id)
        REFERENCES node_certificate_renewal_requests(request_id, node_id) ON DELETE CASCADE,
    FOREIGN KEY (expired_certificate_id, node_id) REFERENCES node_certificates(id, node_id) ON DELETE CASCADE,
    FOREIGN KEY (issued_certificate_id, node_id) REFERENCES node_certificates(id, node_id) ON DELETE CASCADE
);

CREATE INDEX node_certificate_recoveries_node_idx ON node_certificate_recoveries (node_id, recovered_at DESC);

CREATE FUNCTION prevent_node_certificate_recovery_mutation_434()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'node certificate recoveries are append-only';
END;
$$;

CREATE TRIGGER node_certificate_recoveries_append_only BEFORE UPDATE ON node_certificate_recoveries
    FOR EACH ROW EXECUTE FUNCTION prevent_node_certificate_recovery_mutation_434();
CREATE TRIGGER node_certificate_recoveries_append_only_del BEFORE DELETE ON node_certificate_recoveries
    FOR EACH ROW WHEN (NOT node_purge_permits(OLD.node_id))
    EXECUTE FUNCTION prevent_node_certificate_recovery_mutation_434();
CREATE TRIGGER node_certificate_recoveries_truncate_protected BEFORE TRUNCATE ON node_certificate_recoveries
    FOR EACH STATEMENT EXECUTE FUNCTION prevent_node_certificate_lifecycle_truncate();

ALTER TABLE node_certificate_events DROP CONSTRAINT node_certificate_events_check,
    DROP CONSTRAINT node_certificate_events_event_type_check,
    ADD CONSTRAINT node_certificate_events_event_type_check
        CHECK (event_type IN ('issued', 'renewed', 'revoked', 'recovered')),
    ADD CONSTRAINT node_certificate_events_check CHECK (
        (event_type = 'issued' AND related_certificate_id IS NULL AND reason IS NULL) OR
        (event_type IN ('renewed', 'recovered') AND related_certificate_id IS NOT NULL AND reason IS NULL) OR
        (event_type = 'revoked' AND related_certificate_id IS NULL AND reason IS NOT NULL AND
         reason = btrim(reason) AND char_length(reason) BETWEEN 1 AND 256)
    );

INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES ('node.certificate.recovered', true, true, true, 1, 24, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('node.certificate.recovered.zh-cn', 1, 'sms', '',
     '节点{{.node_name}}({{.node_ip}})证书已过期{{.expired_for}}，已用原密钥自动恢复，新证书到期{{.not_after}}。',
     ARRAY['node_name','node_ip','expired_for','not_after'], '2026-10-21 00:00:00+00'),
    ('node.certificate.recovered.zh-cn', 1, 'email', '节点证书过期自动恢复：{{.node_name}}',
     '节点 {{.node_name}}（{{.node_ip}}）的身份证书已过期 {{.expired_for}}（原到期 {{.expired_at}} UTC），节点于 {{.recovered_at}}（UTC）用原密钥自动恢复，新证书到期 {{.not_after}}（UTC），无需人工处理。若该节点不应再上线，请在节点详情吊销其证书。',
     ARRAY['node_name','node_ip','expired_for','expired_at','recovered_at','not_after'], '2026-10-21 00:00:00+00');

REVOKE ALL ON node_certificate_recoveries FROM PUBLIC;
GRANT SELECT, INSERT ON node_certificate_recoveries TO cdnca_control_app, cdnca_control_runtime;
