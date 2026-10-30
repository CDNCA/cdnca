LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_347_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 346 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 346 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=346 AND
        migration_id='346_acme_http01_node_purge' AND
        checksum_sha256='7fda0b7754abf4a43e4d7ff9e3760a2cb125b1a88a98c676c827d4bf56f57972' AND
        down_checksum_sha256='a5b4033a06efbf85a9b5f23364621201f27d31198ab346d6b24ca75d8d174831' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (SELECT 1 FROM notification_event_policies WHERE event_type='acme.http01.epoch_drift') THEN
        RAISE EXCEPTION 'migration 347 requires the exact verified 346 release head' USING ERRCODE='P3470';
    END IF;
END;
$migration_347_up$;

-- ADR-0003 epoch membership drift: a node that joins a site's line group
-- while the site's HTTP-01 epoch is open stays out of the site's serving set
-- until the epoch closes. Platform members holding nodes.manage are told once
-- per epoch and drifting node set. Email only by default (it resolves itself
-- when the epoch closes); SMS can be switched on in the delivery policy.
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported, updated_at
) VALUES ('acme.http01.epoch_drift', true, false, true, 1, 1, true, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('acme.http01.epoch_drift.zh-cn', 1, 'sms', '',
     '站点{{.site_domain}}证书验证期间新加入{{.node_count}}个节点({{.node_names}})，验证结束前暂不参与该站点解析。',
     ARRAY['site_domain','node_count','node_names','epoch_opened_at'], '2026-10-18 00:00:00+00'),
    ('acme.http01.epoch_drift.zh-cn', 1, 'email', 'HTTP-01 证书验证期间节点暂不参与解析',
     '站点{{.site_domain}}的 HTTP-01 证书验证周期（开始于{{.epoch_opened_at}}）冻结了参与节点，期间新加入线路组的{{.node_count}}个节点（{{.node_names}}）在验证结束前不参与该站点的解析。验证结束（全部 challenge 撤回或过期）后自动恢复，无需处理；长期不恢复请检查该站点的证书签发任务。',
     ARRAY['site_domain','node_count','node_names','epoch_opened_at'], '2026-10-18 00:00:00+00');
