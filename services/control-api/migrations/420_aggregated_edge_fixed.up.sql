LOCK TABLE schema_migrations, aggregated_edge_site_schedules, aggregated_edge_line_targets,
    aggregated_edge_switch_events, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_420_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 419 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 419 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=419 AND
        migration_id='419_official_rule_pack_enablement' AND
        checksum_sha256='946e4a466fd59cfe0d24eefe819f544f3bd26293e7b8ff03ad1e7cf4f864bb4c' AND
        down_checksum_sha256='991d8645e2aaadc71c3741c28813fb788fb4534c46804fabd1851521768558a3' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type='aggregated_edge.schedule.alert'
       ) THEN
        RAISE EXCEPTION 'migration 420 requires the exact verified 419 release head' USING ERRCODE='P4200';
    END IF;
END;
$migration_420_up$;

-- Aggregated edge strategy fixed (ADR 0008 §6.3 固定, ae-fixed): a line stays
-- on its designated supply; probes keep running and only alert. An unhealthy
-- current supply with a healthy alternative is alert current_unhealthy (switch
-- history reason current_unhealthy, like all_unhealthy it records the alert,
-- not a DNS change); manual switching is unchanged.
--
-- Origin gating (ae-fixed, 用户 10-20): failover first asks whether the
-- origin is up (originfailover PoolStatus.Overall, migration 419's probes). origin_unhealthy: the current supply failed and so did the
-- origin, nothing switches; edge_all_unhealthy: every supply failed while the
-- origin is up (all_unhealthy stays for an unknown origin). alert_kept /
-- freeze_kept: the operator chose 保持 for the current alert / freeze (reset
-- when the alert changes / on unfreeze).
ALTER TABLE aggregated_edge_site_schedules DROP CONSTRAINT aggregated_edge_site_schedules_strategy_check;
ALTER TABLE aggregated_edge_site_schedules ADD CONSTRAINT aggregated_edge_site_schedules_strategy_420_check
    CHECK (strategy IN ('failover', 'quality', 'fixed'));
ALTER TABLE aggregated_edge_site_schedules ADD COLUMN freeze_kept boolean NOT NULL DEFAULT false;
ALTER TABLE aggregated_edge_line_targets DROP CONSTRAINT aggregated_edge_line_targets_alert_check;
ALTER TABLE aggregated_edge_line_targets ADD CONSTRAINT aggregated_edge_line_targets_alert_420_check
    CHECK (alert IN ('', 'all_unhealthy', 'current_unhealthy', 'origin_unhealthy', 'edge_all_unhealthy'));
ALTER TABLE aggregated_edge_line_targets ADD COLUMN alert_kept boolean NOT NULL DEFAULT false;
ALTER TABLE aggregated_edge_switch_events DROP CONSTRAINT aggregated_edge_switch_events_reason_394_check;
ALTER TABLE aggregated_edge_switch_events ADD CONSTRAINT aggregated_edge_switch_events_reason_420_check
    CHECK (reason IN ('failover', 'failback', 'quality', 'manual', 'unbind', 'bind', 'freeze', 'unfreeze',
        'all_unhealthy', 'current_unhealthy', 'origin_unhealthy', 'edge_all_unhealthy', 'recovered'));

-- Notification center: scheduling alerts needing a decision (platform
-- operations event, to platform members holding edge.aggregated.manage).
-- link is the console path of the site's schedule page.
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES ('aggregated_edge.schedule.alert', true, true, true, 1, 24, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('aggregated_edge.schedule.alert.zh-cn', 1, 'sms', '',
     '聚合边缘告警：站点{{.site_domain}}线路{{.line}}：{{.alert_text}}（源站：{{.origin}}），请到后台处理：{{.link}}',
     ARRAY['site_domain','line','alert_text','origin','link'], '2026-10-20 00:00:00+00'),
    ('aggregated_edge.schedule.alert.zh-cn', 1, 'email', '聚合边缘告警：{{.site_domain}}',
     '站点 {{.site_domain}} 的线路 {{.line}}：{{.alert_text}}。源站状态：{{.origin}}。请打开调度页 {{.link}} 选择切到某个供给或保持当前指向（冻结时可解冻并切换或保持冻结）。',
     ARRAY['site_domain','line','alert_text','origin','link'], '2026-10-20 00:00:00+00');
