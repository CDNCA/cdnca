SELECT pg_advisory_xact_lock(1229016321, 1);

LOCK TABLE
    package_monitor_subscription_owners,
    package_monitor_evaluation_clocks,
    package_monitor_policy_versions,
    package_monitor_policy_templates,
    package_monitor_policy_heads,
    package_monitor_alert_heads,
    package_monitor_transition_facts,
    package_monitor_evaluation_receipts,
    background_jobs,
    notification_events,
    notification_templates,
    notification_outbox,
    audit_events
IN ACCESS EXCLUSIVE MODE NOWAIT;

DO $$
DECLARE
    blocked boolean;
BEGIN
    SELECT
        EXISTS (SELECT 1 FROM package_monitor_alert_heads)
        OR EXISTS (SELECT 1 FROM package_monitor_transition_facts)
        OR EXISTS (SELECT 1 FROM package_monitor_evaluation_receipts)
        OR EXISTS (SELECT 1 FROM package_monitor_evaluation_clocks)
        OR EXISTS (SELECT 1 FROM package_monitor_policy_versions)
        OR EXISTS (SELECT 1 FROM package_monitor_policy_templates)
        OR EXISTS (SELECT 1 FROM package_monitor_policy_heads)
        OR EXISTS (
            SELECT 1
            FROM package_monitor_subscription_owners
            WHERE NOT migration_backfilled
        )
        OR EXISTS (
            SELECT 1
            FROM background_jobs AS job
            WHERE job.kind = 'package.monitor.evaluate.v1'
               OR (
                   EXISTS (SELECT 1 FROM background_job_attempts AS attempt
                           WHERE attempt.job_id = job.id)
                   AND job.kind = 'package.monitor.evaluate.v1'
               )
               OR (
                   EXISTS (SELECT 1 FROM background_job_results AS result
                           WHERE result.job_id = job.id)
                   AND job.kind = 'package.monitor.evaluate.v1'
               )
        )
        OR EXISTS (
            SELECT 1
            FROM notification_events AS event
            WHERE event.event_type LIKE 'package.monitor.%'
        )
        OR EXISTS (
            SELECT 1
            FROM notification_outbox AS outbox
            LEFT JOIN notification_events AS event
              ON event.scope_id = outbox.scope_id AND event.id = outbox.event_id
            WHERE event.event_type LIKE 'package.monitor.%'
               OR (
                   outbox.template_version = 1
                   AND outbox.template_id IN (
                       'package.monitor.traffic.triggered.zh-cn',
                       'package.monitor.traffic.recovered.zh-cn',
                       'package.monitor.bandwidth.triggered.zh-cn',
                       'package.monitor.bandwidth.recovered.zh-cn',
                       'package.monitor.connections.triggered.zh-cn',
                       'package.monitor.connections.recovered.zh-cn',
                       'package.monitor.expiration.triggered.zh-cn',
                       'package.monitor.expiration.recovered.zh-cn'
                   )
               )
        )
        OR EXISTS (
            SELECT 1
            FROM audit_events AS event
            WHERE event.action LIKE 'package_monitor.alert.%'
               OR event.action = 'package_monitor.evaluation.commit'
        )
    INTO blocked;

    IF blocked THEN
        RAISE EXCEPTION 'package_monitor_runtime_facts_prevent_rollback'
            USING ERRCODE = 'P7809';
    END IF;

    IF EXISTS (
        WITH expected(template_id, channel, sha256) AS (
            VALUES
                ('package.monitor.traffic.triggered.zh-cn', 'sms', decode('eaff1a2f04b9b71c1957bbde237f96330e2a2da5ced4136fae13c9d91b6c3865', 'hex')),
                ('package.monitor.traffic.triggered.zh-cn', 'email', decode('a58da2d20580f20a586811287f47f28a33875daf78cb1b2b64f6eb366e9c1753', 'hex')),
                ('package.monitor.traffic.recovered.zh-cn', 'sms', decode('b3c7b68dec06f22d5a4f0bccc259d7baac349bea96088e776810f72d5e05693f', 'hex')),
                ('package.monitor.traffic.recovered.zh-cn', 'email', decode('6659ddde47c97d90d18db05446c8ff6a8e96613f0e06fa39d2037bf47382c9fd', 'hex')),
                ('package.monitor.bandwidth.triggered.zh-cn', 'sms', decode('48caa68232dd7ad2091bf2bb382ee633391b1d601d5fba6b2874ca6b90291034', 'hex')),
                ('package.monitor.bandwidth.triggered.zh-cn', 'email', decode('6c285978a3a77b711b82178732699f5e6594b2b8ae073c6492161c7a9e1b5362', 'hex')),
                ('package.monitor.bandwidth.recovered.zh-cn', 'sms', decode('bff18c0b4b40a2370352a4e0191ec2e0861e63f6fbe415ea00a0276ffa673959', 'hex')),
                ('package.monitor.bandwidth.recovered.zh-cn', 'email', decode('d36497ec486250e93d998435dd127e58d59a85a44f1dfee036a1c67893c1d91b', 'hex')),
                ('package.monitor.connections.triggered.zh-cn', 'sms', decode('20efd9b6e163436457e6411bed5e28dec2a01be19d8160ca40abb20fd83baacf', 'hex')),
                ('package.monitor.connections.triggered.zh-cn', 'email', decode('f734d7c29147ed234a53ad4a378b323c9b62245cf4af986c5783e190ecb2f1dd', 'hex')),
                ('package.monitor.connections.recovered.zh-cn', 'sms', decode('ac57877b34ba8ec3b54e96e945aeffa49d22bc0d4dd4e1e8f84cd9d0c447e5a6', 'hex')),
                ('package.monitor.connections.recovered.zh-cn', 'email', decode('05192bfd65277330643382a4de007b83ba2ec60ad4e134b31fe0ff9bff1daa1c', 'hex')),
                ('package.monitor.expiration.triggered.zh-cn', 'sms', decode('e3cb133a0c58151647c54625e4279030eb30003e91a01f577f8c308959d881c5', 'hex')),
                ('package.monitor.expiration.triggered.zh-cn', 'email', decode('a9c579d084ac8966f1c35c278a043974abfcbe0ec757f7b1c12c3f231cc06916', 'hex')),
                ('package.monitor.expiration.recovered.zh-cn', 'sms', decode('c8ac8e12ddac393a081581a2c67e5fdda97d87801f36553331ed46d793c9b131', 'hex')),
                ('package.monitor.expiration.recovered.zh-cn', 'email', decode('5cbd400f78031406156a153dec149967bc6919c9a704c263a38fa0bb6a297ca6', 'hex'))
        ), actual(template_id, channel, sha256) AS (
            SELECT template.template_id, template.channel,
                   package_monitor_template_sha256_078(
                       template.body, template.channel, template.subject,
                       template.template_id, template.variables, template.version
                   )
            FROM notification_templates AS template
            WHERE template.version = 1
              AND template.template_id IN (
                  'package.monitor.traffic.triggered.zh-cn',
                  'package.monitor.traffic.recovered.zh-cn',
                  'package.monitor.bandwidth.triggered.zh-cn',
                  'package.monitor.bandwidth.recovered.zh-cn',
                  'package.monitor.connections.triggered.zh-cn',
                  'package.monitor.connections.recovered.zh-cn',
                  'package.monitor.expiration.triggered.zh-cn',
                  'package.monitor.expiration.recovered.zh-cn'
              )
        )
        SELECT 1
        FROM (
            (SELECT * FROM expected EXCEPT SELECT * FROM actual)
            UNION ALL
            (SELECT * FROM actual EXCEPT SELECT * FROM expected)
        ) AS drift
    ) THEN
        RAISE EXCEPTION 'package_monitor_runtime_facts_prevent_rollback'
            USING ERRCODE = 'P7809';
    END IF;
END;
$$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates
WHERE version = 1
  AND template_id IN (
      'package.monitor.traffic.triggered.zh-cn',
      'package.monitor.traffic.recovered.zh-cn',
      'package.monitor.bandwidth.triggered.zh-cn',
      'package.monitor.bandwidth.recovered.zh-cn',
      'package.monitor.connections.triggered.zh-cn',
      'package.monitor.connections.recovered.zh-cn',
      'package.monitor.expiration.triggered.zh-cn',
      'package.monitor.expiration.recovered.zh-cn'
  );
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;

DROP TRIGGER audit_events_package_monitor_transition_078 ON audit_events;
DROP TRIGGER audit_events_package_monitor_receipt_078 ON audit_events;
DROP TRIGGER audit_events_package_monitor_clock_078 ON audit_events;
DROP TRIGGER package_monitor_evaluation_receipts_audit_078 ON package_monitor_evaluation_receipts;
DROP TRIGGER package_monitor_evaluation_receipts_head_consistent_078 ON package_monitor_evaluation_receipts;
DROP TRIGGER package_monitor_evaluation_receipts_current_head_078 ON package_monitor_evaluation_receipts;
DROP TRIGGER package_monitor_evaluation_receipts_00_clock_078 ON package_monitor_evaluation_receipts;
DROP TRIGGER package_monitor_alert_heads_receipt_consistent_078 ON package_monitor_alert_heads;
DROP TRIGGER package_monitor_transition_facts_00_clock_078 ON package_monitor_transition_facts;
DROP TRIGGER package_monitor_transition_facts_audit_078 ON package_monitor_transition_facts;
DROP TRIGGER package_monitor_transition_facts_head_consistent_078 ON package_monitor_transition_facts;
DROP TRIGGER package_monitor_alert_heads_fact_consistent_078 ON package_monitor_alert_heads;
DROP TRIGGER package_monitor_alert_heads_no_truncate_078 ON package_monitor_alert_heads;
DROP TRIGGER package_monitor_alert_heads_protect_078 ON package_monitor_alert_heads;
DROP TRIGGER package_monitor_alert_heads_00_clock_078 ON package_monitor_alert_heads;
DROP TRIGGER package_monitor_policy_heads_no_truncate_078 ON package_monitor_policy_heads;
DROP TRIGGER package_monitor_policy_heads_protect_078 ON package_monitor_policy_heads;
DROP TRIGGER package_monitor_transition_facts_immutable_078 ON package_monitor_transition_facts;
DROP TRIGGER package_monitor_evaluation_receipts_immutable_078 ON package_monitor_evaluation_receipts;
DROP TRIGGER package_monitor_evaluation_clocks_immutable_078 ON package_monitor_evaluation_clocks;
DROP TRIGGER package_monitor_evaluation_clocks_bind_078 ON package_monitor_evaluation_clocks;
DROP TRIGGER package_monitor_policy_templates_immutable_078 ON package_monitor_policy_templates;
DROP TRIGGER package_monitor_policy_versions_immutable_078 ON package_monitor_policy_versions;
DROP TRIGGER package_monitor_subscription_owners_immutable_078 ON package_monitor_subscription_owners;
DROP TRIGGER package_monitor_subscription_owners_provenance_078 ON package_monitor_subscription_owners;
DROP TRIGGER package_monitor_subscription_owners_validate_078 ON package_monitor_subscription_owners;

DROP TABLE package_monitor_evaluation_receipts;
DROP TABLE package_monitor_transition_facts;
DROP TABLE package_monitor_alert_heads;
DROP TABLE package_monitor_evaluation_clocks;
DROP TABLE package_monitor_policy_heads;
DROP TABLE package_monitor_policy_templates;
DROP TABLE package_monitor_policy_versions;
DROP TABLE package_monitor_subscription_owners;

DROP FUNCTION validate_package_monitor_audit_078();
DROP FUNCTION validate_package_monitor_receipt_audit_078();
DROP FUNCTION validate_package_monitor_head_receipt_078();
DROP FUNCTION validate_package_monitor_new_receipt_078();
DROP FUNCTION validate_package_monitor_head_fact_078();
DROP FUNCTION validate_package_monitor_evaluation_clock_078();
DROP FUNCTION package_monitor_transaction_clock_078();
DROP FUNCTION bind_package_monitor_evaluation_clock_078();
DROP FUNCTION bind_package_monitor_audit_clock_078();
DROP FUNCTION package_monitor_audit_hash_078(
    uuid, uuid, bigint, uuid, text, text, text, text, text, jsonb, bytea, timestamptz
);
DROP FUNCTION package_monitor_rfc3339nano_078(timestamptz);
DROP FUNCTION package_monitor_json_canonical_078(jsonb);
DROP FUNCTION package_monitor_go_json_string_078(text);
DROP FUNCTION protect_package_monitor_alert_head_078();
DROP FUNCTION protect_package_monitor_policy_head_078();
DROP FUNCTION prevent_package_monitor_immutable_078();
DROP FUNCTION validate_package_monitor_owner_provenance_078();
DROP FUNCTION validate_package_monitor_owner_078();
DROP FUNCTION package_monitor_threshold_sha256_078(uuid, bigint, text, numeric, numeric, bigint);
DROP FUNCTION package_monitor_template_sha256_078(text, text, text, text, text[], bigint);

DROP INDEX audit_events_package_monitor_identity_078;
DROP INDEX notification_events_monitor_exact_078;
DROP INDEX package_subscription_state_versions_owner_exact_078;
