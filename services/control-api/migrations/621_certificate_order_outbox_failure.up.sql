-- 621（前驱 620）：证书申请的签发任务（dns_acme_outbox）已因不可重试的错误失败，
--   订单却仍停在 pending / validating / issuing（线上一例：所选 DNS API 没有托管该域名的解析域，
--   acme_dns_zone_unavailable 当时按可重试处理，任务 failed 等重试，订单一直 pending），证书列表 0 条、
--   再次申请被 certificate_order_in_flight 挡住、申请记录里也看不到失败原因。
--   本迁移把这类订单按调度的规则（acmeruntime.settleFailure）置 failed：
--     failure_code = 该订单最近一条签发任务的 last_error_code（只认调度的不可重试码，见下方列表，
--       与 acmeruntime.terminalFailure 一致）；
--     failure_reason = acme_dns_zone_unavailable 写中文原因（第一个没有被该 DNS API 任何解析域覆盖的域名，
--       都覆盖时取第一个域名；与 dnsacme.DNSZoneUnavailableReason 同文），其余码沿用任务的 last_error_reason；
--     revision+1；订单状态事件由 369 的触发器照常写出。
--   已是 failed 的订单（如线上已手工处理的单）不在 pending /
--   validating / issuing 里，不会被改。迁移不写 audit_events（哈希链在应用层计算），也不改任务行：
--   调度认领会跳过订单已 failed 的任务。
LOCK TABLE schema_migrations, certificate_orders, dns_acme_outbox IN ACCESS EXCLUSIVE MODE;

DO $migration_621_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 620 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 620 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=620 AND migration_id='620_http_policy_orphan_cleanup' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (SELECT 1 FROM information_schema.columns
           WHERE table_schema = current_schema() AND table_name = 'certificate_orders' AND column_name = 'failure_reason') THEN
        RAISE EXCEPTION 'migration 621 requires the verified 620 release head with certificate_orders.failure_reason (567)'
            USING ERRCODE='P6210';
    END IF;
END;
$migration_621_up$;

WITH latest AS (
    SELECT DISTINCT ON (outbox.scope_id, outbox.aggregate_id)
        outbox.scope_id, outbox.aggregate_id, outbox.status, outbox.last_error_code, outbox.last_error_reason
    FROM dns_acme_outbox outbox
    WHERE outbox.aggregate_type = 'certificate_order'
    ORDER BY outbox.scope_id, outbox.aggregate_id, outbox.updated_at DESC, outbox.id DESC
), stuck AS (
    SELECT certificate_order.scope_id, certificate_order.id, latest.last_error_code AS code,
        CASE WHEN latest.last_error_code = 'acme_dns_zone_unavailable' THEN
            format('所选 DNS API 下没有托管 %s 的解析域，无法用 DNS 验证；请添加该域名所在 DNS 服务商的 API，或改用 HTTP 验证',
                COALESCE((
                    SELECT regexp_replace(domain.name, '^\*\.', '')
                    FROM unnest(certificate_order.domains) WITH ORDINALITY AS domain(name, position)
                    WHERE NOT EXISTS (
                        SELECT 1 FROM dns_zones zone
                        WHERE zone.scope_id = certificate_order.scope_id
                          AND zone.provider_id = certificate_order.dns_provider_id
                          AND (regexp_replace(domain.name, '^\*\.', '') = zone.name OR
                               right(regexp_replace(domain.name, '^\*\.', ''), char_length(zone.name) + 1) = '.' || zone.name))
                    ORDER BY domain.position LIMIT 1),
                    regexp_replace(certificate_order.domains[1], '^\*\.', '')))
        ELSE latest.last_error_reason END AS reason
    FROM certificate_orders certificate_order
    JOIN latest ON latest.scope_id = certificate_order.scope_id AND latest.aggregate_id = certificate_order.id
    WHERE certificate_order.status IN ('pending', 'validating', 'issuing')
      AND latest.status = 'failed'
      AND latest.last_error_code IN (
          'acme_dns_zone_unavailable', 'acme_dns_provider_platform_managed', 'acme_renewal_skipped_auto_renew_off',
          'acme_authorization_invalid', 'acme_order_rejected', 'acme_http01_node_aggregate_required',
          'acme_http01_node_unsupported', 'acme_http01_no_serving_node', 'acme_eab_required')
)
UPDATE certificate_orders certificate_order SET
    status = 'failed', failure_code = stuck.code, failure_reason = stuck.reason,
    revision = certificate_order.revision + 1,
    updated_at = greatest(certificate_order.updated_at, statement_timestamp())
FROM stuck
WHERE certificate_order.scope_id = stuck.scope_id AND certificate_order.id = stuck.id;
