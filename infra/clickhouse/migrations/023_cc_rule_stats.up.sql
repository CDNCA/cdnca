-- cc-metrics (023; 022 is ge-waf security_event_evidence): CC rule
-- statistics the nodes report (cc_stats, cdnca.autodefense.report/v1). Read
-- by the CC page (manual tuning) and by automatic defense (user 10-19 14:10:
-- one upstream for both).
--
-- One row per report row: the counts a node saw for one site, CC policy,
-- rule and minute since its previous report. Queries sum them (FINAL first:
-- row_id is derived from node, seq and index, so a redelivered report
-- replaces its own rows instead of counting twice). rule_id is the nil UUID
-- for site level counts outside any rule.
CREATE TABLE IF NOT EXISTS cc_rule_stats_v1
(
    tenant_id UUID,
    site_id UUID,
    policy_id String,
    policy_version UInt64,
    rule_id UUID,
    minute DateTime('UTC'),
    node_id UUID,
    row_id UUID,
    matched UInt64,
    triggered UInt64,
    challenged UInt64,
    blocked UInt64,
    passed UInt64,
    ja4_unavailable UInt64,
    top_clients Map(String, UInt64),
    top_paths Map(String, UInt64),
    report_seq UInt64,
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMMDD(minute)
ORDER BY (tenant_id, site_id, minute, rule_id, row_id)
TTL minute + INTERVAL 35 DAY DELETE;
