LOCK TABLE schema_migrations, sites, autodefense_report_receipts, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_423_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 422 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 422 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=422 AND
        migration_id='422_node_security_xdp_alerts' AND
        checksum_sha256='2464075f330342eb8dc3aeab8371ba0465711bc820678d1d8b7b235bea82c6c5' AND
        down_checksum_sha256='a1adaf5012a11bde72bf5290bea9225a73b881635a6e251c82e8b53d624a7e0d' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.waf_adapt_exclusions') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 423 requires the exact verified 422 release head' USING ERRCODE='P4230';
    END IF;
END;
$migration_423_up$;

-- 415（r136 ri-06，预留号 419：合入时改号）。Adaptive WAF on the control
-- plane (ADR 0011 sections 3.3, 3.4, 4.2): nodes report waf_evidence hourly;
-- the control plane only adds their counts up (no profile, no sample, no
-- original report), promotes site x rule x parameter exclusions through
-- shadow (72 hours) to active (30 days, platform settings) and delivers them
-- with the typed parameters in the autodefense snapshot (waf_adapt).

-- Per site: the grey zone challenge switch (inherit = the platform default)
-- the daily activation counter (at most 4 new active exclusions a day) and
-- the revision of the site's waf_adapt (raised on every change: the
-- snapshot distributor rebuilds on it).
CREATE TABLE waf_adapt_sites (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    grey_challenge text NOT NULL DEFAULT 'inherit' CHECK (grey_challenge IN ('inherit', 'on', 'off')),
    activation_day date,
    activations smallint NOT NULL DEFAULT 0 CHECK (activations BETWEEN 0 AND 32),
    evaluated_at timestamptz CHECK (evaluated_at IS NULL OR isfinite(evaluated_at)),
    revision bigint NOT NULL CHECK (revision > 0),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (tenant_scope_id, site_id),
    FOREIGN KEY (tenant_scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE
);

-- One row per site x rule x parameter (ADR waf_adapt_candidates):
--   stage: candidate (evidence merged, not promoted: below the thresholds,
--     frozen, capped or cooling down) /
--     shadow (delivered, counts what it would flip) / suggested (passed
--     the shadow period without module.autodefense.auto or with the waf
--     module not "智能自动": shown, "采纳" makes it manual) / active
--     (delivered into t=) / rejected (a person rejected or revoked it);
--   manual: none (automatic) / exclude (a person adopted or set the
--     exclusion: delivered active, renewed, never changed automatically) /
--     keep (a person locked the parameter without exclusion);
--   flipped / flipped_attack: the node exclusion results summed over the
--     current shadow or active period;
--   rejections: person rejections; 3 = permanent (never proposed again).
CREATE TABLE waf_adapt_exclusions (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    rule_id integer NOT NULL CHECK (rule_id BETWEEN 900000 AND 999999),
    location text NOT NULL CHECK (location IN ('args', 'cookie', 'header')),
    name text NOT NULL CHECK (name ~ '^[A-Za-z0-9_.\[\]-]{1,64}$'),
    exclusion_id text NOT NULL CHECK (exclusion_id ~ '^[0-9a-f]{16}$'),
    param_key text NOT NULL CHECK (param_key ~ '^[0-9a-f]{16}$'),
    value_type text NOT NULL CHECK (value_type IN ('number', 'ident', 'text', 'json', 'binary', 'url')),
    len_bucket smallint NOT NULL CHECK (len_bucket BETWEEN 0 AND 7),
    charset integer NOT NULL CHECK (charset BETWEEN 0 AND 8191),
    stage text NOT NULL CHECK (stage IN ('candidate', 'shadow', 'suggested', 'active', 'rejected')),
    stage_since timestamptz NOT NULL CHECK (isfinite(stage_since)),
    until timestamptz CHECK (until IS NULL OR until > stage_since),
    manual text NOT NULL DEFAULT 'none' CHECK (manual IN ('none', 'exclude', 'keep')),
    manual_by text CHECK (manual_by IS NULL OR length(manual_by) BETWEEN 1 AND 128),
    manual_at timestamptz,
    rejections smallint NOT NULL DEFAULT 0 CHECK (rejections BETWEEN 0 AND 3),
    cooldown_until timestamptz,
    -- day_bits: bit d = the rule hit the parameter d days before last_day
    -- (unix day), the nodes' days bitmaps ORed (16 days).
    day_bits integer NOT NULL CHECK (day_bits BETWEEN 1 AND 65535),
    last_day integer NOT NULL CHECK (last_day > 0),
    flipped bigint NOT NULL DEFAULT 0 CHECK (flipped >= 0),
    flipped_attack bigint NOT NULL DEFAULT 0 CHECK (flipped_attack >= 0 AND flipped_attack <= flipped),
    first_seen timestamptz NOT NULL CHECK (isfinite(first_seen)),
    last_seen timestamptz NOT NULL CHECK (last_seen >= first_seen),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (tenant_scope_id, site_id, rule_id, location, name),
    UNIQUE (tenant_scope_id, site_id, exclusion_id),
    FOREIGN KEY (tenant_scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE,
    CHECK ((stage IN ('shadow', 'active')) = (until IS NOT NULL)),
    CHECK ((manual = 'none') = (manual_by IS NULL AND manual_at IS NULL)),
    CHECK (manual <> 'exclude' OR stage = 'active')
);

-- The added-up counts of each row per UTC report day (unix day): every node
-- and report of the day summed, the source bitmaps ORed. Kept 16 days.
CREATE TABLE waf_adapt_evidence (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    rule_id integer NOT NULL,
    location text NOT NULL,
    name text NOT NULL,
    day integer NOT NULL CHECK (day > 0),
    hits bigint NOT NULL CHECK (hits >= 0),
    challenged bigint NOT NULL CHECK (challenged >= 0),
    passed bigint NOT NULL CHECK (passed >= 0),
    failed_sources bigint NOT NULL CHECK (failed_sources >= 0),
    clean bigint NOT NULL CHECK (clean >= 0),
    attack_after bigint NOT NULL CHECK (attack_after >= 0),
    sources bigint NOT NULL,
    -- the exclusion results of the day (shadow or active on the nodes).
    flipped bigint NOT NULL CHECK (flipped >= 0),
    flipped_attack bigint NOT NULL CHECK (flipped_attack >= 0),
    PRIMARY KEY (tenant_scope_id, site_id, rule_id, location, name, day),
    FOREIGN KEY (tenant_scope_id, site_id, rule_id, location, name)
        REFERENCES waf_adapt_exclusions(tenant_scope_id, site_id, rule_id, location, name) ON DELETE CASCADE
);

-- The parameters' dominant clean types as the nodes report them (ADR
-- waf_adapt_typed_params), per parameter key: conflict = two reports
-- disagreed on the type, which keeps the parameter untyped for good; clean
-- and sources are the largest clean count of one rule per report summed
-- and the source bitmaps ORed; day_bits / last_day as above.
CREATE TABLE waf_adapt_typed_params (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    param_key text NOT NULL CHECK (param_key ~ '^[0-9a-f]{16}$'),
    value_type text NOT NULL CHECK (value_type IN ('number', 'ident', 'text', 'json', 'binary', 'url')),
    max_len_bucket smallint NOT NULL CHECK (max_len_bucket BETWEEN 0 AND 7),
    charset integer NOT NULL CHECK (charset BETWEEN 0 AND 8191),
    conflict boolean NOT NULL,
    clean bigint NOT NULL CHECK (clean >= 0),
    sources bigint NOT NULL,
    day_bits integer NOT NULL CHECK (day_bits BETWEEN 1 AND 65535),
    last_day integer NOT NULL CHECK (last_day > 0),
    first_seen timestamptz NOT NULL,
    last_seen timestamptz NOT NULL CHECK (last_seen >= first_seen),
    PRIMARY KEY (tenant_scope_id, site_id, param_key),
    FOREIGN KEY (tenant_scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE
);

-- The ingest receipt of a waf_evidence report (node + site + seq idempotency).
ALTER TABLE autodefense_report_receipts DROP CONSTRAINT autodefense_report_receipts_kind_check;
ALTER TABLE autodefense_report_receipts ADD CONSTRAINT autodefense_report_receipts_kind_check
    CHECK (kind IN ('minute', 'state', 'candidate', 'verdicts', 'adjust', 'node_event', 'drift', 'waf_evidence'));

REVOKE ALL ON waf_adapt_sites, waf_adapt_exclusions, waf_adapt_evidence, waf_adapt_typed_params FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON waf_adapt_sites, waf_adapt_exclusions, waf_adapt_evidence, waf_adapt_typed_params
    TO cdnca_control_app, cdnca_control_runtime;

-- Notices (FX65 channel): an exclusion went active, was revoked or expired.
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported, default_email, updated_at
) VALUES ('security.waf.auto_exclusion_active', true, false, true, 1, 1, true, true, now()),
         ('security.waf.auto_exclusion_revoked', true, false, true, 1, 1, true, true, now()),
         ('security.waf.auto_exclusion_expired', true, false, true, 1, 1, true, true, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('security.waf.auto_exclusion_active.zh-cn', 1, 'email', 'WAF 自动排除已生效：{{.domain}}',
     '网站 {{.domain}} 的参数 {{.param}} 不再按 WAF 规则 {{.rule}} 检测（影子期验证通过，有效至 {{.until}}）。强分规则、检测器与形态检查仍然生效；可在控制台“WAF / 智能自动”撤销。',
     ARRAY['domain','param','rule','until'], '2026-10-20 00:00:00+00'),
    ('security.waf.auto_exclusion_revoked.zh-cn', 1, 'email', 'WAF 自动排除已撤销：{{.domain}}',
     '网站 {{.domain}} 的参数 {{.param}} 已恢复按 WAF 规则 {{.rule}} 检测（原因：{{.reason}}）。',
     ARRAY['domain','param','rule','reason'], '2026-10-20 00:00:00+00'),
    ('security.waf.auto_exclusion_expired.zh-cn', 1, 'email', 'WAF 自动排除已到期：{{.domain}}',
     '网站 {{.domain}} 的参数 {{.param}} 对 WAF 规则 {{.rule}} 的自动排除已到期（近 7 天证据不足以续期），规则恢复检测。',
     ARRAY['domain','param','rule'], '2026-10-20 00:00:00+00');
