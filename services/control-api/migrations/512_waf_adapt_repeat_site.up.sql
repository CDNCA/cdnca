-- 512（r136 defer-small2 第 8 项；分支占位 520，merge-p9 改为 512、前驱 511，空占位 500–519 已删；
-- 常量集中在 waf_adapt_repeat_site_512_contract_test.go）。
-- WAF 灰区重复来源阈值改为站点设置（ADR 0011 §3.2a“1.0.36 可做站点级”提前）：
-- repeat_threshold / repeat_window 同为 NULL = 节点常量（edgeconfig DynamicWAFRepeatThreshold 20 /
-- DynamicWAFRepeatWindow 60）；同时设置时只下发给声明 CAPABILITY_NAME_WAF_REPEAT_SITE(64) 的节点。
-- 范围与 edgeconfig DynamicWAFRepeat{Threshold,Window}{Min,Max} 一致。
LOCK TABLE schema_migrations, waf_adapt_sites IN ACCESS EXCLUSIVE MODE;

DO $migration_512_up$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) <> 511 OR
       (SELECT count(*) FROM schema_migrations) <> 511 OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
            table_name='waf_adapt_sites' AND column_name IN ('repeat_threshold', 'repeat_window')
       ) THEN
        RAISE EXCEPTION 'migration 512 requires head 511 and waf_adapt_sites without repeat settings' USING ERRCODE='P5120';
    END IF;
END;
$migration_512_up$;

ALTER TABLE waf_adapt_sites
    ADD COLUMN repeat_threshold integer CHECK (repeat_threshold BETWEEN 2 AND 1000),
    ADD COLUMN repeat_window integer CHECK (repeat_window BETWEEN 10 AND 600),
    ADD CONSTRAINT waf_adapt_sites_repeat_pair_512 CHECK ((repeat_threshold IS NULL) = (repeat_window IS NULL));
