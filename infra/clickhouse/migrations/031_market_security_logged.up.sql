-- 031: the observe-only WAF / CC decisions
-- (action log) of a relayed leaf window, in requests, on its summary row
-- (secdigest Extension.logged). events / blocked / challenged / banned keep
-- counting enforced decisions only, as attack alerts sum them. Rows stored
-- before this, or relayed by a leaf that does not send it, read 0.
ALTER TABLE market_security_events_v1
    ADD COLUMN IF NOT EXISTS logged UInt64 DEFAULT 0 AFTER banned;
