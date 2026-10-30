DROP VIEW IF EXISTS site_realtime_access_facts_mv_v1;
DROP TABLE IF EXISTS site_realtime_access_facts_v1 SYNC;
ALTER TABLE access_events DROP COLUMN IF EXISTS listen_port;
