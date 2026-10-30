-- P0090: bind firewall event fields to the frozen realtime-monitoring authority.
-- predecessor_up_sha256=39c3c346c876ba435fd91dd35642274b85bba55230ceb0f167167c4e6850ab21
-- predecessor_down_sha256=287a8572d1a03e9a82478daada1447ac5b03875d45414c5150cd498466749d78

ALTER TABLE security_events ADD COLUMN IF NOT EXISTS method LowCardinality(String) DEFAULT '';
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS listen_port UInt16 DEFAULT 0;
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS destination_port UInt16 DEFAULT 0;
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS protocol LowCardinality(String) DEFAULT '';
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS request_class LowCardinality(String) DEFAULT '';
