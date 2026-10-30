ALTER TABLE security_events DROP COLUMN IF EXISTS request_class;
ALTER TABLE security_events DROP COLUMN IF EXISTS protocol;
ALTER TABLE security_events DROP COLUMN IF EXISTS destination_port;
ALTER TABLE security_events DROP COLUMN IF EXISTS listen_port;
ALTER TABLE security_events DROP COLUMN IF EXISTS method;
