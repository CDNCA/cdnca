DROP VIEW IF EXISTS security_event_evidence_mv_v1;
DROP TABLE IF EXISTS security_event_evidence_state_v1;
ALTER TABLE security_events DROP COLUMN IF EXISTS request_body_excerpt;
ALTER TABLE security_events DROP COLUMN IF EXISTS user_agent;
ALTER TABLE security_events DROP COLUMN IF EXISTS matched;
ALTER TABLE security_events DROP COLUMN IF EXISTS detector;
ALTER TABLE security_events DROP COLUMN IF EXISTS policy_id;
