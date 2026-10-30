-- r136 l4-attr (027 占位，合入时主会话改号): an L4 session fact names the
-- package subscription its forward belonged to in the release that served it
-- (L4SessionEventV1.package_subscription_id, L4_PACKAGE_ATTRIBUTION), so a
-- forward moved to another package keeps its past bytes on the old one. The
-- nil UUID is a forward without a package. 1.0.35 is a fresh install: no
-- backfill.
ALTER TABLE l4_session_facts_v1
    ADD COLUMN IF NOT EXISTS package_subscription_id UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000') AFTER stream_id;
