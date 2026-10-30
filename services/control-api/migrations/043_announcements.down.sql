LOCK TABLE announcements, announcement_versions, announcement_audience_users,
    announcement_audience_groups, announcement_recipient_snapshots,
    announcement_inbox_events, announcement_inbox_states, announcement_write_requests,
    announcement_state_facts, announcement_state_watermarks
    IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM announcements)
       OR EXISTS (SELECT 1 FROM announcement_versions)
       OR EXISTS (SELECT 1 FROM announcement_audience_users)
       OR EXISTS (SELECT 1 FROM announcement_audience_groups)
       OR EXISTS (SELECT 1 FROM announcement_recipient_snapshots)
       OR EXISTS (SELECT 1 FROM announcement_inbox_events)
       OR EXISTS (SELECT 1 FROM announcement_inbox_states)
       OR EXISTS (SELECT 1 FROM announcement_write_requests)
       OR EXISTS (SELECT 1 FROM announcement_state_facts)
       OR EXISTS (SELECT 1 FROM announcement_state_watermarks WHERE current_watermark <> 0) THEN
        RAISE EXCEPTION 'migration 043 rollback requires announcement facts to be archived and absent';
    END IF;
END;
$$;

DROP TRIGGER IF EXISTS announcement_state_facts_truncate_guard ON announcement_state_facts;
DROP TRIGGER IF EXISTS announcement_state_facts_append_only ON announcement_state_facts;
DROP FUNCTION IF EXISTS protect_announcement_state_fact();
DROP TRIGGER IF EXISTS announcement_inbox_states_state_fact ON announcement_inbox_states;
DROP FUNCTION IF EXISTS record_announcement_inbox_state_fact();
DROP TRIGGER IF EXISTS announcement_inbox_events_state_fact ON announcement_inbox_events;
DROP FUNCTION IF EXISTS record_announcement_inbox_event_fact();
DROP TRIGGER IF EXISTS announcement_audience_groups_state_fact ON announcement_audience_groups;
DROP TRIGGER IF EXISTS announcement_audience_users_state_fact ON announcement_audience_users;
DROP FUNCTION IF EXISTS record_announcement_selector_fact();
DROP TRIGGER IF EXISTS announcement_versions_state_fact ON announcement_versions;
DROP FUNCTION IF EXISTS record_announcement_version_fact();
DROP FUNCTION IF EXISTS append_announcement_version_fact(uuid, uuid, bigint, timestamptz);
DROP FUNCTION IF EXISTS next_announcement_state_watermark(uuid);
DROP TRIGGER IF EXISTS announcement_state_watermarks_truncate_guard ON announcement_state_watermarks;
DROP TRIGGER IF EXISTS announcement_state_watermarks_guard ON announcement_state_watermarks;
DROP FUNCTION IF EXISTS protect_announcement_state_watermark();
DROP TRIGGER IF EXISTS announcement_versions_current_published_truth ON announcement_versions;
DROP TRIGGER IF EXISTS announcements_current_published_truth ON announcements;
DROP FUNCTION IF EXISTS ensure_current_published_version_truth();

DROP TRIGGER IF EXISTS announcement_write_requests_truncate_guard ON announcement_write_requests;
DROP TRIGGER IF EXISTS announcement_write_requests_guard ON announcement_write_requests;
DROP FUNCTION IF EXISTS protect_announcement_write_request();
DROP TRIGGER IF EXISTS announcement_inbox_states_truncate_guard ON announcement_inbox_states;
DROP TRIGGER IF EXISTS announcement_inbox_states_guard ON announcement_inbox_states;
DROP FUNCTION IF EXISTS protect_announcement_inbox_state();
DROP TRIGGER IF EXISTS announcement_inbox_events_truncate_guard ON announcement_inbox_events;
DROP TRIGGER IF EXISTS announcement_inbox_events_guard ON announcement_inbox_events;
DROP FUNCTION IF EXISTS protect_announcement_inbox_event();
DROP TRIGGER IF EXISTS announcement_recipient_snapshots_truncate_guard ON announcement_recipient_snapshots;
DROP TRIGGER IF EXISTS announcement_recipient_snapshots_guard ON announcement_recipient_snapshots;
DROP FUNCTION IF EXISTS protect_announcement_recipient_snapshot();
DROP TRIGGER IF EXISTS announcement_audience_groups_truncate_guard ON announcement_audience_groups;
DROP TRIGGER IF EXISTS announcement_audience_groups_guard ON announcement_audience_groups;
DROP TRIGGER IF EXISTS announcement_audience_users_truncate_guard ON announcement_audience_users;
DROP TRIGGER IF EXISTS announcement_audience_users_guard ON announcement_audience_users;
DROP FUNCTION IF EXISTS protect_announcement_selector();
DROP TRIGGER IF EXISTS announcement_versions_truncate_guard ON announcement_versions;
DROP TRIGGER IF EXISTS announcement_versions_state_guard ON announcement_versions;
DROP FUNCTION IF EXISTS protect_announcement_version();
DROP TRIGGER IF EXISTS announcements_truncate_guard ON announcements;
DROP TRIGGER IF EXISTS announcements_state_guard ON announcements;
DROP FUNCTION IF EXISTS protect_announcement_root();

DROP TABLE IF EXISTS announcement_write_requests;
DROP TABLE IF EXISTS announcement_inbox_states;
DROP TABLE IF EXISTS announcement_inbox_events;
DROP TABLE IF EXISTS announcement_recipient_snapshots;
DROP TABLE IF EXISTS announcement_audience_groups;
DROP TABLE IF EXISTS announcement_audience_users;
ALTER TABLE announcements DROP CONSTRAINT IF EXISTS announcements_current_published_fk;
ALTER TABLE announcements DROP CONSTRAINT IF EXISTS announcements_head_version_fk;
DROP TABLE IF EXISTS announcement_versions;
DROP TABLE IF EXISTS announcements;
DROP TABLE IF EXISTS announcement_state_facts;
DROP TABLE IF EXISTS announcement_state_watermarks;
DROP FUNCTION IF EXISTS announcement_valid_body(text);
DROP FUNCTION IF EXISTS announcement_valid_title(text);
DROP FUNCTION IF EXISTS announcement_codepoint_is_format(integer);
DROP FUNCTION IF EXISTS announcement_codepoint_is_go_space(integer);

DELETE FROM custom_rbac_permission_catalog
WHERE permission_name IN ('announcements.read', 'announcements.manage');
DELETE FROM role_permissions
WHERE permission_name IN ('announcements.read', 'announcements.manage');
DELETE FROM permissions
WHERE name IN ('announcements.read', 'announcements.manage');
