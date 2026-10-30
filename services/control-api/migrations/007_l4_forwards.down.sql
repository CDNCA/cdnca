DROP TABLE IF EXISTS l4_write_requests;
DROP TRIGGER IF EXISTS l4_publish_intents_append_only ON l4_publish_intents;
DROP FUNCTION IF EXISTS prevent_l4_publish_intent_mutation();
DROP TABLE IF EXISTS l4_publish_intents;
DROP TABLE IF EXISTS l4_scope_publish_counters;
DROP TABLE IF EXISTS l4_forwards;

DELETE FROM role_permissions WHERE permission_name IN ('streams.read', 'streams.manage');
DELETE FROM permissions WHERE name IN ('streams.read', 'streams.manage');
