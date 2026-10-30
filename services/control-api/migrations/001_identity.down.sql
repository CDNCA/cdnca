DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events;
DROP FUNCTION IF EXISTS prevent_audit_event_mutation();
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS auth_sessions;
DROP TABLE IF EXISTS role_assignments;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS memberships;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS access_scopes;
DROP TABLE IF EXISTS tenants;

