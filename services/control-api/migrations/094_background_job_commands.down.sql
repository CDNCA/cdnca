LOCK TABLE schema_migrations,
    background_job_command_receipts,
    background_job_command_rbac_grant_additions_094,
    background_job_command_rbac_catalog_additions_094,
    permissions,
    custom_rbac_permission_catalog,
    roles,
    role_permissions,
    audit_events,
    background_jobs,
    dns_reconcile_cancel_facts,
    dns_reconcile_provider_recovery_continuations,
    custom_role_revisions
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 94 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 94 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL
           OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 94
          AND migration_id = '094_background_job_commands'
          AND checksum_sha256 = '68da50b82c6597f264d66a3ca366f8738652ae608ddf04edccc6b4a191bfebc8'
          AND integrity_state = 'verified'
          AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 93
          AND migration_id = '093_upgrade_rollout_persistence'
          AND checksum_sha256 = '3614fd6c9d624f2e75ded822c2de8fe62940267c4a5e9b76340a37e428e319af'
          AND down_checksum_sha256 = '522de2c6ff1747157b9b0cce959724f18d9395f1c20638d4bfcbdcafb29b734a'
          AND integrity_state = 'verified'
          AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 094 rollback requires the exact verified 094 head'
            USING ERRCODE = 'P9400';
    END IF;
    IF EXISTS (SELECT 1 FROM background_job_command_receipts) OR EXISTS (
        SELECT 1 FROM audit_events
        WHERE action IN ('job.cancel','job.retry')
    ) OR EXISTS (
        SELECT 1 FROM background_jobs
        WHERE job_command_operation IS NOT NULL OR job_command_xact_id IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM dns_reconcile_cancel_facts
        WHERE job_transition_xact_id IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM dns_reconcile_provider_recovery_continuations
        WHERE job_transition_xact_id IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 094 rollback would discard job command facts'
            USING ERRCODE = 'P9401';
    END IF;
    IF (SELECT count(*) FROM background_job_command_rbac_catalog_additions_094
        WHERE permission_name='jobs.manage' AND source_migration=94) <> 1 OR
       NOT EXISTS (SELECT 1 FROM custom_rbac_permission_catalog
                   WHERE permission_name='jobs.manage') OR
       EXISTS (SELECT 1 FROM custom_rbac_permission_catalog
               WHERE permission_name='jobs.manage_all') OR
       (SELECT count(*) FROM permissions WHERE name IN ('jobs.manage','jobs.manage_all')) <> 2 OR
       EXISTS (
           SELECT role_id,permission_name FROM role_permissions
           WHERE permission_name IN ('jobs.manage','jobs.manage_all')
           EXCEPT
           SELECT role_id,permission_name
           FROM background_job_command_rbac_grant_additions_094
           WHERE source_migration=94
       ) OR EXISTS (
           SELECT 1 FROM custom_role_revisions
           WHERE 'jobs.manage'=ANY(permissions) OR 'jobs.manage_all'=ANY(permissions)
       ) THEN
        RAISE EXCEPTION 'migration 094 rollback found unowned RBAC facts'
            USING ERRCODE = 'P9401';
    END IF;
END;
$$;

DROP TRIGGER audit_events_job_command_no_truncate_094 ON audit_events;
DROP FUNCTION prevent_background_job_command_audit_truncate_094();
DROP INDEX audit_events_job_command_denied_identity_094;
DROP TRIGGER audit_events_job_command_success_receipt_094 ON audit_events;
DROP FUNCTION validate_background_job_command_success_audit_094();

DROP TRIGGER background_jobs_command_receipt_final_094 ON background_jobs;
DROP FUNCTION validate_background_job_command_mutation_094();
DROP TRIGGER dns_reconcile_cancel_transition_final_094 ON dns_reconcile_cancel_facts;
DROP FUNCTION validate_dns_reconcile_cancel_transition_094();
DROP TRIGGER dns_reconcile_provider_recovery_transition_final_094
    ON dns_reconcile_provider_recovery_continuations;
DROP FUNCTION validate_dns_reconcile_provider_recovery_transition_094();
DROP TRIGGER background_job_command_receipts_immutable_094 ON background_job_command_receipts;
DROP TRIGGER background_job_command_receipts_final_094 ON background_job_command_receipts;
DROP TRIGGER background_job_command_receipts_validate_094 ON background_job_command_receipts;
DROP TABLE background_job_command_receipts;
DROP FUNCTION validate_background_job_command_receipt_094();
DROP FUNCTION dns_reconcile_background_job_recovery_final_094(background_jobs,background_jobs);
DROP FUNCTION dns_reconcile_provider_recovery_final_094(background_jobs);
DROP FUNCTION dns_reconcile_cancel_final_094(background_jobs);

DROP TRIGGER background_jobs_mark_command_mutation_094 ON background_jobs;
DROP FUNCTION mark_background_job_command_mutation_094();
DROP FUNCTION dns_reconcile_background_job_cancel_094(background_jobs,background_jobs);
ALTER TABLE background_jobs
    DROP CONSTRAINT background_jobs_job_command_marker_094,
    DROP COLUMN job_command_operation,
    DROP COLUMN job_command_xact_id;

DROP TRIGGER a_dns_reconcile_cancel_facts_transition_094 ON dns_reconcile_cancel_facts;
DROP TRIGGER a_dns_reconcile_provider_recovery_transition_094
    ON dns_reconcile_provider_recovery_continuations;
DROP FUNCTION mark_dns_reconcile_job_transition_source_094();
ALTER TABLE dns_reconcile_cancel_facts
    DROP COLUMN job_transition_xact_id;
ALTER TABLE dns_reconcile_provider_recovery_continuations
    DROP COLUMN job_transition_xact_id;

DROP TRIGGER roles_project_background_job_command_permissions_094 ON roles;
DROP FUNCTION project_background_job_command_permissions_094();

DROP TRIGGER background_job_command_rbac_catalog_delete_guard_094 ON custom_rbac_permission_catalog;
DROP FUNCTION protect_background_job_command_catalog_094();
DROP TRIGGER background_job_command_rbac_grants_protect_094
    ON background_job_command_rbac_grant_additions_094;
DROP TRIGGER background_job_command_rbac_catalog_protect_094
    ON background_job_command_rbac_catalog_additions_094;
DROP FUNCTION protect_background_job_command_rbac_provenance_094();

ALTER TABLE background_job_command_rbac_grant_additions_094
    DROP CONSTRAINT background_job_command_rbac_grant_role_permission_094_fk;
ALTER TABLE role_permissions DISABLE TRIGGER role_permissions_system_role_guard;
DELETE FROM role_permissions permission
USING background_job_command_rbac_grant_additions_094 addition
WHERE permission.role_id=addition.role_id
  AND permission.permission_name=addition.permission_name
  AND addition.source_migration=94;
ALTER TABLE role_permissions ENABLE TRIGGER role_permissions_system_role_guard;

DROP TABLE background_job_command_rbac_grant_additions_094;
DROP TABLE background_job_command_rbac_catalog_additions_094;

DELETE FROM custom_rbac_permission_catalog
WHERE permission_name='jobs.manage';
DELETE FROM permissions
WHERE name IN ('jobs.manage','jobs.manage_all');

CREATE OR REPLACE FUNCTION guard_system_role_permission_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_role_id uuid;
    target_system_role boolean;
    target_role_name text;
    target_permission_name text;
    scope_kind text;
    protected_permission boolean;
BEGIN
    target_role_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.role_id ELSE NEW.role_id END;
    target_permission_name := CASE
        WHEN TG_OP = 'DELETE' THEN OLD.permission_name ELSE NEW.permission_name
    END;
    SELECT role.system_role, role.name, scope.kind
      INTO target_system_role, target_role_name, scope_kind
    FROM roles role JOIN access_scopes scope ON scope.id = role.scope_id
    WHERE role.id = target_role_id;
    IF NOT target_system_role THEN
        IF EXISTS (SELECT 1 FROM custom_roles WHERE id = target_role_id) AND pg_trigger_depth() < 2 THEN
            RAISE EXCEPTION 'custom role permission projection is protected';
        END IF;
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;
    SELECT EXISTS (
        SELECT 1 FROM custom_rbac_permission_catalog
        WHERE permission_name = target_permission_name
    ) INTO protected_permission;

    IF TG_OP = 'UPDATE' OR (TG_OP = 'DELETE' AND protected_permission) THEN
        RAISE EXCEPTION 'system role permissions are immutable';
    END IF;
    IF TG_OP = 'INSERT' AND scope_kind = 'tenant' AND
       (NEW.permission_name IN (
            'platform.admin', 'identity.impersonation.manage', 'billing.adjustments.manage',
            'api_keys.admin.manage', 'packages.manage', 'nodes.read', 'nodes.manage',
            'control.upgrades.check', 'node_ca.manage', 'system_configuration.read',
            'system_configuration.manage'
        ) OR
        (NEW.permission_name = 'package_subscriptions.read' AND
         target_role_name NOT IN ('tenant_owner', 'tenant_viewer')) OR
        (NEW.permission_name = 'package_subscriptions.manage' AND
         target_role_name <> 'tenant_owner') OR
        (NEW.permission_name = 'plugin_webhooks.read' AND
         target_role_name NOT IN ('tenant_owner', 'tenant_admin', 'tenant_member', 'tenant_viewer')) OR
        (NEW.permission_name = 'plugin_webhooks.manage' AND
         target_role_name NOT IN ('tenant_owner', 'tenant_admin')) OR
        (target_role_name = 'tenant_viewer' AND
         NEW.permission_name NOT LIKE '%.read' AND
         NEW.permission_name NOT IN (
             'identity.self.update', 'identity.password.change', 'api_keys.self.manage',
             'identity_verification.self.manage', 'promotions.quote', 'promotions.redeem'
         ))) THEN
        RAISE EXCEPTION 'invalid tenant system role permission';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;
