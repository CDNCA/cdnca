LOCK TABLE permissions,
    access_scopes,
    roles,
    role_permissions,
    custom_rbac_permission_catalog,
    custom_rbac_system_role_permission_additions,
    custom_role_revisions,
    promotion_policy_catalog_watermark,
    promotion_policies,
    promotion_policy_versions,
    promotion_policy_product_targets,
    promotion_policy_tenant_targets,
    promotion_quotes,
    promotion_quote_policies,
    promotion_reservations,
    promotion_reservation_events,
    promotion_renewal_price_snapshots,
    promotion_renewal_bindings,
    promotion_adjustment_decisions,
    promotion_write_requests
    IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM promotion_policies)
       OR EXISTS (SELECT 1 FROM promotion_policy_versions)
       OR EXISTS (SELECT 1 FROM promotion_policy_product_targets)
       OR EXISTS (SELECT 1 FROM promotion_policy_tenant_targets)
       OR EXISTS (SELECT 1 FROM promotion_quotes)
       OR EXISTS (SELECT 1 FROM promotion_quote_policies)
       OR EXISTS (SELECT 1 FROM promotion_reservations)
       OR EXISTS (SELECT 1 FROM promotion_reservation_events)
       OR EXISTS (SELECT 1 FROM promotion_renewal_price_snapshots)
       OR EXISTS (SELECT 1 FROM promotion_renewal_bindings)
       OR EXISTS (SELECT 1 FROM promotion_adjustment_decisions)
       OR EXISTS (SELECT 1 FROM promotion_write_requests)
       OR EXISTS (
           SELECT 1 FROM promotion_policy_catalog_watermark WHERE current_position <> 0
       ) THEN
        RAISE EXCEPTION 'migration 044 rollback requires promotion facts to be archived and absent'
            USING ERRCODE = 'P0001';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM role_permissions permission
        JOIN roles role ON role.id = permission.role_id
        JOIN access_scopes scope ON scope.id = role.scope_id
        WHERE permission.permission_name IN (
            'promotions.read', 'promotions.manage', 'promotions.quote', 'promotions.redeem'
        ) AND NOT (
            role.system_role AND (
                (scope.kind = 'platform' AND role.name = 'platform_owner') OR
                (scope.kind = 'tenant' AND role.name = 'tenant_owner'
                    AND permission.permission_name IN (
                        'promotions.read', 'promotions.quote', 'promotions.redeem'
                    )) OR
                (scope.kind = 'tenant' AND role.name = 'tenant_viewer'
                    AND permission.permission_name = 'promotions.read')
            )
        )
    ) OR EXISTS (
        SELECT 1 FROM custom_role_revisions
        WHERE permissions && ARRAY[
            'promotions.read', 'promotions.manage', 'promotions.quote', 'promotions.redeem'
        ]::text[]
    ) OR EXISTS (
        SELECT 1 FROM custom_rbac_system_role_permission_additions
        WHERE permission_name IN (
            'promotions.read', 'promotions.manage', 'promotions.quote', 'promotions.redeem'
        )
    ) THEN
        RAISE EXCEPTION 'migration 044 promotion permissions are referenced by RBAC facts'
            USING ERRCODE = 'P0001';
    END IF;
END;
$$;

DROP TRIGGER promotion_adjustment_decisions_no_truncate ON promotion_adjustment_decisions;
DROP TRIGGER promotion_adjustment_decisions_append_only ON promotion_adjustment_decisions;
DROP TRIGGER promotion_renewal_bindings_no_truncate ON promotion_renewal_bindings;
DROP TRIGGER promotion_renewal_bindings_append_only ON promotion_renewal_bindings;
DROP TRIGGER promotion_renewal_price_snapshots_no_truncate ON promotion_renewal_price_snapshots;
DROP TRIGGER promotion_renewal_price_snapshots_append_only ON promotion_renewal_price_snapshots;
DROP TRIGGER promotion_reservation_events_no_truncate ON promotion_reservation_events;
DROP TRIGGER promotion_reservation_events_append_only ON promotion_reservation_events;
DROP TRIGGER promotion_reservations_no_truncate ON promotion_reservations;
DROP TRIGGER promotion_reservations_append_only ON promotion_reservations;
DROP TRIGGER promotion_quote_policies_no_truncate ON promotion_quote_policies;
DROP TRIGGER promotion_quote_policies_append_only ON promotion_quote_policies;
DROP TRIGGER promotion_quotes_no_truncate ON promotion_quotes;
DROP TRIGGER promotion_quotes_append_only ON promotion_quotes;
DROP TRIGGER promotion_policy_tenant_targets_no_truncate ON promotion_policy_tenant_targets;
DROP TRIGGER promotion_policy_tenant_targets_append_only ON promotion_policy_tenant_targets;
DROP TRIGGER promotion_policy_product_targets_no_truncate ON promotion_policy_product_targets;
DROP TRIGGER promotion_policy_product_targets_append_only ON promotion_policy_product_targets;
DROP TRIGGER promotion_policy_versions_no_truncate ON promotion_policy_versions;
DROP TRIGGER promotion_policy_versions_append_only ON promotion_policy_versions;
DROP TRIGGER promotion_policies_no_truncate ON promotion_policies;
DROP TRIGGER promotion_policies_append_only ON promotion_policies;
DROP TRIGGER promotion_policy_versions_assign_catalog_position ON promotion_policy_versions;
DROP TRIGGER promotion_write_requests_no_truncate ON promotion_write_requests;
DROP TRIGGER promotion_write_requests_protect ON promotion_write_requests;

DROP TRIGGER promotion_adjustments_valid ON promotion_adjustment_decisions;
DROP TRIGGER promotion_renewal_bindings_valid ON promotion_renewal_bindings;
DROP TRIGGER promotion_renewal_snapshots_consumed ON promotion_renewal_price_snapshots;
DROP TRIGGER promotion_reservation_events_audited ON promotion_reservation_events;
DROP TRIGGER promotion_reservations_complete ON promotion_reservations;
DROP TRIGGER promotion_quotes_complete ON promotion_quotes;
DROP TRIGGER promotion_policy_versions_complete ON promotion_policy_versions;
DROP TRIGGER promotion_reservation_events_validate ON promotion_reservation_events;
DROP TRIGGER promotion_quotes_validate_source ON promotion_quotes;
DROP TRIGGER promotion_tenant_targets_validate ON promotion_policy_tenant_targets;
DROP TRIGGER promotion_policy_targets_validate ON promotion_policy_product_targets;

DROP FUNCTION assert_promotion_adjustment();
DROP FUNCTION assert_promotion_renewal_binding();
DROP FUNCTION assert_promotion_renewal_snapshot_consumed();
DROP FUNCTION assert_promotion_event_audited();
DROP FUNCTION assert_promotion_reservation_complete();
DROP FUNCTION validate_promotion_reservation_event();
DROP FUNCTION assert_promotion_quote_complete();
DROP FUNCTION reprice_promotion_quote_policies(uuid, boolean);
DROP FUNCTION assert_promotion_quote_source();
DROP FUNCTION assert_promotion_policy_complete();
DROP FUNCTION assert_promotion_tenant_target();
DROP FUNCTION assert_promotion_policy_target();
DROP FUNCTION protect_promotion_write_request();
DROP FUNCTION prevent_promotion_append_mutation();
DROP FUNCTION assign_promotion_policy_catalog_position();

DROP TABLE promotion_write_requests;
DROP TABLE promotion_adjustment_decisions;
DROP TABLE promotion_renewal_bindings;
ALTER TABLE promotion_quotes DROP CONSTRAINT promotion_quotes_renewal_snapshot_fk;
DROP TABLE promotion_renewal_price_snapshots;
DROP TABLE promotion_reservation_events;
DROP TABLE promotion_reservations;
DROP TABLE promotion_quote_policies;
DROP TABLE promotion_quotes;
DROP TABLE promotion_policy_tenant_targets;
DROP TABLE promotion_policy_product_targets;
DROP TABLE promotion_policy_versions;
DROP TABLE promotion_policies;
DROP TABLE promotion_policy_catalog_watermark;

DELETE FROM custom_rbac_permission_catalog
WHERE permission_name IN ('promotions.read', 'promotions.manage', 'promotions.quote', 'promotions.redeem');
DELETE FROM role_permissions
WHERE permission_name IN ('promotions.read', 'promotions.manage', 'promotions.quote', 'promotions.redeem');
DELETE FROM permissions
WHERE name IN ('promotions.read', 'promotions.manage', 'promotions.quote', 'promotions.redeem');
