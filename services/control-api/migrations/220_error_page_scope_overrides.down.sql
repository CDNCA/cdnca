REVOKE USAGE, SELECT ON SEQUENCE error_page_scope_overrides_display_id_seq FROM cdnca_control_app;
REVOKE SELECT, INSERT ON TABLE error_page_scope_overrides,
    error_page_scope_override_revisions, error_page_scope_override_items FROM cdnca_control_app;

DROP TRIGGER error_page_assets_bound_scope_override_guard_220 ON error_page_assets;
DROP FUNCTION protect_scope_override_asset_220();
DROP TRIGGER error_page_scope_override_items_append_only_220 ON error_page_scope_override_items;
DROP TRIGGER error_page_scope_override_revisions_append_only_220 ON error_page_scope_override_revisions;
DROP TRIGGER error_page_scope_overrides_append_only_220 ON error_page_scope_overrides;
DROP FUNCTION protect_error_page_scope_overrides_220();
DROP TRIGGER error_page_scope_override_cardinality_220 ON error_page_scope_override_revisions;
DROP FUNCTION validate_error_page_scope_override_cardinality_220();
DROP TRIGGER error_page_scope_override_items_validate_insert_220 ON error_page_scope_override_items;
DROP FUNCTION validate_error_page_scope_override_item_220();
DROP TRIGGER error_page_scope_override_revisions_validate_insert_220 ON error_page_scope_override_revisions;
DROP FUNCTION validate_error_page_scope_override_revision_220();
DROP TRIGGER error_page_scope_overrides_validate_insert_220 ON error_page_scope_overrides;
DROP FUNCTION validate_error_page_scope_override_identity_220();

DROP TABLE error_page_scope_override_items;
DROP TABLE error_page_scope_override_revisions;
DROP TABLE error_page_scope_overrides;

ALTER TABLE error_page_write_requests
    DROP CONSTRAINT error_page_write_requests_operation_check;
ALTER TABLE error_page_write_requests
    ADD CONSTRAINT error_page_write_requests_operation_check CHECK (operation IN (
        'error_page.asset.initiate', 'error_page.asset.upload', 'error_page.asset.finalize',
        'error_page.asset.reconcile_finalize', 'error_page.asset.delete',
        'error_page.rule.create', 'error_page.rule.update', 'error_page.rule.enable',
        'error_page.rule.disable', 'error_page.rule.delete',
        'error_page.slot.bind', 'error_page.slot.unbind'
    ));
