REVOKE SELECT, INSERT ON TABLE error_page_slots, error_page_slot_revisions
    FROM cdnca_control_app;

DROP TRIGGER error_page_assets_bound_slot_guard_218 ON error_page_assets;
DROP FUNCTION protect_bound_error_page_asset_218();
DROP TRIGGER error_page_slot_revisions_append_only_218 ON error_page_slot_revisions;
DROP TRIGGER error_page_slots_append_only_218 ON error_page_slots;
DROP FUNCTION protect_error_page_slots_218();
DROP TRIGGER error_page_slot_revisions_validate_insert_218 ON error_page_slot_revisions;
DROP FUNCTION validate_error_page_slot_revision_218();
DROP TRIGGER error_page_slots_validate_insert_218 ON error_page_slots;
DROP FUNCTION validate_error_page_slot_identity_218();
DROP TABLE error_page_slot_revisions;
DROP TABLE error_page_slots;

ALTER TABLE error_page_write_requests
    DROP CONSTRAINT error_page_write_requests_operation_check;
ALTER TABLE error_page_write_requests
    ADD CONSTRAINT error_page_write_requests_operation_check CHECK (operation IN (
        'error_page.asset.initiate', 'error_page.asset.upload', 'error_page.asset.finalize',
        'error_page.asset.delete', 'error_page.rule.create', 'error_page.rule.update',
        'error_page.rule.enable', 'error_page.rule.disable', 'error_page.rule.delete'
    ));
