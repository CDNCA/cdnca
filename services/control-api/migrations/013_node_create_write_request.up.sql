ALTER TABLE node_write_requests
    DROP CONSTRAINT node_write_requests_operation_check,
    ADD CONSTRAINT node_write_requests_operation_check
        CHECK (operation IN ('node.create', 'node.update', 'node.batch_admin_state'));
