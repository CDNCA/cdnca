LOCK TABLE node_scheduling_write_requests IN ACCESS EXCLUSIVE MODE;

ALTER TABLE node_scheduling_write_requests
    DROP CONSTRAINT node_scheduling_write_requests_operation_check,
    ADD CONSTRAINT node_scheduling_write_requests_operation_check CHECK (operation IN (
        'node_scheduling.group.put',
        'node_scheduling.group.create',
        'node_scheduling.group.update',
        'node_scheduling.group.rollback',
        'node_scheduling.target_snapshot.create'
    ));
