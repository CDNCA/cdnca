LOCK TABLE node_scheduling_write_requests IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM node_scheduling_write_requests
        WHERE operation <> 'node_scheduling.group.put'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P8101',
            MESSAGE = 'migration 081 rollback cannot represent operation-scoped node scheduling facts';
    END IF;
END;
$$;

ALTER TABLE node_scheduling_write_requests
    DROP CONSTRAINT node_scheduling_write_requests_operation_check,
    ADD CONSTRAINT node_scheduling_write_requests_operation_check
        CHECK (operation = 'node_scheduling.group.put');
