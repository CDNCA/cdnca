DROP INDEX IF EXISTS sites_locked_at_idx;

DELETE FROM site_write_requests
WHERE operation IN ('site.lock', 'site.unlock');

ALTER TABLE site_write_requests
    DROP CONSTRAINT site_write_requests_operation_check,
    ADD CONSTRAINT site_write_requests_operation_check CHECK (
        operation IN ('site.create', 'site.update', 'site.delete')
    );

ALTER TABLE sites
    DROP CONSTRAINT IF EXISTS sites_lock_metadata_complete,
    DROP COLUMN IF EXISTS locked_by_user_id,
    DROP COLUMN IF EXISTS locked_at,
    DROP COLUMN IF EXISTS lock_reason;
