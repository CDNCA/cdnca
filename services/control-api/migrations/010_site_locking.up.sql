ALTER TABLE sites
    ADD COLUMN lock_reason text,
    ADD COLUMN locked_at timestamptz,
    ADD COLUMN locked_by_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    ADD CONSTRAINT sites_lock_metadata_complete CHECK (
        (
            lock_reason IS NULL
            AND locked_at IS NULL
            AND locked_by_user_id IS NULL
        )
        OR
        (
            lock_reason IS NOT NULL
            AND char_length(btrim(lock_reason)) BETWEEN 1 AND 500
            AND locked_at IS NOT NULL
            AND locked_by_user_id IS NOT NULL
        )
    );

ALTER TABLE site_write_requests
    DROP CONSTRAINT site_write_requests_operation_check,
    ADD CONSTRAINT site_write_requests_operation_check CHECK (
        operation IN ('site.create', 'site.update', 'site.delete', 'site.lock', 'site.unlock')
    );

CREATE INDEX sites_locked_at_idx
    ON sites (locked_at DESC)
    WHERE locked_at IS NOT NULL AND deleted_at IS NULL;
