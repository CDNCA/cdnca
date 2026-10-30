ALTER TABLE security_events
    DROP COLUMN IF EXISTS origin_total_us,
    DROP COLUMN IF EXISTS origin_first_byte_us,
    DROP COLUMN IF EXISTS origin_connect_us,
    DROP COLUMN IF EXISTS ja4,
    DROP COLUMN IF EXISTS response_body,
    DROP COLUMN IF EXISTS request_body,
    DROP COLUMN IF EXISTS response_headers,
    DROP COLUMN IF EXISTS request_headers,
    DROP COLUMN IF EXISTS installation_id,
    DROP COLUMN IF EXISTS task_id;

ALTER TABLE access_events
    DROP COLUMN IF EXISTS origin_total_us,
    DROP COLUMN IF EXISTS origin_first_byte_us,
    DROP COLUMN IF EXISTS origin_connect_us,
    DROP COLUMN IF EXISTS ja4,
    DROP COLUMN IF EXISTS response_body,
    DROP COLUMN IF EXISTS request_body,
    DROP COLUMN IF EXISTS response_headers,
    DROP COLUMN IF EXISTS request_headers,
    DROP COLUMN IF EXISTS installation_id,
    DROP COLUMN IF EXISTS task_id;
