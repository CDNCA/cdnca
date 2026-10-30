ALTER TABLE access_events
    ADD COLUMN IF NOT EXISTS task_id Nullable(String) DEFAULT NULL AFTER config_version_id,
    ADD COLUMN IF NOT EXISTS installation_id String DEFAULT '' AFTER task_id,
    ADD COLUMN IF NOT EXISTS request_headers Map(String, String) DEFAULT map() AFTER installation_id,
    ADD COLUMN IF NOT EXISTS response_headers Map(String, String) DEFAULT map() AFTER request_headers,
    ADD COLUMN IF NOT EXISTS request_body Nullable(String) DEFAULT NULL AFTER response_headers,
    ADD COLUMN IF NOT EXISTS response_body Nullable(String) DEFAULT NULL AFTER request_body,
    ADD COLUMN IF NOT EXISTS ja4 Nullable(String) DEFAULT NULL AFTER response_body,
    ADD COLUMN IF NOT EXISTS origin_connect_us Nullable(UInt64) DEFAULT NULL AFTER ja4,
    ADD COLUMN IF NOT EXISTS origin_first_byte_us Nullable(UInt64) DEFAULT NULL AFTER origin_connect_us,
    ADD COLUMN IF NOT EXISTS origin_total_us Nullable(UInt64) DEFAULT NULL AFTER origin_first_byte_us;

ALTER TABLE security_events
    ADD COLUMN IF NOT EXISTS task_id Nullable(String) DEFAULT NULL AFTER config_version_id,
    ADD COLUMN IF NOT EXISTS installation_id String DEFAULT '' AFTER task_id,
    ADD COLUMN IF NOT EXISTS request_headers Map(String, String) DEFAULT map() AFTER installation_id,
    ADD COLUMN IF NOT EXISTS response_headers Map(String, String) DEFAULT map() AFTER request_headers,
    ADD COLUMN IF NOT EXISTS request_body Nullable(String) DEFAULT NULL AFTER response_headers,
    ADD COLUMN IF NOT EXISTS response_body Nullable(String) DEFAULT NULL AFTER request_body,
    ADD COLUMN IF NOT EXISTS ja4 Nullable(String) DEFAULT NULL AFTER response_body,
    ADD COLUMN IF NOT EXISTS origin_connect_us Nullable(UInt64) DEFAULT NULL AFTER ja4,
    ADD COLUMN IF NOT EXISTS origin_first_byte_us Nullable(UInt64) DEFAULT NULL AFTER origin_connect_us,
    ADD COLUMN IF NOT EXISTS origin_total_us Nullable(UInt64) DEFAULT NULL AFTER origin_first_byte_us;
