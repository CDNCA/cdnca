LOCK TABLE schema_migrations, platform_announcements_141 IN ACCESS EXCLUSIVE MODE;

DO $migration_245_platform_announcement_presentation_parity_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 245 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 245 OR
       NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=245 AND migration_id='245_platform_announcement_presentation_parity'
           AND checksum_sha256='870b9b514ac812496d96c1b09fd3c0957079c53d101aa94d4de42352ed544bc6' AND integrity_state='verified') OR
       (SELECT count(*) FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='platform_announcements_141' AND
              column_name IN ('content_format','link_url','sort_order','is_visible','is_popup','style_red','style_bold')) <> 7 OR
       to_regprocedure(current_schema() || '.protect_platform_announcement_presentation_245()') IS NULL THEN
        RAISE EXCEPTION 'migration 245 rollback requires the exact verified 245 release head'
            USING ERRCODE = 'P2453';
    END IF;
    IF EXISTS (
        SELECT 1 FROM platform_announcements_141
        WHERE content_format <> 'content' OR link_url IS NOT NULL OR sort_order <> 100 OR
              NOT is_visible OR is_popup OR style_red OR style_bold OR NOT announcement_valid_body(body)
    ) THEN
        RAISE EXCEPTION 'migration 245 rollback cannot discard platform announcement presentation settings'
            USING ERRCODE = 'P2454';
    END IF;
END;
$migration_245_platform_announcement_presentation_parity_down$;

DROP TRIGGER platform_announcements_245_presentation_guard ON platform_announcements_141;
DROP FUNCTION protect_platform_announcement_presentation_245();
DROP TRIGGER zzz_platform_announcements_245_presentation_fact ON platform_announcements_141;
DROP FUNCTION append_platform_announcement_presentation_fact_245();

ALTER TABLE platform_announcements_141
    DROP CONSTRAINT IF EXISTS platform_announcements_245_body_check,
    DROP CONSTRAINT IF EXISTS platform_announcements_245_sort_order_check,
    DROP CONSTRAINT IF EXISTS platform_announcements_245_link_url_check,
    DROP CONSTRAINT IF EXISTS platform_announcements_245_content_format_check,
    DROP COLUMN style_bold,
    DROP COLUMN style_red,
    DROP COLUMN is_popup,
    DROP COLUMN is_visible,
    DROP COLUMN sort_order,
    DROP COLUMN link_url,
    DROP COLUMN content_format,
    ADD CONSTRAINT platform_announcements_141_body_check CHECK (announcement_valid_body(body));
