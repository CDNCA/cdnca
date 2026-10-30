LOCK TABLE schema_migrations, announcement_versions, announcement_state_facts IN ACCESS EXCLUSIVE MODE;

DO $migration_244_announcement_presentation_parity_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 244 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 244 OR
       (SELECT count(*) FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='announcement_versions' AND
              column_name IN ('content_format','link_url','sort_order','is_visible','is_popup','style_red','style_bold')) <> 7 OR
       to_regprocedure(current_schema() || '.protect_announcement_presentation_244()') IS NULL OR
       to_regprocedure(current_schema() || '.append_announcement_presentation_fact_244()') IS NULL THEN
        RAISE EXCEPTION 'migration 244 rollback requires the exact verified 244 release head'
            USING ERRCODE = 'P2443';
    END IF;
    IF EXISTS (SELECT 1 FROM announcement_versions WHERE content_format <> 'content' OR link_url IS NOT NULL OR sort_order <> 100 OR NOT is_visible OR is_popup OR style_red OR style_bold) THEN
        RAISE EXCEPTION 'migration 244 rollback cannot discard announcement presentation settings'
            USING ERRCODE = 'P2443';
    END IF;
END;
$migration_244_announcement_presentation_parity_down$;

DROP TRIGGER zzz_announcement_presentation_fact_244 ON announcement_versions;
DROP FUNCTION append_announcement_presentation_fact_244();
DROP TRIGGER zzz_announcement_presentation_guard_244 ON announcement_versions;
DROP FUNCTION protect_announcement_presentation_244();

ALTER TABLE announcement_versions
    DROP CONSTRAINT IF EXISTS announcement_versions_body_244_check,
    DROP CONSTRAINT IF EXISTS announcement_versions_sort_order_244_check,
    DROP CONSTRAINT IF EXISTS announcement_versions_link_url_244_check,
    DROP CONSTRAINT IF EXISTS announcement_versions_content_format_244_check,
    DROP COLUMN style_bold,
    DROP COLUMN style_red,
    DROP COLUMN is_popup,
    DROP COLUMN is_visible,
    DROP COLUMN sort_order,
    DROP COLUMN link_url,
    DROP COLUMN content_format,
    ADD CONSTRAINT announcement_versions_body_check CHECK (announcement_valid_body(body));
