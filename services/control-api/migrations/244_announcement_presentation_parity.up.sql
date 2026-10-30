LOCK TABLE schema_migrations, announcement_versions, announcement_state_facts IN ACCESS EXCLUSIVE MODE;

DO $migration_244_announcement_presentation_parity$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 243 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 243 OR
       NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 243 AND migration_id = '243_waf_custom_rule_report_state' AND
              checksum_sha256 = '840b9a1fd7b2687cc54410baa1ad8d1f0591306d626a65946ba9b32606049ecd' AND
              down_checksum_sha256 = 'a1456159b91a9ad96ae5c125de7517feb9d9705004304a5e804482867f87d4eb' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='announcement_versions' AND
              column_name IN ('content_format','link_url','sort_order','is_visible','is_popup','style_red','style_bold')
       ) THEN
        RAISE EXCEPTION 'migration 244 requires the exact verified 243 release head and untouched announcement presentation schema'
            USING ERRCODE = 'P2440';
    END IF;
END;
$migration_244_announcement_presentation_parity$;

ALTER TABLE announcement_versions
    ADD COLUMN content_format text NOT NULL DEFAULT 'content',
    ADD COLUMN link_url text,
    ADD COLUMN sort_order bigint NOT NULL DEFAULT 100,
    ADD COLUMN is_visible boolean NOT NULL DEFAULT true,
    ADD COLUMN is_popup boolean NOT NULL DEFAULT false,
    ADD COLUMN style_red boolean NOT NULL DEFAULT false,
    ADD COLUMN style_bold boolean NOT NULL DEFAULT false,
    DROP CONSTRAINT IF EXISTS announcement_versions_body_check,
    ADD CONSTRAINT announcement_versions_content_format_244_check CHECK (content_format IN ('content', 'link')),
    ADD CONSTRAINT announcement_versions_link_url_244_check CHECK (
        (content_format = 'content' AND link_url IS NULL) OR
        (content_format = 'link' AND link_url IS NOT NULL AND link_url ~ '^https?://[^[:space:]]+$')
    ),
    ADD CONSTRAINT announcement_versions_sort_order_244_check CHECK (sort_order BETWEEN 0 AND 999999),
    ADD CONSTRAINT announcement_versions_body_244_check CHECK (
        (content_format = 'link' AND body = '') OR
        (content_format = 'content' AND announcement_valid_body(body))
    );

CREATE FUNCTION protect_announcement_presentation_244()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.status <> 'draft' AND (
        NEW.content_format IS DISTINCT FROM OLD.content_format OR
        NEW.link_url IS DISTINCT FROM OLD.link_url OR
        NEW.sort_order IS DISTINCT FROM OLD.sort_order OR
        NEW.is_visible IS DISTINCT FROM OLD.is_visible OR
        NEW.is_popup IS DISTINCT FROM OLD.is_popup OR
        NEW.style_red IS DISTINCT FROM OLD.style_red OR
        NEW.style_bold IS DISTINCT FROM OLD.style_bold
    ) THEN
        RAISE EXCEPTION 'announcement presentation is sealed after draft';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER zzz_announcement_presentation_guard_244
BEFORE UPDATE OF content_format,link_url,sort_order,is_visible,is_popup,style_red,style_bold ON announcement_versions
FOR EACH ROW EXECUTE FUNCTION protect_announcement_presentation_244();

CREATE FUNCTION append_announcement_presentation_fact_244()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    base_payload jsonb;
    next_value bigint;
BEGIN
    SELECT payload INTO base_payload
      FROM announcement_state_facts
     WHERE tenant_scope_id=NEW.tenant_scope_id AND fact_type='version'
       AND announcement_id=NEW.announcement_id AND announcement_version=NEW.version
     ORDER BY watermark DESC LIMIT 1;
    IF base_payload IS NULL THEN
        RETURN NEW;
    END IF;
    base_payload := jsonb_set(base_payload, '{content_format}', to_jsonb(NEW.content_format), true);
    base_payload := jsonb_set(base_payload, '{link_url}', COALESCE(to_jsonb(NEW.link_url), 'null'::jsonb), true);
    base_payload := jsonb_set(base_payload, '{sort_order}', to_jsonb(NEW.sort_order), true);
    base_payload := jsonb_set(base_payload, '{is_visible}', to_jsonb(NEW.is_visible), true);
    base_payload := jsonb_set(base_payload, '{is_popup}', to_jsonb(NEW.is_popup), true);
    base_payload := jsonb_set(base_payload, '{style_red}', to_jsonb(NEW.style_red), true);
    base_payload := jsonb_set(base_payload, '{style_bold}', to_jsonb(NEW.style_bold), true);
    next_value := next_announcement_state_watermark(NEW.tenant_scope_id);
    INSERT INTO announcement_state_facts(
        tenant_scope_id,watermark,fact_type,announcement_id,announcement_version,payload,occurred_at
    ) VALUES (
        NEW.tenant_scope_id,next_value,'version',NEW.announcement_id,NEW.version,base_payload,NEW.state_changed_at
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER zzz_announcement_presentation_fact_244
AFTER INSERT OR UPDATE ON announcement_versions
FOR EACH ROW EXECUTE FUNCTION append_announcement_presentation_fact_244();

DO $runtime_grants_244$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cdnca_control_app') THEN
        GRANT SELECT, INSERT, UPDATE ON announcement_versions TO cdnca_control_app;
        GRANT SELECT, INSERT ON announcement_state_facts TO cdnca_control_app;
    END IF;
END;
$runtime_grants_244$;
