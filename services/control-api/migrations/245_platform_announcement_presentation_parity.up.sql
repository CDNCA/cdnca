LOCK TABLE schema_migrations, platform_announcements_141 IN ACCESS EXCLUSIVE MODE;

DO $migration_245_platform_announcement_presentation_parity$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 244 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 244 OR
       EXISTS (SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified'
           OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL) OR
       NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 244 AND migration_id = '244_announcement_presentation_parity' AND
              checksum_sha256 = 'fb48336c010e6e89458c6a7531760c0405d3ee19aed2b5eb4456d2019d67ad94' AND
              down_checksum_sha256 = '1c4731e8901b175c52f4ce1081ce276d60930a0496714bf27cd00c2597fca061' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='platform_announcements_141' AND
              column_name IN ('content_format','link_url','sort_order','is_visible','is_popup','style_red','style_bold')
       ) THEN
        RAISE EXCEPTION 'migration 245 requires the exact verified 244 release head and untouched platform announcement presentation schema'
            USING ERRCODE = 'P2450';
    END IF;
END;
$migration_245_platform_announcement_presentation_parity$;

ALTER TABLE platform_announcements_141
    ADD COLUMN content_format text NOT NULL DEFAULT 'content',
    ADD COLUMN link_url text,
    ADD COLUMN sort_order bigint NOT NULL DEFAULT 100,
    ADD COLUMN is_visible boolean NOT NULL DEFAULT true,
    ADD COLUMN is_popup boolean NOT NULL DEFAULT false,
    ADD COLUMN style_red boolean NOT NULL DEFAULT false,
    ADD COLUMN style_bold boolean NOT NULL DEFAULT false,
    DROP CONSTRAINT IF EXISTS platform_announcements_141_body_check,
    ADD CONSTRAINT platform_announcements_245_content_format_check CHECK (content_format IN ('content', 'link')),
    ADD CONSTRAINT platform_announcements_245_link_url_check CHECK (
        (content_format = 'content' AND link_url IS NULL) OR
        (content_format = 'link' AND link_url IS NOT NULL AND link_url ~ '^https?://[^[:space:]]+$')
    ),
    ADD CONSTRAINT platform_announcements_245_sort_order_check CHECK (sort_order BETWEEN 0 AND 999999),
    ADD CONSTRAINT platform_announcements_245_body_check CHECK (
        (content_format = 'link' AND body = '') OR
        (content_format = 'content' AND octet_length(body) BETWEEN 1 AND 65536 AND length(btrim(body)) > 0)
    );

CREATE FUNCTION protect_platform_announcement_presentation_245()
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
        RAISE EXCEPTION 'platform announcement presentation is sealed after draft'
            USING ERRCODE = 'P2451';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER platform_announcements_245_presentation_guard
BEFORE UPDATE OF content_format,link_url,sort_order,is_visible,is_popup,style_red,style_bold
ON platform_announcements_141
FOR EACH ROW EXECUTE FUNCTION protect_platform_announcement_presentation_245();

CREATE FUNCTION append_platform_announcement_presentation_fact_245()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    requested_scope_id uuid;
    base_payload jsonb;
    next_value bigint;
BEGIN
    FOR requested_scope_id IN
        SELECT DISTINCT tenant_scope_id FROM platform_announcement_recipients_141
        WHERE announcement_id=NEW.id ORDER BY tenant_scope_id
    LOOP
        SELECT payload INTO base_payload FROM announcement_state_facts
        WHERE tenant_scope_id=requested_scope_id AND fact_type='version'
          AND announcement_id=NEW.id AND announcement_version=NEW.version
        ORDER BY watermark DESC LIMIT 1;
        IF base_payload IS NOT NULL THEN
            base_payload := base_payload || jsonb_build_object(
                'content_format', NEW.content_format, 'link_url', NEW.link_url,
                'sort_order', NEW.sort_order, 'is_visible', NEW.is_visible,
                'is_popup', NEW.is_popup, 'style_red', NEW.style_red, 'style_bold', NEW.style_bold
            );
            next_value := next_announcement_state_watermark(requested_scope_id);
            INSERT INTO announcement_state_facts(
                tenant_scope_id,watermark,fact_type,announcement_id,announcement_version,payload,occurred_at
            ) VALUES(requested_scope_id,next_value,'version',NEW.id,NEW.version,base_payload,NEW.updated_at);
        END IF;
    END LOOP;
    RETURN NEW;
END;
$$;

CREATE TRIGGER zzz_platform_announcements_245_presentation_fact
AFTER UPDATE OF status ON platform_announcements_141
FOR EACH ROW EXECUTE FUNCTION append_platform_announcement_presentation_fact_245();
ALTER TABLE platform_announcements_141 ENABLE ALWAYS TRIGGER platform_announcements_245_presentation_guard;
ALTER TABLE platform_announcements_141 ENABLE ALWAYS TRIGGER zzz_platform_announcements_245_presentation_fact;

DO $runtime_grants_245$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cdnca_control_app') THEN
        GRANT SELECT, INSERT, UPDATE ON platform_announcements_141 TO cdnca_control_app;
    END IF;
END;
$runtime_grants_245$;
