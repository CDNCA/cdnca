LOCK TABLE schema_migrations, platform_announcements_141, platform_announcement_recipients_141,
    announcement_state_watermarks, announcement_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_255$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 254 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 254 OR
       NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=254
           AND migration_id='254_announcement_archive_lifecycle'
           AND checksum_sha256='27753a49a290dd4e66c3455f239365f9181d068875776473067ad34af27e5bdb'
           AND down_checksum_sha256='5c20769769af5607ede0b8febc20bd63b0906ce7810bf45fb724210b26bd774f'
           AND integrity_state='verified' AND applied_at IS NOT NULL) OR
       to_regclass(current_schema() || '.platform_announcement_archive_255') IS NOT NULL OR
       to_regclass(current_schema() || '.platform_announcement_snapshots_255') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 255 requires the exact verified 254 release head' USING ERRCODE='P2550';
    END IF;
END;
$migration_255$;

ALTER TABLE platform_announcements_141 ADD CONSTRAINT platform_announcements_255_scope_id_key
    UNIQUE (platform_scope_id,id);

CREATE TABLE platform_announcement_archive_255 (
    platform_scope_id uuid NOT NULL,
    announcement_id uuid NOT NULL,
    archived boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    archived_at timestamptz,
    archived_by_user_id uuid,
    changed_at timestamptz NOT NULL CHECK (isfinite(changed_at)),
    changed_by_user_id uuid NOT NULL,
    PRIMARY KEY (platform_scope_id,announcement_id),
    FOREIGN KEY (platform_scope_id,announcement_id) REFERENCES platform_announcements_141(platform_scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (platform_scope_id,changed_by_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    FOREIGN KEY (platform_scope_id,archived_by_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    CHECK ((archived AND archived_at IS NOT NULL AND isfinite(archived_at) AND archived_by_user_id IS NOT NULL)
        OR (NOT archived AND archived_at IS NULL AND archived_by_user_id IS NULL))
);

INSERT INTO platform_announcement_archive_255(platform_scope_id,announcement_id,changed_at,changed_by_user_id)
SELECT platform_scope_id,id,updated_at,created_by_user_id FROM platform_announcements_141;

CREATE TABLE platform_announcement_snapshots_255 (
    platform_scope_id uuid NOT NULL,
    announcement_id uuid NOT NULL,
    watermark bigint NOT NULL DEFAULT 0 CHECK (watermark >= 0),
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload)='object'),
    baseline boolean NOT NULL DEFAULT false,
    PRIMARY KEY (platform_scope_id,announcement_id,watermark),
    FOREIGN KEY (platform_scope_id,announcement_id) REFERENCES platform_announcements_141(platform_scope_id,id) ON DELETE RESTRICT
);
CREATE INDEX platform_announcement_snapshots_255_watermark_idx
    ON platform_announcement_snapshots_255(platform_scope_id,watermark,announcement_id);

CREATE FUNCTION platform_announcement_snapshot_255(requested_id uuid)
RETURNS jsonb LANGUAGE sql AS $$
    SELECT jsonb_strip_nulls(jsonb_build_object(
        'id',item.id,'platform_scope_id',item.platform_scope_id,'version',item.version,'revision',item.revision,
        'status',item.status,'title',item.title,'body',item.body,'format',item.content_format,'link_url',item.link_url,
        'sort_order',item.sort_order,'visible',item.is_visible,'popup',item.is_popup,'red',item.style_red,'bold',item.style_bold,
        'audience',item.audience,'withdrawal_visibility',item.withdrawal_visibility,
        'recipient_count',(SELECT count(*) FROM platform_announcement_recipients_141 WHERE announcement_id=item.id),
        'published_at',item.published_at,'withdrawn_at',item.withdrawn_at,'created_at',item.created_at,
        'state_changed_at',greatest(item.updated_at,archive.changed_at),
        'archived',archive.archived,'lifecycle_revision',archive.revision,'archived_at',archive.archived_at
    ))
    FROM platform_announcements_141 item JOIN platform_announcement_archive_255 archive
        ON archive.platform_scope_id=item.platform_scope_id AND archive.announcement_id=item.id
    WHERE item.id=requested_id;
$$;

INSERT INTO platform_announcement_snapshots_255(platform_scope_id,announcement_id,payload,baseline)
SELECT platform_scope_id,id,platform_announcement_snapshot_255(id),true FROM platform_announcements_141;

CREATE FUNCTION protect_platform_announcement_snapshot_255()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' OR pg_trigger_depth() < 2 THEN
        RAISE EXCEPTION 'global announcement snapshots are trigger-owned append-only facts' USING ERRCODE='P2551';
    END IF;
    NEW.watermark := next_announcement_state_watermark(NEW.platform_scope_id);
    NEW.baseline := false;
    RETURN NEW;
END;
$$;
CREATE TRIGGER platform_announcement_snapshots_255_guard
BEFORE INSERT OR UPDATE OR DELETE ON platform_announcement_snapshots_255
FOR EACH ROW EXECUTE FUNCTION protect_platform_announcement_snapshot_255();
CREATE TRIGGER platform_announcement_snapshots_255_no_truncate
BEFORE TRUNCATE ON platform_announcement_snapshots_255
FOR EACH STATEMENT EXECUTE FUNCTION protect_platform_announcement_snapshot_255();

CREATE FUNCTION protect_platform_announcement_archive_255()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE') THEN
        RAISE EXCEPTION 'global announcement archive history cannot be removed' USING ERRCODE='P2552';
    END IF;
    IF TG_OP='INSERT' THEN
        IF pg_trigger_depth() < 2 OR NEW.archived OR NEW.revision <> 1 THEN
            RAISE EXCEPTION 'global announcement archive must start active' USING ERRCODE='P2552';
        END IF;
    ELSIF NEW.platform_scope_id IS DISTINCT FROM OLD.platform_scope_id
       OR NEW.announcement_id IS DISTINCT FROM OLD.announcement_id OR NEW.revision <> OLD.revision+1
       OR NEW.archived=OLD.archived OR NEW.changed_at < OLD.changed_at
       OR (NEW.archived AND (NEW.archived_at IS DISTINCT FROM NEW.changed_at
            OR NEW.archived_by_user_id IS DISTINCT FROM NEW.changed_by_user_id)) THEN
        RAISE EXCEPTION 'invalid global announcement archive transition' USING ERRCODE='P2552';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER platform_announcement_archive_255_guard
BEFORE INSERT OR UPDATE OR DELETE ON platform_announcement_archive_255
FOR EACH ROW EXECUTE FUNCTION protect_platform_announcement_archive_255();
CREATE TRIGGER platform_announcement_archive_255_no_truncate
BEFORE TRUNCATE ON platform_announcement_archive_255
FOR EACH STATEMENT EXECUTE FUNCTION protect_platform_announcement_archive_255();

CREATE FUNCTION guard_archived_global_announcement_255()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status='draft' AND EXISTS(SELECT 1 FROM platform_announcement_archive_255
        WHERE platform_scope_id=OLD.platform_scope_id AND announcement_id=OLD.id AND archived) THEN
        RAISE EXCEPTION 'restore the global announcement before editing or publishing' USING ERRCODE='P2554';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER platform_announcements_255_archive_guard
BEFORE UPDATE ON platform_announcements_141 FOR EACH ROW EXECUTE FUNCTION guard_archived_global_announcement_255();

CREATE FUNCTION capture_global_announcement_255()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE requested_id uuid;
BEGIN
    IF TG_TABLE_NAME='platform_announcements_141' THEN
        requested_id := NEW.id;
        IF TG_OP='INSERT' THEN
            INSERT INTO platform_announcement_archive_255(platform_scope_id,announcement_id,changed_at,changed_by_user_id)
            VALUES(NEW.platform_scope_id,NEW.id,NEW.created_at,NEW.created_by_user_id);
        END IF;
    ELSE
        requested_id := NEW.announcement_id;
    END IF;
    INSERT INTO platform_announcement_snapshots_255(platform_scope_id,announcement_id,payload)
    SELECT platform_scope_id,id,platform_announcement_snapshot_255(id) FROM platform_announcements_141 WHERE id=requested_id;
    RETURN NEW;
END;
$$;
CREATE TRIGGER zzzz_platform_announcements_255_snapshot
AFTER INSERT OR UPDATE ON platform_announcements_141 FOR EACH ROW EXECUTE FUNCTION capture_global_announcement_255();
CREATE TRIGGER platform_announcement_archive_255_snapshot
AFTER UPDATE ON platform_announcement_archive_255 FOR EACH ROW EXECUTE FUNCTION capture_global_announcement_255();

ALTER TABLE platform_announcement_snapshots_255 ENABLE ALWAYS TRIGGER platform_announcement_snapshots_255_guard;
ALTER TABLE platform_announcement_snapshots_255 ENABLE ALWAYS TRIGGER platform_announcement_snapshots_255_no_truncate;
ALTER TABLE platform_announcement_archive_255 ENABLE ALWAYS TRIGGER platform_announcement_archive_255_guard;
ALTER TABLE platform_announcement_archive_255 ENABLE ALWAYS TRIGGER platform_announcement_archive_255_no_truncate;
ALTER TABLE platform_announcement_archive_255 ENABLE ALWAYS TRIGGER platform_announcement_archive_255_snapshot;
ALTER TABLE platform_announcements_141 ENABLE ALWAYS TRIGGER platform_announcements_255_archive_guard;
ALTER TABLE platform_announcements_141 ENABLE ALWAYS TRIGGER zzzz_platform_announcements_255_snapshot;

ALTER TABLE announcement_write_requests DROP CONSTRAINT announcement_write_requests_operation_254_check;
ALTER TABLE announcement_write_requests ADD CONSTRAINT announcement_write_requests_operation_255_check CHECK (operation IN (
    'announcement.create','announcement.update','announcement.schedule','announcement.publish','announcement.scheduled_publish',
    'announcement.revise','announcement.withdraw','announcement.archive','announcement.restore','announcement.deliver','announcement.read',
    'announcement.global.create','announcement.global.update','announcement.global.publish','announcement.global.withdraw',
    'announcement.global.archive','announcement.global.restore'
));

DO $runtime_grants_255$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='cdnca_control_app') THEN
        GRANT SELECT,INSERT,UPDATE ON platform_announcement_archive_255 TO cdnca_control_app;
        GRANT SELECT,INSERT ON platform_announcement_snapshots_255 TO cdnca_control_app;
        GRANT SELECT,INSERT,UPDATE ON announcement_state_watermarks TO cdnca_control_app;
        GRANT EXECUTE ON FUNCTION next_announcement_state_watermark(uuid) TO cdnca_control_app;
    END IF;
END;
$runtime_grants_255$;
