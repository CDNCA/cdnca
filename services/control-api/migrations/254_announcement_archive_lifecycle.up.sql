LOCK TABLE schema_migrations, announcements, announcement_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_254_announcement_archive_lifecycle$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 253 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 253 OR
       NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=253 AND migration_id='253_notification_dispatch_observation'
          AND integrity_state='verified' AND applied_at IS NOT NULL
       ) OR
       EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema=current_schema() AND table_name IN ('announcement_archive_254','announcement_lifecycle_facts_254')) THEN
        RAISE EXCEPTION 'migration 254 requires the exact verified 253 release head and untouched announcement archive schema'
            USING ERRCODE='P2540';
    END IF;
END;
$migration_254_announcement_archive_lifecycle$;

CREATE TABLE announcement_archive_254 (
    tenant_scope_id uuid NOT NULL,
    announcement_id uuid NOT NULL,
    archived boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    archived_at timestamptz,
    archived_by_user_id uuid,
    changed_at timestamptz NOT NULL,
    changed_by_user_id uuid NOT NULL,
    PRIMARY KEY (tenant_scope_id, announcement_id),
    FOREIGN KEY (tenant_scope_id, announcement_id)
        REFERENCES announcements(tenant_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, changed_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, archived_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK ((archived AND archived_at IS NOT NULL AND archived_by_user_id IS NOT NULL)
        OR (NOT archived AND archived_at IS NULL AND archived_by_user_id IS NULL))
);

INSERT INTO announcement_archive_254(
    tenant_scope_id,announcement_id,changed_at,changed_by_user_id
)
SELECT tenant_scope_id,id,created_at,created_by_user_id FROM announcements;

CREATE INDEX announcement_archive_254_scope_state_idx
    ON announcement_archive_254(tenant_scope_id,archived,changed_at DESC,announcement_id DESC);

CREATE TABLE announcement_lifecycle_facts_254 (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    announcement_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    watermark bigint NOT NULL DEFAULT 0 CHECK (watermark >= 0),
    state text NOT NULL CHECK (state IN ('active','archived')),
    actor_user_id uuid NOT NULL,
    occurred_at timestamptz NOT NULL,
    request_id text NOT NULL CHECK (octet_length(request_id) BETWEEN 1 AND 128),
    FOREIGN KEY (tenant_scope_id, announcement_id)
        REFERENCES announcements(tenant_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

INSERT INTO announcement_lifecycle_facts_254(
    id,tenant_scope_id,announcement_id,revision,state,actor_user_id,occurred_at,request_id
)
SELECT gen_random_uuid(),announcement.tenant_scope_id,announcement.id,1,'active',
       announcement.created_by_user_id,announcement.created_at,
       'migration-254-baseline-' || announcement.id::text
FROM announcements announcement;

CREATE INDEX announcement_lifecycle_facts_254_lookup_idx
    ON announcement_lifecycle_facts_254(tenant_scope_id,announcement_id,revision DESC);

CREATE FUNCTION protect_announcement_lifecycle_facts_254()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP IN ('UPDATE','DELETE','TRUNCATE') THEN
        RAISE EXCEPTION 'announcement lifecycle facts are append-only' USING ERRCODE='P2541';
    END IF;
    NEW.watermark := next_announcement_state_watermark(NEW.tenant_scope_id);
    RETURN NEW;
END;
$$;

CREATE TRIGGER announcement_lifecycle_facts_254_append_only
BEFORE INSERT OR UPDATE OR DELETE ON announcement_lifecycle_facts_254
FOR EACH ROW EXECUTE FUNCTION protect_announcement_lifecycle_facts_254();
CREATE TRIGGER announcement_lifecycle_facts_254_no_truncate
BEFORE TRUNCATE ON announcement_lifecycle_facts_254
FOR EACH STATEMENT EXECUTE FUNCTION protect_announcement_lifecycle_facts_254();

ALTER TABLE announcement_write_requests DROP CONSTRAINT announcement_write_requests_operation_141_check;
ALTER TABLE announcement_write_requests ADD CONSTRAINT announcement_write_requests_operation_254_check CHECK (operation IN (
    'announcement.create', 'announcement.update', 'announcement.schedule',
    'announcement.publish', 'announcement.scheduled_publish', 'announcement.revise',
    'announcement.withdraw', 'announcement.archive', 'announcement.restore',
    'announcement.deliver', 'announcement.read',
    'announcement.global.create', 'announcement.global.update',
    'announcement.global.publish', 'announcement.global.withdraw'
));

DO $runtime_grants_254$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='cdnca_control_app') THEN
        GRANT SELECT,INSERT,UPDATE ON announcement_archive_254 TO cdnca_control_app;
        GRANT SELECT,INSERT ON announcement_lifecycle_facts_254 TO cdnca_control_app;
    END IF;
END;
$runtime_grants_254$;
