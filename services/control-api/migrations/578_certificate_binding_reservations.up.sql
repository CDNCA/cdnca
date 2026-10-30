-- 578（fix-dnscert4 增量，fix-mig570split 从 570 拆出）：用户改动优先于在途的自动续签下发。
-- ①续签下发占用的绑定版本号（certificate_site_binding_reservations）：用户改绑/发布跳过已占号；
-- ②用户改绑时撤销在途续签下发（certificate_renewal_deliveries.state 加 superseded_by_user），之后按新绑定重新调度；
-- ③039 的绑定事实守卫 protect_certificate_site_binding() 改为认预留号。
-- 570 已在线上应用（73 schema 574），不得原地修改，增量一律走新号。前驱 577（market_node_delivery_state），守卫钉 577 校验和。
LOCK TABLE schema_migrations, certificate_renewal_deliveries, certificate_site_binding_facts IN ACCESS EXCLUSIVE MODE;

DO $migration_578_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 577 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 577 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=577 AND
        migration_id='577_market_node_delivery_state' AND
        checksum_sha256='5b9876a08e2db27cc541ca2cbefc8df9bf8dfa52d41e2e3a6a0922104c301875' AND
        down_checksum_sha256='f464ba85a833ade3b0eb4e2e1c926a9eda39da504d88a2565bc0f2acedd48e83' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('certificate_site_binding_reservations') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 578 requires the exact verified 577 release head' USING ERRCODE='P5780';
    END IF;
END;
$migration_578_up$;

-- 570 的两条状态 CHECK 是自动命名的：按定义找到原名，删掉后用同名重建（down 同样按名还原）。
-- state 加 superseded_by_user（fix-dnscert4：用户改绑或发布了其中的站点，本轮下发已撤销，按用户新绑定重新调度）。
DO $migration_578_state$
DECLARE
    state_check text;
    failure_check text;
BEGIN
    SELECT conname INTO STRICT state_check FROM pg_constraint
    WHERE conrelid = 'certificate_renewal_deliveries'::regclass AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%''activated''%';
    SELECT conname INTO STRICT failure_check FROM pg_constraint
    WHERE conrelid = 'certificate_renewal_deliveries'::regclass AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%''retry_wait''%' AND pg_get_constraintdef(oid) LIKE '%failure_code IS NOT NULL%';
    EXECUTE format('ALTER TABLE certificate_renewal_deliveries DROP CONSTRAINT %I, ADD CONSTRAINT %I CHECK '
        '(state IN (''delivering'', ''retry_wait'', ''activated'', ''skipped'', ''failed'', ''superseded_by_user''))',
        state_check, state_check);
    EXECUTE format('ALTER TABLE certificate_renewal_deliveries DROP CONSTRAINT %I, ADD CONSTRAINT %I CHECK '
        '(state NOT IN (''retry_wait'', ''skipped'', ''failed'', ''superseded_by_user'') OR failure_code IS NOT NULL)',
        failure_check, failure_check);
END;
$migration_578_state$;
DROP INDEX certificate_renewal_deliveries_due_570_idx;
CREATE INDEX certificate_renewal_deliveries_due_578_idx
    ON certificate_renewal_deliveries(next_attempt_at) WHERE state IN ('delivering', 'retry_wait', 'superseded_by_user');

-- fix-dnscert4：续签下发占用的绑定版本号。一站一行，记最高已占号与占用它的续签请求（只增不减、不删）。
-- 节点按站点绑定版本号排序证书（同号不同版本即冲突），续签下发途中新版本已到部分节点；用户此后改绑/发布
-- 从 greatest(最新绑定事实, 已占号)+1 取号，不会与节点上已有的续签版本同号。续签自己切换时写回它占的号。
CREATE TABLE certificate_site_binding_reservations (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    reserved_revision bigint NOT NULL CHECK (reserved_revision > 0),
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128 AND request_id = btrim(request_id) AND request_id !~ '[[:cntrl:]]'
    ),
    reserved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_scope_id, site_id)
);

CREATE FUNCTION protect_certificate_site_binding_reservation_578()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'UPDATE' OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id OR
       NEW.site_id IS DISTINCT FROM OLD.site_id OR NEW.reserved_revision < OLD.reserved_revision THEN
        RAISE EXCEPTION 'certificate binding reservations only advance' USING ERRCODE='P5781';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER certificate_site_binding_reservations_protect_578
BEFORE UPDATE OR DELETE ON certificate_site_binding_reservations
FOR EACH ROW EXECUTE FUNCTION protect_certificate_site_binding_reservation_578();
CREATE TRIGGER certificate_site_binding_reservations_no_truncate_578
BEFORE TRUNCATE ON certificate_site_binding_reservations
FOR EACH STATEMENT EXECUTE FUNCTION protect_certificate_site_binding_reservation_578();

GRANT SELECT, INSERT, UPDATE ON certificate_site_binding_reservations TO cdnca_control_app, cdnca_control_runtime;

-- 039 的绑定事实守卫改为认预留号：下一号 = greatest(最新事实, 已占号)+1；占号的续签请求可写回它占的号
-- （须高于最新事实）。expected_revision 仍是 sequence-1（跳过的号没有事实）。其余校验与 039 相同。
CREATE OR REPLACE FUNCTION protect_certificate_site_binding()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    site_scope_id uuid;
    site_deleted_at timestamptz;
    site_domain text;
    latest_sequence bigint;
    reserved bigint;
    reserved_by text;
    previous_action text;
    previous_asset_id uuid;
    previous_version_id uuid;
    previous_default boolean;
    asset_deleted_at timestamptz;
    version_not_after timestamptz;
    version_sans text[];
    active_version_id uuid;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'certificate site binding facts are immutable';
    END IF;
    SELECT scope_id, deleted_at, domain INTO site_scope_id, site_deleted_at, site_domain
    FROM sites WHERE id = NEW.site_id;
    IF site_scope_id IS DISTINCT FROM NEW.tenant_scope_id OR site_deleted_at IS NOT NULL THEN
        RAISE EXCEPTION 'certificate binding site scope is invalid';
    END IF;
    SELECT COALESCE(max(sequence), 0) INTO latest_sequence
    FROM certificate_site_binding_facts
    WHERE tenant_scope_id = NEW.tenant_scope_id AND site_id = NEW.site_id;
    SELECT reserved_revision, request_id INTO reserved, reserved_by
    FROM certificate_site_binding_reservations
    WHERE tenant_scope_id = NEW.tenant_scope_id AND site_id = NEW.site_id;
    SELECT action, asset_id, version_id, is_default
      INTO previous_action, previous_asset_id, previous_version_id, previous_default
    FROM certificate_site_binding_facts
    WHERE tenant_scope_id = NEW.tenant_scope_id AND site_id = NEW.site_id
    ORDER BY sequence DESC LIMIT 1;
    IF NOT (NEW.sequence = GREATEST(latest_sequence, COALESCE(reserved, 0)) + 1 OR
            (NEW.sequence = reserved AND reserved > latest_sequence AND NEW.request_id = reserved_by))
       OR NEW.expected_revision <> NEW.sequence - 1 THEN
        RAISE EXCEPTION 'certificate binding revision is invalid';
    END IF;
    IF NEW.action = 'unbind' THEN
        IF previous_action IS DISTINCT FROM 'bind'
           OR NEW.asset_id IS DISTINCT FROM previous_asset_id
           OR NEW.version_id IS DISTINCT FROM previous_version_id
           OR NEW.is_default IS DISTINCT FROM previous_default THEN
            RAISE EXCEPTION 'certificate unbind fact does not match current binding';
        END IF;
        RETURN NEW;
    END IF;
    SELECT deleted_at INTO asset_deleted_at
    FROM certificate_assets
    WHERE tenant_scope_id = NEW.tenant_scope_id AND id = NEW.asset_id;
    SELECT not_after, sans INTO version_not_after, version_sans
    FROM certificate_asset_versions
    WHERE tenant_scope_id = NEW.tenant_scope_id AND asset_id = NEW.asset_id AND id = NEW.version_id;
    SELECT version_id INTO active_version_id
    FROM certificate_asset_activation_facts
    WHERE tenant_scope_id = NEW.tenant_scope_id AND asset_id = NEW.asset_id
    ORDER BY sequence DESC LIMIT 1;
    IF asset_deleted_at IS NOT NULL OR version_not_after IS NULL OR version_not_after <= NEW.changed_at
       OR NOT certificate_asset_domain_covered(version_sans, site_domain)
       OR active_version_id IS DISTINCT FROM NEW.version_id
       OR EXISTS (
           SELECT 1 FROM certificate_asset_revocation_facts
           WHERE tenant_scope_id = NEW.tenant_scope_id
             AND asset_id = NEW.asset_id AND version_id = NEW.version_id
       ) THEN
        RAISE EXCEPTION 'certificate binding requires a live active version';
    END IF;
    RETURN NEW;
END;
$$;
