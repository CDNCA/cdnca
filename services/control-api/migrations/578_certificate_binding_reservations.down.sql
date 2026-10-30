-- 578 回退：删绑定预留号表，绑定事实守卫回到 039（下一号 = 最新事实+1），续签下发状态去掉 superseded_by_user。
LOCK TABLE schema_migrations, certificate_renewal_deliveries, certificate_site_binding_facts,
    certificate_site_binding_reservations IN ACCESS EXCLUSIVE MODE;

DO $migration_578_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 578 OR
       (SELECT max(version) FROM schema_migrations) <> 578 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=578 AND
        migration_id='578_certificate_binding_reservations' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 578 down requires the exact verified migration head' USING ERRCODE='P5782';
    END IF;
    -- 039 的守卫要求绑定号连续：有续签占过号（可能已跳号）就不能回退。
    IF EXISTS (SELECT 1 FROM certificate_site_binding_reservations) THEN
        RAISE EXCEPTION 'migration 578 down: certificate binding reservations exist' USING ERRCODE='P5783';
    END IF;
    IF EXISTS (SELECT 1 FROM certificate_renewal_deliveries WHERE state = 'superseded_by_user') THEN
        RAISE EXCEPTION 'migration 578 down: superseded renewal deliveries exist' USING ERRCODE='P5784';
    END IF;
END;
$migration_578_down$;

CREATE OR REPLACE FUNCTION protect_certificate_site_binding()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    site_scope_id uuid;
    site_deleted_at timestamptz;
    site_domain text;
    expected_sequence bigint;
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
    SELECT COALESCE(max(sequence), 0) + 1 INTO expected_sequence
    FROM certificate_site_binding_facts
    WHERE tenant_scope_id = NEW.tenant_scope_id AND site_id = NEW.site_id;
    SELECT action, asset_id, version_id, is_default
      INTO previous_action, previous_asset_id, previous_version_id, previous_default
    FROM certificate_site_binding_facts
    WHERE tenant_scope_id = NEW.tenant_scope_id AND site_id = NEW.site_id
    ORDER BY sequence DESC LIMIT 1;
    IF NEW.sequence <> expected_sequence OR NEW.expected_revision <> expected_sequence - 1 THEN
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
DROP TABLE certificate_site_binding_reservations;
DROP FUNCTION protect_certificate_site_binding_reservation_578();

DROP INDEX certificate_renewal_deliveries_due_578_idx;
CREATE INDEX certificate_renewal_deliveries_due_570_idx
    ON certificate_renewal_deliveries(next_attempt_at) WHERE state IN ('delivering', 'retry_wait');
DO $migration_578_down_state$
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
        '(state IN (''delivering'', ''retry_wait'', ''activated'', ''skipped'', ''failed''))',
        state_check, state_check);
    EXECUTE format('ALTER TABLE certificate_renewal_deliveries DROP CONSTRAINT %I, ADD CONSTRAINT %I CHECK '
        '(state NOT IN (''retry_wait'', ''skipped'', ''failed'') OR failure_code IS NOT NULL)',
        failure_check, failure_check);
END;
$migration_578_down_state$;
