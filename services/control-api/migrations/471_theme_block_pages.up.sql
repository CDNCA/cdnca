LOCK TABLE schema_migrations, theme_error_pages IN ACCESS EXCLUSIVE MODE;

DO $migration_471_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 470 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 470 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=470 AND
        migration_id='470_security_binding_rebind' AND
        checksum_sha256='8cd9d16c1667942d09a969d3b66e181756e06817c3c8497a29aeae543cff4a67' AND
        down_checksum_sha256='b721fc75a3ea289c21582f1890bfd00b3292c8a6929b74821b743a32e0aa02b1' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 471 requires the exact verified 470 release head' USING ERRCODE='P4710';
    END IF;
END;
$migration_471_up$;

-- 471 (sec-followup P13): a theme renders the node's own block pages too,
-- edge_route 403 (WAF / ACL / ban block) and 429 (CC / rate limit), so a
-- request the node refuses gets the platform's branded page instead of the
-- bare OpenResty one. The 360 category check and the 391 status check are
-- replaced; the 360 one is unnamed and found by its definition.
DO $migration_471_category$
DECLARE check_name name;
BEGIN
    SELECT conname INTO check_name FROM pg_constraint
    WHERE conrelid = 'theme_error_pages'::regclass AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%category%edge_connect%no_host%unknown_site%'
      AND pg_get_constraintdef(oid) NOT LIKE '%status_code%';
    IF check_name IS NULL THEN
        RAISE EXCEPTION 'migration 471: the 360 theme error page category check is missing' USING ERRCODE='P4711';
    END IF;
    EXECUTE format('ALTER TABLE theme_error_pages DROP CONSTRAINT %I', check_name);
END;
$migration_471_category$;

ALTER TABLE theme_error_pages DROP CONSTRAINT theme_error_pages_status_391;
ALTER TABLE theme_error_pages ADD CONSTRAINT theme_error_pages_category_471
    CHECK (category IN ('edge_connect', 'edge_route', 'no_host', 'unknown_site'));
ALTER TABLE theme_error_pages ADD CONSTRAINT theme_error_pages_status_471 CHECK (
    (category = 'edge_connect' AND status_code IN (502, 503, 504)) OR
    (category = 'edge_route' AND status_code IN (403, 429)) OR
    (category = 'no_host' AND status_code = 400) OR
    (category = 'unknown_site' AND status_code IN (403, 404, 410, 421))
);
