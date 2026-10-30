LOCK TABLE schema_migrations, rule_pack_enablements, site_security_mounts IN ACCESS EXCLUSIVE MODE;

DO $migration_454_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 453 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 453 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=453 AND
        migration_id='453_origin_follow_redirect' AND
        checksum_sha256='dd662c6010efd183e056c42688b6a80ca464e33846de259d4ec590e90c76fc6b' AND
        down_checksum_sha256='60b8427fa5730fbb9765fa97e0ff8e736e2f77e8155707b4990ba8a92d8f8318' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 454 requires the exact verified 453 release head' USING ERRCODE='P4540';
    END IF;
END;
$migration_454_up$;

-- 454 (r136 waf-php2shell; placeholder number, renumbered on merge). Official
-- virtual patch packs (system/waf-php-vpatch) are on by default: the control
-- plane's own platform row (no user, 419) may now be state enabled as well as
-- inherit, still open to lower levels (a tenant or site switches it off or
-- tunes its parameters). When such a pack arrives or changes version the
-- control plane recomputes every site's mounts itself, so those rows have no
-- publishing user either.
ALTER TABLE rule_pack_enablements
    DROP CONSTRAINT rule_pack_enablements_system_row_419,
    ADD CONSTRAINT rule_pack_enablements_system_row_454 CHECK (updated_by_user_id IS NOT NULL OR
        level = 'platform' AND rule_id IS NULL AND state IN ('inherit', 'enabled') AND allow_lower AND
        priority IS NULL AND params IS NULL);
ALTER TABLE site_security_mounts ALTER COLUMN published_by_user_id DROP NOT NULL;
