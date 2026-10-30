LOCK TABLE schema_migrations, permissions, role_permissions, plugin_security_advisories,
    plugin_security_advisory_acks IN ACCESS EXCLUSIVE MODE;

DO $migration_296_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 296 OR
       (SELECT max(version) FROM schema_migrations) <> 296 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=296 AND
        migration_id='296_market_buyer' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 296 down requires the exact verified migration head' USING ERRCODE='P2962';
    END IF;
    -- Acknowledgements cannot be expressed before 296; refuse instead of
    -- silently dropping them.
    IF EXISTS (SELECT 1 FROM plugin_security_advisory_acks) THEN
        RAISE EXCEPTION 'migration 296 down refused: advisory acknowledgements exist'
            USING ERRCODE='P2963';
    END IF;
END;
$migration_296_down$;

DROP TRIGGER plugin_security_advisory_acks_no_truncate_296 ON plugin_security_advisory_acks;
DROP TRIGGER plugin_security_advisory_acks_protect_296 ON plugin_security_advisory_acks;
DROP TABLE plugin_security_advisory_acks;
DROP FUNCTION protect_plugin_advisory_ack_296();
DROP TABLE plugin_security_advisories;

DELETE FROM role_permissions WHERE permission_name IN ('marketplace.browse','marketplace.purchase','marketplace.sell');
DELETE FROM permissions WHERE name IN ('marketplace.browse','marketplace.purchase','marketplace.sell');
