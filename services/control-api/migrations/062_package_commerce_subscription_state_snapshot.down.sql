LOCK TABLE package_subscriptions, package_subscription_state_versions,
    package_subscription_state_commit_watermarks
    IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM package_subscription_state_versions)
       OR EXISTS (SELECT 1 FROM package_subscription_state_commit_watermarks) THEN
        RAISE EXCEPTION 'migration 062 rollback requires package subscription state facts to be absent';
    END IF;
END;
$$;

DROP TRIGGER package_subscriptions_capture_state_version ON package_subscriptions;
DROP FUNCTION capture_package_subscription_state_version();
DROP TRIGGER package_subscription_state_versions_no_truncate
    ON package_subscription_state_versions;
DROP TRIGGER package_subscription_state_versions_append_only
    ON package_subscription_state_versions;
DROP TRIGGER package_subscription_state_versions_prepare
    ON package_subscription_state_versions;
DROP FUNCTION prepare_package_subscription_state_version();
DROP TABLE package_subscription_state_commit_watermarks;
DROP TABLE package_subscription_state_versions;
