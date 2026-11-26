-- 698（前驱 697_analytics_log_export_downloads）。
-- 订阅暂停只有两条写入路径：计费对接 service.suspend（bridgelocal，NewBridgeActor）与管理员已售套餐「暂停」。
-- 暂停来源随暂停版本行的快照写入（snapshot.suspend_source，Go 侧 Subscription.SuspendSource）；
-- 698 之前的暂停版本没有这个键，按同一订阅的计费对接 suspend 请求是否覆盖暂停时刻推导，否则为管理员。
-- package_subscription_suspend_source_698 供订阅与网站读取共用；未暂停时为 NULL。
-- 错误码：头检查 P6980；down 头检查 P6981。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_698_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 697 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 697 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=697 AND
        migration_id='697_analytics_log_export_downloads' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure('package_subscription_suspend_source_698(uuid)') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 698 requires the exact verified 697 release head' USING ERRCODE='P6980';
    END IF;
END;
$migration_698_up$;

CREATE FUNCTION package_subscription_suspend_source_698(target_subscription_id uuid) RETURNS text
LANGUAGE sql STABLE AS $$
    SELECT CASE WHEN subscription.suspended_at IS NULL THEN NULL ELSE COALESCE(
        (SELECT version.snapshot->>'suspend_source' FROM package_subscription_versions version
          WHERE version.subscription_id=subscription.id AND version.operation='suspend'
            AND version.created_at=subscription.suspended_at
            AND version.snapshot->>'suspend_source' IN ('billing_bridge','admin')
          ORDER BY version.revision DESC LIMIT 1),
        (SELECT 'billing_bridge' WHERE EXISTS (
            SELECT 1 FROM billing_bridge_requests request
            JOIN billing_bridge_services service ON service.id=request.service_id
            WHERE service.subscription_id=subscription.id AND request.action='suspend'
              AND request.created_at<=subscription.suspended_at
              AND (request.completed_at IS NULL OR request.completed_at>=subscription.suspended_at))),
        'admin') END
    FROM package_subscriptions subscription WHERE subscription.id=target_subscription_id
$$;

REVOKE ALL ON FUNCTION package_subscription_suspend_source_698(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION package_subscription_suspend_source_698(uuid) TO cdnca_control_app, cdnca_control_runtime;
