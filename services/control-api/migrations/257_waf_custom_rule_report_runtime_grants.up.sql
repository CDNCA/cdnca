-- The full migration chain requires this externally provisioned runtime role.
-- Reject overlapping direct grants so down can remove only this migration's grants.
DO $waf_report_runtime_grants_257$
DECLARE
    runtime_role oid := to_regrole('cdnca_control_app');
BEGIN
    IF runtime_role IS NULL THEN
        RAISE EXCEPTION 'migration 257 requires the provisioned cdnca_control_app role'
            USING ERRCODE = '42704';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_class relation
        CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl, acldefault('r', relation.relowner))) acl
        WHERE relation.oid = 'waf_custom_rule_report_state'::regclass
          AND acl.grantee = runtime_role
          AND acl.privilege_type IN ('SELECT', 'INSERT', 'UPDATE')
    ) THEN
        RAISE EXCEPTION 'migration 257 requires review of existing cdnca_control_app WAF report SELECT, INSERT or UPDATE grants'
            USING ERRCODE = 'P2571';
    END IF;
END;
$waf_report_runtime_grants_257$;

GRANT SELECT, INSERT, UPDATE ON waf_custom_rule_report_state TO cdnca_control_app;
