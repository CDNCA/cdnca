-- Requires the verified 257 ACL with no intervening external ACL changes.
-- Preserve unrelated grants and report rows; dependent grants must block rollback.
REVOKE SELECT, INSERT, UPDATE ON waf_custom_rule_report_state FROM cdnca_control_app RESTRICT;
