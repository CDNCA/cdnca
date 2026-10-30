package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestOPS14HighRiskOperations183Contract(t *testing.T) {
	predecessorUp := readHighRiskOperationsMigration(t, "182_node_isolation.up.sql")
	predecessorDown := readHighRiskOperationsMigration(t, "182_node_isolation.down.sql")
	upBytes := readHighRiskOperationsMigration(t, "183_high_risk_operations.up.sql")
	downBytes := readHighRiskOperationsMigration(t, "183_high_risk_operations.down.sql")
	up, down := string(upBytes), string(downBytes)

	for _, required := range []string{
		"migration 183 requires the exact verified 182 release head",
		fmt.Sprintf("%x", sha256.Sum256(predecessorUp)),
		fmt.Sprintf("%x", sha256.Sum256(predecessorDown)),
		"CREATE TABLE high_risk_operations",
		"CREATE TABLE high_risk_operation_receipts",
		"scope_id,tenant_id",
		"FOREIGN KEY(scope_id,tenant_id) REFERENCES access_scopes(id,tenant_id)",
		"FOREIGN KEY(tenant_id,job_id) REFERENCES background_jobs(tenant_id,id)",
		"FOREIGN KEY(scope_id,parent_operation_id) REFERENCES high_risk_operations(scope_id,id)",
		"FOREIGN KEY(proposed_by_scope_id,proposed_by) REFERENCES memberships(scope_id,user_id)",
		"FOREIGN KEY(approved_by_scope_id,approved_by) REFERENCES memberships(scope_id,user_id)",
		"system_operations.manage",
		"system_operations.execute",
		"step_up_required",
		"default_credential_remediation",
		"managed_password_reset",
		"node_reregister",
		"control_endpoint_change",
		"disk_cleanup",
		"site_script_removal",
		"pending_approval",
		"approval_base_revision",
		"approval_idempotency_key",
		"proposal_idempotency_key",
		"proposal_digest",
		"health_contract_sha256",
		"high-risk approval facts cannot change after queueing",
		"terminal high-risk execution requires a matching immutable receipt",
		"rollback operation must reverse the same scoped parent references",
		"high-risk operation receipts are append-only",
		"REVOKE ALL ON high_risk_operations,high_risk_operation_receipts FROM PUBLIC",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("183 up missing %q", required)
		}
	}

	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 183 rollback requires the exact verified 183 and 182 release heads",
		upSHA,
		fmt.Sprintf("%x", sha256.Sum256(predecessorUp)),
		fmt.Sprintf("%x", sha256.Sum256(predecessorDown)),
		"rollback would discard high-risk operation, job, receipt, or audit facts",
		"all non-system high-risk operation grants to be removed",
		"DROP TABLE high_risk_operation_receipts",
		"DROP TABLE high_risk_operations",
		"DROP FUNCTION protect_high_risk_operation_183()",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("183 down missing %q", required)
		}
	}
	if strings.Contains(down, "DROP TABLE background_jobs") || strings.Contains(down, "DROP TABLE access_scopes") {
		t.Fatal("183 down must not remove shared authority tables")
	}
}

func readHighRiskOperationsMigration(t *testing.T, name string) []byte {
	t.Helper()
	contents, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}
