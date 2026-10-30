package acmeworker

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRecoverableSQLFencesRevokedCertificateAuthority33(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve current test file")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), "pgstore.go"))
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(source), "func (s *PGOperationStore) Recoverable")
	end := strings.Index(string(source), "func hasACMEBinding048")
	if start < 0 || end <= start {
		t.Fatal("isolate PGOperationStore.Recoverable")
	}
	recoverable := string(source[start:end])
	for _, required := range []string{
		"JOIN certificate_orders certificate_order",
		"certificate_order.scope_id=operation.tenant_scope_id",
		"certificate_order.id=operation.certificate_order_id",
		"LEFT JOIN certificate_orders renewal_parent",
		"renewal_parent.scope_id=certificate_order.scope_id",
		"renewal_parent.id=certificate_order.renewal_of_order_id",
		"WHERE ((latest.status='active' AND latest.lease_expires_at <= statement_timestamp())",
		"OR (latest.status='retry_wait' AND latest.next_reconcile_at <= statement_timestamp()))",
		"certificate_order.status IN ('pending','validating','issuing','issued')",
		"certificate_order.renewal_of_order_id IS NULL",
		"renewal_parent.status IN ('active','renewal_due')",
	} {
		if !strings.Contains(recoverable, required) {
			t.Errorf("Recoverable SQL missing certificate authority fence %q", required)
		}
	}
}
